// device_fpga.c : hyper-reV UDP DMA implementation
// ============================================================================
// [hyper-reV] 원본 device_fpga.c(~4000줄, 물리 FPGA USB)를 완전 교체
// 목적: "-device fpga" 사용하는 모든 프로그램이 자동으로 hyper-reV HV에 UDP 연결
// 장점: leechcore.dll 하나만 교체하면 됨 (외부 플러그인 DLL 불필요)
//
// 동작 흐름:
//   1. 프로그램이 "-device fpga" 또는 "fpga://IP:PORT" 로 호출
//   2. leechcore.c의 LcCreate_FetchDevice()가 DeviceFPGA_Open() 호출
//   3. DeviceFPGA_Open()이 hvdma.ini에서 IP 읽거나 파라미터에서 IP 파싱
//   4. UDP 소켓으로 타겟 PC의 hyper-reV HV에 연결
//   5. ReadScatter/WriteScatter 콜백이 UDP DMA 프로토콜로 메모리 읽기/쓰기
//
// 연결 방법:
//   fpga                         → hvdma.ini에서 IP 읽기
//   fpga://192.168.1.100         → 직접 IP 지정 (포트: 28473)
//   fpga://192.168.1.100:28473   → IP:PORT 직접 지정
//
// 필요 파일: leechcore.dll 옆에 hvdma.ini (타겟 IP 한 줄)
// ============================================================================

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#include "leechcore.h"
#include "leechcore_device.h"
#include "leechcore_internal.h"

// ============================================================================
// DMA 프로토콜 정의 (HV dma_protocol.h 와 동일)
// 핵심: magic=0x48564430("HVD0"), UDP 기반 scatter read/write
// ============================================================================

#define DMA_PROTOCOL_MAGIC      0x48564430      // "HVD0"
#define DMA_PROTOCOL_VERSION    0x0001
#define DMA_MAX_SCATTER_SIZE    0x1000
#define DMA_MAX_SCATTER_COUNT   0x1000

// 메시지 타입 (HV dma_protocol.h msg_type_t 와 동일)
#define DMA_MSG_PING_REQ            0x01
#define DMA_MSG_PING_RSP            0x02
#define DMA_MSG_OPEN_REQ            0x03
#define DMA_MSG_OPEN_RSP            0x04
#define DMA_MSG_CLOSE_REQ           0x05
#define DMA_MSG_CLOSE_RSP           0x06
#define DMA_MSG_READ_SCATTER_REQ    0x07
#define DMA_MSG_READ_SCATTER_RSP    0x08
#define DMA_MSG_WRITE_SCATTER_REQ   0x09
#define DMA_MSG_WRITE_SCATTER_RSP   0x0A
#define DMA_MSG_KEEPALIVE_REQ       0x11
#define DMA_MSG_KEEPALIVE_RSP       0x12

#pragma pack(push, 1)

// 공통 헤더 (16B) - 모든 DMA 메시지 앞에 붙음
typedef struct tdDMA_MSG_HDR {
    DWORD   magic;          // DMA_PROTOCOL_MAGIC
    DWORD   cb_msg;         // 전체 메시지 크기
    WORD    type;           // 메시지 타입
    WORD    version;        // DMA_PROTOCOL_VERSION
    DWORD   session_id;     // 세션 ID
} DMA_MSG_HDR, * PDMA_MSG_HDR;

// Scatter 공통 헤더 (8B)
typedef struct tdDMA_SCATTER_HDR {
    DWORD   count;          // scatter 엔트리 수
    DWORD   cb_total;       // 전체 데이터 크기
} DMA_SCATTER_HDR, * PDMA_SCATTER_HDR;

// Scatter 엔트리 (16B) - HV scatter_entry_t 와 동일
typedef struct tdDMA_SCATTER_ENTRY {
    QWORD   qw_addr;        // Guest Physical Address
    DWORD   cb;             // 크기
    DWORD   f;              // 플래그
} DMA_SCATTER_ENTRY, * PDMA_SCATTER_ENTRY;

// Open 응답 데이터
typedef struct tdDMA_OPEN_RSP_DATA {
    QWORD   pa_max;         // Guest 최대 물리주소
    DWORD   success;        // 성공 여부
    DWORD   flags;          // 플래그
} DMA_OPEN_RSP_DATA, * PDMA_OPEN_RSP_DATA;

// Write 결과
typedef struct tdDMA_WRITE_RESULT {
    DWORD   f;              // =1이면 성공
} DMA_WRITE_RESULT, * PDMA_WRITE_RESULT;

#pragma pack(pop)

// [핵심] 컴파일 타임 검증 - sizeof 불일치시 빌드 실패
// sizeof(DMA_MSG_HDR) != 16 이면 pragma pack 미적용 또는 타입 크기 오류
// C11 static_assert 대신 범용 typedef 트릭 사용 (모든 C 컴파일러 호환)
typedef char _check_sizeof_DMA_MSG_HDR[sizeof(DMA_MSG_HDR) == 16 ? 1 : -1];
typedef char _check_sizeof_DMA_SCATTER_HDR[sizeof(DMA_SCATTER_HDR) == 8 ? 1 : -1];
typedef char _check_sizeof_DMA_SCATTER_ENTRY[sizeof(DMA_SCATTER_ENTRY) == 16 ? 1 : -1];

// ============================================================================
// 내부 컨텍스트 구조체
// 핵심: SOCKET + session_id + pa_max + 버퍼
// ============================================================================

typedef struct tdHVDMA_CONTEXT {
    SOCKET      sock;               // UDP 소켓 (connected)
    DWORD       session_id;         // 세션 ID
    QWORD       pa_max;             // Guest 최대 물리주소
    BOOL        is_connected;       // 연결 상태
    BYTE* send_buf;           // 송신 버퍼
    DWORD       send_buf_size;
    BYTE* recv_buf;           // 수신 버퍼
    DWORD       recv_buf_size;
    CRITICAL_SECTION lock;          // 동기화
    // [v10.4] All-Slot Fill 975중복 패킷 필터링용
    // HV response_seq는 매 응답마다 증가 → 이전 seq의 chunk는 stale
    DWORD       last_accepted_seq;  // 마지막 수락한 response_seq
} HVDMA_CONTEXT, * PHVDMA_CONTEXT;

#define HVDMA_DEFAULT_PORT  28473

// [핵심] 버퍼 크기: CHUNK_SIZE=32 → 한 VMEXIT에서 응답 완료
// ============================================================================
// v4: CHUNK=32 → 89 UDP frames → 1 VMEXIT 완료 → 99.20 MB/s
// v5a: 동일 CHUNK=32 + TDBAL reprogramming + keepalive
//      CHUNK=64 시도 → 178 frames burst 중 OS Q1 kill로 실패
//      32로 유지, 안정성 우선 확인
// ============================================================================
#define HVDMA_BUF_SIZE      (2 * 1024 * 1024)   // 2MB

#define HVDMA_CHUNK_SIZE    32  // multi-buffer batch TX 후 재평가 예정

// [v5] 파이프라이닝: single buffer → W=1 (stop-and-wait)
// dual-buffer는 16 desc ring에서 포화 → 실패
// 200MB/s 달성 시: 별도 페이지에 128 desc + 16 buffer 필요
#define HVDMA_PIPELINE_WINDOW   1

// UDP 재시도 설정
#define HVDMA_MAX_RETRIES       1
// [핵심 v5] Intel I225-V 최적화 - 공격적 timeout 단축
// 정상 응답: 1-5ms, 50ms는 과잉 → 15ms로 단축 (Windows timer 1tick)
// retry: 1회만 (실패 즉시 stall 후보, 연속 2실패=stall 확정)
// 총 stall 감지: 2 chunks × 15ms = 30ms (was 200ms)
#define HVDMA_RECV_TIMEOUT      15
#define HVDMA_OPEN_MAX_RETRIES  30
#define HVDMA_OPEN_RECV_TIMEOUT 200

// ============================================================================
// UDP 통신 함수
// ============================================================================

static BOOL _UdpSend(PHVDMA_CONTEXT ctx, const BYTE* pb, DWORD cb)
{
    int ret = send(ctx->sock, (const char*)pb, (int)cb, 0);
    return (ret == (int)cb);
}

// ============================================================================
// Multi-UDP Chunked Response Protocol
// ============================================================================
// HV가 큰 응답을 독립 UDP 패킷(chunk)으로 분할 전송
// 각 chunk = [chunk_hdr 8B] + [data ≤1464B]
// IP fragmentation 없음 → fragment 손실 문제 완전 해결
// ============================================================================

// ============================================================================
// Multi-UDP Chunked Response Protocol
// ============================================================================
// HV가 큰 응답을 독립 UDP 패킷(chunk)으로 분할 전송
// 각 chunk = [chunk_hdr 8B] + [data ≤1464B]
// IP fragmentation 없음 → fragment 손실 문제 완전 해결
// chunk_index로 순서 무관 조립, 빠진 chunk만 실패 처리
// ============================================================================

#pragma pack(push, 1)
typedef struct {
    WORD chunk_index;       // 0-based chunk 번호
    WORD chunk_total;       // 총 chunk 수
    DWORD total_size;       // 전체 응답 크기 (chunk_hdr 제외)
    DWORD response_seq;     // 응답 시퀀스 번호 (HV가 매 응답 증가, 크로스오염 방지)
} CHUNK_HDR, * PCHUNK_HDR;
#pragma pack(pop)

#define CHUNK_HDR_SIZE      12
#define CHUNK_DATA_MAX      1460    // MTU(1500) - IP(20) - UDP(8) - chunk_hdr(12)
#define CHUNK_BURST_TIMEOUT 10      // ms - chunk간 대기 (정상: <2ms 도착)

// 단일 chunk 수신 (OPEN/CLOSE/PING 등 소형 응답)
// chunk_hdr를 벗기고 data만 버퍼에 넣음
static BOOL _UdpRecvSingle(PHVDMA_CONTEXT ctx, BYTE* pb, DWORD cb_max, DWORD* pcb_received)
{
    BYTE chunk_buf[1500];
    int ret = recv(ctx->sock, (char*)chunk_buf, sizeof(chunk_buf), 0);
    if (ret < (int)CHUNK_HDR_SIZE) return FALSE;

    DWORD data_size = (DWORD)ret - CHUNK_HDR_SIZE;
    if (data_size > cb_max) data_size = cb_max;

    memcpy(pb, chunk_buf + CHUNK_HDR_SIZE, data_size);
    *pcb_received = data_size;

    if (data_size < sizeof(DMA_MSG_HDR)) return FALSE;
    PDMA_MSG_HDR hdr = (PDMA_MSG_HDR)pb;
    if (hdr->magic != DMA_PROTOCOL_MAGIC) return FALSE;
    return TRUE;
}

// 요청 전송 + Multi-UDP chunk 수신 조립
// [핵심] drain 대신 stale skip 방식:
//   - chunk_index==0인 패킷만 응답 시작으로 인정
//   - chunk_index>0이 먼저 오면 이전 응답의 잔여 stale → 무시
//   - 이렇게 하면 drain 불필요 → 현재 응답 chunk를 먹어치우는 문제 해결
static BOOL _DmaRoundTrip(
    PHVDMA_CONTEXT ctx,
    const BYTE* req, DWORD req_size,
    BYTE* rsp, DWORD rsp_max, DWORD* pcb_rsp)
{
    // 요청 전송
    if (!_UdpSend(ctx, req, req_size)) return FALSE;

    BYTE chunk_buf[1500];
    WORD total_chunks = 0;
    DWORD total_size = 0;
    DWORD response_seq = 0;     // chunk 0의 seq → 이 seq만 수락
    WORD chunks_received = 0;
    int stale_skipped = 0;

    // 첫 chunk: HV 처리 + stale skip 시간 포함
    DWORD timeout = HVDMA_RECV_TIMEOUT;
    setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    // Phase 1: chunk_index==0 찾기 (stale skip)
    // [핵심] chunk_index!=0 OR 이전 response_seq의 chunk 0 → skip
    // [v10.4] All-Slot Fill: 975 중복 → response_seq <= last_accepted 도 skip!
    // 최신 chunk 0 (가장 높은 seq) 를 원하지만, 먼저 만나는 chunk 0 수락
    for (;;)
    {
        int ret = recv(ctx->sock, (char*)chunk_buf, sizeof(chunk_buf), 0);
        if (ret < (int)CHUNK_HDR_SIZE) {
            static int rt_timeout_count = 0;
            rt_timeout_count++;
            if (rt_timeout_count <= 20 || (rt_timeout_count % 100) == 0) {
                printf("[HVDMA-RT] timeout chunk0 (stale=%d) [#%d]\n", stale_skipped, rt_timeout_count);
                fflush(stdout);
            }
            return FALSE;
        }

        PCHUNK_HDR chdr = (PCHUNK_HDR)chunk_buf;

        // stale chunk: 이전 응답의 잔여 → skip
        if (chdr->chunk_index != 0) {
            stale_skipped++;
            continue;
        }

        // [v10.4] 이전 response_seq의 duplicate → skip (All-Slot Fill 975중복 방어)
        if (ctx->last_accepted_seq > 0 && chdr->response_seq <= ctx->last_accepted_seq) {
            stale_skipped++;
            continue;
        }

        // chunk 0 도착 → 응답 시작!
        total_chunks = chdr->chunk_total;
        total_size = chdr->total_size;
        response_seq = chdr->response_seq;

        DWORD chunk_data_size = (DWORD)ret - CHUNK_HDR_SIZE;
        if (chunk_data_size <= rsp_max) {
            memcpy(rsp, chunk_buf + CHUNK_HDR_SIZE, chunk_data_size);
        }
        chunks_received = 1;

        if (stale_skipped > 0) {
            printf("[HVDMA-RT] skipped %d stale, seq=%d total=%d size=%d\n",
                stale_skipped, response_seq, total_chunks, total_size);
            fflush(stdout);
        }
        break;
    }

    // 단일 chunk 응답 (OPEN 등 소형)
    if (total_chunks <= 1) goto done;

    // Phase 2: 나머지 chunks 수신 (burst mode, response_seq 일치만 수락)
    timeout = CHUNK_BURST_TIMEOUT;
    setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    while (chunks_received < total_chunks)
    {
        int ret = recv(ctx->sock, (char*)chunk_buf, sizeof(chunk_buf), 0);
        if (ret < (int)CHUNK_HDR_SIZE) break;  // burst 끝

        PCHUNK_HDR chdr = (PCHUNK_HDR)chunk_buf;

        // [핵심] 다른 response_seq → 다른 응답의 chunk → skip
        if (chdr->response_seq != response_seq) continue;

        DWORD chunk_data_size = (DWORD)ret - CHUNK_HDR_SIZE;

        // chunk 데이터를 올바른 offset에 배치
        DWORD offset = (DWORD)chdr->chunk_index * CHUNK_DATA_MAX;
        if (offset + chunk_data_size <= rsp_max) {
            memcpy(rsp + offset, chunk_buf + CHUNK_HDR_SIZE, chunk_data_size);
        }

        chunks_received++;
    }

done:
    // timeout 복원
    timeout = HVDMA_RECV_TIMEOUT;
    setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    // [핵심] PARTIAL → FALSE 유지
    // scatter read response에서 chunk 누락 → 해당 MEM entry가 0으로 남음
    // → LeechCore가 "성공적으로 읽은 0"으로 간주 → BAD DTB, ntoskrnl 못 찾음
    // PARTIAL은 반드시 실패 처리 → retry에서 전체 재수신
    if (chunks_received < total_chunks) {
        printf("[HVDMA-RT] PARTIAL %d/%d chunks (seq=%d)\n", chunks_received, total_chunks, response_seq);
        fflush(stdout);
        return FALSE;
    }

    // 응답 크기 설정
    *pcb_rsp = (total_size <= rsp_max) ? total_size : rsp_max;

    // DMA 헤더 검증
    if (*pcb_rsp < sizeof(DMA_MSG_HDR)) {
        printf("[HVDMA-RT] rsp too small: %d < %d\n", *pcb_rsp, (int)sizeof(DMA_MSG_HDR));
        fflush(stdout);
        return FALSE;
    }
    PDMA_MSG_HDR hdr = (PDMA_MSG_HDR)rsp;
    if (hdr->magic != DMA_PROTOCOL_MAGIC) {
        printf("[HVDMA-RT] bad magic: 0x%08X (expect 0x%08X)\n", hdr->magic, DMA_PROTOCOL_MAGIC);
        printf("[HVDMA-RT] first 16 bytes: ");
        for (int i = 0; i < 16 && i < (int)*pcb_rsp; i++) printf("%02X ", rsp[i]);
        printf("\n");
        fflush(stdout);
        return FALSE;
    }

    // [v10.4] 수락된 seq 기록 → 다음 호출에서 이전 seq 중복 skip
    ctx->last_accepted_seq = response_seq;

    return TRUE;
}

// ============================================================================
// DMA Open/Close
// ============================================================================

static BOOL _DmaOpen(PHVDMA_CONTEXT ctx)
{
    DMA_MSG_HDR req = { 0 };
    req.magic = DMA_PROTOCOL_MAGIC;
    req.cb_msg = sizeof(DMA_MSG_HDR);
    req.type = DMA_MSG_OPEN_REQ;
    req.version = DMA_PROTOCOL_VERSION;
    req.session_id = 0;

    printf("[HVDMA-DEBUG] sizeof(DMA_MSG_HDR) = %d (expect 16)\n", (int)sizeof(DMA_MSG_HDR));
    printf("[HVDMA-DEBUG] Raw bytes (%d): ", (int)sizeof(req));
    {
        const unsigned char* p = (const unsigned char*)&req;
        for (int i = 0; i < (int)sizeof(req); i++) printf("%02X ", p[i]);
        printf("\n");
    }
    fflush(stdout);

    // [핵심] OPEN 전용 retry: 짧은 timeout + 많은 재시도
    // HV가 NIC 인터럽트 VMEXIT에서 즉시 폴링하므로 대부분 1-3회에 성공
    // 만약 poll race로 실패해도 30회까지 재시도
    DWORD old_timeout = HVDMA_RECV_TIMEOUT;
    DWORD open_timeout = HVDMA_OPEN_RECV_TIMEOUT;
    setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO,
        (const char*)&open_timeout, sizeof(open_timeout));

    BOOL success = FALSE;
    DWORD cb_recv = 0;

    for (int attempt = 0; attempt < HVDMA_OPEN_MAX_RETRIES; attempt++)
    {
        printf("[HVDMA-OPEN] attempt %d/%d\n", attempt + 1, HVDMA_OPEN_MAX_RETRIES);
        fflush(stdout);

        if (!_UdpSend(ctx, (BYTE*)&req, sizeof(req)))
            continue;

        if (!_UdpRecvSingle(ctx, ctx->recv_buf, ctx->recv_buf_size, &cb_recv))
            continue;

        PDMA_MSG_HDR rsp_hdr = (PDMA_MSG_HDR)ctx->recv_buf;
        if (rsp_hdr->type != DMA_MSG_OPEN_RSP) continue;
        if (cb_recv < sizeof(DMA_MSG_HDR) + sizeof(DMA_OPEN_RSP_DATA)) continue;

        PDMA_OPEN_RSP_DATA rsp_data = (PDMA_OPEN_RSP_DATA)(ctx->recv_buf + sizeof(DMA_MSG_HDR));
        if (!rsp_data->success) continue;

        ctx->session_id = rsp_hdr->session_id;
        ctx->pa_max = rsp_data->pa_max;
        ctx->is_connected = TRUE;
        ctx->last_accepted_seq = 0;  // [v10.4] seq 필터 초기화
        success = TRUE;

        printf("[HVDMA-OPEN] SUCCESS on attempt %d! session=0x%08X pa_max=0x%llX\n",
            attempt + 1, ctx->session_id, (unsigned long long)ctx->pa_max);
        fflush(stdout);

        // [v10.4] OPEN 성공 후 소켓 drain: All-Slot Fill 974개 잔여 패킷 제거
        // non-blocking recv로 소켓 버퍼 비우기 → ReadScatter stale 방지
        {
            DWORD drain_timeout = 1;  // 1ms non-blocking
            setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO,
                (const char*)&drain_timeout, sizeof(drain_timeout));
            BYTE drain_buf[1500];
            int drain_count = 0;
            while (recv(ctx->sock, (char*)drain_buf, sizeof(drain_buf), 0) > 0)
                drain_count++;
            if (drain_count > 0)
                printf("[HVDMA-OPEN] drained %d stale packets from socket\n", drain_count);
        }
        break;
    }

    // recv timeout 복원 (ReadScatter용)
    setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO,
        (const char*)&old_timeout, sizeof(old_timeout));

    return success;
}

static void _DmaClose(PHVDMA_CONTEXT ctx)
{
    if (ctx->sock != INVALID_SOCKET) {
        DMA_MSG_HDR req = { 0 };
        req.magic = DMA_PROTOCOL_MAGIC;
        req.cb_msg = sizeof(DMA_MSG_HDR);
        req.type = DMA_MSG_CLOSE_REQ;
        req.version = DMA_PROTOCOL_VERSION;
        req.session_id = ctx->session_id;
        _UdpSend(ctx, (BYTE*)&req, sizeof(req));
        closesocket(ctx->sock);
        ctx->sock = INVALID_SOCKET;
    }
    ctx->is_connected = FALSE;
}


// ============================================================================
// [파이프라이닝] ReadScatter 구현
// ============================================================================
// 기존: 요청→응답→요청→응답 (Stop-and-Wait) = N × RTT
// 개선: 요청×W → 응답×W (Pipeline Window) = N/W × RTT
//
// HV spinlock이 순차 처리 보장 → 응답도 요청 순서대로 도착
// SO_RCVBUF=4MB → 커널이 W개 응답 동시 버퍼링
// ============================================================================

// 진단용 카운터 (전역)
static int s_pipeline_call = 0;

// ----------------------------------------------------------------------------
// Phase 1 helper: 요청 빌드 + UDP 전송 (응답 안 기다림)
// [핵심] send_buf에 요청 빌드 후 즉시 전송. UDP send()는 논블로킹이므로
// 커널 송신 버퍼에 넣고 바로 리턴 → 다음 요청 즉시 빌드 가능
// ----------------------------------------------------------------------------
static BOOL _SendScatterRequest(
    PHVDMA_CONTEXT ctx,
    PPMEM_SCATTER ppMEMs,
    DWORD* valid_map,
    DWORD chunk_start,
    DWORD chunk_count)
{
    DWORD req_size = sizeof(DMA_MSG_HDR) + sizeof(DMA_SCATTER_HDR)
        + chunk_count * sizeof(DMA_SCATTER_ENTRY);

    if (req_size > ctx->send_buf_size) return FALSE;

    PDMA_MSG_HDR req_hdr = (PDMA_MSG_HDR)ctx->send_buf;
    req_hdr->magic = DMA_PROTOCOL_MAGIC;
    req_hdr->cb_msg = req_size;
    req_hdr->type = DMA_MSG_READ_SCATTER_REQ;
    req_hdr->version = DMA_PROTOCOL_VERSION;
    req_hdr->session_id = ctx->session_id;

    PDMA_SCATTER_HDR scatter_hdr = (PDMA_SCATTER_HDR)(ctx->send_buf + sizeof(DMA_MSG_HDR));
    scatter_hdr->count = chunk_count;

    PDMA_SCATTER_ENTRY entries = (PDMA_SCATTER_ENTRY)(
        ctx->send_buf + sizeof(DMA_MSG_HDR) + sizeof(DMA_SCATTER_HDR));

    DWORD cb_total = 0;
    for (DWORD i = 0; i < chunk_count; i++)
    {
        DWORD orig_idx = valid_map[chunk_start + i];
        entries[i].qw_addr = ppMEMs[orig_idx]->qwA;
        entries[i].cb = ppMEMs[orig_idx]->cb;
        entries[i].f = 0;
        cb_total += ppMEMs[orig_idx]->cb;
    }
    scatter_hdr->cb_total = cb_total;

    return _UdpSend(ctx, ctx->send_buf, req_size);
}

// ----------------------------------------------------------------------------
// Phase 2a helper: Multi-UDP 응답 수신 (전송 없이 수신만)
// [핵심] _DmaRoundTrip의 수신 부분만 추출
// HV spinlock 순차 처리 → 응답 순서 보장 → chunk0 기준 응답 경계 식별
// ----------------------------------------------------------------------------
static BOOL _RecvDmaResponse(
    PHVDMA_CONTEXT ctx,
    BYTE* rsp, DWORD rsp_max, DWORD* pcb_rsp)
{
    BYTE chunk_buf[1500];
    WORD total_chunks = 0;
    DWORD total_size = 0;
    DWORD response_seq = 0;
    WORD chunks_received = 0;
    int stale_skipped = 0;

    // Phase 1: chunk_index==0 찾기
    // [파이프라이닝] 이전 응답의 잔여 chunk가 있을 수 있음 → skip
    // [v10.4] All-Slot Fill: 975 중복 → response_seq <= last_accepted 도 skip!
    DWORD timeout = HVDMA_RECV_TIMEOUT;
    setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    for (;;)
    {
        int ret = recv(ctx->sock, (char*)chunk_buf, sizeof(chunk_buf), 0);
        if (ret < (int)CHUNK_HDR_SIZE) {
            // [v5] 로그 스팸 방지: 초기 20회 + 이후 100회마다 1회
            static int timeout_count = 0;
            timeout_count++;
            if (timeout_count <= 20 || (timeout_count % 100) == 0) {
                printf("[PIPE-RECV] timeout waiting chunk0 (skipped %d stale) [#%d]\n",
                    stale_skipped, timeout_count);
                fflush(stdout);
            }
            return FALSE;
        }

        PCHUNK_HDR chdr = (PCHUNK_HDR)chunk_buf;
        if (chdr->chunk_index != 0) {
            stale_skipped++;
            continue;
        }

        // [v10.4] 이전 response_seq의 duplicate → skip
        if (ctx->last_accepted_seq > 0 && chdr->response_seq <= ctx->last_accepted_seq) {
            stale_skipped++;
            continue;
        }

        total_chunks = chdr->chunk_total;
        total_size = chdr->total_size;
        response_seq = chdr->response_seq;

        DWORD chunk_data_size = (DWORD)ret - CHUNK_HDR_SIZE;
        if (chunk_data_size <= rsp_max) {
            memcpy(rsp, chunk_buf + CHUNK_HDR_SIZE, chunk_data_size);
        }
        chunks_received = 1;
        break;
    }

    if (total_chunks <= 1) goto done;

    // Phase 2: 나머지 chunks (response_seq 일치만 수락)
    timeout = CHUNK_BURST_TIMEOUT;
    setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    while (chunks_received < total_chunks)
    {
        int ret = recv(ctx->sock, (char*)chunk_buf, sizeof(chunk_buf), 0);
        if (ret < (int)CHUNK_HDR_SIZE) break;

        PCHUNK_HDR chdr = (PCHUNK_HDR)chunk_buf;
        if (chdr->response_seq != response_seq) continue;

        DWORD chunk_data_size = (DWORD)ret - CHUNK_HDR_SIZE;
        DWORD offset = (DWORD)chdr->chunk_index * CHUNK_DATA_MAX;
        if (offset + chunk_data_size <= rsp_max) {
            memcpy(rsp + offset, chunk_buf + CHUNK_HDR_SIZE, chunk_data_size);
        }
        chunks_received++;
    }

done:
    timeout = HVDMA_RECV_TIMEOUT;
    setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    if (chunks_received < total_chunks) {
        printf("[PIPE-RECV] PARTIAL %d/%d (seq=%d)\n", chunks_received, total_chunks, response_seq);
        fflush(stdout);
        return FALSE;
    }

    *pcb_rsp = (total_size <= rsp_max) ? total_size : rsp_max;

    if (*pcb_rsp < sizeof(DMA_MSG_HDR)) return FALSE;
    PDMA_MSG_HDR hdr = (PDMA_MSG_HDR)rsp;
    if (hdr->magic != DMA_PROTOCOL_MAGIC) return FALSE;

    // [v10.4] 수락된 seq 기록 → 다음 호출에서 이전 seq 중복 skip
    ctx->last_accepted_seq = response_seq;

    return TRUE;
}

// ----------------------------------------------------------------------------
// Phase 2b helper: 응답 파싱 + 데이터 복사
// [핵심] recv_buf의 scatter response를 ppMEMs에 복사
// ----------------------------------------------------------------------------
static BOOL _ParseScatterResponse(
    PHVDMA_CONTEXT ctx,
    PPMEM_SCATTER ppMEMs,
    DWORD* valid_map,
    DWORD chunk_start,
    DWORD chunk_count,
    DWORD cb_recv)
{
    s_pipeline_call++;

    PDMA_MSG_HDR rsp_hdr = (PDMA_MSG_HDR)ctx->recv_buf;
    if (rsp_hdr->type != DMA_MSG_READ_SCATTER_RSP) {
        printf("[PIPE-ERR#%d] type mismatch: got %d expect %d\n",
            s_pipeline_call, rsp_hdr->type, DMA_MSG_READ_SCATTER_RSP);
        fflush(stdout);
        return FALSE;
    }

    PDMA_SCATTER_HDR rsp_scatter = (PDMA_SCATTER_HDR)(ctx->recv_buf + sizeof(DMA_MSG_HDR));
    if (rsp_scatter->count != chunk_count) {
        printf("[PIPE-ERR#%d] count mismatch: rsp=%d req=%d\n",
            s_pipeline_call, rsp_scatter->count, chunk_count);
        fflush(stdout);
        return FALSE;
    }

    PDMA_SCATTER_ENTRY rsp_entries = (PDMA_SCATTER_ENTRY)(
        ctx->recv_buf + sizeof(DMA_MSG_HDR) + sizeof(DMA_SCATTER_HDR));

    BYTE* data_ptr = ctx->recv_buf + sizeof(DMA_MSG_HDR) + sizeof(DMA_SCATTER_HDR)
        + chunk_count * sizeof(DMA_SCATTER_ENTRY);

    DWORD data_offset = 0;
    DWORD f_ok = 0, f_fail = 0, all_zero_pages = 0, bounds_fail = 0;
    for (DWORD i = 0; i < chunk_count; i++)
    {
        DWORD orig_idx = valid_map[chunk_start + i];
        PMEM_SCATTER pMEM = ppMEMs[orig_idx];

        if (rsp_entries[i].f)
        {
            DWORD cb = rsp_entries[i].cb;
            DWORD data_end = (DWORD)(data_ptr - ctx->recv_buf) + data_offset + cb;
            if (data_end <= cb_recv && cb <= pMEM->cb) {
                memcpy(pMEM->pb, data_ptr + data_offset, cb);
                pMEM->f = TRUE;
                data_offset += cb;
                f_ok++;
                BOOL is_zero = TRUE;
                for (DWORD z = 0; z < cb && is_zero; z += 64)
                    if (*(QWORD*)(pMEM->pb + z) != 0) is_zero = FALSE;
                if (is_zero) all_zero_pages++;
            }
            else {
                bounds_fail++;
                if (bounds_fail <= 3) {
                    printf("[PIPE-BOUNDS#%d] i=%d PA=%016llX data_end=%d cb_recv=%d cb=%d pMEM_cb=%d\n",
                        s_pipeline_call, i, pMEM->qwA, data_end, cb_recv, cb, pMEM->cb);
                    fflush(stdout);
                }
            }
        }
        else {
            f_fail++;
        }
    }

    // [진단] 첫 10개 + 에러시 상세 출력
    if (s_pipeline_call <= 10 || bounds_fail > 0 || f_fail > 0) {
        printf("[PIPE-DATA#%d] f_ok=%d f_fail=%d all_zero=%d bounds_fail=%d\n",
            s_pipeline_call, f_ok, f_fail, all_zero_pages, bounds_fail);
        if (s_pipeline_call <= 10) {
            for (DWORD i = 0; i < chunk_count && i < 3; i++) {
                DWORD orig_idx = valid_map[chunk_start + i];
                PMEM_SCATTER pMEM = ppMEMs[orig_idx];
                if (pMEM->f) {
                    printf("  PA=%016llX: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
                        pMEM->qwA,
                        pMEM->pb[0], pMEM->pb[1], pMEM->pb[2], pMEM->pb[3],
                        pMEM->pb[4], pMEM->pb[5], pMEM->pb[6], pMEM->pb[7],
                        pMEM->pb[8], pMEM->pb[9], pMEM->pb[10], pMEM->pb[11],
                        pMEM->pb[12], pMEM->pb[13], pMEM->pb[14], pMEM->pb[15]);
                }
            }
        }
        // [DIAG] f_fail pages - which PA failed to map? (fires for ALL chunks)
        if (f_fail > 0) {
            for (DWORD i = 0; i < chunk_count; i++) {
                DWORD orig_idx = valid_map[chunk_start + i];
                PMEM_SCATTER pMEM = ppMEMs[orig_idx];
                if (!pMEM->f) {
                    printf("  >>> FAIL PA=%016llX (cb=%d) - HV EPT map failed\n",
                        pMEM->qwA, pMEM->cb);
                }
            }
        }
        fflush(stdout);
    }
    return TRUE;
}

// ============================================================================
// 동기 처리 + retry + stall recovery
// ============================================================================
// 패턴: ~120 chunks 정상 → 8 chunks 연속 실패 → 다시 정상
// 원인: HV가 일시적으로 RX 불능 (OS 드라이버 간섭 추정)
// 해결: retry 5회, progressive backoff (50/100/200/500/1000ms)
//       → 1초 stall도 커버 가능
// ============================================================================
static BOOL _ReadScatterChunkSync(
    PHVDMA_CONTEXT ctx,
    PPMEM_SCATTER ppMEMs,
    DWORD* valid_map,
    DWORD chunk_start,
    DWORD chunk_count)
{
    int retry;
    DWORD cb_recv = 0;
    // [FIX v5] retry 2→1: 15ms timeout 1회로 충분
    // 정상이면 <5ms에 응답. 15ms timeout = 실패 확정.
    // stall detection: 연속 2 chunk 실패 = 2×15ms = 30ms에 확정

    for (retry = 0; retry < 1; retry++) {
        if (!_SendScatterRequest(ctx, ppMEMs, valid_map, chunk_start, chunk_count))
            continue;

        cb_recv = 0;
        if (_RecvDmaResponse(ctx, ctx->recv_buf, ctx->recv_buf_size, &cb_recv)) {
            if (_ParseScatterResponse(ctx, ppMEMs, valid_map, chunk_start, chunk_count, cb_recv)) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

// ============================================================================
// LeechCore 콜백: ReadScatter (파이프라이닝)
// ============================================================================
// [핵심] 7530 pages = 118 chunks 일 때:
//   기존: 118 × (send + wait + recv) ≈ 118 × 20ms = 2.4초
//   개선: 8 windows × (16×send + 16×recv) ≈ 8 × 200ms = 0.6초 (~4배)
//
// 동작원리:
//   Phase 1: W개 요청 연속 발사 (UDP send = 논블로킹)
//   Phase 2: W개 응답 순차 수신 (HV spinlock = 순서 보장)
//   → HV가 idle 없이 연속 처리, 네트워크 RTT 오버랩
// ============================================================================

VOID DeviceFPGA_ReadScatter(
    _In_ PLC_CONTEXT ctxLC,
    _In_ DWORD cpMEMs,
    _Inout_ PPMEM_SCATTER ppMEMs)
{
    static int s_scatter_call = 0;
    s_scatter_call++;

    // [진단] 고해상도 타이밍 - 파이프라이닝 효과 측정
    LARGE_INTEGER t_start, t_end, freq;
    QueryPerformanceCounter(&t_start);
    QueryPerformanceFrequency(&freq);

    PHVDMA_CONTEXT ctx = (PHVDMA_CONTEXT)ctxLC->hDevice;
    if (!ctx || !ctx->is_connected || cpMEMs == 0) return;

    EnterCriticalSection(&ctx->lock);

    // valid_map: 유효한 MEM_SCATTER 인덱스만 추출 (동적 할당으로 오버플로우 방지)
    DWORD* valid_map = (DWORD*)malloc(cpMEMs * sizeof(DWORD));
    if (!valid_map) {
        LeaveCriticalSection(&ctx->lock);
        return;
    }
    DWORD cValid = 0;
    for (DWORD i = 0; i < cpMEMs; i++) {
        if (MEM_SCATTER_ADDR_ISVALID(ppMEMs[i])) {
            valid_map[cValid++] = i;
        }
    }

    if (cValid == 0) {
        free(valid_map);
        LeaveCriticalSection(&ctx->lock);
        return;
    }

    // 총 chunk 수 계산
    DWORD num_chunks = (cValid + HVDMA_CHUNK_SIZE - 1) / HVDMA_CHUNK_SIZE;

    // [핵심] 2-pass 동기 처리
    // ============================================================================
    // 문제: HV가 ~120 chunks 후 1-2초 stall → 해당 chunks 영구 실패
    //       → page table entries 누락 → EPROCESS walk 실패
    //
    // 해결: 1st pass에서 실패한 chunks 기록 → stall이 끝난 후 2nd pass 재시도
    //   1st pass: 232 OK (464ms) + 9 fail (50ms×5 retry = 2.5초) = ~3초
    //   2nd pass: 9 retry (stall 해소됨) → 9 × 2ms = 18ms
    //   → 모든 pages 100% 수집!
    //
    // 핵심 통찰: #6-#9가 stall 후 항상 완벽 동작 = stall은 일시적
    // ============================================================================
    {
        // 실패 chunk 기록용 배열 (최대 num_chunks)
        DWORD* failed_offsets = (DWORD*)malloc(num_chunks * sizeof(DWORD));
        DWORD* failed_counts = (DWORD*)malloc(num_chunks * sizeof(DWORD));
        DWORD fail_count = 0;
        DWORD pass1_ok = 0;

        // === Pass 1: 전체 스캔 ===
        // [v5] HV가 매 VMEXIT마다 TXDCTL keepalive 실행
        // → OS의 Q1 kill이 즉시(~μs) 복구됨 → stall 거의 불가능
        // throttle은 안전장치로 200 chunks마다만 (이전: 50)
        DWORD consecutive_fails = 0;
        BOOL tx_stall_detected = FALSE;
        DWORD chunks_since_pause = 0;
        DWORD offset = 0;
        while (offset < cValid) {
            DWORD chunk = cValid - offset;
            if (chunk > HVDMA_CHUNK_SIZE) chunk = HVDMA_CHUNK_SIZE;

            if (tx_stall_detected) {
                if (failed_offsets && failed_counts) {
                    failed_offsets[fail_count] = offset;
                    failed_counts[fail_count] = chunk;
                    fail_count++;
                }
            }
            else if (_ReadScatterChunkSync(ctx, ppMEMs, valid_map, offset, chunk)) {
                pass1_ok++;
                consecutive_fails = 0;
                chunks_since_pause++;
                // [v4] throttle Sleep 제거 — Sleep(1)은 15ms 소모
                // HV keepalive + inject DD wait가 TX ring 관리
                // if (chunks_since_pause >= 200) {
                //     Sleep(1);
                //     chunks_since_pause = 0;
                // }
            }
            else {
                consecutive_fails++;
                if (failed_offsets && failed_counts) {
                    failed_offsets[fail_count] = offset;
                    failed_counts[fail_count] = chunk;
                    fail_count++;
                }
                // 연속 2회 실패 = TX stall 확정 → 즉시 나머지 스킵
                if (consecutive_fails >= 2) {
                    tx_stall_detected = TRUE;
                    if (s_scatter_call <= 20) {
                        printf("[PIPE] TX stall detected at chunk %d/%d, skipping to Pass2\n",
                            pass1_ok + fail_count, num_chunks);
                        fflush(stdout);
                    }
                }
            }
            offset += chunk;
        }

        // === Pass 2: 실패한 chunks 즉시 재시도 ===
        // [v4] Sleep 제거: HV가 inject 진입 시 TXDCTL 사전체크→자동복구
        // 클라이언트는 재요청만 보내면 됨 (HV recovery = ~10μs, 대기 불필요)
        DWORD pass2_ok = 0;
        if (fail_count > 0) {
            DWORD i;
            for (i = 0; i < fail_count; i++) {
                if (_ReadScatterChunkSync(ctx, ppMEMs, valid_map,
                    failed_offsets[i], failed_counts[i])) {
                    pass2_ok++;
                }
            }
            if (s_scatter_call <= 20) {
                printf("[PIPE] Pass2 recovery: %d/%d chunks recovered (immediate retry)\n",
                    pass2_ok, fail_count);
                fflush(stdout);
            }
        }

        if (failed_offsets) free(failed_offsets);
        if (failed_counts)  free(failed_counts);

        QueryPerformanceCounter(&t_end);
        double ms = (double)(t_end.QuadPart - t_start.QuadPart) * 1000.0 / freq.QuadPart;
        if (s_scatter_call <= 20) {
            printf("[PIPE] ReadScatter #%d SYNC: %d pages in %.1fms (%.0f pages/sec) [p1=%d p2=%d/%d]\n",
                s_scatter_call, cValid, ms, cValid * 1000.0 / ms,
                pass1_ok, pass2_ok, fail_count);

            // [DIAG-AGG] Per-ReadScatter aggregate: 전체 페이지 f 상태 확인
            // EPROCESS #5 디버깅: 모든 chunk 성공인데 walk 실패 → 데이터 내용 문제 추적
            // f_total: f=1인 페이지 수, zero_total: f=1이지만 데이터 전부 0인 페이지 수
            // unmapped: f=0인 페이지 수 (EPT에 없는 GPA)
            DWORD f_total = 0, zero_total = 0, unmapped_total = 0;
            for (DWORD vi = 0; vi < cValid; vi++) {
                PMEM_SCATTER pM = ppMEMs[valid_map[vi]];
                if (pM->f) {
                    f_total++;
                    BOOL is_z = TRUE;
                    for (DWORD z = 0; z < pM->cb && is_z; z += 64)
                        if (*(QWORD*)(pM->pb + z) != 0) is_z = FALSE;
                    if (is_z) zero_total++;
                }
                else {
                    unmapped_total++;
                }
            }
            printf("[DIAG-AGG#%d] total=%d mapped=%d(%.1f%%) unmapped=%d zero_pages=%d(%.1f%%)\n",
                s_scatter_call, cValid, f_total, f_total * 100.0 / cValid,
                unmapped_total, zero_total, zero_total * 100.0 / cValid);

            // 첫 10개 unmapped PA 출력 (어떤 GPA가 EPT에 없는지)
            if (unmapped_total > 0) {
                DWORD shown = 0;
                for (DWORD vi = 0; vi < cValid && shown < 10; vi++) {
                    PMEM_SCATTER pM = ppMEMs[valid_map[vi]];
                    if (!pM->f) {
                        printf("  [UNMAPPED] PA=%016llX cb=%d\n", pM->qwA, pM->cb);
                        shown++;
                    }
                }
                if (unmapped_total > 10)
                    printf("  ... and %d more unmapped pages\n", unmapped_total - 10);
            }
            fflush(stdout);
        }
        free(valid_map);
        LeaveCriticalSection(&ctx->lock);
        return;
    }

    // [파이프라이닝] Window 단위로 처리
    printf("[PIPE] ReadScatter #%d: cpMEMs=%d valid=%d chunks=%d window=%d\n",
        s_scatter_call, cpMEMs, cValid, num_chunks, HVDMA_PIPELINE_WINDOW);
    fflush(stdout);

    DWORD total_ok = 0, total_fail = 0;
    BOOL hv_dead = FALSE;
    DWORD consecutive_fail = 0;  // 연속 실패 카운터

    for (DWORD base = 0; base < num_chunks && !hv_dead; base += HVDMA_PIPELINE_WINDOW)
    {
        DWORD window = num_chunks - base;
        if (window > HVDMA_PIPELINE_WINDOW) window = HVDMA_PIPELINE_WINDOW;

        // ============ Phase 1: 요청 연속 발사 ============
        DWORD send_ok = 0;
        for (DWORD w = 0; w < window; w++)
        {
            DWORD chunk_idx = base + w;
            DWORD chunk_start = chunk_idx * HVDMA_CHUNK_SIZE;
            DWORD chunk_count = cValid - chunk_start;
            if (chunk_count > HVDMA_CHUNK_SIZE) chunk_count = HVDMA_CHUNK_SIZE;

            if (_SendScatterRequest(ctx, ppMEMs, valid_map, chunk_start, chunk_count))
                send_ok++;
        }

        // ============ Phase 2: 응답 순차 수신 + 파싱 ============
        DWORD window_ok = 0;
        for (DWORD w = 0; w < window; w++)
        {
            DWORD chunk_idx = base + w;
            DWORD chunk_start = chunk_idx * HVDMA_CHUNK_SIZE;
            DWORD chunk_count = cValid - chunk_start;
            if (chunk_count > HVDMA_CHUNK_SIZE) chunk_count = HVDMA_CHUNK_SIZE;

            DWORD cb_recv = 0;
            BOOL chunk_ok = FALSE;
            int retry;

            // [핵심] 재시도 로직: timeout이면 같은 요청 재전송 (최대 3회)
            // HV가 살아있지만 RX에서 패킷 놓치는 경우 복구
            for (retry = 0; retry < 3 && !chunk_ok; retry++) {
                if (retry > 0) {
                    // 재전송: 동일 chunk 다시 보내기
                    _SendScatterRequest(ctx, ppMEMs, valid_map, chunk_start, chunk_count);
                    if (s_scatter_call <= 20) {
                        printf("[PIPE] chunk %d retry %d\n", chunk_idx, retry);
                        fflush(stdout);
                    }
                }

                if (_RecvDmaResponse(ctx, ctx->recv_buf, ctx->recv_buf_size, &cb_recv)) {
                    if (_ParseScatterResponse(ctx, ppMEMs, valid_map, chunk_start, chunk_count, cb_recv)) {
                        chunk_ok = TRUE;
                    }
                }
            }

            if (chunk_ok) {
                total_ok++;
                window_ok++;
                consecutive_fail = 0;
            }
            else {
                total_fail++;
                consecutive_fail++;
                // [핵심] 5회 연속 실패 시에만 HV 사망 판정
                // 이전: 1회 실패 → 즉시 사망 → 전체 포기
                // 변경: 간헐적 miss는 재시도로 복구, 진짜 사망만 감지
                if (consecutive_fail >= 5) {
                    hv_dead = TRUE;
                    printf("[PIPE] HV not responding after %d consecutive failures\n", consecutive_fail);
                    fflush(stdout);
                }
                break;  // window 나머지 포기 (다음 window에서 재시도)
            }
        }

        // [v4] Window간 대기 제거 — Sleep(1)은 Windows에서 ~15ms 소모
        // PIPELINE_WINDOW=1이면 매 chunk마다 15ms = 216 chunks × 15ms = 3.4초!
        // 6.40 MB/s 원인. 제거 시 99 MB/s 달성.
        // TX ring drain은 HV inject의 DD wait가 자체 처리함
        // if (!hv_dead && base + HVDMA_PIPELINE_WINDOW < num_chunks) {
        //     Sleep(1);
        // }
    }

    if (total_fail > 0 || s_scatter_call <= 5) {
        printf("[PIPE] ReadScatter #%d DONE: %d/%d chunks OK\n",
            s_scatter_call, total_ok, num_chunks);
        fflush(stdout);
    }

    // [핵심] HV 사망 감지 후 소켓 drain → 다음 ReadScatter 호출 준비
    // stale 응답이 커널 버퍼에 남아있을 수 있음
    if (hv_dead) {
        DWORD drain_timeout = 50;  // 50ms 짧게
        setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&drain_timeout, sizeof(drain_timeout));
        BYTE drain_buf[1500];
        int drained = 0;
        while (recv(ctx->sock, (char*)drain_buf, sizeof(drain_buf), 0) > 0) drained++;
        DWORD normal_timeout = HVDMA_RECV_TIMEOUT;
        setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&normal_timeout, sizeof(normal_timeout));
        if (drained > 0) {
            printf("[PIPE] drained %d stale packets after HV recovery\n", drained);
            fflush(stdout);
        }
    }

    // [진단] 타이밍: 파이프라이닝 효과 측정
    QueryPerformanceCounter(&t_end);
    double ms = (double)(t_end.QuadPart - t_start.QuadPart) * 1000.0 / freq.QuadPart;
    if (s_scatter_call <= 20 || ms > 2000.0) {
        double mbps = (cValid * 4096.0 / 1024.0 / 1024.0) / (ms / 1000.0);
        printf("[PIPE] ReadScatter #%d TIME: %d pages (%.1fMB) in %.1fms = %.1f MB/s\n",
            s_scatter_call, cValid, cValid * 4096.0 / 1024.0 / 1024.0, ms, mbps);
        fflush(stdout);
    }

    free(valid_map);
    LeaveCriticalSection(&ctx->lock);
}

// ============================================================================
// WriteScatter 구현
// [핵심] 데이터를 청크 단위로 묶어서 UDP로 전송
// Write는 파이프라이닝 불필요 (사용 빈도 낮음, 소량)
// ============================================================================

static BOOL _WriteScatterChunk(
    PHVDMA_CONTEXT ctx,
    PPMEM_SCATTER ppMEMs,
    DWORD* valid_map,
    DWORD chunk_start,
    DWORD chunk_count)
{
    // Write 요청: HDR + SCATTER_HDR + entries + data
    DWORD entries_size = chunk_count * sizeof(DMA_SCATTER_ENTRY);
    DWORD data_size = 0;
    for (DWORD i = 0; i < chunk_count; i++) {
        DWORD orig_idx = valid_map[chunk_start + i];
        data_size += ppMEMs[orig_idx]->cb;
    }

    DWORD req_size = sizeof(DMA_MSG_HDR) + sizeof(DMA_SCATTER_HDR)
        + entries_size + data_size;

    if (req_size > ctx->send_buf_size) return FALSE;

    PDMA_MSG_HDR req_hdr = (PDMA_MSG_HDR)ctx->send_buf;
    req_hdr->magic = DMA_PROTOCOL_MAGIC;
    req_hdr->cb_msg = req_size;
    req_hdr->type = DMA_MSG_WRITE_SCATTER_REQ;
    req_hdr->version = DMA_PROTOCOL_VERSION;
    req_hdr->session_id = ctx->session_id;

    PDMA_SCATTER_HDR scatter_hdr = (PDMA_SCATTER_HDR)(ctx->send_buf + sizeof(DMA_MSG_HDR));
    scatter_hdr->count = chunk_count;
    scatter_hdr->cb_total = data_size;

    PDMA_SCATTER_ENTRY entries = (PDMA_SCATTER_ENTRY)(
        ctx->send_buf + sizeof(DMA_MSG_HDR) + sizeof(DMA_SCATTER_HDR));

    BYTE* data_ptr = ctx->send_buf + sizeof(DMA_MSG_HDR) + sizeof(DMA_SCATTER_HDR) + entries_size;
    DWORD data_offset = 0;

    for (DWORD i = 0; i < chunk_count; i++)
    {
        DWORD orig_idx = valid_map[chunk_start + i];
        PMEM_SCATTER pMEM = ppMEMs[orig_idx];
        entries[i].qw_addr = pMEM->qwA;
        entries[i].cb = pMEM->cb;
        entries[i].f = 0;
        memcpy(data_ptr + data_offset, pMEM->pb, pMEM->cb);
        data_offset += pMEM->cb;
    }

    DWORD cb_recv = 0;
    BOOL rt_ok = _DmaRoundTrip(ctx, ctx->send_buf, req_size,
        ctx->recv_buf, ctx->recv_buf_size, &cb_recv);
    if (!rt_ok) return FALSE;

    // Write 응답 파싱: 각 엔트리의 성공 여부
    PDMA_MSG_HDR rsp_hdr = (PDMA_MSG_HDR)ctx->recv_buf;
    if (rsp_hdr->type != DMA_MSG_WRITE_SCATTER_RSP) return FALSE;

    PDMA_SCATTER_HDR rsp_scatter = (PDMA_SCATTER_HDR)(ctx->recv_buf + sizeof(DMA_MSG_HDR));
    if (rsp_scatter->count != chunk_count) return FALSE;

    PDMA_WRITE_RESULT results = (PDMA_WRITE_RESULT)(
        ctx->recv_buf + sizeof(DMA_MSG_HDR) + sizeof(DMA_SCATTER_HDR));

    for (DWORD i = 0; i < chunk_count; i++)
    {
        DWORD orig_idx = valid_map[chunk_start + i];
        ppMEMs[orig_idx]->f = results[i].f ? TRUE : FALSE;
    }
    return TRUE;
}

// ============================================================================
// LeechCore 콜백: WriteScatter
// ============================================================================

VOID DeviceFPGA_WriteScatter(
    _In_ PLC_CONTEXT ctxLC,
    _In_ DWORD cpMEMs,
    _Inout_ PPMEM_SCATTER ppMEMs)
{
    PHVDMA_CONTEXT ctx = (PHVDMA_CONTEXT)ctxLC->hDevice;
    if (!ctx || !ctx->is_connected || cpMEMs == 0) return;

    EnterCriticalSection(&ctx->lock);

    // [핵심] cpMEMs > DMA_MAX_SCATTER_COUNT 가능 → 동적 할당
    DWORD* valid_map = (DWORD*)malloc(cpMEMs * sizeof(DWORD));
    if (!valid_map) {
        LeaveCriticalSection(&ctx->lock);
        return;
    }
    DWORD cValid = 0;
    for (DWORD i = 0; i < cpMEMs; i++) {
        if (MEM_SCATTER_ADDR_ISVALID(ppMEMs[i])) {
            valid_map[cValid++] = i;
        }
    }

    if (cValid == 0) {
        free(valid_map);
        LeaveCriticalSection(&ctx->lock);
        return;
    }

    // Write 청크: 16개씩 (16 * 4KB = 64KB, UDP 제한 내)
    DWORD write_chunk = 16;
    DWORD offset = 0;
    while (offset < cValid)
    {
        DWORD chunk = cValid - offset;
        if (chunk > write_chunk) chunk = write_chunk;
        _WriteScatterChunk(ctx, ppMEMs, valid_map, offset, chunk);
        offset += chunk;
    }

    free(valid_map);
    LeaveCriticalSection(&ctx->lock);
}

// ============================================================================
// LeechCore 콜백: GetOption
// 핵심: LC_OPT_CORE_ADDR_MAX, VOLATILE, READONLY 등 기본 옵션 응답
// FPGA 관련 옵션(LC_OPT_FPGA_*)은 가짜 값 반환하여 호환성 유지
// ============================================================================

BOOL DeviceFPGA_GetOption(
    _In_ PLC_CONTEXT ctxLC,
    _In_ QWORD fOption,
    _Out_ PQWORD pqwValue)
{
    PHVDMA_CONTEXT ctx = (PHVDMA_CONTEXT)ctxLC->hDevice;
    if (!ctx) return FALSE;

    if (fOption == LC_OPT_CORE_ADDR_MAX) {
        *pqwValue = ctx->pa_max;
        return TRUE;
    }
    if (fOption == LC_OPT_CORE_VOLATILE) {
        *pqwValue = 1;
        return TRUE;
    }
    if (fOption == LC_OPT_CORE_READONLY) {
        *pqwValue = 0;
        return TRUE;
    }
    // FPGA 호환 옵션: 프로그램이 FPGA 정보 쿼리할 때 가짜 값 반환
    // 이래야 Lone-DMA-Test 등 FPGA 전용 프로그램이 정상 동작
    if (fOption == LC_OPT_FPGA_FPGA_ID) {
        *pqwValue = 0x01;       // 가짜 FPGA ID
        return TRUE;
    }
    if (fOption == LC_OPT_FPGA_VERSION_MAJOR) {
        *pqwValue = 4;          // 가짜 펌웨어 v4.x
        return TRUE;
    }
    if (fOption == LC_OPT_FPGA_VERSION_MINOR) {
        *pqwValue = 14;         // 가짜 펌웨어 v4.14
        return TRUE;
    }
    if (fOption == LC_OPT_FPGA_DEVICE_ID) {
        *pqwValue = 0x0400;     // 가짜 PCIe Device ID
        return TRUE;
    }
    if (fOption == LC_OPT_FPGA_ALGO_TINY) {
        *pqwValue = 0;
        return TRUE;
    }
    if (fOption == LC_OPT_FPGA_ALGO_SYNCHRONOUS) {
        *pqwValue = 1;          // 동기 모드 (UDP는 동기)
        return TRUE;
    }
    return FALSE;
}

// ============================================================================
// LeechCore 콜백: SetOption (대부분 무시, 호환성용)
// ============================================================================

BOOL DeviceFPGA_SetOption(
    _In_ PLC_CONTEXT ctxLC,
    _In_ QWORD fOption,
    _In_ QWORD qwValue)
{
    // FPGA 설정 변경 요청은 조용히 성공 반환 (실제 FPGA 없으므로)
    return TRUE;
}

// ============================================================================
// LeechCore 콜백: Command (호환성용 - 대부분 미지원 반환)
// ============================================================================

BOOL DeviceFPGA_Command(
    _In_ PLC_CONTEXT ctxLC,
    _In_ QWORD fOption,
    _In_ DWORD cbDataIn,
    _In_reads_opt_(cbDataIn) PBYTE pbDataIn,
    _Out_opt_ PBYTE* ppbDataOut,
    _Out_opt_ PDWORD pcbDataOut)
{
    // FPGA Command 기능 미지원 (PCIe config space 등)
    if (ppbDataOut) *ppbDataOut = NULL;
    if (pcbDataOut) *pcbDataOut = 0;
    return FALSE;
}

// ============================================================================
// LeechCore 콜백: Close
// ============================================================================

VOID DeviceFPGA_Close(_Inout_ PLC_CONTEXT ctxLC)
{
    PHVDMA_CONTEXT ctx = (PHVDMA_CONTEXT)ctxLC->hDevice;
    if (!ctx) return;

    _DmaClose(ctx);
    DeleteCriticalSection(&ctx->lock);

    if (ctx->send_buf) { free(ctx->send_buf); ctx->send_buf = NULL; }
    if (ctx->recv_buf) { free(ctx->recv_buf); ctx->recv_buf = NULL; }

    free(ctx);
    ctxLC->hDevice = NULL;
}

// ============================================================================
// hvdma.ini 파일 읽기: leechcore.dll 옆에 위치
// 포맷: 한 줄에 IP 또는 IP:PORT
// ============================================================================

static BOOL _ReadConfigFile(_Out_ CHAR szIP[64], _Out_ PWORD pwPort)
{
    CHAR szPath[MAX_PATH] = { 0 };
    HMODULE hSelf = NULL;

    // leechcore.dll의 경로 구하기
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)_ReadConfigFile, &hSelf);
    if (!hSelf) return FALSE;
    GetModuleFileNameA(hSelf, szPath, MAX_PATH);

    // 파일명을 hvdma.ini로 교체
    char* lastSlash = strrchr(szPath, '\\');
    if (!lastSlash) lastSlash = strrchr(szPath, '/');
    if (lastSlash)
        strcpy_s(lastSlash + 1, MAX_PATH - (lastSlash + 1 - szPath), "hvdma.ini");
    else
        strcpy_s(szPath, MAX_PATH, "hvdma.ini");

    FILE* f = NULL;
    fopen_s(&f, szPath, "r");
    if (!f) return FALSE;

    CHAR line[128] = { 0 };
    if (!fgets(line, sizeof(line), f)) { fclose(f); return FALSE; }
    fclose(f);

    // 공백 제거
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' || line[len - 1] == ' '))
        line[--len] = 0;
    if (len == 0) return FALSE;

    // IP:PORT 파싱
    const char* colon = strchr(line, ':');
    if (colon) {
        size_t ip_len = colon - line;
        if (ip_len >= 64) return FALSE;
        memcpy(szIP, line, ip_len);
        szIP[ip_len] = 0;
        *pwPort = (WORD)atoi(colon + 1);
    }
    else {
        strcpy_s(szIP, 64, line);
        *pwPort = HVDMA_DEFAULT_PORT;
    }
    return TRUE;
}

// ============================================================================
// 연결 문자열 파싱
// 지원 형식:
//   fpga                           → hvdma.ini에서 읽기
//   fpga://192.168.1.100:28473     → 직접 지정
//   fpga://192.168.1.100           → 포트 기본값 사용
//   rawudp://192.168.1.100:28473   → rawudp도 호환
// ============================================================================

static BOOL _ParseConnectionString(
    _In_ LPCSTR szDevice,
    _Out_ CHAR szIP[64],
    _Out_ PWORD pwPort)
{
    LPCSTR p = szDevice;

    // 접두사 제거
    if (_strnicmp(p, "fpga://", 7) == 0) p += 7;
    else if (_strnicmp(p, "rawudp://", 9) == 0) p += 9;
    else if (_strnicmp(p, "hvdma://", 8) == 0) p += 8;
    else if (_stricmp(p, "fpga") == 0) p += 4;
    else if (_stricmp(p, "rawudp") == 0) p += 6;
    else if (_stricmp(p, "hvdma") == 0) p += 5;

    // 접두사 뒤에 IP가 없으면 config 파일에서 읽기
    if (p[0] == 0 || p[0] == ' ') {
        return _ReadConfigFile(szIP, pwPort);
    }

    // 파라미터 문자열 건너뛰기 (fpga://pciegen=1,... 같은 형식)
    // IP가 아닌 파라미터가 오면 config 파일에서 읽기
    if ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')) {
        return _ReadConfigFile(szIP, pwPort);
    }

    // IP:PORT 파싱
    const char* colon = strchr(p, ':');
    if (colon) {
        size_t ip_len = colon - p;
        if (ip_len >= 64) return FALSE;
        memcpy(szIP, p, ip_len);
        szIP[ip_len] = 0;
        *pwPort = (WORD)atoi(colon + 1);
    }
    else {
        size_t ip_len = strlen(p);
        if (ip_len >= 64) return FALSE;
        strcpy_s(szIP, 64, p);
        *pwPort = HVDMA_DEFAULT_PORT;
    }
    if (*pwPort == 0) *pwPort = HVDMA_DEFAULT_PORT;
    return TRUE;
}

// ============================================================================
// UDP 소켓 생성 + connected
// ============================================================================

static SOCKET _UdpCreate(LPCSTR szIP, WORD wPort)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return INVALID_SOCKET;

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;

    // [핵심] ICMP Port Unreachable 무시
    // Guest OS가 port 28473에 아무것도 안 열려있으면 ICMP 에러를 sender로 보냄
    // Windows는 이걸 connected UDP 소켓에 전달 → recvfrom() = error 10054
    // SIO_UDP_CONNRESET=FALSE로 설정하면 이 ICMP 에러를 소켓에 전달하지 않음
    // → recvfrom()은 정상적으로 HV 응답을 기다림
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
    {
        BOOL bNewBehavior = FALSE;
        DWORD dwBytesReturned = 0;
        WSAIoctl(sock, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior),
            NULL, 0, &dwBytesReturned, NULL, NULL);
    }

    DWORD timeout = HVDMA_RECV_TIMEOUT;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    // [핵심] 버퍼 크기: CHUNK_SIZE=256 → 응답 ~1MB (719 UDP chunks)
    // 2MB로 설정: 응답 1개 + 여유분
    int rcvbuf = 2 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char*)&rcvbuf, sizeof(rcvbuf));
    int sndbuf = 512 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char*)&sndbuf, sizeof(sndbuf));

    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(wPort);
    inet_pton(AF_INET, szIP, &addr.sin_addr);

    // connected UDP: default peer 설정
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    return sock;
}

// ============================================================================
// [진단용] 단일 PA 페이지 읽기 헬퍼
// Post-Open 진단에서 페이지테이블 walk에 사용
// ============================================================================
static BOOL _DiagReadPage(PHVDMA_CONTEXT ctx, QWORD pa, BYTE* out_page)
{
    DWORD req_sz = sizeof(DMA_MSG_HDR) + sizeof(DMA_SCATTER_HDR) + sizeof(DMA_SCATTER_ENTRY);
    PDMA_MSG_HDR h = (PDMA_MSG_HDR)ctx->send_buf;
    h->magic = DMA_PROTOCOL_MAGIC;
    h->cb_msg = req_sz;
    h->type = DMA_MSG_READ_SCATTER_REQ;
    h->version = DMA_PROTOCOL_VERSION;
    h->session_id = ctx->session_id;

    PDMA_SCATTER_HDR s = (PDMA_SCATTER_HDR)(ctx->send_buf + sizeof(DMA_MSG_HDR));
    s->count = 1;
    s->cb_total = 0x1000;

    PDMA_SCATTER_ENTRY e = (PDMA_SCATTER_ENTRY)(
        ctx->send_buf + sizeof(DMA_MSG_HDR) + sizeof(DMA_SCATTER_HDR));
    e->qw_addr = pa;
    e->cb = 0x1000;
    e->f = 0;

    DWORD cb_recv = 0;
    if (!_DmaRoundTrip(ctx, ctx->send_buf, req_sz, ctx->recv_buf, ctx->recv_buf_size, &cb_recv))
        return FALSE;

    PDMA_SCATTER_ENTRY re = (PDMA_SCATTER_ENTRY)(
        ctx->recv_buf + sizeof(DMA_MSG_HDR) + sizeof(DMA_SCATTER_HDR));
    if (!re->f) return FALSE;

    BYTE* data = ctx->recv_buf + sizeof(DMA_MSG_HDR) + sizeof(DMA_SCATTER_HDR)
        + sizeof(DMA_SCATTER_ENTRY);
    memcpy(out_page, data, 0x1000);
    return TRUE;
}

// ============================================================================
// DeviceFPGA_Open - 메인 진입점
// leechcore.c에서 "-device fpga" 시 호출됨
// 원본: FTD3XX.dll로 물리 FPGA USB 연결
// 교체: UDP로 hyper-reV HV 연결
// ============================================================================

_Success_(return)
BOOL DeviceFPGA_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    CHAR szIP[64] = { 0 };
    WORD wPort = 0;

    if (ppLcCreateErrorInfo) { *ppLcCreateErrorInfo = NULL; }

    lcprintf(ctxLC, "DEVICE: FPGA: [hyper-reV] UDP DMA mode\n");
    lcprintf(ctxLC, "DEVICE: FPGA: [hyper-reV] BUILD=0xFB sizeof(HDR)=%d\n", (int)sizeof(DMA_MSG_HDR));

    // 연결 문자열 파싱
    if (!_ParseConnectionString(ctxLC->Config.szDevice, szIP, &wPort)) {
        lcprintf(ctxLC, "DEVICE: FPGA: ERROR: No target IP. Use fpga://ip:port or create hvdma.ini\n");
        return FALSE;
    }

    lcprintf(ctxLC, "DEVICE: FPGA: [hyper-reV] Connecting to %s:%d (UDP)\n", szIP, wPort);

    // UDP 소켓 생성
    SOCKET sock = _UdpCreate(szIP, wPort);
    if (sock == INVALID_SOCKET) {
        lcprintf(ctxLC, "DEVICE: FPGA: ERROR: Failed to create UDP socket to %s:%d\n", szIP, wPort);
        return FALSE;
    }

    // 컨텍스트 할당
    PHVDMA_CONTEXT ctx = (PHVDMA_CONTEXT)calloc(1, sizeof(HVDMA_CONTEXT));
    if (!ctx) {
        closesocket(sock);
        return FALSE;
    }

    ctx->sock = sock;
    ctx->send_buf_size = HVDMA_BUF_SIZE;
    ctx->recv_buf_size = HVDMA_BUF_SIZE;
    ctx->send_buf = (BYTE*)malloc(ctx->send_buf_size);
    ctx->recv_buf = (BYTE*)malloc(ctx->recv_buf_size);
    InitializeCriticalSection(&ctx->lock);

    if (!ctx->send_buf || !ctx->recv_buf) {
        lcprintf(ctxLC, "DEVICE: FPGA: ERROR: Failed to allocate buffers\n");
        goto fail;
    }

    // DMA Open - HV와 세션 수립
    if (!_DmaOpen(ctx)) {
        lcprintf(ctxLC, "DEVICE: FPGA: ERROR: DMA Open failed (no response from HV at %s:%d)\n", szIP, wPort);
        goto fail;
    }

    lcprintf(ctxLC, "DEVICE: FPGA: [hyper-reV] Connected! Session=0x%08X PA_MAX=0x%llX\n",
        ctx->session_id, ctx->pa_max);

    // ============================================================================
    // [진단] Post-Open 물리 메모리 검증
    // PA 0x1000, 0x1AD000(일반적 SYSTEM DTB) 읽어서 데이터 유효성 확인
    // ReadScatter 콜백 등록 전이므로 _DmaRoundTrip 직접 사용
    // ============================================================================
    {
        DWORD test_addrs[] = { 0x1000, 0x10000, 0x100000, 0x1AD000 };
        DWORD ntest = sizeof(test_addrs) / sizeof(test_addrs[0]);

        DWORD req_size = sizeof(DMA_MSG_HDR) + sizeof(DMA_SCATTER_HDR)
            + ntest * sizeof(DMA_SCATTER_ENTRY);

        PDMA_MSG_HDR req_hdr = (PDMA_MSG_HDR)ctx->send_buf;
        req_hdr->magic = DMA_PROTOCOL_MAGIC;
        req_hdr->cb_msg = req_size;
        req_hdr->type = DMA_MSG_READ_SCATTER_REQ;
        req_hdr->version = DMA_PROTOCOL_VERSION;
        req_hdr->session_id = ctx->session_id;

        PDMA_SCATTER_HDR sh = (PDMA_SCATTER_HDR)(ctx->send_buf + sizeof(DMA_MSG_HDR));
        sh->count = ntest;
        sh->cb_total = ntest * 0x1000;

        PDMA_SCATTER_ENTRY entries = (PDMA_SCATTER_ENTRY)(
            ctx->send_buf + sizeof(DMA_MSG_HDR) + sizeof(DMA_SCATTER_HDR));
        for (DWORD i = 0; i < ntest; i++) {
            entries[i].qw_addr = test_addrs[i];
            entries[i].cb = 0x1000;
            entries[i].f = 0;
        }

        DWORD cb_recv = 0;
        if (_DmaRoundTrip(ctx, ctx->send_buf, req_size, ctx->recv_buf, ctx->recv_buf_size, &cb_recv)) {
            printf("[DIAG] Post-Open read OK (cb_recv=%d)\n", cb_recv);

            // 응답 파싱: 각 PA의 첫 16바이트
            PDMA_SCATTER_HDR rsh = (PDMA_SCATTER_HDR)(ctx->recv_buf + sizeof(DMA_MSG_HDR));
            PDMA_SCATTER_ENTRY re = (PDMA_SCATTER_ENTRY)(
                ctx->recv_buf + sizeof(DMA_MSG_HDR) + sizeof(DMA_SCATTER_HDR));
            BYTE* data = ctx->recv_buf + sizeof(DMA_MSG_HDR) + sizeof(DMA_SCATTER_HDR)
                + ntest * sizeof(DMA_SCATTER_ENTRY);

            DWORD off = 0;
            for (DWORD i = 0; i < rsh->count && i < ntest; i++) {
                if (re[i].f) {
                    printf("[DIAG] PA=%08X: %02X %02X %02X %02X %02X %02X %02X %02X "
                        "%02X %02X %02X %02X %02X %02X %02X %02X\n",
                        test_addrs[i],
                        data[off + 0], data[off + 1], data[off + 2], data[off + 3],
                        data[off + 4], data[off + 5], data[off + 6], data[off + 7],
                        data[off + 8], data[off + 9], data[off + 10], data[off + 11],
                        data[off + 12], data[off + 13], data[off + 14], data[off + 15]);
                    off += re[i].cb;
                }
                else {
                    printf("[DIAG] PA=%08X: FAIL (unmapped)\n", test_addrs[i]);
                }
            }
        }
        else {
            printf("[DIAG] Post-Open read FAILED!\n");
        }
        fflush(stdout);
    }

    // ============================================================================
    // [진단] Page Table Walk - EPROCESS VA→PA 변환 추적
    // ============================================================================
    // NTOS=PML4[496] 성공, EPROCESS=PML4[351] 실패 확인됨
    // 4레벨 페이지테이블 walk을 수동으로 수행하여 실패 지점 특정
    //
    // Walk 경로: PML4 → PDPT → PD → PT → 최종 PA
    // DTB(CR3) = 0x1AD000 (MemProcFS 로그에서 확인)
    // EPROCESS VA = 0xFFFFAF8816F31080 → PML4[351], PDPT[16], PD[183], PT[305]
    // NTOS VA = 0xFFFFF80575200000 → PML4[496] (비교용)
    // ============================================================================
    {
        printf("\n[PT-WALK] === Page Table Walk Diagnostic ===\n");

        BYTE page_buf[0x1000];
        QWORD dtb_pa = 0x1AD000;  /* MemProcFS 로그에서 확인된 DTB */
        DWORD t, i;
        QWORD pml4e, pdpte, pde, pte;
        QWORD pdpt_pa, pd_pa, pt_pa, final_pa;

        /* VA에서 페이지테이블 인덱스 계산 매크로 */
#define PML4_IDX(va) ((DWORD)(((va) >> 39) & 0x1FF))
#define PDPT_IDX(va) ((DWORD)(((va) >> 30) & 0x1FF))
#define PD_IDX(va)   ((DWORD)(((va) >> 21) & 0x1FF))
#define PT_IDX(va)   ((DWORD)(((va) >> 12) & 0x1FF))

/* [주의] 이 VA는 부팅마다 달라질 수 있음!
   memprocfs -v -vv -vvv 로그에서 확인 후 업데이트 */
        QWORD target_vas[2] = { 0xFFFFAF8816F31080ULL, 0xFFFFF80575200000ULL };
        const char* target_names[2] = { "EPROCESS", "NTOS" };

        /* Step 1: PML4 페이지 읽기 */
        printf("[PT-WALK] Reading PML4 at PA=0x%llX...\n", dtb_pa);
        if (!_DiagReadPage(ctx, dtb_pa, page_buf)) {
            printf("[PT-WALK] FATAL: Cannot read PML4 page!\n");
        }
        else {
            QWORD* pml4 = (QWORD*)page_buf;
            DWORD k_valid = 0, k_zero = 0, k_bad = 0;

            /* 커널 영역 PML4 엔트리 통계 (256-511) */
            for (i = 256; i < 512; i++) {
                QWORD pa_field;
                if (pml4[i] == 0) { k_zero++; continue; }
                pa_field = pml4[i] & 0x0000FFFFFFFFF000ULL;
                if ((pml4[i] & 1) && pa_field < ctx->pa_max) k_valid++;
                else if (pml4[i] & 1) k_bad++;
            }
            printf("[PT-WALK] PML4 kernel stats: valid=%d zero=%d bad_pa=%d\n", k_valid, k_zero, k_bad);

            /* Self-referential entry 확인 */
            for (i = 256; i < 512; i++) {
                if ((pml4[i] & 0x0000FFFFFFFFF083ULL) == (dtb_pa | 0x03))
                    printf("[PT-WALK] PML4 self-ref at [%d] = 0x%016llX\n", i, pml4[i]);
            }

            /* 각 타겟 VA에 대해 4레벨 walk 수행 */
            for (t = 0; t < 2; t++) {
                QWORD va = target_vas[t];
                DWORD idx_pml4 = PML4_IDX(va);
                DWORD idx_pdpt = PDPT_IDX(va);
                DWORD idx_pd = PD_IDX(va);
                DWORD idx_pt = PT_IDX(va);

                printf("\n[PT-WALK] --- %s VA=0x%llX ---\n", target_names[t], va);
                printf("[PT-WALK] Indices: PML4[%d] PDPT[%d] PD[%d] PT[%d]\n",
                    idx_pml4, idx_pdpt, idx_pd, idx_pt);

                /* Level 1: PML4 */
                pml4e = pml4[idx_pml4];
                printf("[PT-WALK] L1 PML4[%d] = 0x%016llX", idx_pml4, pml4e);
                if (!(pml4e & 1)) { printf(" -> NOT PRESENT!\n"); continue; }
                pdpt_pa = pml4e & 0x0000FFFFFFFFF000ULL;
                printf(" -> RW=%d US=%d NX=%d PDPT_PA=0x%llX",
                    (int)((pml4e >> 1) & 1), (int)((pml4e >> 2) & 1),
                    (int)((pml4e >> 63) & 1), pdpt_pa);
                if (pdpt_pa >= ctx->pa_max) { printf(" EXCEEDS paMax!\n"); continue; }
                printf("\n");

                /* Level 2: PDPT */
                printf("[PT-WALK] L2 Reading PDPT at PA=0x%llX...\n", pdpt_pa);
                if (!_DiagReadPage(ctx, pdpt_pa, page_buf)) {
                    printf("[PT-WALK] L2 FAIL: Cannot read PDPT!\n"); continue;
                }
                pdpte = ((QWORD*)page_buf)[idx_pdpt];
                printf("[PT-WALK] L2 PDPT[%d] = 0x%016llX", idx_pdpt, pdpte);
                if (!(pdpte & 1)) { printf(" -> NOT PRESENT!\n"); continue; }
                if (pdpte & 0x80) {
                    final_pa = (pdpte & 0x0000FFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
                    printf(" -> 1GB LARGE PAGE! PA=0x%llX\n", final_pa); continue;
                }
                pd_pa = pdpte & 0x0000FFFFFFFFF000ULL;
                printf(" -> PD_PA=0x%llX", pd_pa);
                if (pd_pa >= ctx->pa_max) { printf(" EXCEEDS paMax!\n"); continue; }
                printf("\n");

                /* Level 3: PD */
                printf("[PT-WALK] L3 Reading PD at PA=0x%llX...\n", pd_pa);
                if (!_DiagReadPage(ctx, pd_pa, page_buf)) {
                    printf("[PT-WALK] L3 FAIL: Cannot read PD!\n"); continue;
                }
                pde = ((QWORD*)page_buf)[idx_pd];
                printf("[PT-WALK] L3 PD[%d] = 0x%016llX", idx_pd, pde);
                if (!(pde & 1)) { printf(" -> NOT PRESENT!\n"); continue; }
                if (pde & 0x80) {
                    final_pa = (pde & 0x0000FFFFFFE00000ULL) | (va & 0x1FFFFFULL);
                    printf(" -> 2MB LARGE PAGE! PA=0x%llX\n", final_pa); continue;
                }
                pt_pa = pde & 0x0000FFFFFFFFF000ULL;
                printf(" -> PT_PA=0x%llX", pt_pa);
                if (pt_pa >= ctx->pa_max) { printf(" EXCEEDS paMax!\n"); continue; }
                printf("\n");

                /* Level 4: PT */
                printf("[PT-WALK] L4 Reading PT at PA=0x%llX...\n", pt_pa);
                if (!_DiagReadPage(ctx, pt_pa, page_buf)) {
                    printf("[PT-WALK] L4 FAIL: Cannot read PT!\n"); continue;
                }
                pte = ((QWORD*)page_buf)[idx_pt];
                printf("[PT-WALK] L4 PT[%d] = 0x%016llX", idx_pt, pte);
                if (!(pte & 1)) { printf(" -> NOT PRESENT!\n"); continue; }
                final_pa = (pte & 0x0000FFFFFFFFF000ULL) | (va & 0xFFFULL);
                printf(" -> FINAL PA=0x%llX\n", final_pa);

                /* 최종 PA 읽기 시도 */
                printf("[PT-WALK] Reading final PA=0x%llX...\n", final_pa);
                if (!_DiagReadPage(ctx, final_pa, page_buf)) {
                    printf("[PT-WALK] FAIL: Cannot read final page!\n");
                }
                else {
                    DWORD page_off = (DWORD)(va & 0xFFF);
                    printf("[PT-WALK] SUCCESS! Data at offset 0x%X:\n", page_off);
                    printf("[PT-WALK]   %02X %02X %02X %02X %02X %02X %02X %02X "
                        "%02X %02X %02X %02X %02X %02X %02X %02X\n",
                        page_buf[page_off + 0], page_buf[page_off + 1],
                        page_buf[page_off + 2], page_buf[page_off + 3],
                        page_buf[page_off + 4], page_buf[page_off + 5],
                        page_buf[page_off + 6], page_buf[page_off + 7],
                        page_buf[page_off + 8], page_buf[page_off + 9],
                        page_buf[page_off + 10], page_buf[page_off + 11],
                        page_buf[page_off + 12], page_buf[page_off + 13],
                        page_buf[page_off + 14], page_buf[page_off + 15]);
                }
            }

            /* HV Heap 범위와 페이지테이블 PA 충돌 체크 */
            printf("\n[PT-WALK] HV Heap PA range: 0x746CB000 - 0x74AE4000\n");

            /* 일반 커널 PML4 스캔: 모든 valid 엔트리의 PDPT 읽기 시도 */
            printf("[PT-WALK] === Kernel PML4 PDPT Readability Scan ===\n");
            {
                DWORD pdpt_ok = 0, pdpt_fail = 0;
                for (i = 256; i < 512; i++) {
                    BYTE tmp[0x1000];
                    QWORD scan_pa;
                    if (!(pml4[i] & 1)) continue;
                    scan_pa = pml4[i] & 0x0000FFFFFFFFF000ULL;
                    if (scan_pa >= ctx->pa_max) {
                        printf("[PT-WALK] PML4[%d] PA=0x%llX EXCEEDS paMax!\n", i, scan_pa);
                        continue;
                    }
                    if (_DiagReadPage(ctx, scan_pa, tmp)) {
                        pdpt_ok++;
                    }
                    else {
                        pdpt_fail++;
                        printf("[PT-WALK] PML4[%d] PDPT_PA=0x%llX -> READ FAIL!\n", i, scan_pa);
                    }
                }
                printf("[PT-WALK] PDPT scan: %d readable, %d FAILED\n", pdpt_ok, pdpt_fail);
            }
        }

        printf("[PT-WALK] === End ===\n\n");
        fflush(stdout);
    }

    // LeechCore 콜백 등록
    ctxLC->hDevice = (HANDLE)ctx;
    ctxLC->pfnReadScatter = DeviceFPGA_ReadScatter;
    ctxLC->pfnWriteScatter = DeviceFPGA_WriteScatter;
    ctxLC->pfnGetOption = DeviceFPGA_GetOption;
    ctxLC->pfnSetOption = DeviceFPGA_SetOption;
    ctxLC->pfnCommand = DeviceFPGA_Command;
    ctxLC->pfnClose = DeviceFPGA_Close;
    ctxLC->fMultiThread = FALSE;    // UDP는 단일 스레드 (lock으로 보호)

    // Config 설정
    ctxLC->Config.fWritable = TRUE;
    ctxLC->Config.fVolatile = TRUE;
    ctxLC->Config.paMax = ctx->pa_max;

    // MemMap: 0 ~ pa_max 전체 범위
    LcMemMap_AddRange(ctxLC, 0, ctx->pa_max, 0);

    // FPGA처럼 보이는 출력 (다른 프로그램이 파싱할 수 있음)
    lcprintfv(ctxLC,
        "DEVICE: FPGA: hyper-reV PCIe gen2 x4 [300,25,500] [v4.14,%04x] [SYNC,NORM]\n",
        0x0400);

    return TRUE;

fail:
    if (ctx) {
        _DmaClose(ctx);
        DeleteCriticalSection(&ctx->lock);
        if (ctx->send_buf) free(ctx->send_buf);
        if (ctx->recv_buf) free(ctx->recv_buf);
        free(ctx);
    }
    ctxLC->hDevice = NULL;
    return FALSE;
}