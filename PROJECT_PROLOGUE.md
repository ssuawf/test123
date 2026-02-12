# hyper-reV 소프트웨어 DMA 프로젝트 — 전체 컨텍스트 브리핑

## 1. 프로젝트 개요

**hyper-reV**는 Microsoft Hyper-V에 기생(parasitic)하여 동작하는 Ring -1 하이퍼바이저로, 물리 FPGA DMA 장비 없이 **소프트웨어만으로** 타겟 PC의 물리 메모리를 원격 읽기/쓰기하는 시스템이다.

**핵심 아이디어**: 타겟 PC에서 Hyper-V가 켜진 상태로 USB 부팅 → hyper-reV가 Hyper-V에 기생 주입 → NIC(Intel I225-V)의 EPT를 후킹하여 특정 UDP 패킷을 가로챔 → 공격 PC의 LeechCore/MemProcFS가 "fpga://" 디바이스로 연결 → 물리 메모리 접근

**아키텍처 다이어그램**:
```
[공격 PC]                              [타겟 PC]
MemProcFS/PCILeech                     Windows + Hyper-V
    ↓                                      ↑
LeechCore.dll (수정됨)                  hyper-reV (Ring -1)
    ↓ UDP                                  ↑ EPT hook
    └──── LAN ─────────────────────────────┘
         port 28473                   Intel I225-V NIC
         "HVD0" protocol             읽기전용 RX 폴링
                                      TX Queue 1 격리
```

## 2. 두 개의 핵심 파일

### 2.1 `device_fpga.c` (LeechCore측, 공격 PC) — ~1513줄
- 원래 4000줄짜리 물리 FPGA USB 코드를 **완전히 교체**
- `-device fpga` 또는 `fpga://IP:PORT`로 호출하면 hyper-reV HV에 UDP 연결
- leechcore.dll 하나만 교체하면 기존 PCILeech/MemProcFS 생태계 전부 호환

**프로토콜**:
- Magic: `0x48564430` ("HVD0")
- 메시지: OPEN/CLOSE/READ_SCATTER/WRITE_SCATTER/PING/KEEPALIVE
- 헤더 16B (magic, cb_msg, type, version, session_id) + scatter 데이터

**현재 설정값**:
```c
#define HVDMA_CHUNK_SIZE        32      // 1회 요청당 32 pages
#define HVDMA_PIPELINE_WINDOW   1       // stop-and-wait (파이프라이닝 비활성)
#define HVDMA_RECV_TIMEOUT      50      // 50ms (정상 2ms에 25배 마진)
#define HVDMA_BUF_SIZE          (2*1024*1024)  // 2MB 버퍼
```

**핵심 메커니즘 — 2-pass 동기 처리**:
```
Pass 1: 전체 chunks 순차 전송 (동기, 요청→응답→요청→응답)
  - 대부분 성공 (~232/241), 일부 실패 (~9개, HV TX stall 때문)
  - 실패한 chunk의 offset/count 기록
  
Sleep(1000ms): HV stall 완전 해소 대기

Pass 2: 실패한 chunks만 재시도
  - stall 해소 후이므로 100% 성공 예상
  - 누락된 page table entries 복구 → EPROCESS walk 성공!
```

**_ReadScatterChunkSync 함수**: 단일 chunk 동기 처리
- 5회 retry with progressive backoff: [0, 50, 100, 200, 500]ms
- 각 retry마다 50ms recv timeout
- 최대 1.1초/chunk 소비 (stall 1초 커버)

### 2.2 `network.cpp` (HV측, 타겟 PC) — ~2097줄
- Ring -1에서 NIC 하드웨어를 직접 제어
- I225-V(igc) NIC 전용 (Intel 2.5GbE)

**RX 아키텍처 (100% 읽기전용)**:
- 4개 RX 큐 전부 폴링 (MRQC/RETA 레지스터 수정 없음!)
- 큐별 buffer address 캐시 + RDT 추적
- Guest ISR보다 먼저 패킷 읽기 (POLL_INTERVAL_TSC = 0, 모든 VMEXIT에서 즉시)
- 패킷을 로컬 버퍼에 복사 후 처리 (Guest 버퍼 재사용으로 인한 TOCTOU 방지)

**TX 아키텍처 (최소 변조)**:
- TX Queue 1 전용 격리: hidden page 기반, OS의 Q0과 완전 분리
- `inject_tx_frame_intel_igc()`: descriptor 작성 → TDT bump → DD-wait
- MAX_TX_WAIT = 500000 spins (~5ms)
- Q1 미초기화시 Q0 fallback 지원

**Deferred TX State Machine**:
```
문제: 큰 응답(512 pages)은 722 UDP frames → 1 VMEXIT에서 8.7ms 소요
      → Hyper-V watchdog (~1초이지만 VMEXIT 독점은 위험)
      
해결: MAX_CHUNKS_PER_EXIT = 100으로 제한
      나머지는 다음 VMEXIT에서 이어서 전송 (deferred_tx 상태 머신)
      deferred_tx.active 동안 RX poll 스킵 (buffer 보호)
```

**Chunked UDP 프로토콜 (HV→LeechCore 응답)**:
```c
// chunk_hdr_t (12B) — 각 UDP frame 앞에 붙음
struct chunk_hdr_t {
    uint16_t chunk_index;    // 0-based index
    uint16_t chunk_total;    // 전체 chunk 수  
    uint32_t total_size;     // 전체 payload 크기
    uint32_t response_seq;   // 응답 시퀀스 (stale 패킷 필터링용)
};
// Max UDP payload: 1472B - 12B header = 1460B data per chunk
```

**vCPU 경합 방지**: atomic spinlock으로 process_pending() 직렬화
- Multi-vCPU 환경에서 동시 RX 처리 → 중복 응답/seq 점프 방지

## 3. 현재 상태 & 문제점

### 3.1 동작하는 것 ✅
- USB 부팅 → Hyper-V 기생 주입 성공 (AMD CPU, Intel NIC)
- UDP 통신 양방향 성공 (공격 PC ↔ 타겟 PC)
- ReadScatter 기본 동작: 작은 요청 100% 성공 (#1-#4: 1~53 pages)


### 3.2 핵심 미해결 문제 ❌
**EPROCESS walk 실패** — MemProcFS "Unable to walk EPROCESS #5" 오류

**원인 체인**:
```
ReadScatter #5 (대형, ~7700 pages)
  → ~120 chunks 후 HV TX stall 발생 (1-2초)
  → 9 chunks 실패 = 288 pages 누락
  → page table entries 누락
  → EPROCESS 링크드 리스트 walk 불가
```

**TX Stall 원인 추정**:
- ~10,000 inject calls 후 발생 (일관적 패턴)
- OS igc 드라이버의 NAPI polling 또는 watchdog 간섭 가능성
- TX ring descriptor DD-wait timeout (MAX_TX_WAIT=500K spins)
- stall은 일시적 (1-2초 후 자연 해소) → HV는 죽지 않음

### 3.3 다음 단계 (구현 예정)
**2-pass recovery 테스트**: device_fpga.c에 이미 구현됨, 테스트 필요
```
예상 결과:
  Pass 1: ~3초 (232 OK + 9 fail + backoff)
  Sleep(1000)
  Pass 2: 9 chunks × 2ms = 18ms (100% 복구 예상)
  총: ~4초, 모든 pages 수집 → EPROCESS walk 성공!
```

테스트 커맨드:
```
memprocfs.exe -device fpga://192.168.1.1:28473 -v -cr3 0x1AD000
```

**2-pass 성공 후 추가 최적화 방향**:
1. CHUNK_SIZE 튜닝 (32 → 64? stall 전 throughput 향상)
2. TX stall 근본 원인 해결 (inject 함수 최적화)
3. 응답 완료 시그널 패킷 도입 (공식 RawUDP의 inactivity timer 참고)
4. WriteScatter 구현 확장

## 4. 프로토콜 상세

### 4.1 LeechCore → HV (요청)
```
[DMA_MSG_HDR: 16B]
  magic=0x48564430, cb_msg, type, version=1, session_id

[DMA_SCATTER_HDR: 8B]  (READ_SCATTER_REQ일 때)
  count=N, cb_total=N*4096

[DMA_SCATTER_ENTRY × N: 16B each]
  qw_addr (GPA), cb (보통 4096), f (flags)
```

### 4.2 HV → LeechCore (응답, chunked UDP)
```
[chunk_hdr_t: 12B] + [data: ≤1460B]

chunk 0: [chunk_hdr] + [DMA_MSG_HDR + DMA_SCATTER_HDR + scatter_entries...]
chunk 1-N: [chunk_hdr] + [continuation data...]

LeechCore에서 chunk_total 개 모이면 reassemble → 전체 응답 파싱
response_seq로 stale 패킷 필터링 (이전 요청의 지연 응답 무시)
```

### 4.3 OPEN 핸드셰이크
```
LeechCore: OPEN_REQ → HV
HV: 물리메모리 최대주소 조회 → OPEN_RSP (pa_max, success=1)
LeechCore: pa_max를 LC_CONFIG에 설정 → 이후 ReadScatter 가능
```

## 5. 감지 벡터 분석 (45개 검증 완료)

프로젝트는 EAC/BattlEye/Vanguard 등 안티치트 감지를 회피하도록 설계됨:

- **부트 체인**: USB 부팅 + Secure Boot OFF + TPM OFF (HVCI 환경)
- **NIC 은닉**: RX 읽기전용 (MRQC/RETA 수정 없음), TX stats 클리어 제거, Q1 격리
- **EPT**: Hyper-V 기생이므로 별도 EPT 없음 (Hyper-V의 SLAT 사용)
- **타이밍**: VMEXIT 오버헤드 최소 (POLL_INTERVAL=0, fast path DD=0 체크만)
- **네트워크**: IP ID 랜덤화, TTL 표준화, 커스텀 프로토콜 (표준 포트 아님)
- **프로세스**: 타겟에 에이전트/드라이버 없음 (Ring -1 하이퍼바이저만)

## 6. 진화 히스토리 (시간순)

| 날짜 | 마일스톤 |
|------|----------|
| 02-08 AM | 아키텍처 설계, 감지벡터 분석 (31→45개), LeechCore 플러그인 |
| 02-08 PM | USB 부팅 성공, UEFI 디버그, AMD/Intel 불일치 해결 |
| 02-08 Night | NIC 초기화 (RTL8125B/I225-V), 네트워크 디버그 시작 |
| 02-09 | RX ring sync 문제, IGC 레지스터 오프셋 수정, 멀티큐 폴링 |
| 02-10 AM | TX Q1 DD timeout, Magic 불일치, TOCTOU race, 캐시 버그 |
| 02-10 PM | Build 0xFB: DMA 첫 성공! 39 응답, TX descriptor DEXT 수정 |
| 02-11 AM | IP 프래그먼트→chunked UDP 전환, vCPU race fix, 100% 전송 |
| 02-11 PM | Deferred TX, CHUNK 256→32, sync 전환, retry+backoff |
| 02-12 | 2-pass recovery 구현, progressive backoff 최적화 |

## 7. 빌드 & 테스트

### 공격 PC (LeechCore 빌드)
- Visual Studio 2019+, `LeechCore-master/` 솔루션
- `device_fpga.c` 교체 → 빌드 → `leechcore.dll` 교체
- 테스트: `memprocfs.exe -device fpga://IP:PORT -v -cr3 0x1AD000`
- 또는: `memprocfs.exe -device fpga -v` (hvdma.ini에서 IP 읽기)

### 타겟 PC (hyper-reV)
- Visual Studio, hyper-reV 솔루션
- `network.cpp`는 `src/network/` 하위
- USB 부팅으로 Hyper-V에 주입
- 디버그 출력: CPUID probe tool (`hv_probe.exe`)

## 8. 참고: Valkyrie TCP 분석 (unknowncheats 유출 DLL)

IDA Pro로 분석한 대안 구현 — TCP 16개 병렬 연결:
- 192.168.1.1:3005, 고정 4120B 패킷, magic 0x12345678
- 64+ MEMs: 16 스레드 병렬 / <64 MEMs: round-robin
- TCP이므로 패킷 손실 없음, retry 불필요
- **단점**: 타겟에 서버 에이전트 필요 → 안티치트 탐지 가능
- **우리 장점**: HV 기반 → 타겟에 프로세스/드라이버 없음 → 은닉성

## 9. 공식 LeechCore RawUDP (ufrisk)

- `device_fpga.c`에 통합, UDP port 28474
- FT601 USB 파이프를 UDP로 에뮬레이션 (`DeviceFPGA_UDP_FT60x_*`)
- NeTV2 FPGA 보드용, RETRY_ON_ERROR=0 (하드웨어 안정성 의존)
- "inactivity timer" 시그널 패킷으로 응답 완료 감지 (0xeffffff3 + 0xdeceffff)
- **참고 포인트**: 시그널 패킷 방식을 우리 구현에 적용 가능

## 10. 핵심 정의/오프셋 (하이퍼바이저 측)

### NIC 레지스터 (I225-V / igc)
```
// RX Queue 0-3
RDH(q):  0xC010 + q*0x40   // head
RDT(q):  0xC018 + q*0x40   // tail
RDBAL(q): 0xC000 + q*0x40  // base addr low
RDBAH(q): 0xC004 + q*0x40  // base addr high
RDLEN(q): 0xC008 + q*0x40  // ring length

// TX Queue 1 (격리)
TDBAL1: 0xE000 + 0x40 = 0xE040
TDBAH1: 0xE044
TDLEN1: 0xE048
TDH1:   0xE050
TDT1:   0xE058
TXDCTL1: 0xE068
```

### DMA 프로토콜
```
Magic:    0x48564430 ("HVD0")
Port:     28473
Version:  0x0001
Chunk:    max 1460B data + 12B header per UDP frame
```



## 12. 현재 구현 상태 요약

```
[완료] USB 부팅 → HV 주입
[완료] NIC 초기화 (I225-V, 4큐 RX, Q1 TX)
[완료] UDP 양방향 통신
[완료] ReadScatter 기본 동작
[완료] Chunked UDP 응답 프로토콜
[완료] vCPU race condition 해결
[완료] Deferred TX state machine
[완료] Progressive backoff retry
[완료] 2-pass recovery 코드 작성

[테스트 필요] 2-pass recovery 실제 테스트
[미구현] WriteScatter 확장
[미구현] TX stall 근본 원인 해결
[미구현] 응답 완료 시그널 패킷
[미구현] CHUNK_SIZE 최적화 (32 → ?)
```

---
*이 문서는 2026-02-12 기준, ~90개 대화 세션의 전체 컨텍스트를 압축한 것임*
*첨부된 device_fpga.c와 network.cpp가 현재 최신 코드*
