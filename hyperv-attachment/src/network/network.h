#pragma once
#include <cstdint>

// ============================================================================
// Network Module - NIC    DMA  
// ============================================================================
//
// [ : TCP  UDP]
//  : TCP  (LeechCore   HV)
//  : Ring -1 TCP    (ACK, ,  )
//  : UDP  
//   - HV: NIC RX ring UDP    / TX ring  
//   - PC: LeechCore  UDP  
//   - DMA   -  TCP 
//
// [ ]
// 1. set_up(): PCI   NIC   RX/TX ring 
// 2. process_pending(): VMEXIT   RX ring   DMA  
// 3. send_response(): DMA  UDP  TX ring 
//
// [Ring -1 ]
// - AC NIC    UDP 
// - HV Guest NDIS        
// -  /  
// ============================================================================

namespace network
{
    // NIC  + RX/TX ring  + 
    void set_up();

    // VMEXIT : RX ring DMA    
    // :   
    std::uint8_t process_pending();

    // DMA  UDP  TX ring 
    // dma_response: DMA   
    // size:  
    // : 1=, 0=
    std::uint8_t send_response(const std::uint8_t* dma_response, std::uint32_t size);

    //   ()
    std::uint8_t send_packet(const std::uint8_t* data, std::uint32_t size);

    // 
    inline std::uint8_t is_initialized = 0;
    inline std::uint64_t attack_pc_identifier = 0;

    //  ()
    inline std::uint64_t packets_received = 0;
    inline std::uint64_t packets_sent = 0;
    inline std::uint64_t packets_dropped = 0;
    // [핵심] 0xF8: cache miss 카운터 - DD=1 시점에 cache[idx]==0이면 패킷 스킵
    inline volatile std::uint32_t dbg_cache_miss = 0;
    inline volatile std::uint32_t dbg_cache_hit = 0;
    inline volatile std::uint32_t dbg_precache_update = 0; // 0xFA: proactive cache 성공 횟수
    // 0xFB: 회전 스캐너 진단
    inline volatile std::uint32_t dbg_scan_total = 0;   // 총 스캔한 descriptor 수
    inline volatile std::uint32_t dbg_scan_dd0 = 0;     // DD=0 발견 (READ format)
    inline volatile std::uint32_t dbg_scan_dd1 = 0;     // DD=1 발견 (WB format)
    inline volatile std::uint32_t dbg_scan_addr_zero = 0; // DD=0이지만 addr=0
    inline volatile std::uint64_t dbg_scan_first_addr = 0; // 첫 DD=0 descriptor의 pkt_addr
    inline volatile std::uint64_t dbg_scan_first_hdr = 0;  // 첫 DD=0 descriptor의 hdr_addr (staterr 위치)

    // [핵심] 디버그 진단 변수 - CPUID probe로 노출
    inline std::uint32_t dbg_rx_call_count = 0;      // process_rx_packet 호출 횟수
    inline std::uint32_t dbg_rx_udp_count = 0;       // UDP 파싱 성공 횟수
    inline std::uint32_t dbg_rx_port_match = 0;      // dst_port==28473 매칭 횟수
    inline std::uint32_t dbg_rx_dma_call = 0;        // process_complete_dma_payload 호출 횟수
    inline std::uint16_t dbg_last_dst_port = 0;      // 마지막 수신 UDP dst_port
    inline std::uint32_t dbg_last_payload_magic = 0;  // 마지막 UDP payload 첫 4바이트
    inline std::uint16_t dbg_last_pkt_len = 0;       // 마지막 수신 패킷 길이
    inline std::uint32_t dbg_igc_dd_count = 0;       // DD=1 감지 횟수
    inline std::uint16_t dbg_attack_src_port = 0;      // [핵심] 공격 PC ephemeral src_port (host order)
    inline std::uint32_t dbg_active_rx_queues = 0;     // [핵심] 활성 RX 큐 개수 (igc: 최대 4)

    // [핵심] TX Q1 디버그 카운터
    inline std::uint32_t dbg_txq1_dd_ok = 0;          // DD 정상 세팅 횟수
    inline std::uint32_t dbg_txq1_dd_timeout = 0;     // DD 타임아웃 횟수
    inline std::uint32_t dbg_txq1_last_tdh = 0;       // 마지막 TX 후 TDH 값
    inline std::uint32_t dbg_txq1_last_cmd = 0;       // 마지막 TX cmd_type_len (DEXT 확인용)
    inline std::uint32_t dbg_txq1_last_olinfo = 0;    // 마지막 TX olinfo_status (PAYLEN 확인용)
    inline std::uint32_t dbg_txq1_q0_fallback = 0;    // Q0 fallback 사용 횟수

    // [핵심] DMA→TX 경로 진단 카운터
    inline std::uint32_t dbg_dma_rsp_size = 0;         // 마지막 dma::process 리턴값
    inline std::uint32_t dbg_dma_rsp_nonzero = 0;      // rsp_size > 0 횟수
    inline std::uint32_t dbg_send_response_enter = 0;   // send_response 진입 횟수
    inline std::uint32_t dbg_send_response_fail = 0;    // send_response 실패 사유 (bitfield)

    // [핵심] dma::process 내부 실패 사유 추적
    // 1=size<hdr, 2=magic, 3=version, 4=cb_msg>size, 5=unknown_type
    inline std::uint32_t dbg_dma_fail_reason = 0;
    inline std::uint32_t dbg_dma_last_version = 0;      // 받은 version 값
    inline std::uint32_t dbg_dma_last_type = 0;          // 받은 type 값
    inline std::uint32_t dbg_dma_last_cbmsg = 0;         // 받은 cb_msg 값
    inline std::uint32_t dbg_dma_payload_size = 0;       // ip_frag에서 넘어온 dma_size

    // [핵심] raw 패킷 덤프: volatile scalar (컴파일러 최적화 방지)
    // 배열 방식은 dead store elimination으로 제거될 수 있음
    inline volatile std::uint32_t dbg_pkt_eth0 = 0;       // pkt_data[0..3] ETH dst mac
    inline volatile std::uint32_t dbg_pkt_ip0 = 0;        // pkt_data[14..17] IP ver+tos+totlen
    inline volatile std::uint32_t dbg_pkt_ip4 = 0;        // pkt_data[18..21] IP id+flags+frag
    inline volatile std::uint32_t dbg_pkt_udp0 = 0;       // UDP ports (src+dst)
    inline volatile std::uint32_t dbg_pkt_dma0 = 0;       // DMA payload[0..3] = magic
    inline volatile std::uint32_t dbg_pkt_dma4 = 0;       // DMA payload[4..7] = cb_msg
    inline volatile std::uint32_t dbg_pkt_dma8 = 0;       // DMA payload[8..11] = type+version
    inline volatile std::uint32_t dbg_pkt_dma12 = 0;      // DMA payload[12..15] = session_id

    // [핵심] IP 파싱 중간값 캡처 (ip_frag에서 사용되는 실제 값)
    inline volatile std::uint32_t dbg_ip_total = 0;        // ntohs(ip->total_length)
    inline volatile std::uint32_t dbg_ip_ihl = 0;          // (ver_ihl & 0x0F) * 4
    inline volatile std::uint32_t dbg_udp_payload_ptr_off = 0; // udp_payload - pkt_data 오프셋

    // [핵심] 0xF3 byte-level + 0xF4 buf_addr/raw 비교
    inline volatile std::uint32_t dbg_udp_len = 0;        // ntohs(udp->length) - 패딩 vs 실제크기 판별
    inline volatile std::uint32_t dbg_udp_chksum = 0;     // UDP checksum (0이면 no checksum)
    inline volatile std::uint32_t dbg_payload_b0 = 0;     // udp_payload[0] 개별바이트
    inline volatile std::uint32_t dbg_payload_b4 = 0;     // udp_payload[4] 개별바이트 (cb_msg 첫바이트)
    inline volatile std::uint32_t dbg_payload_b5 = 0;     // udp_payload[5]
    inline volatile std::uint32_t dbg_payload_b8 = 0;     // udp_payload[8] (type 첫바이트)
    inline volatile std::uint32_t dbg_payload_b10 = 0;    // udp_payload[10] (version 첫바이트)
    inline volatile std::uint32_t dbg_pkt_len = 0;        // descriptor가 리포트한 패킷 길이

    // [핵심] 0xF4~0xF6 buf_addr + raw/copy 비교 진단
    inline volatile std::uint64_t dbg_buf_addr = 0;
    inline volatile std::uint32_t dbg_desc_idx = 0;
    inline volatile std::uint32_t dbg_wb_staterr = 0;
    inline volatile std::uint32_t dbg_raw_ip_total = 0;
    inline volatile std::uint32_t dbg_copy_ip_total = 0;
    inline volatile std::uint32_t dbg_raw_dma4 = 0;
    inline volatile std::uint32_t dbg_copy_dma4 = 0;
    inline volatile std::uint32_t dbg_raw_byte17 = 0;
    inline volatile std::uint32_t dbg_copy_byte17 = 0;

    // [핵심] 0xF7: guest buffer 전체 hex dump (DMA port 패킷만)
    // 원본 guest buffer에서 읽은 첫 64바이트를 16개 DWORD로 저장
    // 이것을 Wireshark hex와 1:1 비교해서 정확한 차이점 확인
    inline volatile std::uint32_t dbg_hex[16] = {};  // 64바이트 = 16 * 4바이트

    // [핵심 0xFB] TX 진단은 nic::igc_hv_tx struct 멤버로 이동
    // (inline 스칼라/배열 모두 freestanding 링커에서 TU간 공유 안 됨)

    // [핵심] Fragment 진단 - ReadScatter 62KB → ~43 IP fragments 필요
    // OPEN(32B)=단일패킷 OK, ReadScatter=fragment 안 도착 → 추적 필요
    inline volatile std::uint32_t dbg_frag_last_count = 0;    // fragment_and_send 리턴값 (예상: ~43)
    inline volatile std::uint32_t dbg_frag_last_rspsize = 0;  // 마지막 DMA rsp 크기 (62488 등)
    inline volatile std::uint32_t dbg_inject_total = 0;        // inject 함수 총 호출 횟수
    inline volatile std::uint32_t dbg_inject_success = 0;      // inject 리턴 1 (DD OK) 횟수
    inline volatile std::uint32_t dbg_inject_fail = 0;         // inject 리턴 0 (드랍/타임아웃) 횟수
    inline volatile std::uint32_t dbg_inject_last_len = 0;     // 마지막 inject frame_len
    inline volatile std::uint32_t dbg_inject_first_len = 0;    // send_response 호출 후 첫 inject frame_len
    inline volatile std::uint32_t dbg_inject_is_first = 0;     // 내부 플래그: 첫 fragment 추적용

    // [핵심] 첫 fragment 프레임 헤더 캡처 (OPEN=74B vs Fragment=1514B 비교용)
    // inject에서 is_first=1일 때 프레임 첫 48바이트 저장
    // OPEN이 정상 도착하고 Fragment가 안 도착하면 헤더 차이 확인
    inline volatile std::uint32_t dbg_first_hdr[12] = {};  // 48 bytes = ETH(14)+IP(20)+UDP(8)+DATA(6)

    // [핵심 0xFB] NIC TX 통계 레지스터 - wire 전송 실제 여부 판별
    // GPTC: 성공적으로 전송된 패킷 수 (Good Packets Transmitted Count)
    // TPT: 총 전송 패킷 수 (에러 포함)
    inline volatile std::uint32_t dbg_nic_gptc = 0;   // Good Packets TX Count (0x4080)
    inline volatile std::uint32_t dbg_nic_tpt = 0;    // Total Packets TX (0x40D4)
    inline volatile std::uint32_t dbg_nic_gotcl = 0;  // Good Octets TX (low, 0x4090)
}