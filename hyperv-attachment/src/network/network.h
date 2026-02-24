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
    // [�ٽ�] 0xF8: cache miss ī���� - DD=1 ������ cache[idx]==0�̸� ��Ŷ ��ŵ
    inline volatile std::uint32_t dbg_cache_miss = 0;
    inline volatile std::uint32_t dbg_cache_hit = 0;
    inline volatile std::uint32_t dbg_precache_update = 0; // 0xFA: proactive cache ���� Ƚ��
    // 0xFB: ȸ�� ��ĳ�� ����
    inline volatile std::uint32_t dbg_scan_total = 0;   // �� ��ĵ�� descriptor ��
    inline volatile std::uint32_t dbg_scan_dd0 = 0;     // DD=0 �߰� (READ format)
    inline volatile std::uint32_t dbg_scan_dd1 = 0;     // DD=1 �߰� (WB format)
    inline volatile std::uint32_t dbg_scan_addr_zero = 0; // DD=0일때 addr=0
    inline volatile std::uint32_t dbg_ecam_status = 0;   // ECAM에서 읽은 PCI Status
    inline volatile std::uint32_t dbg_ecam_capptr = 0;   // ECAM에서 읽은 cap pointer
    inline volatile std::uint64_t dbg_scan_first_addr = 0; // ù DD=0 descriptor�� pkt_addr
    inline volatile std::uint64_t dbg_scan_first_hdr = 0;  // ù DD=0 descriptor�� hdr_addr (staterr ��ġ)

    // [�ٽ�] ����� ���� ���� - CPUID probe�� ����
    inline std::uint32_t dbg_rx_call_count = 0;      // process_rx_packet ȣ�� Ƚ��
    inline std::uint32_t dbg_rx_udp_count = 0;       // UDP �Ľ� ���� Ƚ��
    inline std::uint32_t dbg_rx_port_match = 0;      // dst_port==28473 ��Ī Ƚ��
    inline std::uint32_t dbg_rx_dma_call = 0;        // process_complete_dma_payload ȣ�� Ƚ��
    inline std::uint16_t dbg_last_dst_port = 0;      // ������ ���� UDP dst_port
    inline std::uint32_t dbg_last_payload_magic = 0;  // ������ UDP payload ù 4����Ʈ
    inline std::uint16_t dbg_last_pkt_len = 0;       // ������ ���� ��Ŷ ����
    inline std::uint32_t dbg_igc_dd_count = 0;       // DD=1 ���� Ƚ��
    inline std::uint16_t dbg_attack_src_port = 0;      // [�ٽ�] ���� PC ephemeral src_port (host order)
    inline std::uint32_t dbg_active_rx_queues = 0;     // [�ٽ�] Ȱ�� RX ť ���� (igc: �ִ� 4)

    // [�ٽ�] TX Q1 ����� ī����
    inline std::uint32_t dbg_txq1_dd_ok = 0;          // DD ���� ���� Ƚ��
    inline std::uint32_t dbg_txq1_dd_timeout = 0;     // DD Ÿ�Ӿƿ� Ƚ��
    inline std::uint32_t dbg_txq1_last_tdh = 0;       // ������ TX �� TDH ��
    inline std::uint32_t dbg_txq1_last_cmd = 0;       // ������ TX cmd_type_len (DEXT Ȯ�ο�)
    inline std::uint32_t dbg_txq1_last_olinfo = 0;    // ������ TX olinfo_status (PAYLEN Ȯ�ο�)
    inline std::uint32_t dbg_txq1_q0_fallback = 0;    // Q0 fallback ��� Ƚ��
    inline volatile std::uint32_t dbg_txq1_re_enable = 0;    // [TX stall fix] Q1 auto re-enable count (TXDCTL.ENABLE lost)
    inline volatile std::uint32_t dbg_txq1_consec_max = 0;  // [TX stall fix] max consecutive DD timeout seen
    inline volatile std::uint32_t dbg_nic_wake_count = 0;    // [NIC wake] SLU/LU 복구 횟수
    inline volatile std::uint32_t dbg_last_recovery_ctrl = 0;   // 마지막 recovery 시 CTRL 값
    inline volatile std::uint32_t dbg_last_recovery_status = 0; // 마지막 recovery 시 STATUS 값
    inline volatile std::uint32_t dbg_last_recovery_tdbal = 0;  // 마지막 recovery 시 TDBAL 값
    inline volatile std::uint32_t dbg_last_recovery_txdctl = 0; // 마지막 recovery 시 TXDCTL 값
    inline volatile std::uint32_t dbg_poll_entered = 0;      // [STALL DIAG] process_pending() 실제 RX poll까지 도달 횟수

    // [�ٽ�] DMA��TX ��� ���� ī����
    inline std::uint32_t dbg_dma_rsp_size = 0;         // ������ dma::process ���ϰ�
    inline std::uint32_t dbg_dma_rsp_nonzero = 0;      // rsp_size > 0 Ƚ��
    inline std::uint32_t dbg_send_response_enter = 0;   // send_response ���� Ƚ��
    inline std::uint32_t dbg_send_response_fail = 0;    // send_response ���� ���� (bitfield)

    // [�ٽ�] dma::process ���� ���� ���� ����
    // 1=size<hdr, 2=magic, 3=version, 4=cb_msg>size, 5=unknown_type
    inline std::uint32_t dbg_dma_fail_reason = 0;
    inline std::uint32_t dbg_dma_last_version = 0;      // ���� version ��
    inline std::uint32_t dbg_dma_last_type = 0;          // ���� type ��
    inline std::uint32_t dbg_dma_last_cbmsg = 0;         // ���� cb_msg ��
    inline std::uint32_t dbg_dma_payload_size = 0;       // ip_frag���� �Ѿ�� dma_size

    // [�ٽ�] raw ��Ŷ ����: volatile scalar (�����Ϸ� ����ȭ ����)
    // �迭 ����� dead store elimination���� ���ŵ� �� ����
    inline volatile std::uint32_t dbg_pkt_eth0 = 0;       // pkt_data[0..3] ETH dst mac
    inline volatile std::uint32_t dbg_pkt_ip0 = 0;        // pkt_data[14..17] IP ver+tos+totlen
    inline volatile std::uint32_t dbg_pkt_ip4 = 0;        // pkt_data[18..21] IP id+flags+frag
    inline volatile std::uint32_t dbg_pkt_udp0 = 0;       // UDP ports (src+dst)
    inline volatile std::uint32_t dbg_pkt_dma0 = 0;       // DMA payload[0..3] = magic
    inline volatile std::uint32_t dbg_pkt_dma4 = 0;       // DMA payload[4..7] = cb_msg
    inline volatile std::uint32_t dbg_pkt_dma8 = 0;       // DMA payload[8..11] = type+version
    inline volatile std::uint32_t dbg_pkt_dma12 = 0;      // DMA payload[12..15] = session_id

    // [�ٽ�] IP �Ľ� �߰��� ĸó (ip_frag���� ���Ǵ� ���� ��)
    inline volatile std::uint32_t dbg_ip_total = 0;        // ntohs(ip->total_length)
    inline volatile std::uint32_t dbg_ip_ihl = 0;          // (ver_ihl & 0x0F) * 4
    inline volatile std::uint32_t dbg_udp_payload_ptr_off = 0; // udp_payload - pkt_data ������

    // [�ٽ�] 0xF3 byte-level + 0xF4 buf_addr/raw ��
    inline volatile std::uint32_t dbg_udp_len = 0;        // ntohs(udp->length) - �е� vs ����ũ�� �Ǻ�
    inline volatile std::uint32_t dbg_udp_chksum = 0;     // UDP checksum (0�̸� no checksum)
    inline volatile std::uint32_t dbg_payload_b0 = 0;     // udp_payload[0] ��������Ʈ
    inline volatile std::uint32_t dbg_payload_b4 = 0;     // udp_payload[4] ��������Ʈ (cb_msg ù����Ʈ)
    inline volatile std::uint32_t dbg_payload_b5 = 0;     // udp_payload[5]
    inline volatile std::uint32_t dbg_payload_b8 = 0;     // udp_payload[8] (type ù����Ʈ)
    inline volatile std::uint32_t dbg_payload_b10 = 0;    // udp_payload[10] (version ù����Ʈ)
    inline volatile std::uint32_t dbg_pkt_len = 0;        // descriptor�� ����Ʈ�� ��Ŷ ����

    // [�ٽ�] 0xF4~0xF6 buf_addr + raw/copy �� ����
    inline volatile std::uint64_t dbg_buf_addr = 0;
    inline volatile std::uint32_t dbg_desc_idx = 0;
    inline volatile std::uint32_t dbg_wb_staterr = 0;
    inline volatile std::uint32_t dbg_raw_ip_total = 0;
    inline volatile std::uint32_t dbg_copy_ip_total = 0;
    inline volatile std::uint32_t dbg_raw_dma4 = 0;
    inline volatile std::uint32_t dbg_copy_dma4 = 0;
    inline volatile std::uint32_t dbg_raw_byte17 = 0;
    inline volatile std::uint32_t dbg_copy_byte17 = 0;

    // [�ٽ�] 0xF7: guest buffer ��ü hex dump (DMA port ��Ŷ��)
    // ���� guest buffer���� ���� ù 64����Ʈ�� 16�� DWORD�� ����
    // �̰��� Wireshark hex�� 1:1 ���ؼ� ��Ȯ�� ������ Ȯ��
    inline volatile std::uint32_t dbg_hex[16] = {};  // 64����Ʈ = 16 * 4����Ʈ
    // [진단] TX 프레임 스냅샷 (flush_deferred_tx에서 inject 직전 캡처)
    inline volatile std::uint32_t dbg_tx_snap[16] = {};  // 첫 TX 프레임 64바이트
    inline volatile std::uint32_t dbg_tx_snap_ports = 0; // our_src_port<<16 | attack_src_port

    // [�ٽ� 0xFB] TX ������ nic::igc_hv_tx struct ����� �̵�
    // (inline ��Į��/�迭 ��� freestanding ��Ŀ���� TU�� ���� �� ��)

    // [�ٽ�] Fragment ���� - ReadScatter 62KB �� ~43 IP fragments �ʿ�
    // OPEN(32B)=������Ŷ OK, ReadScatter=fragment �� ���� �� ���� �ʿ�
    inline volatile std::uint32_t dbg_frag_last_count = 0;    // fragment_and_send ���ϰ� (����: ~43)
    inline volatile std::uint32_t dbg_inject_total = 0;        // inject 함수 총 호출 횟수
    inline volatile std::uint32_t dbg_inject_success = 0;      // inject 리턴 1 (DD OK) 횟수
    inline volatile std::uint32_t dbg_inject_fail = 0;         // inject 리턴 0 (실패/타임아웃) 횟수
    inline volatile std::uint32_t dbg_inject_last_len = 0;     // 마지막 inject frame_len

    // [TIMING] worst-case 요청 breakdown (TSC 단위)
    // 가장 느린 요청의 각 단계별 시간 기록
    inline volatile std::uint64_t dbg_timing_worst_total = 0;  // 전체 (parse+EPT+TX)
    inline volatile std::uint64_t dbg_timing_worst_parse = 0;  // 헤더 파싱
    inline volatile std::uint64_t dbg_timing_worst_ept = 0;    // dma::process (EPT walk)
    inline volatile std::uint64_t dbg_timing_worst_tx = 0;     // send_response (TX inject)
    inline volatile std::uint32_t dbg_timing_worst_rsp = 0;    // 응답 크기 (bytes)
    inline volatile std::uint32_t dbg_timing_call_count = 0;   // 총 처리 횟수

    // [TIMING] 4KB read 전용 (rsp < 8KB) — latency spike 추적
    inline volatile std::uint64_t dbg_timing_small_worst = 0;
    inline volatile std::uint64_t dbg_timing_small_parse = 0;
    inline volatile std::uint64_t dbg_timing_small_ept = 0;
    inline volatile std::uint64_t dbg_timing_small_tx = 0;
    inline volatile std::uint32_t dbg_timing_small_rsp = 0;
    inline volatile std::uint32_t dbg_timing_small_count = 0;

}








