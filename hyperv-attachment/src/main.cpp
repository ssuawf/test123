// ============================================================================
// [핵심] hyper-reV main.cpp - CPUID PROBE 디버그 버전
// ============================================================================
// CPUID probe: 타겟 OS에서 magic CPUID 호출 → HV가 가로채서 상태 리턴
//
// AMD VMCB: save_state.rax만 접근 가능 (RBX/RCX/RDX는 VMCB에 없음)
// MSVC __cpuid: int[4]로 32bit EAX만 캡처 → 결과를 32bit로 인코딩
//
// Magic Leaf 목록 (각각 EAX 32bit 리턴):
//   0x48565200 → 0xAA | is_initialized (magic confirm)
//   0x48565201 → nic_type | bus<<8 | dev<<16 | func<<24
//   0x48565202 → vendor_id | device_id<<16
//   0x48565203 → mmio_base_gpa low 32bit
//   0x48565204 → mmio_base_gpa high 32bit
//   0x48565205 → rx_count | tx_count<<16
//   0x48565206 → ecam_base low 32bit
//   0x48565207 → mac[0-3]
//   0x48565208 → mac[4] | mac[5]<<8 | attack_mac_learned<<16
//   0x48565209 → packets_received low 32bit
//   0x4856520A → packets_sent low 32bit
//   0x4856520B → vmexit_total_count low 32bit
//   0x4856520C → poll_counter low 32bit  
//   0x4856520D → rx_ring_gpa low 32bit
//   0x4856520E → rx_ring_gpa high 32bit
//   0x4856520F → our_rx_index | nic.initialized<<16
// ============================================================================

#include "arch/arch.h"
#include "memory_manager/memory_manager.h"
#include "memory_manager/heap_manager.h"
#include "structures/virtual_address.h"
#include <ia32-doc/ia32.hpp>
#include <cstdint>

#include "crt/crt.h"
#include "interrupts/interrupts.h"
#include "slat/slat.h"
#include "slat/cr3/cr3.h"
#include "slat/violation/violation.h"

#include "dma/dma_handler.h"
#include "network/network.h"
#include "network/nic.h"

#ifndef _INTELMACHINE
#include <intrin.h>
#endif

typedef std::uint64_t(*vmexit_handler_t)(
    std::uint64_t a1, std::uint64_t a2,
    std::uint64_t a3, std::uint64_t a4);

namespace
{
    std::uint8_t* original_vmexit_handler = nullptr;
    std::uint64_t uefi_boot_physical_base_address = 0;
    std::uint64_t uefi_boot_image_size = 0;
}

// [핵심] VMEXIT 카운터 - HV alive 확인용
static volatile std::uint64_t vmexit_total_count = 0;
// [핵심] network retry 카운터 (is_initialized=0일 때 증가)
static volatile std::uint64_t probe_poll_counter = 0;

void clean_up_uefi_boot_image()
{
    const auto mapped_uefi_boot_base = static_cast<std::uint8_t*>(
        memory_manager::map_host_physical(uefi_boot_physical_base_address));

    crt::set_memory(mapped_uefi_boot_base, 0, uefi_boot_image_size);
}

void process_first_vmexit()
{
    static std::uint8_t is_first_vmexit = 1;

    if (is_first_vmexit == 1)
    {
        slat::process_first_vmexit();
        interrupts::set_up();
        clean_up_uefi_boot_image();

        dma::set_up();
        network::set_up();

        is_first_vmexit = 0;
    }

    static std::uint8_t has_hidden_heap_pages = 0;
    static std::uint64_t vmexit_count = 0;

    if (has_hidden_heap_pages == 0 && 10000 <= ++vmexit_count)
    {
        has_hidden_heap_pages = slat::hide_heap_pages(slat::hyperv_cr3());
    }
}

std::uint64_t do_vmexit_premature_return()
{
#ifdef _INTELMACHINE
    return 0;
#else
    return __readgsqword(0);
#endif
}

// ============================================================================
// CPUID Probe Handler  
// ============================================================================
constexpr std::uint64_t PROBE_LEAF_BASE = 0x48565200;
constexpr std::uint64_t PROBE_LEAF_MAX = 0x4856529B;  // 0xFB: first-frag header 0x90-0x9B 추가

std::uint8_t handle_cpuid_probe()
{
#ifndef _INTELMACHINE
    vmcb_t* vmcb = arch::get_vmcb();
    const std::uint64_t leaf = vmcb->save_state.rax;

    if (leaf < PROBE_LEAF_BASE || leaf > PROBE_LEAF_MAX)
        return 0;

    std::uint32_t result = 0;
    const std::uint32_t sub = static_cast<std::uint32_t>(leaf - PROBE_LEAF_BASE);

    switch (sub)
    {
    case 0x00: // magic + is_initialized + build tag
        // [핵심] 0xFB = ROTATING-SCANNER: 전체 ring 회전 스캔으로 DD=0 캐싱
        result = 0xAA00FB00u | static_cast<std::uint32_t>(network::is_initialized);
        break;

    case 0x01: // nic_type | bus | dev | func (use_adv_desc in bit4 of nic_type byte)
        // [핵심] bit0-3: nic_type, bit4: use_adv_desc, bit5: intel_gen(igc)
        result = static_cast<std::uint32_t>(nic::state.nic_type);
        if (nic::state.use_adv_desc) result |= 0x10;
        if (nic::state.intel_gen == nic::intel_gen_t::IGC) result |= 0x20;
        result |= (static_cast<std::uint32_t>(nic::state.bus) << 8);
        result |= (static_cast<std::uint32_t>(nic::state.dev) << 16);
        result |= (static_cast<std::uint32_t>(nic::state.func) << 24);
        break;

    case 0x02: // vendor_id | device_id
        result = static_cast<std::uint32_t>(nic::state.vendor_id);
        result |= (static_cast<std::uint32_t>(nic::state.device_id) << 16);
        break;

    case 0x03: // mmio low
        result = static_cast<std::uint32_t>(nic::state.mmio_base_gpa);
        break;

    case 0x04: // mmio high
        result = static_cast<std::uint32_t>(nic::state.mmio_base_gpa >> 32);
        break;

    case 0x05: // rx_count | tx_count
        result = (nic::state.rx_count & 0xFFFF);
        result |= ((nic::state.tx_count & 0xFFFF) << 16);
        break;

    case 0x06: // ecam
        result = static_cast<std::uint32_t>(nic::ecam_base_detected);
        break;

    case 0x07: // mac[0-3]
        result = static_cast<std::uint32_t>(nic::state.mac[0]);
        result |= (static_cast<std::uint32_t>(nic::state.mac[1]) << 8);
        result |= (static_cast<std::uint32_t>(nic::state.mac[2]) << 16);
        result |= (static_cast<std::uint32_t>(nic::state.mac[3]) << 24);
        break;

    case 0x08: // mac[4-5] + attack_mac_learned
        result = static_cast<std::uint32_t>(nic::state.mac[4]);
        result |= (static_cast<std::uint32_t>(nic::state.mac[5]) << 8);
        result |= (static_cast<std::uint32_t>(nic::state.attack_mac_learned) << 16);
        break;

    case 0x09: // packets_received
        result = static_cast<std::uint32_t>(network::packets_received);
        break;

    case 0x0A: // packets_sent
        result = static_cast<std::uint32_t>(network::packets_sent);
        break;

    case 0x0B: // vmexit count
        result = static_cast<std::uint32_t>(vmexit_total_count);
        break;

    case 0x0C: // poll counter
        result = static_cast<std::uint32_t>(probe_poll_counter);
        break;

    case 0x0D: // rx_ring_gpa low
        result = static_cast<std::uint32_t>(nic::state.rx_ring_gpa);
        break;

    case 0x0E: // rx_ring_gpa high
        result = static_cast<std::uint32_t>(nic::state.rx_ring_gpa >> 32);
        break;

    case 0x0F: // our_rx_index | nic.initialized
        result = (nic::state.our_rx_index & 0xFFFF);
        result |= (static_cast<std::uint32_t>(nic::state.initialized) << 16);
        break;

        // ========================================================================
        // [핵심] 디버그 진단 leaves (0x10-0x17)
        // ========================================================================
    case 0x10: // dbg_rx_call_count (process_rx_packet 호출 횟수)
        result = network::dbg_rx_call_count;
        break;

    case 0x11: // dbg_rx_udp_count (UDP 파싱 성공) | dbg_rx_port_match (포트 매칭)
        result = (network::dbg_rx_udp_count & 0xFFFF);
        result |= ((network::dbg_rx_port_match & 0xFFFF) << 16);
        break;

    case 0x12: // dbg_rx_dma_call (process_complete_dma_payload 호출 횟수)
        result = network::dbg_rx_dma_call;
        break;

    case 0x13: // dbg_last_dst_port | dbg_last_pkt_len
        result = static_cast<std::uint32_t>(network::dbg_last_dst_port);
        result |= (static_cast<std::uint32_t>(network::dbg_last_pkt_len) << 16);
        break;

    case 0x14: // dbg_last_payload_magic (마지막 UDP payload 첫 4바이트)
        result = network::dbg_last_payload_magic;
        break;

    case 0x15: // dbg_igc_dd_count (DD=1 감지 횟수)
        result = network::dbg_igc_dd_count;
        break;

    case 0x16: // use_adv_desc | rx_buf_cache_valid | last_known_rdt(외부 접근 불가→0)
        result = static_cast<std::uint32_t>(nic::state.use_adv_desc);
        result |= (static_cast<std::uint32_t>(nic::rx_buf_cache_valid) << 8);
        break;

    case 0x17: // packets_dropped low 32
        result = static_cast<std::uint32_t>(network::packets_dropped);
        break;

    case 0x18: // attack_src_port | our_src_port
        // [핵심] 공격 PC ephemeral port 진단 - 응답이 올바른 포트로 가는지 확인
        result = static_cast<std::uint32_t>(network::dbg_attack_src_port);
        break;

    case 0x19: // [핵심] 멀티큐 진단: active_queues | q0_count | q1_count | q2_count
        // byte0: 활성 RX 큐 수, byte1-3: Q0~Q2 desc count (축약)
        result = (nic::igc_num_active_queues & 0xFF);
        result |= ((nic::igc_rxq[0].count / 16) & 0xFF) << 8;   // Q0 desc/16
        result |= ((nic::igc_rxq[1].count / 16) & 0xFF) << 16;  // Q1 desc/16
        result |= ((nic::igc_rxq[2].count / 16) & 0xFF) << 24;  // Q2 desc/16
        break;

    case 0x1A: // [핵심] TX Q1 격리 상태
        // byte0: initialized, byte1: our_tdt, byte2-3: desc_count/16
        result = static_cast<std::uint32_t>(nic::igc_hv_tx.initialized);
        result |= (static_cast<std::uint32_t>(nic::igc_hv_tx.our_tdt & 0xFF) << 8);
        result |= ((nic::igc_hv_tx.desc_count / 16) & 0xFFFF) << 16;
        break;

    case 0x1B: // [핵심] VA→PA offset low32
        result = static_cast<std::uint32_t>(nic::heap_va_to_pa_offset & 0xFFFFFFFF);
        break;

    case 0x1C: // VA→PA offset high32
        result = static_cast<std::uint32_t>(
            static_cast<std::uint64_t>(nic::heap_va_to_pa_offset) >> 32);
        break;

    case 0x1D: // TX Q1 desc_ring_gpa low32
        result = static_cast<std::uint32_t>(nic::igc_hv_tx.desc_ring_gpa);
        break;

    case 0x1E: // TX Q1 data_buf_gpa low32
        result = static_cast<std::uint32_t>(nic::igc_hv_tx.data_buf_gpa);
        break;

    case 0x1F: // TX Q1 TXDCTL 최종값 (bit25=ENABLE)
        result = nic::igc_hv_tx.dbg_txdctl_val;
        break;

    case 0x20: // TX Q1 DD 성공 횟수
        result = network::dbg_txq1_dd_ok;
        break;

    case 0x21: // TX Q1 DD 타임아웃 횟수
        result = network::dbg_txq1_dd_timeout;
        break;

    case 0x22: // TX Q1 마지막 TDH + Q0 fallback count
        result = (network::dbg_txq1_q0_fallback << 16) | (network::dbg_txq1_last_tdh & 0xFFFF);
        break;

    case 0x23: // desc_ring_gpa high32 (0이어야 정상)
        result = static_cast<std::uint32_t>(nic::igc_hv_tx.desc_ring_gpa >> 32);
        break;

    case 0x24: // dma::process 마지막 리턴값 + rsp_nonzero 횟수
        result = (network::dbg_dma_rsp_nonzero << 16) | (network::dbg_dma_rsp_size & 0xFFFF);
        break;

    case 0x25: // send_response 진입 횟수
        result = network::dbg_send_response_enter;
        break;

    case 0x26: // send_response 실패 사유 비트필드
        // bit0=!init, bit1=!mac, bit2=!txbuf, bit3=frag0
        result = network::dbg_send_response_fail;
        break;

    case 0x27: // dma::process 실패 사유 (1=size,2=magic,3=ver,4=cbmsg,5=type)
        result = network::dbg_dma_fail_reason;
        break;

    case 0x28: // 받은 version(hi16) + type(lo16)
        result = (network::dbg_dma_last_version << 16) | (network::dbg_dma_last_type & 0xFFFF);
        break;

    case 0x29: // 받은 cb_msg
        result = network::dbg_dma_last_cbmsg;
        break;

    case 0x2A: // ip_frag에서 넘어온 payload size
        result = network::dbg_dma_payload_size;
        break;

    case 0x2B: // TX descriptor cmd_type_len (DEXT=bit29 확인용)
        result = network::dbg_txq1_last_cmd;
        break;

    case 0x2C: // TX descriptor olinfo_status (PAYLEN 확인용, before NIC writeback)
        result = network::dbg_txq1_last_olinfo;
        break;

        // 0x30~0x42: volatile scalar 진단 (패킷 + IP + DMA + UDP)
    case 0x30: result = network::dbg_pkt_eth0; break;
    case 0x31: result = network::dbg_pkt_ip0; break;
    case 0x32: result = network::dbg_pkt_ip4; break;
    case 0x33: result = network::dbg_pkt_udp0; break;
    case 0x34: result = network::dbg_pkt_dma0; break;    // DMA magic
    case 0x35: result = network::dbg_pkt_dma4; break;    // cb_msg
    case 0x36: result = network::dbg_pkt_dma8; break;    // type+version
    case 0x37: result = network::dbg_pkt_dma12; break;   // session_id
    case 0x38: result = network::dbg_ip_total; break;     // IP total_length
    case 0x39: result = network::dbg_ip_ihl; break;       // IP IHL*4
    case 0x3A: result = network::dbg_udp_payload_ptr_off; break; // udp_payload offset
        // 0xF3 추가
    case 0x3B: result = network::dbg_udp_len; break;     // UDP length
    case 0x3C: result = network::dbg_udp_chksum; break;  // UDP checksum
    case 0x3D: result = network::dbg_payload_b0; break;   // byte[0]
    case 0x3E: result = network::dbg_payload_b4; break;   // byte[4] (cb_msg LSB)
    case 0x3F: result = network::dbg_payload_b5; break;   // byte[5]
    case 0x40: result = network::dbg_payload_b8; break;   // byte[8] (type LSB)
    case 0x41: result = network::dbg_payload_b10; break;  // byte[10] (version LSB)
    case 0x42: result = network::dbg_pkt_len; break;      // descriptor pkt_len
        // 0xF4: buf_addr + raw/copy 비교
    case 0x43: result = static_cast<std::uint32_t>(network::dbg_buf_addr & 0xFFFFFFFF); break; // buf_addr low32
    case 0x44: result = static_cast<std::uint32_t>(network::dbg_buf_addr >> 32); break;        // buf_addr high32
    case 0x45: result = network::dbg_desc_idx; break;      // descriptor index
    case 0x46: result = network::dbg_wb_staterr; break;    // write-back staterr
    case 0x47: result = network::dbg_raw_ip_total; break;  // 원본 IP total
    case 0x48: result = network::dbg_copy_ip_total; break; // 복사본 IP total
    case 0x49: result = network::dbg_raw_dma4; break;      // 원본 cb_msg dword
    case 0x4A: result = network::dbg_copy_dma4; break;     // 복사본 cb_msg dword
    case 0x4B: result = network::dbg_raw_byte17; break;    // 원본 byte[17]
    case 0x4C: result = network::dbg_copy_byte17; break;   // 복사본 byte[17]
        // 0xF7: guest buffer hex dump (16 DWORDs = 64 bytes)
    case 0x50: result = network::dbg_hex[0]; break;   // byte 0-3
    case 0x51: result = network::dbg_hex[1]; break;   // byte 4-7
    case 0x52: result = network::dbg_hex[2]; break;   // byte 8-11
    case 0x53: result = network::dbg_hex[3]; break;   // byte 12-15
    case 0x54: result = network::dbg_hex[4]; break;   // byte 16-19
    case 0x55: result = network::dbg_hex[5]; break;   // byte 20-23
    case 0x56: result = network::dbg_hex[6]; break;   // byte 24-27
    case 0x57: result = network::dbg_hex[7]; break;   // byte 28-31
    case 0x58: result = network::dbg_hex[8]; break;   // byte 32-35
    case 0x59: result = network::dbg_hex[9]; break;   // byte 36-39
    case 0x5A: result = network::dbg_hex[10]; break;  // byte 40-43
    case 0x5B: result = network::dbg_hex[11]; break;  // byte 44-47
    case 0x5C: result = network::dbg_hex[12]; break;  // byte 48-51
    case 0x5D: result = network::dbg_hex[13]; break;  // byte 52-55
    case 0x5E: result = network::dbg_hex[14]; break;  // byte 56-59
    case 0x5F: result = network::dbg_hex[15]; break;  // byte 60-63
        // 0xF8: cache hit/miss counters
    case 0x60: result = network::dbg_cache_hit; break;
    case 0x61: result = network::dbg_cache_miss; break;
    case 0x62: result = network::dbg_precache_update; break; // 0xFA: proactive cache 성공 횟수
        // 0xFB: 회전 스캐너 진단
    case 0x63: result = network::dbg_scan_total; break;
    case 0x64: result = network::dbg_scan_dd0; break;
    case 0x65: result = network::dbg_scan_dd1; break;
    case 0x66: result = network::dbg_scan_addr_zero; break;
    case 0x67: result = static_cast<std::uint32_t>(network::dbg_scan_first_addr); break;
    case 0x68: result = static_cast<std::uint32_t>(network::dbg_scan_first_addr >> 32); break;
    case 0x69: result = static_cast<std::uint32_t>(network::dbg_scan_first_hdr); break;
    case 0x6A: result = static_cast<std::uint32_t>(network::dbg_scan_first_hdr >> 32); break;

        // 0xFB: TX 진단 - 단순 one-liner (복잡한 {} 블록은 컴파일러가 무시함!)
        // leaf 0x1E = igc_hv_tx.data_buf_gpa → 0x7476B100 동작확인 (같은 패턴 사용)
    case 0x70: // 상수 테스트: 이 값이 나오면 leaf 실행 확인
        result = 0xCAFE0070;
        break;
    case 0x71: // data_buf_va low32 (main.cpp가 보는 값)
        result = static_cast<std::uint32_t>(reinterpret_cast<std::uint64_t>(nic::igc_hv_tx.data_buf_va));
        break;
    case 0x72: // data_buf_va high32
        result = static_cast<std::uint32_t>(reinterpret_cast<std::uint64_t>(nic::igc_hv_tx.data_buf_va) >> 32);
        break;
    case 0x73: // desc_ring_va low32
        result = static_cast<std::uint32_t>(reinterpret_cast<std::uint64_t>(nic::igc_hv_tx.desc_ring_va));
        break;
    case 0x74: // &igc_hv_tx 주소 low32 (struct 인스턴스 주소)
        result = static_cast<std::uint32_t>(reinterpret_cast<std::uint64_t>(&nic::igc_hv_tx));
        break;
    case 0x75: // &igc_hv_tx 주소 high32
        result = static_cast<std::uint32_t>(reinterpret_cast<std::uint64_t>(&nic::igc_hv_tx) >> 32);
        break;
    case 0x76: // diag_canary (inject에서 기록, 0이면 cross-TU 문제)
        result = nic::igc_hv_tx.diag_canary;
        break;
    case 0x77: // TX frame[0:3] = DST MAC 앞 4바이트
        result = nic::igc_hv_tx.diag_eth_dw0;
        break;
    case 0x78: // TX frame[4:7] = DST MAC[4:5] + SRC MAC[0:1]
        result = nic::igc_hv_tx.diag_eth_dw1;
        break;
    case 0x79: // TX frame[8:11] = SRC MAC[2:5]
        result = nic::igc_hv_tx.diag_eth_dw2;
        break;
    case 0x7A: // TX frame[30:33] = DST IP
        result = nic::igc_hv_tx.diag_ip_dst;
        break;
    case 0x7B: // TX frame[34:37] = UDP src_port + dst_port
        result = nic::igc_hv_tx.diag_udp_ports;
        break;
    case 0x7C: // our_src_port raw (passed to fragment_and_send)
        result = nic::igc_hv_tx.diag_our_port;
        break;
    case 0x7D: // attack_src_port raw
        result = nic::igc_hv_tx.diag_atk_port;
        break;
    case 0x7E: // TX frame[38:41] = UDP len + chksum
        result = nic::igc_hv_tx.diag_udp_raw8;
        break;

        // 0xFB: NIC TX 통계 레지스터 (MMIO read-on-clear!)
        // probe에서 읽으면 NIC가 카운터를 클리어하므로, 캐시된 값 사용
    case 0x80: result = network::dbg_nic_gptc; break;   // Good Packets TX
    case 0x81: result = network::dbg_nic_tpt; break;    // Total Packets TX
    case 0x82: result = network::dbg_nic_gotcl; break;  // Good Octets TX (low)

        // --- Fragment 진단 (0x83-0x8A) ---
        // [핵심] OPEN(32B)=단일패킷 OK, ReadScatter(62KB)=~43 fragments 안도착
        // fragment_and_send가 실제로 43개 만드는지, inject가 성공하는지 추적
    case 0x83: result = network::dbg_frag_last_count; break;  // fragment_and_send 리턴값 (예상: ~43)
    case 0x84: result = network::dbg_frag_last_rspsize; break; // DMA rsp 크기 (예상: 62488)
    case 0x85: result = network::dbg_inject_total; break;      // inject 총 호출 횟수
    case 0x86: result = network::dbg_inject_success; break;    // inject DD OK 횟수
    case 0x87: result = network::dbg_inject_fail; break;       // inject 드랍/타임아웃 횟수
    case 0x88: result = network::dbg_inject_first_len; break;  // 첫 fragment frame_len (예상: 1514)
    case 0x89: result = network::dbg_inject_last_len; break;   // 마지막 fragment frame_len
    case 0x8A: result = network::dbg_inject_is_first; break;   // is_first 플래그 (0=정상 클리어됨)

        // --- 첫 Fragment 프레임 헤더 hex dump (0x90-0x9B) ---
        // [핵심] OPEN(74B) 도착 vs Fragment(1514B) 미도착 → 헤더 차이 확인
        // 프레임 첫 48바이트 = ETH(14) + IP(20) + UDP(8) + DATA(6)
    case 0x90: result = network::dbg_first_hdr[0];  break; // frame[0:3]   DST MAC[0:3]
    case 0x91: result = network::dbg_first_hdr[1];  break; // frame[4:7]   DST MAC[4:5] + SRC MAC[0:1]
    case 0x92: result = network::dbg_first_hdr[2];  break; // frame[8:11]  SRC MAC[2:5]
    case 0x93: result = network::dbg_first_hdr[3];  break; // frame[12:15] EtherType + IP ver_ihl + tos
    case 0x94: result = network::dbg_first_hdr[4];  break; // frame[16:19] IP total_len + identification
    case 0x95: result = network::dbg_first_hdr[5];  break; // frame[20:23] IP flags_frag + ttl + protocol
    case 0x96: result = network::dbg_first_hdr[6];  break; // frame[24:27] IP checksum + src_ip[0:1]
    case 0x97: result = network::dbg_first_hdr[7];  break; // frame[28:31] src_ip[2:3] + dst_ip[0:1]
    case 0x98: result = network::dbg_first_hdr[8];  break; // frame[32:35] dst_ip[2:3] + UDP src_port
    case 0x99: result = network::dbg_first_hdr[9];  break; // frame[36:39] UDP dst_port + UDP length
    case 0x9A: result = network::dbg_first_hdr[10]; break; // frame[40:43] UDP checksum + DMA data[0:1]
    case 0x9B: result = network::dbg_first_hdr[11]; break; // frame[44:47] DMA data[2:5]
    }

    vmcb->save_state.rax = static_cast<std::uint64_t>(result);
    arch::advance_guest_rip();
    return 1;
#else
    return 0;
#endif
}

// ============================================================================
// VMEXIT Handler
// ============================================================================
std::uint64_t vmexit_handler_detour(
    const std::uint64_t a1, const std::uint64_t a2,
    const std::uint64_t a3, const std::uint64_t a4)
{
    process_first_vmexit();
    vmexit_total_count++;

    const std::uint64_t exit_reason = arch::get_vmexit_reason();

    // CPUID probe
    if (arch::is_cpuid(exit_reason) == 1)
    {
        if (handle_cpuid_probe() == 1)
            return do_vmexit_premature_return();
    }

    // SLAT violation
    if (arch::is_slat_violation(exit_reason) == 1
        && slat::violation::process() == 1)
    {
        return do_vmexit_premature_return();
    }

    // NIC polling
    network::process_pending();

    // network retry 카운터
    if (!network::is_initialized)
        probe_poll_counter++;

    // NMI
    if (arch::is_non_maskable_interrupt_exit(exit_reason) == 1)
    {
        interrupts::process_nmi();
    }

    return reinterpret_cast<vmexit_handler_t>(
        original_vmexit_handler)(a1, a2, a3, a4);
}

// ============================================================================
// Entry Point
// ============================================================================
void entry_point(
    std::uint8_t** const vmexit_handler_detour_out,
    std::uint8_t* const original_vmexit_handler_routine,
    const std::uint64_t heap_physical_base,
    const std::uint64_t heap_physical_usable_base,
    const std::uint64_t heap_total_size,
    const std::uint64_t _uefi_boot_physical_base_address,
    const std::uint32_t _uefi_boot_image_size,
#ifdef _INTELMACHINE
    const std::uint64_t reserved_one)
{
    (void)reserved_one;
#else
    const std::uint8_t* const get_vmcb_gadget)
{
    arch::parse_vmcb_gadget(get_vmcb_gadget);
#endif

    original_vmexit_handler = original_vmexit_handler_routine;
    uefi_boot_physical_base_address = _uefi_boot_physical_base_address;
    uefi_boot_image_size = _uefi_boot_image_size;

    heap_manager::initial_physical_base = heap_physical_base;
    heap_manager::initial_size = heap_total_size;

    *vmexit_handler_detour_out = reinterpret_cast<std::uint8_t*>(
        vmexit_handler_detour);

    const std::uint64_t heap_physical_end = heap_physical_base + heap_total_size;
    const std::uint64_t heap_usable_size = heap_physical_end
        - heap_physical_usable_base;

    void* const mapped_heap_usable_base = memory_manager::map_host_physical(
        heap_physical_usable_base);

    // [핵심] VA→GPA offset 계산 - 힙 VA에서 물리주소를 역산하는 상수
    // map_host_physical(PA) = VA 이므로 offset = VA - PA
    // 이후: GPA = VA - offset (모든 힙 할당 페이지에 적용)
    nic::heap_va_to_pa_offset = static_cast<std::int64_t>(
        reinterpret_cast<std::uint64_t>(mapped_heap_usable_base))
        - static_cast<std::int64_t>(heap_physical_usable_base);
    nic::heap_va_pa_valid = 1;

    heap_manager::set_up(mapped_heap_usable_base, heap_usable_size);

    slat::set_up();
}