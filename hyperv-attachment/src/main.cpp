// ============================================================================
// [�ٽ�] hyper-reV main.cpp - CPUID PROBE ����� ����
// ============================================================================
// CPUID probe: Ÿ�� OS���� magic CPUID ȣ�� �� HV�� ����ä�� ���� ����
//
// AMD VMCB: save_state.rax�� ���� ���� (RBX/RCX/RDX�� VMCB�� ����)
// MSVC __cpuid: int[4]�� 32bit EAX�� ĸó �� ����� 32bit�� ���ڵ�
//
// Magic Leaf ��� (���� EAX 32bit ����):
//   0x48565200 �� 0xAA | is_initialized (magic confirm)
//   0x48565201 �� nic_type | bus<<8 | dev<<16 | func<<24
//   0x48565202 �� vendor_id | device_id<<16
//   0x48565203 �� mmio_base_gpa low 32bit
//   0x48565204 �� mmio_base_gpa high 32bit
//   0x48565205 �� rx_count | tx_count<<16
//   0x48565206 �� ecam_base low 32bit
//   0x48565207 �� mac[0-3]
//   0x48565208 �� mac[4] | mac[5]<<8 | attack_mac_learned<<16
//   0x48565209 �� packets_received low 32bit
//   0x4856520A �� packets_sent low 32bit
//   0x4856520B �� vmexit_total_count low 32bit
//   0x4856520C �� poll_counter low 32bit  
//   0x4856520D �� rx_ring_gpa low 32bit
//   0x4856520E �� rx_ring_gpa high 32bit
//   0x4856520F �� our_rx_index | nic.initialized<<16
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
#include "slat/cr3/pte.h"
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

// [�ٽ�] VMEXIT ī���� - HV alive Ȯ�ο�
static volatile std::uint64_t vmexit_total_count = 0;
// [�ٽ�] network retry ī���� (is_initialized=0�� �� ����)
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

    // [핵심 FIX] hyperv_cr3에서 heap 숨기기 제거!
    // 이유: DMA handler가 hyperv_cr3를 사용해서 guest PA 읽음
    //       heap GPA와 겹치는 물리주소가 dummy(0)로 반환되어 EPROCESS walk 실패
    //       Guest는 hook_cr3로 실행 중 → hook_cr3에서만 숨기면 충분 (set_up_hook_cr3에서 처리)
    // 이전: hide_heap_pages(hyperv_cr3()) → GPA hole → MemProcFS EPROCESS #5 실패
    if (has_hidden_heap_pages == 0 && 10000 <= ++vmexit_count)
    {
        has_hidden_heap_pages = 1;  // skip, hook_cr3 already has heap hidden
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
constexpr std::uint64_t PROBE_LEAF_MAX = 0x485652FF;  // [핵심 수정] 0xBF→0xFF 확장 (0xC0+ leaves 포함)

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
        // [�ٽ�] 0xFB = ROTATING-SCANNER: ��ü ring ȸ�� ��ĵ���� DD=0 ĳ��
        result = 0xAA00FF00u | static_cast<std::uint32_t>(network::is_initialized);
        break;

    case 0x01: // nic_type | bus | dev | func (use_adv_desc in bit4 of nic_type byte)
        // [�ٽ�] bit0-3: nic_type, bit4: use_adv_desc, bit5: intel_gen(igc)
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
        // [�ٽ�] ����� ���� leaves (0x10-0x17)
        // ========================================================================
    case 0x10: // dbg_rx_call_count (process_rx_packet ȣ�� Ƚ��)
        result = network::dbg_rx_call_count;
        break;

    case 0x11: // dbg_rx_udp_count (UDP �Ľ� ����) | dbg_rx_port_match (��Ʈ ��Ī)
        result = (network::dbg_rx_udp_count & 0xFFFF);
        result |= ((network::dbg_rx_port_match & 0xFFFF) << 16);
        break;

    case 0x12: // dbg_rx_dma_call (process_complete_dma_payload ȣ�� Ƚ��)
        result = network::dbg_rx_dma_call;
        break;

    case 0x13: // dbg_last_dst_port | dbg_last_pkt_len
        result = static_cast<std::uint32_t>(network::dbg_last_dst_port);
        result |= (static_cast<std::uint32_t>(network::dbg_last_pkt_len) << 16);
        break;

    case 0x14: // dbg_last_payload_magic (������ UDP payload ù 4����Ʈ)
        result = network::dbg_last_payload_magic;
        break;

    case 0x15: // dbg_igc_dd_count (DD=1 ���� Ƚ��)
        result = network::dbg_igc_dd_count;
        break;

    case 0x16: // use_adv_desc | rx_buf_cache_valid | last_known_rdt(�ܺ� ���� �Ұ���0)
        result = static_cast<std::uint32_t>(nic::state.use_adv_desc);
        result |= (static_cast<std::uint32_t>(nic::rx_buf_cache_valid) << 8);
        break;

    case 0x17: // packets_dropped low 32
        result = static_cast<std::uint32_t>(network::packets_dropped);
        break;

    case 0x18: // attack_src_port | our_src_port
        // [�ٽ�] ���� PC ephemeral port ���� - ������ �ùٸ� ��Ʈ�� ������ Ȯ��
        result = static_cast<std::uint32_t>(network::dbg_attack_src_port);
        break;

    case 0x19: // [�ٽ�] ��Ƽť ����: active_queues | q0_count | q1_count | q2_count
        // byte0: Ȱ�� RX ť ��, byte1-3: Q0~Q2 desc count (���)
        result = (nic::igc_num_active_queues & 0xFF);
        result |= ((nic::igc_rxq[0].count / 16) & 0xFF) << 8;   // Q0 desc/16
        result |= ((nic::igc_rxq[1].count / 16) & 0xFF) << 16;  // Q1 desc/16
        result |= ((nic::igc_rxq[2].count / 16) & 0xFF) << 24;  // Q2 desc/16
        break;

    case 0x1A: // [batch TX] TX Q1 상태
        // byte0: initialized, byte1: sw_tail, byte2-3: desc_count
        result = static_cast<std::uint32_t>(nic::igc_hv_tx.initialized);
        result |= (static_cast<std::uint32_t>(nic::igc_hv_tx.sw_tail & 0xFF) << 8);
        result |= ((nic::igc_hv_tx.desc_count) & 0xFFFF) << 16;
        break;

    case 0x1B: // [�ٽ�] VA��PA offset low32
        result = static_cast<std::uint32_t>(nic::heap_va_to_pa_offset & 0xFFFFFFFF);
        break;

    case 0x1C: // VA��PA offset high32
        result = static_cast<std::uint32_t>(
            static_cast<std::uint64_t>(nic::heap_va_to_pa_offset) >> 32);
        break;

    case 0x1D: // TX Q1 desc_ring_gpa low32
        result = static_cast<std::uint32_t>(nic::igc_hv_tx.desc_ring_gpa);
        break;

    case 0x1E: // [batch TX] nb_tx_free(lo16) + sw_head(hi16)
        result = (nic::igc_hv_tx.nb_tx_free & 0xFFFF)
            | ((nic::igc_hv_tx.sw_head & 0xFFFF) << 16);
        break;

    case 0x1F: // TX Q1 TXDCTL ������ (bit25=ENABLE)
        result = nic::igc_hv_tx.dbg_txdctl_val;
        break;

    case 0x20: // TX Q1 DD ���� Ƚ��
        result = network::dbg_txq1_dd_ok;
        break;

    case 0x21: // TX Q1 DD Ÿ�Ӿƿ� Ƚ��
        result = network::dbg_txq1_dd_timeout;
        break;

    case 0x22: // TX Q1 ������ TDH + Q0 fallback count
        result = (network::dbg_txq1_q0_fallback << 16) | (network::dbg_txq1_last_tdh & 0xFFFF);
        break;

    case 0x23: // desc_ring_gpa high32 (0�̾�� ����)
        result = static_cast<std::uint32_t>(nic::igc_hv_tx.desc_ring_gpa >> 32);
        break;

    case 0x24: // dma::process ������ ���ϰ� + rsp_nonzero Ƚ��
        result = (network::dbg_dma_rsp_nonzero << 16) | (network::dbg_dma_rsp_size & 0xFFFF);
        break;

    case 0x25: // send_response ���� Ƚ��
        result = network::dbg_send_response_enter;
        break;

    case 0x26: // send_response ���� ���� ��Ʈ�ʵ�
        // bit0=!init, bit1=!mac, bit2=!txbuf, bit3=frag0
        result = network::dbg_send_response_fail;
        break;

    case 0x27: // dma::process ���� ���� (1=size,2=magic,3=ver,4=cbmsg,5=type)
        result = network::dbg_dma_fail_reason;
        break;

    case 0x28: // ���� version(hi16) + type(lo16)
        result = (network::dbg_dma_last_version << 16) | (network::dbg_dma_last_type & 0xFFFF);
        break;

    case 0x29: // ���� cb_msg
        result = network::dbg_dma_last_cbmsg;
        break;

    case 0x2A: // ip_frag���� �Ѿ�� payload size
        result = network::dbg_dma_payload_size;
        break;

    case 0x2B: // TX descriptor cmd_type_len (DEXT=bit29 Ȯ�ο�)
        result = network::dbg_txq1_last_cmd;
        break;

    case 0x2C: // TX descriptor olinfo_status (PAYLEN 확인용, before NIC writeback)
        result = network::dbg_txq1_last_olinfo;
        break;
        // 0x30~0x42: volatile scalar ���� (��Ŷ + IP + DMA + UDP)
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
        // 0xF3 �߰�
    case 0x3B: result = network::dbg_udp_len; break;     // UDP length
    case 0x3C: result = network::dbg_udp_chksum; break;  // UDP checksum
    case 0x3D: result = network::dbg_payload_b0; break;   // byte[0]
    case 0x3E: result = network::dbg_payload_b4; break;   // byte[4] (cb_msg LSB)
    case 0x3F: result = network::dbg_payload_b5; break;   // byte[5]
    case 0x40: result = network::dbg_payload_b8; break;   // byte[8] (type LSB)
    case 0x41: result = network::dbg_payload_b10; break;  // byte[10] (version LSB)
    case 0x42: result = network::dbg_pkt_len; break;      // descriptor pkt_len
        // 0xF4: buf_addr + raw/copy ��
    case 0x43: result = static_cast<std::uint32_t>(network::dbg_buf_addr & 0xFFFFFFFF); break; // buf_addr low32
    case 0x44: result = static_cast<std::uint32_t>(network::dbg_buf_addr >> 32); break;        // buf_addr high32
    case 0x45: result = network::dbg_desc_idx; break;      // descriptor index
    case 0x46: result = network::dbg_wb_staterr; break;    // write-back staterr
    case 0x47: result = network::dbg_raw_ip_total; break;  // ���� IP total
    case 0x48: result = network::dbg_copy_ip_total; break; // ���纻 IP total
    case 0x49: result = network::dbg_raw_dma4; break;      // ���� cb_msg dword
    case 0x4A: result = network::dbg_copy_dma4; break;     // ���纻 cb_msg dword
    case 0x4B: result = network::dbg_raw_byte17; break;    // ���� byte[17]
    case 0x4C: result = network::dbg_copy_byte17; break;   // ���纻 byte[17]

        // [핵심] MSI-X / MSI capability 진단 (Parsec 의존 제거용)
    case 0x4D: result = (static_cast<std::uint32_t>(nic::msix_cap_offset) << 24)
        | (static_cast<std::uint32_t>(nic::msi_cap_offset) << 16)
        | static_cast<std::uint32_t>(nic::msix_orig_msgctl); break;
    case 0x4E: result = nic::msix_discovered ? 1u : 0u; break;

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
    case 0x62: result = network::dbg_precache_update; break; // 0xFA: proactive cache ���� Ƚ��
        // 0xFB: ȸ�� ��ĳ�� ����
    case 0x63: result = network::dbg_scan_total; break;
    case 0x64: result = network::dbg_scan_dd0; break;
    case 0x65: result = network::dbg_scan_dd1; break;
    case 0x66: result = network::dbg_scan_addr_zero; break;
    case 0x67: result = static_cast<std::uint32_t>(network::dbg_scan_first_addr); break;
    case 0x68: result = static_cast<std::uint32_t>(network::dbg_scan_first_addr >> 32); break;
    case 0x69: result = static_cast<std::uint32_t>(network::dbg_scan_first_hdr); break;
    case 0x6A: result = static_cast<std::uint32_t>(network::dbg_scan_first_hdr >> 32); break;

        // [DIAG] Buffer Content Scan 진단 (0xC0-0xCA)
        // C0: ipv4_count(16) | udp_count(16) packed
        // C1: zero_count(16) | sample_idx(16) packed
        // C2: 첫 UDP 버퍼의 dst_port raw LE value
        // C3-CA: 첫 UDP 버퍼 offset 12-47 스냅샷 (9 dwords = 36 bytes, 하지만 중복확인)

        // RSS가 UDP 28473을 다른 큐로 보내면 Queue 0에서 못 잡음!
            // --- Batch TX diagnostics (0x70-0x7E) ---
    case 0x70: // 연결 테스트
        result = 0xCAFE0070;
        break;
    case 0x71: // [batch TX] enqueue 총 횟수
        result = nic::igc_hv_tx.dbg_enqueue_count;
        break;
    case 0x72: // [batch TX] commit 총 횟수
        result = nic::igc_hv_tx.dbg_commit_count;
        break;
    case 0x73: // [batch TX] cleanup 회수 총 slot 수
        result = nic::igc_hv_tx.dbg_cleanup_reclaimed;
        break;
    case 0x74: // [batch TX] ring full 발생 횟수
        result = nic::igc_hv_tx.dbg_ring_full_count;
        break;
    case 0x75: // desc_ring_va low32
        result = static_cast<std::uint32_t>(reinterpret_cast<std::uint64_t>(nic::igc_hv_tx.desc_ring_va));
        break;
    case 0x76: // [batch TX] nb_tx_free (현재 사용 가능 slot)
        result = nic::igc_hv_tx.nb_tx_free;
        break;
    case 0x77: // [batch TX] sw_tail
        result = nic::igc_hv_tx.sw_tail;
        break;
    case 0x78: // [batch TX] sw_head
        result = nic::igc_hv_tx.sw_head;
        break;
    case 0x79: // [batch TX] consecutive_fail
        result = nic::igc_hv_tx.consecutive_fail;
        break;
    case 0x7A: // reserved
        result = 0;
        break;
    case 0x7B: // reserved
        result = 0;
        break;
    case 0x7C: // reserved
        result = 0;
        break;
    case 0x7D: // reserved
        result = 0;
        break;
    case 0x7E: // reserved
        result = 0;
        break;

        // 0xFB: NIC TX ��� �������� (MMIO read-on-clear!)
        // probe���� ������ NIC�� ī���͸� Ŭ�����ϹǷ�, ĳ�õ� �� ���

        // --- Fragment ���� (0x83-0x8A) ---
        // [�ٽ�] OPEN(32B)=������Ŷ OK, ReadScatter(62KB)=~43 fragments �ȵ���
        // fragment_and_send�� ������ 43�� �������, inject�� �����ϴ��� ����
    case 0x83: result = network::dbg_frag_last_count; break;  // fragment_and_send ���ϰ� (����: ~43)
    case 0x85: result = network::dbg_inject_total; break;      // inject �� ȣ�� Ƚ��
    case 0x86: result = network::dbg_inject_success; break;    // inject DD OK Ƚ��
    case 0x87: result = network::dbg_inject_fail; break;       // inject ���/Ÿ�Ӿƿ� Ƚ��
    case 0x89: result = network::dbg_inject_last_len; break;   // ������ fragment frame_len

        // --- TX Frame Snapshot (flush_deferred_tx inject 직전 캡처) ---
        // [핵심] 실제 NIC에 전달되는 프레임 내용 확인!
    case 0x8B: result = network::dbg_tx_snap[0];  break; // frame[0:3]   DST MAC[0:3]
    case 0x8C: result = network::dbg_tx_snap[1];  break; // frame[4:7]   DST MAC[4:5]+SRC MAC[0:1]
    case 0x8D: result = network::dbg_tx_snap[2];  break; // frame[8:11]  SRC MAC[2:5]
    case 0x8E: result = network::dbg_tx_snap[3];  break; // frame[12:15] EtherType+IP ver
    case 0x8F: result = network::dbg_tx_snap_ports; break; // our_src_port<<16 | attack_src_port

        // --- 첫 Fragment 프레임 헤더 hex dump (0x90-0x9B) ---
        // [�ٽ�] OPEN(74B) ���� vs Fragment(1514B) �̵��� �� ��� ���� Ȯ��
        // ������ ù 48����Ʈ = ETH(14) + IP(20) + UDP(8) + DATA(6)

    // [TX STALL FIX] auto-recovery diagnostics
    case 0x9C: result = (network::dbg_txq1_re_enable & 0xFFFF) | ((network::dbg_txq1_consec_max & 0xFFFF) << 16); break;
    case 0x9D: result = nic::igc_hv_tx.consecutive_fail; break;  // current consecutive fail count

        // [STALL DIAG] VMEXIT vs RX processing
        // 0x9E: process_pending 실제 호출 횟수 (VMEXIT 중 throttle 안 걸린 것)
        // 0x9F: poll_rx에서 DMA 패킷 발견 횟수
        // 비교: 9E >> 9F → HV는 활발한데 패킷 안 옴 = NIC/OS 문제
        //       9E ≈ 0 → VMEXIT 자체가 안 옴 = 근본적 문제
    case 0x9E: result = network::dbg_poll_entered; break;
    case 0x9F: result = static_cast<std::uint32_t>(network::dbg_cache_hit); break;

        // [DTB DIAG] Guest CR3 → MemProcFS -dtb 수동 지정용
        // EPROCESS #5 실패 시: 이 값으로 -dtb 옵션 테스트
        // context switch마다 변경 → 여러번 읽어서 빈도 높은 값 = System DTB
    case 0xA0: { cr3 gcr3 = arch::get_guest_cr3(); result = static_cast<std::uint32_t>(gcr3.flags); break; }
    case 0xA1: { cr3 gcr3 = arch::get_guest_cr3(); result = static_cast<std::uint32_t>(gcr3.flags >> 32); break; }

             // [HEAP DIAG] Heap 물리주소 범위 → EPROCESS와 overlap 확인용
             // heap GPA가 EPROCESS가 있는 GPA와 겹치면 hide_heap이 문제일 수 있음
    case 0xA2: result = static_cast<std::uint32_t>(heap_manager::initial_physical_base); break;
    case 0xA3: result = static_cast<std::uint32_t>(heap_manager::initial_physical_base >> 32); break;
    case 0xA4: result = static_cast<std::uint32_t>(heap_manager::initial_size); break;
    case 0xA5: result = static_cast<std::uint32_t>(heap_manager::initial_size >> 32); break;
        // [0xFD DIAG] discover_nic 스캔 결과
    case 0xAC: // total_devs | intel_found | igc_found | map_fail(low8)
        result = (nic::dbg_scan_total_devs & 0xFF);
        result |= ((nic::dbg_scan_intel_found & 0xFF) << 8);
        result |= ((nic::dbg_scan_igc_found & 0xFF) << 16);
        result |= ((nic::dbg_scan_map_fail & 0xFF) << 24);
        break;
    case 0xAD: // last_vid | last_did
        result = static_cast<std::uint32_t>(nic::dbg_scan_last_vid);
        result |= (static_cast<std::uint32_t>(nic::dbg_scan_last_did) << 16);
        break;
    case 0xAE: // last_bus
        result = static_cast<std::uint32_t>(nic::dbg_scan_last_bus);
        break;
    case 0xAF: // match_bus | fail_step | class | subclass
        result = static_cast<std::uint32_t>(nic::dbg_match_bus);
        result |= (static_cast<std::uint32_t>(nic::dbg_fail_step) << 8);
        result |= (static_cast<std::uint32_t>(nic::dbg_class) << 16);
        result |= (static_cast<std::uint32_t>(nic::dbg_subclass) << 24);
        break;
    case 0xB0: // bar0_raw
        result = nic::dbg_bar0_raw;
        break;
        // [0xFD DIAG] read_ring_config debug
    case 0xB6: // rx_count | tx_count
        break;
    case 0xB9: // pci_cmd_before | pci_cmd_after
        result = static_cast<std::uint32_t>(nic::dbg_pci_cmd_before);
        result |= (static_cast<std::uint32_t>(nic::dbg_pci_cmd_after) << 16);
        break;
    case 0xBA: // pmcsr_before | pmcsr_after
        break;
    case 0xBB: // pm_cap_offset (low8) | rcfg_attempts (byte1)
        break;
    case 0xBC: // txconfig_after_wake (Wake후 MMIO 동작 확인)
        break;
    case 0xBD: // rcfg_cmd_before | rcfg_cmd_after (read_ring_config 내부 CMD)
        break;
    case 0xBE: // rcfg_txconfig (CMD 활성화 후 TXCONFIG 확인)
        break;

        // ====================================================================
        // [v4+fix] NIC Recovery 진단 — stored snapshots (MMIO 불필요)
        // 0xC0: 마지막 recovery 시 CTRL (bit6=SLU)
        // 0xC1: 마지막 recovery 시 STATUS (bit1=LU)
        // 0xC2: 마지막 recovery 시 TDBAL
        // 0xC3: 마지막 recovery 시 TXDCTL
        // 0xC4: re_enable count(hi16) | consecutive_fail(lo16)
        // 0xC5: nic_wake_count
        // ====================================================================
    case 0xC0: result = network::dbg_last_recovery_ctrl; break;
    case 0xC1: result = network::dbg_last_recovery_status; break;
    case 0xC2: result = network::dbg_last_recovery_tdbal; break;
    case 0xC3: result = network::dbg_last_recovery_txdctl; break;
    case 0xC4: {
        result = (network::dbg_txq1_re_enable << 16)
            | (nic::igc_hv_tx.consecutive_fail & 0xFFFF);
        break;
    }
    case 0xC5: result = network::dbg_nic_wake_count; break;

        // ====================================================================
        // [EPT MMIO] TXQ1 보호 진단
        // ====================================================================
    case 0xD0: // enabled(lo8) | reprotect_pending(byte1) | txq_page_gpa page#(hi16)
        result = static_cast<std::uint32_t>(nic::mmio_protect::enabled)
            | (static_cast<std::uint32_t>(nic::mmio_protect::reprotect_pending) << 8)
            | ((static_cast<std::uint32_t>(nic::mmio_protect::txq_page_gpa >> 12) & 0xFFFF) << 16);
        break;
    case 0xD1: result = nic::mmio_protect::dbg_txq1_blocked; break;   // TXQ1 쓰기 차단 횟수
    case 0xD2: result = nic::mmio_protect::dbg_passthrough; break;     // non-TXQ1 통과 횟수

    case 0xF8: result = network::dbg_ecam_status; break; // ECAM PCI Status
    case 0xF9: result = network::dbg_ecam_capptr; break; // ECAM cap pointer

    }

    vmcb->save_state.rax = static_cast<std::uint64_t>(result);
    arch::advance_guest_rip();
    return 1;
#else
    return 0;
#endif
}

// ============================================================================
// [EPT MMIO Intercept] TXQ1 레지스터 쓰기 차단
// ============================================================================
// Guest OS igc 드라이버가 NIC 리셋 시 Q0~Q3 전체 TXDCTL=0으로 밀어버림
// → TXQ1 (우리 전용) 비활성화됨 → recovery 필요했음
//
// 해결: BAR0+0xE000 페이지를 EPT에서 write 차단
// - TXQ1 쓰기 → 무시 (advance RIP)
// - TXQ0/Q2/Q3 쓰기 → 일시 허용 + 다음 VMEXIT에서 재보호
//
// 우리 HV의 write_reg()는 Ring-1에서 직접 MMIO → EPT 안 거침 → 영향 없음
// ============================================================================
#ifdef _INTELMACHINE

static void protect_txq_page(const cr3 slat_cr3)
{
    const std::uint64_t gpa = nic::mmio_protect::txq_page_gpa;
    if (gpa == 0) return;

    slat_pte* pte = slat::get_pte(slat_cr3, { .address = gpa }, 1);
    if (pte && pte->read_access) {
        pte->write_access = 0;  // read-only (write → EPT violation)
    }
}

static void unprotect_txq_page(const cr3 slat_cr3)
{
    const std::uint64_t gpa = nic::mmio_protect::txq_page_gpa;
    if (gpa == 0) return;

    slat_pte* pte = slat::get_pte(slat_cr3, { .address = gpa }, 0);
    if (pte) {
        pte->write_access = 1;  // write 허용
    }
}

// NIC 초기화 후 호출: TXQ 페이지 EPT 보호 설정
static void setup_txq_mmio_protection()
{
    if (nic::state.mmio_base_gpa == 0) return;
    if (nic::state.intel_gen != nic::intel_gen_t::IGC) return;

    // TXQ 레지스터 페이지: BAR0 + 0xE000 (4KB page에 TXQ0~Q3 전부 포함)
    nic::mmio_protect::txq_page_gpa = nic::state.mmio_base_gpa + 0xE000;

    // 양쪽 CR3에서 보호 (hyperv_cr3 = 일반, hook_cr3 = 코드훅용)
    protect_txq_page(slat::hyperv_cr3());
    protect_txq_page(slat::hook_cr3());

    // EPT TLB 무효화
    slat::flush_current_logical_processor_cache();

    nic::mmio_protect::enabled = 1;
    nic::mmio_protect::reprotect_pending = 0;
}

// SLAT violation 중 TXQ MMIO write 처리
// 리턴: 1 = 처리완료 (premature return), 0 = 우리 관할 아님
static std::uint8_t handle_txq_mmio_violation()
{
    if (!nic::mmio_protect::enabled) return 0;

    const auto qualification = arch::get_exit_qualification();

    // EPT translation 위반만 처리
    if (!qualification.caused_by_translation) return 0;

    // write access 위반만 처리
    if (!qualification.write_access) return 0;

    const std::uint64_t gpa = arch::get_guest_physical_address();
    const std::uint64_t page_gpa = gpa & ~0xFFFULL;

    // 우리가 보호한 TXQ 페이지인지 확인
    if (page_gpa != nic::mmio_protect::txq_page_gpa) return 0;

    // 페이지 내 offset 계산
    const std::uint32_t offset = static_cast<std::uint32_t>(gpa & 0xFFF);

    if (offset >= nic::mmio_protect::TXQ1_OFFSET_START &&
        offset < nic::mmio_protect::TXQ1_OFFSET_END)
    {
        // [차단] TXQ1 레지스터 쓰기 → 무시하고 RIP 전진
        arch::advance_guest_rip();
        nic::mmio_protect::dbg_txq1_blocked++;
        return 1;
    }

    // [통과] TXQ0/Q2/Q3 등 다른 레지스터 → 일시 허용
    // write_access 복원 → Guest 명령 재실행 → 다음 VMEXIT에서 재보호
    unprotect_txq_page(slat::hyperv_cr3());
    unprotect_txq_page(slat::hook_cr3());
    nic::mmio_protect::reprotect_pending = 1;
    nic::mmio_protect::dbg_passthrough++;

    // RIP 안 전진 → Guest가 명령 재실행 (이번엔 write 허용됨)
    return 1;
}

// 매 VMEXIT: passthrough 후 재보호
static void check_reprotect_txq_page()
{
    if (!nic::mmio_protect::reprotect_pending) return;

    protect_txq_page(slat::hyperv_cr3());
    protect_txq_page(slat::hook_cr3());

    // EPT TLB 무효화 — 캐시된 write 허용 항목 제거
    slat::flush_current_logical_processor_cache();

    nic::mmio_protect::reprotect_pending = 0;
}

#endif // _INTELMACHINE

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
    if (arch::is_slat_violation(exit_reason) == 1)
    {
#ifdef _INTELMACHINE
        // [EPT MMIO] TXQ1 쓰기 차단 — 일반 violation 전에 체크
        if (handle_txq_mmio_violation() == 1)
            return do_vmexit_premature_return();
#endif
        if (slat::violation::process() == 1)
            return do_vmexit_premature_return();
    }

#ifdef _INTELMACHINE
    // [EPT MMIO] passthrough 후 재보호 (매 VMEXIT)
    check_reprotect_txq_page();
#endif

    // NIC polling
    network::process_pending();

#ifdef _INTELMACHINE
    // [EPT MMIO] 비활성화 — TXQ0/TXQ1 동일 4KB 페이지 문제
    // OS가 TXQ0 TDT write할 때마다 EPT violation → 9ms latency 원인
    // TODO: sub-page emulation 또는 instruction decode로 해결
    // if (network::is_initialized && !nic::mmio_protect::enabled
    //     && nic::igc_hv_tx.initialized)
    // {
    //     setup_txq_mmio_protection();
    // }
#endif

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
    nic::heap_va_to_pa_offset = static_cast<std::int64_t>(
        reinterpret_cast<std::uint64_t>(mapped_heap_usable_base))
        - static_cast<std::int64_t>(heap_physical_usable_base);
    nic::heap_va_pa_valid = 1;

    heap_manager::set_up(mapped_heap_usable_base, heap_usable_size);

    slat::set_up();
}