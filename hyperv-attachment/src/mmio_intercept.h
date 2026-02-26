#pragma once

// ============================================================================
// MMIO Intercept - Shadow Page Swap (Production)
// ============================================================================
// AMD SVM only. Intel EPT uses handle_txq_mmio_violation() in main.cpp
//
// Protects ONE NIC MMIO page via NPT present=0:
//
// Stats Page (BAR0+0x4000): Hide Q1 TX/RX packet/byte counts
//    - All access -> shadow page with adjusted stats (2 VMEXIT)
//    - GPTC/TPT: subtract hv_tx_interval_packets
//    - GOTCL/TOTL: subtract hv_tx_interval_bytes
//    - GPRC/GORCL: subtract hv_rx_interval_packets/bytes
//    - OS stats polling ~2sec interval = negligible overhead (~0.5 NPF/sec)
//
// TXQ Page (BAR0+0xE000): NOT intercepted (performance fix)
//    - Q0-Q3 TX regs share same 4KB -> OS Q0 TDT write = 2 VMEXITs each
//    - No current AC enumerates TX queue configurations
//    - Q1 visible to guest but functionally harmless
//
// Intel I225-V stats are Clear-On-Read (COR):
//   Our NPF handler reads real HW (clears HW counter),
//   subtracts Q1 contribution, writes adjusted value to shadow.
//   Guest reads shadow (not COR), so no double-clear issue.
//
// State machine: IDLE -> STEPPING_STATS -> IDLE
// ============================================================================

#ifndef _INTELMACHINE

#include <cstdint>

#include "arch/arch.h"
#include "memory_manager/memory_manager.h"
#include "memory_manager/heap_manager.h"
#include "structures/virtual_address.h"
#include "slat/slat_def.h"
#include "slat/cr3/cr3.h"
#include "slat/cr3/pte.h"
#include "network/nic.h"
#include "network/network.h"
#include "crt/crt.h"

namespace mmio_intercept
{
    // ========================================================================
    // TXQ Page state (BAR0+0xE000)
    // ========================================================================
    inline std::uint64_t txq_page_gpa = 0;
    inline std::uint64_t txq_real_pfn = 0;
    inline std::uint64_t txq_shadow_gpa = 0;
    inline void* txq_shadow_va = nullptr;
    inline slat_pte* txq_cached_pte = nullptr;

    // Q1 offset range within page
    constexpr std::uint32_t TXQ1_START = 0x40;
    constexpr std::uint32_t TXQ1_END = 0x80;

    // ========================================================================
    // Stats Page state (BAR0+0x4000)
    // ========================================================================
    inline std::uint64_t stats_page_gpa = 0;
    inline std::uint64_t stats_real_pfn = 0;
    inline std::uint64_t stats_shadow_gpa = 0;
    inline void* stats_shadow_va = nullptr;
    inline slat_pte* stats_cached_pte = nullptr;

    // Intel I225-V TX stats register offsets (within 0x4000 page)
    // All offsets relative to page base (page_offset = reg - 0x4000)
    constexpr std::uint32_t GPTC_OFF = 0x080;  // Good Packets TX Count (COR)
    constexpr std::uint32_t GOTCL_OFF = 0x090;  // Good Octets TX Count Low (COR)
    constexpr std::uint32_t GOTCH_OFF = 0x094;  // Good Octets TX Count High (COR)
    constexpr std::uint32_t TPT_OFF = 0x0D4;  // Total Packets TX
    constexpr std::uint32_t TOTL_OFF = 0x0D0;  // Total Octets TX Low
    constexpr std::uint32_t TOTH_OFF = 0x0C4;  // Total Octets TX High

    // Intel I225-V RX stats register offsets (within 0x4000 page)
    // Hides DMA packets consumed by HV from Q0 RX counters
    constexpr std::uint32_t GPRC_OFF = 0x074;  // Good Packets RX Count (COR)
    constexpr std::uint32_t GORCL_OFF = 0x088;  // Good Octets RX Count Low (COR)
    constexpr std::uint32_t GORCH_OFF = 0x08C;  // Good Octets RX Count High (COR)

    // ========================================================================
    // State machine
    // ========================================================================
    inline std::uint8_t is_active = 0;

    enum class state_t : std::uint8_t
    {
        IDLE = 0,
        STEPPING_TXQ = 1,    // TXQ page temporarily exposed
        STEPPING_STATS = 2   // Stats page temporarily exposed
    };

    inline state_t current_state = state_t::IDLE;

    // ========================================================================
    // NPT PTE helpers
    // ========================================================================

    inline slat_pte* get_pte_for(std::uint64_t gpa, slat_pte*& cache)
    {
        if (cache) return cache;
        virtual_address_t va;
        va.address = gpa;
        cache = slat::get_pte(slat::hyperv_cr3(), va, 1);
        return cache;
    }

    inline void protect(slat_pte* pte)
    {
        if (!pte) return;
        pte->present = 0;
        vmcb_t* vmcb = arch::get_vmcb();
        vmcb->control.tlb_control = tlb_control_t::flush_guest_tlb_entries;
    }

    inline void expose_pfn(slat_pte* pte, std::uint64_t pfn)
    {
        if (!pte) return;
        pte->page_frame_number = pfn;
        pte->present = 1;
        pte->write = 1;
        vmcb_t* vmcb = arch::get_vmcb();
        vmcb->control.tlb_control = tlb_control_t::flush_guest_tlb_entries;
    }

    // ========================================================================
    // TXQ Shadow Page refresh (same as before)
    // ========================================================================
    inline void refresh_txq_shadow()
    {
        if (!txq_shadow_va || txq_real_pfn == 0) return;

        void* real_va = memory_manager::map_host_physical(txq_real_pfn << 12);
        if (!real_va) return;

        auto* shadow = static_cast<std::uint32_t*>(txq_shadow_va);
        auto* real = static_cast<volatile std::uint32_t*>(real_va);

        // Q0 (0x00-0x3F): real values
        for (std::uint32_t i = 0; i < 16; i++) shadow[i] = real[i];
        // Q1 (0x40-0x7F): zeros (AC sees "not configured")
        for (std::uint32_t i = 16; i < 32; i++) shadow[i] = 0;
        // Q2-Q3 + rest: real values
        for (std::uint32_t i = 32; i < 1024; i++) shadow[i] = real[i];
    }

    // ========================================================================
    // Stats Shadow Page refresh
    // ========================================================================
    // Reads real NIC stats (COR: clears HW counters on read),
    // subtracts Q1 TX contribution tracked by network::hv_tx_interval_*,
    // writes adjusted values to shadow page.
    // Guest reads shadow = sees only OS traffic.
    // Called on every stats page NPF (~every 2 seconds).
    // ========================================================================
    inline void refresh_stats_shadow()
    {
        if (!stats_shadow_va || stats_real_pfn == 0) return;

        void* real_va = memory_manager::map_host_physical(stats_real_pfn << 12);
        if (!real_va) return;

        auto* shadow = static_cast<volatile std::uint32_t*>(stats_shadow_va);
        auto* real = static_cast<volatile std::uint32_t*>(real_va);

        // Snapshot Q1 TX contribution before reading HW (atomic-ish)
        const std::uint32_t hv_pkts = network::hv_tx_interval_packets;
        const std::uint64_t hv_bytes = network::hv_tx_interval_bytes;

        // Snapshot HV-consumed RX contribution
        const std::uint32_t hv_rx_pkts = network::hv_rx_interval_packets;
        const std::uint64_t hv_rx_bytes = network::hv_rx_interval_bytes;

        // Copy ALL stats from real HW to shadow (COR: this clears HW counters!)
        // Full page copy ensures we capture everything including RX stats
        for (std::uint32_t i = 0; i < 1024; i++)
            shadow[i] = real[i];

        // Now adjust TX counters in shadow by subtracting Q1 contribution
        // Clamp to 0 to handle edge cases (timing, rollover)

        // GPTC: Good Packets Transmitted Count
        std::uint32_t gptc = shadow[GPTC_OFF / 4];
        shadow[GPTC_OFF / 4] = (gptc > hv_pkts) ? (gptc - hv_pkts) : 0;

        // TPT: Total Packets Transmitted
        std::uint32_t tpt = shadow[TPT_OFF / 4];
        shadow[TPT_OFF / 4] = (tpt > hv_pkts) ? (tpt - hv_pkts) : 0;

        // GOTCL/GOTCH: Good Octets Transmitted (64-bit)
        std::uint64_t gotc =
            static_cast<std::uint64_t>(shadow[GOTCL_OFF / 4]) |
            (static_cast<std::uint64_t>(shadow[GOTCH_OFF / 4]) << 32);
        std::uint64_t adj_gotc = (gotc > hv_bytes) ? (gotc - hv_bytes) : 0;
        shadow[GOTCL_OFF / 4] = static_cast<std::uint32_t>(adj_gotc);
        shadow[GOTCH_OFF / 4] = static_cast<std::uint32_t>(adj_gotc >> 32);

        // TOTL/TOTH: Total Octets Transmitted (64-bit)
        std::uint64_t tot =
            static_cast<std::uint64_t>(shadow[TOTL_OFF / 4]) |
            (static_cast<std::uint64_t>(shadow[TOTH_OFF / 4]) << 32);
        std::uint64_t adj_tot = (tot > hv_bytes) ? (tot - hv_bytes) : 0;
        shadow[TOTL_OFF / 4] = static_cast<std::uint32_t>(adj_tot);
        shadow[TOTH_OFF / 4] = static_cast<std::uint32_t>(adj_tot >> 32);

        // Adjust RX counters — hide DMA packets consumed by HV from Q0
        // Prevents AC from detecting "NIC GPRC > OS socket RX count" mismatch

        // GPRC: Good Packets Received Count
        std::uint32_t gprc = shadow[GPRC_OFF / 4];
        shadow[GPRC_OFF / 4] = (gprc > hv_rx_pkts) ? (gprc - hv_rx_pkts) : 0;

        // GORCL/GORCH: Good Octets Received Count (64-bit)
        std::uint64_t gorc =
            static_cast<std::uint64_t>(shadow[GORCL_OFF / 4]) |
            (static_cast<std::uint64_t>(shadow[GORCH_OFF / 4]) << 32);
        std::uint64_t adj_gorc = (gorc > hv_rx_bytes) ? (gorc - hv_rx_bytes) : 0;
        shadow[GORCL_OFF / 4] = static_cast<std::uint32_t>(adj_gorc);
        shadow[GORCH_OFF / 4] = static_cast<std::uint32_t>(adj_gorc >> 32);

        // Reset all interval counters (we've accounted for this interval)
        network::hv_tx_interval_packets = 0;
        network::hv_tx_interval_bytes = 0;
        network::hv_rx_interval_packets = 0;
        network::hv_rx_interval_bytes = 0;
    }

    // ========================================================================
    // NPF handler - called from VMEXIT
    // ========================================================================
    // Stats page only. TXQ page (0xE000) is not intercepted (perf fix).
    // ========================================================================
    inline std::uint8_t handle_npf()
    {
        if (!is_active) return 0;

        vmcb_t* vmcb = arch::get_vmcb();

        npf_exit_info_1 info1;
        info1.flags = vmcb->control.first_exit_info;
        const std::uint64_t faulting_gpa = vmcb->control.second_exit_info;
        const std::uint64_t page_gpa = faulting_gpa & ~0xFFFull;

        // ---- Stats Page (BAR0+0x4000) ----
        // ~0.5 NPF/sec (igc driver reads stats every 2 seconds)
        if (page_gpa == stats_page_gpa)
        {
            // All stats access goes through shadow (read or write)
            // Refresh shadow with adjusted TX/RX stats
            refresh_stats_shadow();
            expose_pfn(stats_cached_pte, stats_shadow_gpa >> 12);
            current_state = state_t::STEPPING_STATS;
            return 1;
        }

        return 0;
    }

    // ========================================================================
    // STEPPING restore - called at top of every VMEXIT
    // ========================================================================
    // Stats page only. No TXQ stepping needed (page not intercepted).
    // ========================================================================
    inline std::uint8_t check_and_restore()
    {
        if (!is_active) return 0;

        if (current_state == state_t::STEPPING_STATS)
        {
            protect(stats_cached_pte);
            current_state = state_t::IDLE;
        }

        return 0;
    }

    // ========================================================================
    // Helper: protect a single page via NPT
    // ========================================================================
    static inline std::uint8_t protect_page_gpa(
        std::uint64_t gpa,
        std::uint64_t& out_real_pfn,
        slat_pte*& out_cached_pte)
    {
        virtual_address_t va;
        va.address = gpa;
        std::uint8_t split_state = 0;
        slat_pte* pte = slat::get_pte(
            slat::hyperv_cr3(), va, 1, &split_state);

        if (!pte) return 0;

        out_real_pfn = pte->page_frame_number;
        out_cached_pte = pte;

        pte->present = 0;

        vmcb_t* vmcb = arch::get_vmcb();
        vmcb->control.tlb_control = tlb_control_t::flush_guest_tlb_entries;
        vmcb->control.clean.nested_paging = 0;

        return 1;
    }

    // ========================================================================
    // Initialization - call AFTER network::set_up()
    // ========================================================================
    // [PERF FIX] Only stats page (0x4000) is intercepted.
    // TXQ page (0xE000) protection REMOVED:
    //   Q0-Q3 TX regs share same 4KB page. OS writes Q0 TDT constantly
    //   -> 2 VMEXITs per write -> system-wide performance degradation.
    //   No current AC (VGK/EAC/BE) enumerates TX queue configurations.
    //   Re-add if future AC detection vector emerges.
    //
    // Stats page (0x4000) interception is nearly free:
    //   igc driver reads stats ~once per 2 seconds -> ~0.5 NPF/sec.
    //   Hides Q1 TX packet/byte counts from GPTC/GOTC/TPT/TOT.
    //   Hides HV-consumed RX counts from GPRC/GORC.
    // ========================================================================
    inline std::uint8_t set_up()
    {
        // IGC NIC only (I225-V, I226-V)
        if (nic::state.nic_type != nic::nic_type_t::INTEL ||
            nic::state.intel_gen != nic::intel_gen_t::IGC)
        {
            is_active = 0;
            return 0;
        }

        if (nic::state.mmio_base_gpa == 0 || !nic::heap_va_pa_valid)
        {
            is_active = 0;
            return 0;
        }

        // ---- Allocate shadow page for stats only ----
        stats_shadow_va = heap_manager::allocate_page();
        if (!stats_shadow_va)
        {
            is_active = 0;
            return 0;
        }

        stats_shadow_gpa = nic::va_to_gpa(stats_shadow_va);
        crt::set_memory(stats_shadow_va, 0, 4096);

        // ---- Page GPAs ----
        stats_page_gpa = nic::state.mmio_base_gpa + 0x4000;

        // ---- TXQ page (0xE000): NO protection ----
        // Q0 TDT writes cause devastating NPF overhead.
        // HV accesses Q1 regs via normal map_guest_physical (page is present).
        // No mmio_bypass needed since NPT present=1 for this page.

        // ---- Protect Stats page only ----
        if (!protect_page_gpa(stats_page_gpa, stats_real_pfn, stats_cached_pte))
        {
            is_active = 0;
            return 0;
        }

        current_state = state_t::IDLE;
        is_active = 1;

        return 1;
    }

} // namespace mmio_intercept

#endif // !_INTELMACHINE