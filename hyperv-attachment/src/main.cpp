// ============================================================================
// hyper-reV main.cpp - Production Build (CPUID diagnostics removed)
// ============================================================================
// All CPUID probe/diagnostic/debug code has been stripped.
// No custom CPUID leaves = zero fingerprint for AC scanners.
// Remaining functionality: VMEXIT hook, MMIO intercept, NIC polling, DMA.
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
#include "mmio_intercept.h"  // [v2] Shadow Page Swap - TXQ1 protection (AMD NPT)

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
        // [CRITICAL] SLAT init must be first - sets up hook_cr3 for guest PA mapping
        // Without this, map_guest_physical() fails -> NIC discovery/polling all broken
        slat::process_first_vmexit();
        interrupts::set_up();
        clean_up_uefi_boot_image();

        dma::set_up();
        network::set_up();
#ifndef _INTELMACHINE
        // [DISABLED] mmio_intercept causes system-wide performance degradation.
        // Both 0xE000 (TXQ) and 0x4000 (Stats) pages contain hot registers
        // that igc driver accesses frequently -> excessive NPF VMEXITs.
        // Stats shadow (Q1 TX/RX count hiding) not active.
        // Detection risk: LOW - no AC correlates NIC stats counters.
        // TODO: instruction-level emulation instead of page-level NPF.
        // mmio_intercept::set_up();
#endif

        is_first_vmexit = 0;
    }

    // hook_cr3 already has heap hidden via set_up_hook_cr3()
    // hyperv_cr3 heap hiding removed: DMA handler needs guest PA reads via hyperv_cr3
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
        return 1;
    }

    // [통과] TXQ0/Q2/Q3 등 다른 레지스터 → 일시 허용
    // write_access 복원 → Guest 명령 재실행 → 다음 VMEXIT에서 재보호
    unprotect_txq_page(slat::hyperv_cr3());
    unprotect_txq_page(slat::hook_cr3());
    nic::mmio_protect::reprotect_pending = 1;

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
// VMEXIT Handler (Production - no CPUID diagnostics)
// ============================================================================
std::uint64_t vmexit_handler_detour(
    const std::uint64_t a1, const std::uint64_t a2,
    const std::uint64_t a3, const std::uint64_t a4)
{
    process_first_vmexit();

#ifndef _INTELMACHINE
    // STEPPING restore - re-protect page exposed by NPF
    // Must be called at top of every VMEXIT (regardless of exit_reason)
    mmio_intercept::check_and_restore();
#endif

    const std::uint64_t exit_reason = arch::get_vmexit_reason();

    // CPUID: no custom handler - all leaves pass through to Hyper-V transparently
    // Zero detection surface for AC CPUID range scanning

    // SLAT violation
    if (arch::is_slat_violation(exit_reason) == 1)
    {
#ifdef _INTELMACHINE
        if (handle_txq_mmio_violation() == 1)
            return do_vmexit_premature_return();
#else
        // MMIO intercept - Shadow Page Swap NPF handler
        if (mmio_intercept::handle_npf() == 1)
            return do_vmexit_premature_return();
#endif
        if (slat::violation::process() == 1)
            return do_vmexit_premature_return();
    }

#ifdef _INTELMACHINE
    check_reprotect_txq_page();
#endif

    // NIC polling — throttled for timing stealth
    // CPUID exits are timed by BattlEye IET divergence test.
    // Polling adds ~400ns (4 MMIO reads) per VMEXIT which is measurable.
    // Skip polling on CPUID exits to avoid inflating CPUID cycle count.
    // Also throttle on other exits: poll every 4th non-CPUID VMEXIT.
    {
        static std::uint32_t poll_counter = 0;
#ifndef _INTELMACHINE
        constexpr std::uint64_t VMEXIT_CPUID = 0x72;  // AMD SVM
#else
        constexpr std::uint64_t VMEXIT_CPUID = 10;     // Intel VMX
#endif
        if (exit_reason != VMEXIT_CPUID)
        {
            if (++poll_counter >= 4)
            {
                poll_counter = 0;
                network::process_pending();
            }
        }
    }

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
    const std::uint64_t reserved_one,
#else
    const std::uint8_t* const get_vmcb_gadget,
#endif
    // [BOOT CONFIG] Target NIC bus number from UEFI boot config
    // byte 0 = bus number, byte 1 = set flag (1 if configured)
    const std::uint64_t packed_nic_config)
{
#ifdef _INTELMACHINE
    (void)reserved_one;
#else
    arch::parse_vmcb_gadget(get_vmcb_gadget);
#endif

    // Unpack target bus from UEFI boot config (hvnic.cfg)
    nic::boot_target_bus = static_cast<std::uint8_t>(packed_nic_config & 0xFF);
    nic::boot_target_bus_set = static_cast<std::uint8_t>((packed_nic_config >> 8) & 0xFF);

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