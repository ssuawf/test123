// ============================================================================
// main.cpp 통합 패치 — mmio_intercept.h
// ============================================================================
//
// [적용 방법] 이 파일은 직접 컴파일하는 게 아님!
//             test123-main/hyperv-attachment/src/main.cpp 에 아래 변경사항 적용
//
// [파일 배치]
//   mmio_intercept_final.h → hyperv-attachment/src/mmio_intercept.h
//
// ============================================================================


// ============================================================================
// [패치 1] Include 추가
// ============================================================================
// 위치: main.cpp 상단, 기존 #include 블록 끝
// 대상 라인: #include "network/nic.h" 다음
// ============================================================================

// --- 기존 ---
#include "dma/dma_handler.h"
#include "network/network.h"
#include "network/nic.h"
// --- 추가 ---
#include "mmio_intercept.h"   // TXQ1 shadow page swap protection


// ============================================================================
// [패치 2] process_first_vmexit() — set_up() 호출 추가
// ============================================================================
// 위치: main.cpp line ~84, network::set_up() 다음
// 이유: BAR0 확정 후 + heap 초기화 후에만 호출 가능
// ============================================================================

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
        mmio_intercept::set_up();   // ← 추가! network 후에 호출

        is_first_vmexit = 0;
    }

    // ... 나머지 동일 ...
}


// ============================================================================
// [패치 3] CPUID Probe — MMIO 진단 leaves 추가
// ============================================================================
// 위치: handle_cpuid_probe() switch문 안, case 0xFA 다음
// Leaf 범위: 0x485652D0 ~ 0x485652D7 (sub = 0xD0 ~ 0xD7)
// ============================================================================

    // ... 기존 case 0xFA ...
    case 0xFA: // thpds_hi(lo16) | v9_mode(hi16)
        result = (network::dbg_hp_thpds_hi & 0xFFFF);
        result |= ((network::dbg_tx_inject_count & 0xFFFF) << 16);
        break;

    // ================================================================
    // [MMIO Intercept] 진단 CPUID leaves (0xD0-0xD7)
    // ================================================================
    //
    // hv_diag에서 조회:
    //   __cpuid(buf, 0x485652D0) → buf[0] = is_active | setup_result
    //   __cpuid(buf, 0x485652D1) → buf[0] = q1_write_dropped
    //   __cpuid(buf, 0x485652D2) → buf[0] = q1_read_shadowed
    //   __cpuid(buf, 0x485652D3) → buf[0] = passthrough
    //   __cpuid(buf, 0x485652D4) → buf[0] = step_restore
    //   __cpuid(buf, 0x485652D5) → buf[0] = last_offset | flags
    //   __cpuid(buf, 0x485652D6) → buf[0] = protected_page_gpa low
    //   __cpuid(buf, 0x485652D7) → buf[0] = protected_page_gpa high
    // ================================================================

    case 0xD0: // is_active(bit0) | state(bit1) | setup_result(byte1)
        result = static_cast<std::uint32_t>(mmio_intercept::is_active);
        result |= (static_cast<std::uint32_t>(mmio_intercept::current_state) << 1);
        result |= (static_cast<std::uint32_t>(mmio_intercept::dbg_setup_result) << 8);
        break;

    case 0xD1: // q1_write_dropped (AC가 Q1에 write 시도한 횟수)
        result = mmio_intercept::dbg_q1_write_dropped;
        break;

    case 0xD2: // q1_read_shadowed (AC가 Q1에서 read한 횟수)
        result = mmio_intercept::dbg_q1_read_shadowed;
        break;

    case 0xD3: // passthrough (non-Q1 정상 pass-through 횟수)
        result = mmio_intercept::dbg_passthrough;
        break;

    case 0xD4: // step_restore (STEPPING→IDLE 복원 횟수)
        result = mmio_intercept::dbg_step_restore;
        break;

    case 0xD5: // last_offset(lo16) | last_was_write(bit16) | last_was_q1(bit17)
        result = (mmio_intercept::dbg_last_offset & 0xFFFF);
        result |= (static_cast<std::uint32_t>(mmio_intercept::dbg_last_was_write) << 16);
        result |= (static_cast<std::uint32_t>(mmio_intercept::dbg_last_was_q1) << 17);
        break;

    case 0xD6: // protected_page_gpa low 32bit
        result = static_cast<std::uint32_t>(mmio_intercept::protected_page_gpa);
        break;

    case 0xD7: // protected_page_gpa high 32bit
        result = static_cast<std::uint32_t>(mmio_intercept::protected_page_gpa >> 32);
        break;

    // ---- switch 끝 ----
    }

    vmcb->save_state.rax = static_cast<std::uint64_t>(result);
    arch::advance_guest_rip();
    return 1;


// ============================================================================
// [패치 4] vmexit_handler_detour() — MMIO 핸들러 통합
// ============================================================================
// 위치: main.cpp line ~700
//
// [변경 사항]
//   1. 함수 최상단: mmio_intercept::check_and_restore() 호출
//      → STEPPING 상태면 페이지 다시 보호 (어떤 VMEXIT이든)
//
//   2. SLAT violation 처리: mmio_intercept::handle_npf() 먼저 시도
//      → 우리 MMIO 페이지면 처리 후 premature return
//      → 아니면 기존 slat::violation::process()로 전달
// ============================================================================

std::uint64_t vmexit_handler_detour(
    const std::uint64_t a1, const std::uint64_t a2,
    const std::uint64_t a3, const std::uint64_t a4)
{
    process_first_vmexit();
    vmexit_total_count++;

    // ================================================================
    // [추가] MMIO intercept: STEPPING 상태 복원
    // ================================================================
    // 이전 VMEXIT에서 MMIO 페이지를 일시 노출했으면,
    // 이번 VMEXIT에서 다시 보호 (present=0)
    //
    // [중요] 이건 exit_reason 체크 전에 해야 함!
    //        STEPPING 중 발생한 VMEXIT가 NPF가 아닐 수 있으므로
    //        (예: timer interrupt, CPUID 등)
    //
    // check_and_restore()는 항상 0 반환 → VMEXIT 처리 계속
    // ================================================================
    mmio_intercept::check_and_restore();

    const std::uint64_t exit_reason = arch::get_vmexit_reason();

    // CPUID probe
    if (arch::is_cpuid(exit_reason) == 1)
    {
        if (handle_cpuid_probe() == 1)
            return do_vmexit_premature_return();
    }

    // ================================================================
    // [변경] SLAT violation: MMIO intercept 먼저 시도
    // ================================================================
    //
    // 순서:
    //   1. mmio_intercept::handle_npf() — 우리 MMIO 페이지면 처리
    //   2. 아니면 slat::violation::process() — 기존 hook 처리
    //
    // [중요] handle_npf()가 1 반환하면 premature return
    //        handle_npf()가 0이면 우리 페이지 아님 → 기존 handler로
    // ================================================================
    if (arch::is_slat_violation(exit_reason) == 1)
    {
        // MMIO intercept 먼저
        if (mmio_intercept::handle_npf() == 1)
            return do_vmexit_premature_return();

        // 기존 SLAT violation handler (hook 등)
        if (slat::violation::process() == 1)
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
// [패치 5] hv_diag.cpp — 진단 출력 추가 (선택사항)
// ============================================================================
// hv_diag.exe에서 MMIO intercept 상태를 확인하는 코드
//
// 기존 hv_diag.cpp에 추가하면 됨
// ============================================================================

/*
    // === MMIO Intercept ===
    int mmio[4];
    
    __cpuid(mmio, 0x485652D0);
    printf("\n=== MMIO Intercept ===\n");
    printf("  active:       %d\n", mmio[0] & 1);
    printf("  state:        %s\n", (mmio[0] >> 1) & 1 ? "STEPPING" : "IDLE");
    printf("  setup_result: 0x%02X\n", (mmio[0] >> 8) & 0xFF);
    
    __cpuid(mmio, 0x485652D1);
    printf("  q1_write_dropped:  %u\n", (unsigned)mmio[0]);
    
    __cpuid(mmio, 0x485652D2);
    printf("  q1_read_shadowed:  %u\n", (unsigned)mmio[0]);
    
    __cpuid(mmio, 0x485652D3);
    printf("  passthrough:       %u\n", (unsigned)mmio[0]);
    
    __cpuid(mmio, 0x485652D4);
    printf("  step_restore:      %u\n", (unsigned)mmio[0]);
    
    __cpuid(mmio, 0x485652D5);
    uint32_t d5 = (uint32_t)mmio[0];
    printf("  last_offset:       0x%03X\n", d5 & 0xFFFF);
    printf("  last_was_write:    %d\n", (d5 >> 16) & 1);
    printf("  last_was_q1:       %d\n", (d5 >> 17) & 1);
    
    __cpuid(mmio, 0x485652D6);
    uint32_t gpa_lo = (uint32_t)mmio[0];
    __cpuid(mmio, 0x485652D7);
    uint32_t gpa_hi = (uint32_t)mmio[0];
    printf("  protected_gpa:     0x%08X%08X\n", gpa_hi, gpa_lo);
    
    // [경고] q1_write_dropped > 0 이면 AC가 Q1 disable 시도한 것
    if (q1_write > 0)
        printf("  *** WARNING: AC attempted %u Q1 writes (all dropped) ***\n", q1_write);
*/
