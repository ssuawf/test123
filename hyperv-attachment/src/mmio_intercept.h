#pragma once
#include <cstdint>

#include "arch/arch.h"
#include "memory_manager/memory_manager.h"
#include "memory_manager/heap_manager.h"
#include "structures/virtual_address.h"
#include "slat/slat_def.h"
#include "slat/cr3/cr3.h"
#include "slat/cr3/pte.h"
#include "network/nic.h"
#include "crt/crt.h"

// ============================================================================
// [핵심] MMIO Intercept — Shadow Page Swap 방식으로 TXQ1 보호
// ============================================================================
//
// [배경] 기존 문제: HV가 TX Q1(0xE040-0xE07F)을 전용 사용하는데,
//        OS/AC가 NIC 레지스터를 스캔하면 Q1이 active인 게 보임
//        → "숨겨진 TX 큐가 있다" = DMA 해킹 탐지
//
// [해결] NPT(Nested Page Table)에서 BAR0+0xE000 페이지를 보호:
//        - Q1 write → advance_guest_rip()으로 건너뜀 (HW 안 건드림)
//        - Q1 read  → Shadow page(Q1=0)에서 읽게 함
//        - Q0/Q2/Q3 → 실제 HW에 정상 pass-through
//
// [왜 Shadow Page Swap?]
//   VMCB save_state에 RAX만 저장됨 → RCX/RDX 등 GPR 접근 불가
//   → instruction decode + GPR 에뮬레이션 불가능
//   → PTE.PFN 교체로 해결 (GPR 안 건드려도 됨!)
//
// [데이터 흐름]
//
//   AC writes TXDCTL1=0 → NPF → advance_rip → skip (1 VMEXIT)
//   AC reads TXDCTL1    → NPF → PFN→shadow → guest reads 0 → restore (2 VMEXIT)
//   OS writes TDT0      → NPF → PFN→real   → guest writes HW → restore (2 VMEXIT)
//
//   결과: AC 입장에서 Q1 = disabled/미사용 ✅
//         실제 HW: Q1 = ENABLE, 우리 큐 정상 ✅
//
// [성능]
//   Q1 접근 (AC 프로빙): 드물어서 무시
//   Q0 TDT write (OS 패킷): 2 VMEXIT/write ≈ 4μs
//   5000 pkt/s 기준: 20ms/sec = 2% CPU overhead (허용 범위)
//
// [의존성]
//   arch::get_vmcb(), arch::advance_guest_rip() — VMCB 접근 (기존 API)
//   slat::get_pte(), slat::hyperv_cr3()         — NPT PTE 조작
//   heap_manager::allocate_page()               — Shadow page 할당
//   nic::va_to_gpa()                            — VA→GPA 변환
//   crt::set_memory()                           — 메모리 초기화
// ============================================================================

namespace mmio_intercept
{
    // ========================================================================
    // [상태 변수]
    // ========================================================================

    // 보호할 MMIO 페이지 GPA (= BAR0 + 0xE000)
    // IGC TX Queue 레지스터: Q0(+0x00), Q1(+0x40), Q2(+0x80), Q3(+0xC0)
    inline std::uint64_t protected_page_gpa = 0;

    // 실제 MMIO 페이지의 원본 PFN (NPT PTE에서 저장, 복원용)
    inline std::uint64_t real_mmio_pfn = 0;

    // Shadow page: heap에서 할당, Q1 영역만 0으로 유지
    inline std::uint64_t shadow_page_gpa = 0;
    inline void*         shadow_page_va  = nullptr;

    // 활성화 여부
    inline std::uint8_t is_active = 0;

    // TXQ1 offset 범위 (page 내 offset)
    // Q1: TDBAL1=0x40, TDBAH1=0x44, TDLEN1=0x48, TDH1=0x50, TDT1=0x58, TXDCTL1=0x68
    constexpr std::uint32_t TXQ1_START = 0x40;
    constexpr std::uint32_t TXQ1_END   = 0x80;

    // ========================================================================
    // [상태 머신]
    // ========================================================================
    // IDLE:     페이지 보호 중 (NPT present=0) → 모든 접근에 NPF 발생
    // STEPPING: 페이지 일시 노출 (present=1)   → guest 명령어 실행 중
    //           다음 VMEXIT에서 자동 복원 → IDLE
    //
    // [주의] STEPPING에서 1개 이상 명령어 실행될 수 있음
    //        BUT: MMIO 접근은 uncached라 매우 느림 → 실질적으로 1개만 실행
    //        그리고 노출된 페이지가 real/shadow이므로 추가 실행 안전
    // ========================================================================
    enum class state_t : std::uint8_t
    {
        IDLE = 0,
        STEPPING = 1
    };

    inline state_t current_state = state_t::IDLE;

    // ========================================================================
    // [진단 카운터] — CPUID probe로 조회 (leaf 0x485652D0-D7)
    // ========================================================================
    inline volatile std::uint32_t dbg_q1_write_dropped = 0;   // Q1 write 드롭
    inline volatile std::uint32_t dbg_q1_read_shadowed = 0;   // Q1 read → shadow
    inline volatile std::uint32_t dbg_passthrough = 0;         // non-Q1 pass-through
    inline volatile std::uint32_t dbg_step_restore = 0;        // STEPPING→IDLE 복원
    inline volatile std::uint32_t dbg_last_offset = 0;         // 마지막 NPF offset
    inline volatile std::uint8_t  dbg_last_was_write = 0;
    inline volatile std::uint8_t  dbg_last_was_q1 = 0;
    inline volatile std::uint32_t dbg_setup_result = 0;        // set_up 결과 코드

    // ========================================================================
    // [NPT PTE 조작]
    // ========================================================================

    // 캐시된 PTE 포인터 (매 VMEXIT마다 page walk 안 하게)
    inline slat_pte* cached_pte = nullptr;

    inline slat_pte* get_mmio_pte()
    {
        if (cached_pte)
            return cached_pte;

        virtual_address_t va = { .flags = protected_page_gpa };
        cached_pte = slat::get_pte(slat::hyperv_cr3(), va, 1);
        return cached_pte;
    }

    // present=0: 모든 guest 접근에 NPF
    inline void protect_page()
    {
        slat_pte* pte = get_mmio_pte();
        if (!pte) return;

        pte->present = 0;

        // [핵심] TLB flush — NPT 변경사항을 즉시 반영
        // flush 안 하면 TLB에 캐시된 이전 매핑으로 접근될 수 있음
        vmcb_t* vmcb = arch::get_vmcb();
        vmcb->control.tlb_control = tlb_control_t::flush_guest_tlb_entries;
    }

    // present=1 + 지정 PFN: guest가 해당 물리 페이지에 접근 가능
    inline void unprotect_page_with_pfn(std::uint64_t pfn)
    {
        slat_pte* pte = get_mmio_pte();
        if (!pte) return;

        pte->page_frame_number = pfn;
        pte->present = 1;
        pte->write = 1;

        vmcb_t* vmcb = arch::get_vmcb();
        vmcb->control.tlb_control = tlb_control_t::flush_guest_tlb_entries;
    }

    // ========================================================================
    // [Shadow Page 갱신]
    // ========================================================================
    // Q1 read NPF 발생 시에만 호출 → 성능 영향 최소 (AC 프로빙은 드물게)
    // real MMIO 전체 복사 후 Q1(0x40-0x7F) 영역만 0으로 덮음
    // ========================================================================

    inline void refresh_shadow_page()
    {
        if (!shadow_page_va || !nic::state.mmio_base_gpa)
            return;

        // real MMIO 페이지를 host VA로 매핑 (HV 접근은 NPT 보호 안 받음)
        void* real_mmio_va = memory_manager::map_host_physical(protected_page_gpa);
        if (!real_mmio_va)
            return;

        auto* shadow = static_cast<std::uint32_t*>(shadow_page_va);
        auto* real   = static_cast<volatile std::uint32_t*>(real_mmio_va);

        // Q0 (0x00-0x3F): 실제 값 복사 — OS 드라이버가 읽어도 정상
        for (std::uint32_t i = 0; i < 16; i++)
            shadow[i] = real[i];

        // Q1 (0x40-0x7F): 전부 0! — AC에게 "Q1 미사용" 보여줌
        for (std::uint32_t i = 16; i < 32; i++)
            shadow[i] = 0;

        // Q2 (0x80-0xBF): 실제 값 복사
        for (std::uint32_t i = 32; i < 48; i++)
            shadow[i] = real[i];

        // Q3 (0xC0-0xFF): 실제 값 복사
        for (std::uint32_t i = 48; i < 64; i++)
            shadow[i] = real[i];

        // 0x100-0xFFF: 나머지 영역 (TX stat 등) — 실제 값 복사
        // 256 bytes(=64 DWORDs) 이후 영역. 페이지 전체 1024 DWORDs
        for (std::uint32_t i = 64; i < 1024; i++)
            shadow[i] = real[i];
    }

    // ========================================================================
    // [핵심] NPF 핸들러 — VMEXIT에서 호출
    // ========================================================================
    //
    // 반환값: 1 = handled (premature return 해야 함)
    //         0 = 우리 페이지 아님 (다른 handler로 전달)
    //
    // 호출 위치: vmexit_handler_detour() → is_slat_violation 체크 시
    // ========================================================================

    inline std::uint8_t handle_npf()
    {
        if (!is_active)
            return 0;

        // ---- VMCB에서 NPF 정보 추출 ----
        vmcb_t* vmcb = arch::get_vmcb();

        const npf_exit_info_1 info1 = { .flags = vmcb->control.first_exit_info };
        const std::uint64_t faulting_gpa = vmcb->control.second_exit_info;

        // ---- 우리 페이지인지 확인 ----
        const std::uint64_t page_gpa = faulting_gpa & ~0xFFFull;
        if (page_gpa != protected_page_gpa)
            return 0;

        // Page 내 offset (0x000 ~ 0xFFF)
        const std::uint32_t offset =
            static_cast<std::uint32_t>(faulting_gpa & 0xFFF);

        const bool is_write = (info1.write_access == 1);
        const bool is_q1 = (offset >= TXQ1_START && offset < TXQ1_END);

        // 진단
        dbg_last_offset = offset;
        dbg_last_was_write = is_write ? 1 : 0;
        dbg_last_was_q1 = is_q1 ? 1 : 0;

        // ================================================================
        // CASE 1: Q1 + Write → 드롭! (1 VMEXIT, 가장 빠름)
        // ================================================================
        //
        // [원리] advance_guest_rip()로 명령어 건너뜀
        //        NRIP_SAVE 활성 → vmcb->control.next_rip 사용 → 정확
        //
        // 예: guest "mov [rax+0xE068], ecx" 실행 시도
        //     → NPF → advance_rip → 다음 명령어로 점프
        //     → ecx 값은 HW에 안 써짐
        //     → AC가 read-back하면 shadow에서 0 반환
        //
        // [GPR 영향] 없음! write 명령어의 source GPR 안 건드림
        //            그냥 실행 안 하고 skip할 뿐
        // ================================================================
        if (is_q1 && is_write)
        {
            arch::advance_guest_rip();
            dbg_q1_write_dropped++;
            return 1;
        }

        // ================================================================
        // CASE 2: Q1 + Read → Shadow page 노출 (2 VMEXIT)
        // ================================================================
        //
        // [원리] PFN을 shadow page로 교체 → present=1
        //        → VMRESUME → guest가 shadow에서 Q1=0 읽음
        //        → 다음 VMEXIT → check_and_restore()에서 present=0 복원
        //
        // [왜 pass-through 안 하고 shadow?]
        //   pass-through하면 실제 HW 값(ENABLE 등)이 보임
        //   shadow에서 읽으면 0 → "Q1 미사용" ✅
        // ================================================================
        if (is_q1 && !is_write)
        {
            refresh_shadow_page();

            std::uint64_t shadow_pfn = shadow_page_gpa >> 12;
            unprotect_page_with_pfn(shadow_pfn);

            current_state = state_t::STEPPING;
            dbg_q1_read_shadowed++;
            return 1;
        }

        // ================================================================
        // CASE 3: Non-Q1 → Real MMIO pass-through (2 VMEXIT)
        // ================================================================
        //
        // [원리] PFN을 원래 MMIO PFN으로 설정 → present=1
        //        → VMRESUME → guest가 실제 HW 접근 (정상)
        //        → 다음 VMEXIT → check_and_restore()에서 present=0 복원
        //
        // OS가 TDT0 write → 여기 → 실제 HW에 쓰임 → 패킷 전송 정상 ✅
        // OS가 RDH0 read  → 여기 → 실제 HW에서 읽힘 → 수신 정상 ✅
        // ================================================================
        unprotect_page_with_pfn(real_mmio_pfn);

        current_state = state_t::STEPPING;
        dbg_passthrough++;
        return 1;
    }

    // ========================================================================
    // [핵심] STEPPING 복원 — 매 VMEXIT 초반에 호출
    // ========================================================================
    //
    // handle_npf()가 페이지를 일시 노출한 후, 다음 VMEXIT에서 복원해야 함
    // 이 VMEXIT는 NPF가 아닐 수 있음 (CPUID, NMI 등) → 별도 체크 필요
    //
    // 호출 위치: vmexit_handler_detour() 최상단, exit_reason 체크 전
    //
    // 반환값: 0 항상 (이건 premature return 안 함 — VMEXIT 처리 계속)
    //         복원만 하고 나머지 handler는 정상 진행
    // ========================================================================

    inline std::uint8_t check_and_restore()
    {
        if (!is_active || current_state != state_t::STEPPING)
            return 0;

        protect_page();
        current_state = state_t::IDLE;
        dbg_step_restore++;
        return 0;  // VMEXIT 처리 계속 진행 (premature return 아님)
    }

    // ========================================================================
    // [초기화] — network::set_up() 이후 호출
    // ========================================================================
    //
    // 순서:
    //   1. IGC NIC 확인
    //   2. Shadow page 할당 (heap 4KB)
    //   3. NPT PTE 찾기 + 원본 PFN 저장
    //   4. 2MB large page → 4KB split (필요 시)
    //   5. PTE present=0 설정 → 보호 시작
    //
    // [주의] BAR0가 확정된 후에만 호출 (network::set_up 완료 후)
    //        heap이 초기화된 후에만 호출 (heap_manager::set_up 완료 후)
    // ========================================================================

    inline std::uint8_t set_up()
    {
        // IGC NIC만 지원 (I225-V, I226-V)
        if (nic::state.nic_type != nic::nic_type_t::INTEL ||
            nic::state.intel_gen != nic::intel_gen_t::IGC)
        {
            is_active = 0;
            dbg_setup_result = 1;  // not IGC
            return 0;
        }

        if (nic::state.mmio_base_gpa == 0)
        {
            is_active = 0;
            dbg_setup_result = 2;  // no BAR0
            return 0;
        }

        // 보호할 페이지 GPA = BAR0 + 0xE000 (TX queue register page)
        protected_page_gpa = nic::state.mmio_base_gpa + 0xE000;

        // ---- Shadow page 할당 ----
        shadow_page_va = heap_manager::allocate_page();
        if (!shadow_page_va)
        {
            is_active = 0;
            dbg_setup_result = 3;  // heap alloc fail
            return 0;
        }

        // Shadow page GPA 계산
        if (!nic::heap_va_pa_valid)
        {
            is_active = 0;
            dbg_setup_result = 4;  // VA→PA not ready
            return 0;
        }
        shadow_page_gpa = nic::va_to_gpa(shadow_page_va);

        // Shadow page 초기화 (전부 0)
        crt::set_memory(shadow_page_va, 0, 4096);

        // ---- NPT PTE 찾기 ----
        // force_split=1: 2MB large page면 4KB로 자동 분할
        virtual_address_t va = { .flags = protected_page_gpa };
        std::uint8_t split_state = 0;
        slat_pte* pte = slat::get_pte(
            slat::hyperv_cr3(), va, 1, &split_state);

        if (!pte)
        {
            is_active = 0;
            dbg_setup_result = 5;  // PTE not found
            return 0;
        }

        // 원본 PFN 저장 (real MMIO pass-through 복원용)
        real_mmio_pfn = pte->page_frame_number;
        cached_pte = pte;

        // ---- 보호 시작: present=0 ----
        pte->present = 0;

        // TLB flush + VMCB clean bit 클리어
        vmcb_t* vmcb = arch::get_vmcb();
        vmcb->control.tlb_control = tlb_control_t::flush_guest_tlb_entries;
        vmcb->control.clean.nested_paging = 0;

        current_state = state_t::IDLE;
        is_active = 1;
        dbg_setup_result = 0xFF;  // success

        return 1;
    }

} // namespace mmio_intercept
