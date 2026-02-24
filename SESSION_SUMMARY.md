# MMIO Intercept v2 — Shadow Page Swap 방식 TXQ1 보호
# 작성일: 2026-02-24
# 프로젝트: hyper-reV (test123-main)

## 1. 프로젝트 개요

AMD SVM 기반 parasitic hypervisor. Microsoft Hyper-V에 기생하여 HVCI 환경에서 탐지 우회.
NIC(Intel I225-V/I226-V)를 직접 제어하여 DMA 없이 네트워크 통신 수행.

**핵심 문제**: HV가 TX Queue 1(TXQ1)을 전용 사용하는데, OS/안티치트가 NIC 레지스터를 스캔하면
TXQ1이 active인 게 보임 → "숨겨진 TX 큐" = DMA 해킹 탐지

**해결**: NPT(Nested Page Table)에서 BAR0+0xE000 페이지를 인터셉트하여
- Q1 write → skip (HW에 안 도달)
- Q1 read → shadow page에서 0 반환
- Q0/Q2/Q3 → 실제 HW pass-through

---

## 2. 아키텍처 결정 이력

### v1: Instruction Decode + GPR 에뮬레이션 (폐기!)
NPF → 명령어 디코드 → source/dest 레지스터 읽기/쓰기
**문제**: VMCB save_state에 RAX/RSP/RIP/CR3만 저장됨!
```
struct vmcb_state_save_t {
    uint8_t  pad[0x150];
    uint64_t cr3;       // 0x150
    uint8_t  pad[0x20];
    uint64_t rip;       // 0x170
    uint8_t  pad[0x58];
    uint64_t rsp;       // 0x1D8
    uint8_t  pad[0x18];
    uint64_t rax;       // 0x1F8
};
```
RCX, RDX, RBX, R8-R15 접근 불가 → `mov [rax+0xE068], ecx` 에뮬 불가능

### v2: Shadow Page Swap (현재 구현)
NPF → NPT PTE.page_frame_number 교체 → guest가 자연스럽게 shadow/real 페이지 접근
GPR 접근 전혀 불필요! PFN만 바꾸면 됨.

---

## 3. 동작 원리 (State Machine)

```
상태: IDLE / STEPPING

[IDLE] (protected_page present=0)
   │
   ├─ Q1 + Write → advance_guest_rip() → IDLE (1 VMEXIT)
   │
   ├─ Q1 + Read  → refresh shadow → PFN=shadow → present=1 → STEPPING (2 VMEXIT)
   │
   └─ Non-Q1     → PFN=real_mmio → present=1 → STEPPING (2 VMEXIT)
         │
         └─ [STEPPING] → 다음 아무 VMEXIT → check_and_restore() → present=0 → IDLE
```

### Shadow Page 구조 (4KB)
```
Offset 0x000-0x03F: Q0 레지스터 → 실제 MMIO에서 복사 (OS 정상 사용)
Offset 0x040-0x07F: Q1 레지스터 → 전부 0 (AC에게 "미사용" 보여줌) ★핵심★
Offset 0x080-0x0BF: Q2 레지스터 → 실제 MMIO에서 복사
Offset 0x0C0-0x0FF: Q3 레지스터 → 실제 MMIO에서 복사
Offset 0x100-0xFFF: 나머지       → 실제 MMIO에서 복사
```

### 성능
- Q1 write: 1 VMEXIT (~2μs) — AC 프로빙, 드묾
- Q1 read:  2 VMEXIT (~4μs) — AC 프로빙, 드묾
- Q0 TDT write: 2 VMEXIT (~4μs) — 패킷 전송마다 발생
- 5000 pkt/s 기준: 20ms/sec = 2% CPU overhead

---

## 4. 프로젝트 구조 & API 레퍼런스

### 파일 트리
```
test123-main/hyperv-attachment/src/
├── main.cpp                    ← VMEXIT handler, CPUID probe, entry point
├── mmio_intercept.h            ← ★NEW★ Shadow Page Swap 구현
├── arch_config.h
├── arch/
│   ├── amd_def.h               ← vmcb_t, npf_exit_info_1, tlb_control_t
│   ├── arch.cpp                ← get_vmcb(), advance_guest_rip() 등
│   └── arch.h
├── crt/
│   ├── crt.cpp                 ← set_memory() 구현
│   └── crt.h
├── dma/
│   ├── dma_handler.cpp         ← ReadScatter/WriteScatter 처리
│   ├── dma_handler.h
│   └── dma_protocol.h          ← magic=0x48564430("HVD0"), cmd7/9/11/13/15
├── interrupts/
│   ├── interrupts.cpp
│   └── interrupts.h
├── memory_manager/
│   ├── heap_manager.cpp
│   ├── heap_manager.h          ← allocate_page(), free_page()
│   ├── memory_manager.cpp
│   └── memory_manager.h        ← map_host_physical(), map_guest_physical()
├── network/
│   ├── network.cpp             ← process_pending(), set_up(), TX/RX 로직
│   ├── network.h
│   ├── nic.h                   ← NIC 상태, BAR0, va_to_gpa(), 레지스터 정의
│   ├── packet.h
│   └── ip_frag.h
├── slat/
│   ├── slat.cpp
│   ├── slat.h
│   ├── slat_def.h              ← slat_pte = pte_64 (AMD), ept_pte (Intel)
│   ├── cr3/
│   │   ├── cr3.h               ← hyperv_cr3(), hook_cr3()
│   │   ├── cr3.cpp
│   │   ├── pte.h               ← get_pte(cr3, va, force_split, split_state)
│   │   ├── pte.cpp             ← PDE/PTE walk, 2MB→4KB split
│   │   └── deep_copy.h/cpp
│   ├── hook/                   ← SLAT hook 관리
│   └── violation/              ← SLAT violation handler
└── structures/
    └── virtual_address.h       ← virtual_address_t (.address 필드!)
```

### 핵심 구조체

```cpp
// ---- VMCB (arch/amd_def.h) ----
struct vmcb_t {
    vmcb_control_area_t control;  // TLB control, exit info, clean bits, next_rip
    vmcb_state_save_t save_state; // RAX, RSP, RIP, CR3 만!
};

// control 주요 필드:
//   .tlb_control          — flush_guest_tlb_entries (NPT 변경 후 필수)
//   .first_exit_info      — npf_exit_info_1 (write_access bit 등)
//   .second_exit_info     — faulting GPA (NPF 대상 주소)
//   .next_rip             — NRIP_SAVE (advance_guest_rip용)
//   .clean.nested_paging  — 0으로 설정 시 NPT 재로드

// ---- NPF Exit Info (arch/amd_def.h) ----
union npf_exit_info_1 {
    uint64_t flags;
    struct {
        uint64_t present : 1;       // 페이지가 present였는지
        uint64_t write_access : 1;  // ★ write=1, read=0 ★
        uint64_t user_access : 1;
        // ... 나머지 비트들
    };
};

// ---- Virtual Address (structures/virtual_address.h) ----
union virtual_address_t {
    uint64_t address;  // ★ .address 필드! (.flags 아님!) ★
    struct {
        uint64_t offset : 12;
        uint64_t pt_idx : 9;
        uint64_t pd_idx : 9;
        uint64_t pdpt_idx : 9;
        uint64_t pml4_idx : 9;
        uint64_t reserved : 16;
    };
};

// ---- SLAT PTE (slat/slat_def.h → ia32-doc pte_64) ----
// AMD: slat_pte = pte_64
// 주요 필드:
//   .present             — 0이면 NPF 발생
//   .write               — write 권한
//   .page_frame_number   — ★ 물리 페이지 PFN (이걸 swap!) ★
```

### 핵심 API

```cpp
// ---- arch (arch.h / arch.cpp) ----
vmcb_t*     arch::get_vmcb();              // 현재 VCPU의 VMCB 포인터
void        arch::advance_guest_rip();      // next_rip(NRIP_SAVE) 사용, RIP 전진
uint64_t    arch::get_vmexit_reason();      // VMEXIT reason code
uint8_t     arch::is_slat_violation(r);     // r == SVM_EXIT_REASON_NPF (0x400)
uint8_t     arch::is_cpuid(r);             // r == 0x72

// ---- slat (slat/cr3/) ----
cr3         slat::hyperv_cr3();            // Hyper-V의 NPT CR3
slat_pte*   slat::get_pte(cr3, va, force_split=0, split_state=nullptr);
//           force_split=1: 2MB large page → 4KB split 자동 수행
uint8_t     slat::split_2mb_pde(large_pde); // 수동 split

// ---- memory (memory_manager/) ----
void*       memory_manager::map_host_physical(uint64_t pa);  // PA→VA 매핑
void*       heap_manager::allocate_page();                    // 4KB 페이지 할당
void        heap_manager::free_page(void*);

// ---- nic (network/nic.h) ----
uint64_t    nic::va_to_gpa(const void* va);  // heap VA → GPA 변환
//           내부: VA - heap_va_to_pa_offset
//           heap_va_pa_valid == 1 이어야 사용 가능

// ---- crt (crt/crt.h) ----
void        crt::set_memory(void* dst, uint8_t val, uint64_t size);
```

---

## 5. main.cpp 통합 지점

### 5.1 Include
```cpp
#include "mmio_intercept.h"  // network/nic.h 다음에 추가
```

### 5.2 초기화 (process_first_vmexit, line ~84)
```cpp
dma::set_up();
network::set_up();
mmio_intercept::set_up();  // ← network 후! BAR0 확정 필요
```

### 5.3 VMEXIT handler (vmexit_handler_detour, line ~700)
```cpp
// 1) 함수 최상단에 check_and_restore 추가 (STEPPING 복원)
mmio_intercept::check_and_restore();

// 2) SLAT violation 처리 순서 변경
if (arch::is_slat_violation(exit_reason) == 1)
{
    if (mmio_intercept::handle_npf() == 1)     // MMIO 먼저!
        return do_vmexit_premature_return();
    if (slat::violation::process() == 1)        // 기존 hook
        return do_vmexit_premature_return();
}
```

### 5.4 CPUID Probe (handle_cpuid_probe switch문, case 0xFA 다음)
```
Leaf 0x485652D0: is_active | state | setup_result
Leaf 0x485652D1: q1_write_dropped
Leaf 0x485652D2: q1_read_shadowed
Leaf 0x485652D3: passthrough count
Leaf 0x485652D4: step_restore count
Leaf 0x485652D5: last_offset | last_was_write | last_was_q1
Leaf 0x485652D6: protected_page_gpa low32
Leaf 0x485652D7: protected_page_gpa high32
```

---

## 6. 파일 목록

| 파일 | 설명 |
|------|------|
| `mmio_intercept.h` | ★핵심★ Shadow Page Swap 전체 구현. src/에 배치 |
| `main_mmio_patch.cpp` | main.cpp 통합 패치 (삽입 위치 + CPUID + hv_diag 코드) |
| `SESSION_SUMMARY.md` | 이 문서 |

---

## 7. 컴파일 전 확인사항

1. **virtual_address_t**: `.address` 필드 사용 (`.flags` 아님!)
2. **slat::get_pte() 4번째 인자**: `std::uint8_t* paging_split_state` — 선택적
3. **nic::heap_va_pa_valid**: entry_point()에서 설정됨 (main.cpp line ~784)
4. **map_host_physical()**: GPA → host VA 매핑. HV 코드에서 접근 시 NPT 보호 안 받음
5. **tlb_control**: NPT PTE 변경 후 반드시 `flush_guest_tlb_entries` 설정!
6. **clean.nested_paging = 0**: set_up()에서만 필요 (첫 PTE 변경 시)

---

## 8. 검증 순서

1. 빌드 후 로드
2. `hv_diag.exe` 실행
3. CPUID 0x485652D0 → `setup_result = 0xFF` = 성공
4. CPUID 0x485652D6/D7 → `protected_gpa = BAR0 + 0xE000`
5. AC 프로빙 시뮬 후:
   - 0xD1: `q1_write_dropped > 0` = Q1 write 차단됨 ✅
   - 0xD2: `q1_read_shadowed > 0` = Q1 read에 0 반환됨 ✅
6. 패킷 전송 확인: `packets_sent` 증가 중 ✅
7. CPUID 0xD4: `step_restore` = `q1_read_shadowed + passthrough` ✅

---

## 9. setup_result 에러 코드

| 코드 | 의미 |
|------|------|
| 0xFF | 성공 |
| 0x01 | IGC NIC 아님 (Intel I225/I226만 지원) |
| 0x02 | BAR0 없음 (network::set_up 안 됨) |
| 0x03 | heap 할당 실패 (shadow page) |
| 0x04 | VA→PA offset 미초기화 |
| 0x05 | NPT PTE 못 찾음 |

---

## 10. 알려진 제한사항 & TODO

- **STEPPING 중 다수 명령어 실행 가능**: MMIO uncached라 1개만 실행될 확률 높지만 보장 안됨
  → 개선: RFLAGS.TF single-step 사용 (미구현)
- **4KB split 영구**: set_up()에서 2MB→4KB split 후 복원 안 함
  → 개선: unload 시 merge_4kb_pt() 호출
- **멀티코어**: per-CPU 상태 없음. 현재 단일 VCPU 가정
  → 개선: per-CPU state 배열 또는 spinlock
- **RTL NIC 미지원**: IGC(Intel I225/I226)만. RTL은 TX queue 구조 다름

---

## 11. 이전 세션 참고 (transcripts/)

- `2026-02-24-00-48-32-ept-mmio-shadow-implementation.txt` — v1(instruction decode) 전체 구현
- `2026-02-24-02-29-06-mmio-shadow-page-swap-v2.txt` — v2(shadow page swap) 전환 과정 + 최종 구현
- `journal.txt` — 전체 세션 카탈로그
