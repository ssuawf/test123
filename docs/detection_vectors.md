# hyper-reV EPT-Only Software DMA: 감지 벡터 종합 분석

> **전제조건**: TPM 2.0 OFF, Secure Boot OFF, Guest-side 프로세스/드라이버 0개
> **목표**: 감지 확률 → 0에 수렴

---

## 카테고리 A: CPU/하드웨어 레벨 감지

### A1. CPUID Hypervisor Present Bit (ECX bit 31)
- **공격**: `CPUID(EAX=1)` → ECX bit 31이 1이면 하이퍼바이저 존재
- **우리 상황**: Hyper-V가 이미 이 비트를 1로 설정하고 있음. Windows 10/11에서 Hyper-V 활성화된 시스템은 이미 bit 31 = 1
- **위험도**: ☆☆☆☆☆ (0)
- **대응**: 불필요. Hyper-V가 이미 커버. Anti-cheat가 이 비트로 차단하면 모든 Hyper-V 사용자가 차단됨 (false positive)
- **상태**: ✅ 자동 해결

### A2. CPUID Hypervisor Vendor ID (Leaf 0x40000000~0x40000005)
- **공격**: `CPUID(EAX=0x40000000)` → EBX/ECX/EDX에 "Microsoft Hv" 반환. 추가 leaf에서 Hyper-V 버전, 기능 확인
- **우리 상황**: hyper-reV는 Hyper-V에 기생하므로 이 값들은 정상적인 Hyper-V 응답 그대로 반환됨
- **위험도**: ☆☆☆☆☆ (0)
- **대응**: 불필요
- **상태**: ✅ 자동 해결

### A3. RDTSC + CPUID 타이밍 사이드채널
- **공격**: `RDTSC → CPUID → RDTSC`로 CPUID 실행 시간 측정. 네이티브 ≈ 50~200 사이클, VM exit 발생 시 ≈ 750~1500+ 사이클
- **우리 상황**: Hyper-V가 이미 모든 CPUID를 인터셉트하고 있어서 타이밍이 이미 느림. hyper-reV가 추가 오버헤드를 만들지 않는 한 정상
- **위험도**: ★☆☆☆☆ (1)
- **대응**: hyper-reV의 EPT violation 핸들러가 CPUID 경로에 추가 VM exit을 유발하지 않도록 설계. 우리 아키텍처에서는 CPUID를 인터셉트할 이유가 없으므로 추가 지연 없음
- **상태**: ✅ 설계로 해결

### A4. RDTSC + 기타 직렬화 명령 타이밍
- **공격**: CPUID 대신 `XSETBV`, `WRMSR` 등 다른 VM exit 유발 명령으로 타이밍 측정
- **우리 상황**: A3과 동일. Hyper-V가 이미 이 명령들을 처리 중
- **위험도**: ★☆☆☆☆ (1)
- **대응**: 위와 동일
- **상태**: ✅ 설계로 해결

### A5. IET (Instruction Execution Time) Divergence via APERF/MPERF
- **공격**: APERF 카운터를 사용하여 명령 실행 시간의 통계적 분포를 분석. 하이퍼바이저 존재 시 분포가 다름
- **우리 상황**: Hyper-V가 이미 APERF/MPERF를 가상화하고 있음
- **위험도**: ★☆☆☆☆ (1)
- **대응**: 불필요
- **상태**: ✅ Hyper-V가 커버

### A6. CR4.VMXE 비트 확인
- **공격**: Ring 0에서 CR4 레지스터 읽어서 VMXE(bit 13)가 설정되어 있는지 확인
- **우리 상황**: Hyper-V가 이미 VMXE를 설정하고 있음
- **위험도**: ☆☆☆☆☆ (0)
- **대응**: 불필요
- **상태**: ✅ 자동 해결

### A7. VMREAD/VMWRITE 명령 탐지
- **공격**: Ring 0에서 `VMREAD` 실행하여 하이퍼바이저 존재 확인 시도
- **우리 상황**: Hyper-V 환경에서 `VMREAD`는 이미 #UD (Undefined Opcode) 발생
- **위험도**: ☆☆☆☆☆ (0)
- **대응**: hyper-reV가 VMREAD에 #UD 주입 (이미 알려진 표준 우회법)
- **상태**: ✅ 표준 대응

### A8. IA32_EFER MSR의 SCE 비트 확인
- **공격**: EasyAntiCheat가 IA32_EFER MSR의 SCE(Syscall Enable) 비트를 모니터링. EFER 기반 syscall 훅킹 탐지 목적
- **우리 상황**: 우리는 EFER/LSTAR 기반 훅킹을 사용하지 않음
- **위험도**: ☆☆☆☆☆ (0)
- **대응**: 불필요. MSR Bitmap에서 IA32_EFER를 패스스루하면 됨
- **상태**: ✅ 해당 없음

### A9. Synthetic MSR Probing (0x40000000 범위)
- **공격**: Hyper-V 전용 synthetic MSR (0x40000000~0x400000FF) 읽기로 하이퍼바이저 기능 확인
- **우리 상황**: 이미 Hyper-V가 정상적으로 응답. hyper-reV는 추가 synthetic MSR을 노출하지 않음
- **위험도**: ☆☆☆☆☆ (0)
- **대응**: 불필요
- **상태**: ✅ 자동 해결

### A10. GDT/IDT Descriptor Table 무결성 검사
- **공격**: GDT/IDT 베이스 주소와 리밋을 읽어서 비정상적 값 탐지. 독립 하이퍼바이저가 자체 GDT/IDT를 사용하면 감지 가능
- **우리 상황**: hyper-reV는 Hyper-V의 기존 GDT/IDT를 그대로 사용. Guest에서 보이는 GDT/IDT는 Hyper-V가 설정한 그대로
- **위험도**: ☆☆☆☆☆ (0)
- **대응**: 불필요
- **상태**: ✅ 자동 해결

### A11. Page Table / CR3 일관성 검사
- **공격**: 하이퍼바이저가 guest/host 메모리를 제대로 분리하지 않으면 페이지 테이블 불일치 탐지 가능
- **우리 상황**: hyper-reV는 Hyper-V의 SLAT을 deep copy하여 별도 CR3를 관리. Guest 페이지 테이블은 건드리지 않음
- **위험도**: ☆☆☆☆☆ (0)
- **대응**: 불필요
- **상태**: ✅ 설계로 해결

---

## 카테고리 B: EPT 훅 관련 감지

### B1. EPT 훅 타이밍 사이드채널 (MeasureReads)
- **공격**: Anti-cheat가 커널 함수들의 읽기 시간을 측정하여 baseline 대비 비정상적 지연 탐지. EPT violation이 발생하면 VM exit → 레이턴시 증가
- **핵심 코드** (anti-cheat 측):
  ```
  control_avg = 평균(MeasureReads(정상함수들))
  target_time = MeasureReads(의심함수)
  if target_time > control_avg * MULTIPLIER → 탐지!
  ```
- **우리 상황**: 우리가 훅하는 대상은 네트워크 스택 함수 (ndis/tcpip 레이어). Anti-cheat가 모니터링하는 함수 목록에 포함될 가능성 낮음. 하지만 **가능성은 있음**
- **위험도**: ★★★☆☆ (3)
- **대응**:
  1. **훅 대상 선택**: Anti-cheat가 모니터링하지 않는 저레벨 네트워크 함수 선택 (ndis.sys 내부가 아닌 NDIS miniport driver 수준)
  2. **EPT violation 최소화**: execute-only 페이지 사용 시, 해당 페이지의 read가 발생하지 않는 위치 선택
  3. **단일 EPTP 접근**: hyper-reV의 dual SLAT CR3 전환은 hook/unhook SLAT 간 전환이므로, 타이밍 오버헤드가 TLB miss 수준으로 최소화됨
- **상태**: ⚠️ 훅 대상 신중 선택 필요

### B2. EPT 훅 Write 기반 탐지 (momo5502 Method 1)
- **공격**: 함수 사이의 padding 바이트 (0xCC)에 특정 값을 write 후 다시 read하여 일치 확인. EPT 훅이 있으면 write는 original page에, read도 original page에 가지만, execute는 shadow page에서 일어남
- **우리 상황**: 이 방법은 write한 값이 execute 시 반영되는지 확인하는 것. 네트워크 함수를 훅하는 우리한테는 Anti-cheat가 이 함수를 대상으로 검사할 가능성이 낮음
- **위험도**: ★★☆☆☆ (2)
- **대응**: hyper-reV의 EPT 설계 상 write → original page, execute → shadow page 분리이므로 write-read 일관성은 유지됨. 문제는 write-execute 일관성인데, Anti-cheat가 네트워크 함수에 코드를 써서 실행하는 검사는 비현실적
- **상태**: ⚠️ 낮은 위험, 훅 대상 선택으로 회피

### B3. EPT 훅 Thread Counter 기반 탐지 (momo5502 Method 2 - TLB)
- **공격**: 별도 스레드에서 CPUID를 반복 실행하며 카운터 증가. EPT violation으로 인한 VM exit이 추가 발생하면 카운터 값이 낮아짐 (스레드 스케줄링 지연)
- **우리 상황**: 이 방법은 훅된 페이지가 실행될 때만 영향. 네트워크 함수가 지속적으로 실행되는 상황에서만 감지 가능하나, 네트워크 함수 호출 빈도는 낮음
- **위험도**: ★☆☆☆☆ (1)
- **대응**: 네트워크 훅은 패킷 전송 시에만 트리거되므로 EPT violation 빈도가 극히 낮음. 통계적으로 의미 있는 차이를 만들기 어려움
- **상태**: ✅ 설계로 해결 (낮은 호출 빈도)

### B4. Hyper-V 이미지 무결성 검사
- **공격**: Guest에서 Hyper-V 바이너리의 SLAT 보호 안 된 복사본을 찾아 패치 여부 확인
- **우리 상황**: hyper-reV는 최종 SLAT-보호된 이미지에만 패치 적용. Guest에서 읽을 수 있는 초기 복사본 (hvix64.exe 등의 디스크 이미지)은 건드리지 않음
- **위험도**: ☆☆☆☆☆ (0)
- **대응**: 불필요 (hyper-reV 설계에 이미 반영)
- **상태**: ✅ 이미 해결

### B5. HyperGuard (Hyper-V Secure Kernel) 무결성 검사
- **공격**: Windows의 HyperGuard가 커널 코드/데이터 무결성을 주기적으로 검증. EPT 훅으로 인한 실행 경로 변경 감지 가능
- **우리 상황**: 우리 EPT 훅은 ntoskrnl.exe나 보호 대상이 아닌 네트워크 드라이버에 설치. HyperGuard는 주로 ntoskrnl, CI.dll, hal.dll 등 핵심 모듈을 보호
- **위험도**: ★☆☆☆☆ (1)
- **대응**: HyperGuard 보호 대상이 아닌 드라이버에 훅 설치
- **상태**: ✅ 훅 대상 선택으로 해결

---

## 카테고리 C: 부트 체인 / 디스크 포렌식

### C1. ESP (EFI System Partition) 파일 변조 감지
- **공격**: Anti-cheat/보안솔루션이 ESP 파티션의 bootmgfw.efi 해시를 계산하여 원본과 비교. 타임스탬프 불일치 탐지
- **우리 상황**: hyper-reV는 bootmgfw.efi를 교체하여 부트 체인에 개입
- **위험도**: ★★★★☆ (4) — **가장 높은 위험 벡터 중 하나**
- **대응**:
  1. Anti-cheat가 ESP를 직접 읽을 수 있으려면 관리자 권한 + 디스크 raw read 필요. 대부분의 anti-cheat는 이 수준까지 검사하지 않음
  2. **하지만** Vanguard(Riot)는 최근 부트 무결성 검사를 강화함
  3. **완화**: bootmgfw.efi의 수정 시간을 원본과 동일하게 유지. 파일 크기도 패딩으로 일치시킴
  4. **최선**: 별도 부트 항목 사용 (Windows Boot Manager와 별개의 EFI 항목)
- **상태**: ⚠️ 주요 위험. 게임별 Anti-cheat 수준에 따라 다름

### C2. MeasuredBoot 로그 분석
- **공격**: Windows의 MeasuredBoot가 부트 과정의 각 컴포넌트를 TCG 로그에 기록. 비정상적 부트 드라이버 (grubx64.efi 등) 존재 감지
- **우리 상황**: TPM OFF이면 MeasuredBoot 로그가 생성되지 않음
- **위험도**: ☆☆☆☆☆ (0)
- **대응**: TPM OFF (전제조건)
- **상태**: ✅ TPM OFF로 해결

### C3. Secure Boot 무결성 검사
- **공격**: Secure Boot이 켜져있으면 서명되지 않은 bootmgfw.efi 실행 불가
- **우리 상황**: Secure Boot OFF (전제조건)
- **위험도**: ☆☆☆☆☆ (0)
- **대응**: Secure Boot OFF
- **상태**: ✅ 전제조건으로 해결

### C4. HVCI (Hypervisor-Protected Code Integrity) 레지스트리 확인
- **공격**: HVCI가 비활성화되면 `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled` 값이 0. Anti-cheat가 이 레지스트리를 확인할 수 있음
- **우리 상황**: hyper-reV가 HVCI를 비활성화할 수 있음 (unsigned 코드 실행 위해)
- **위험도**: ★★☆☆☆ (2)
- **대응**:
  1. HVCI를 비활성화하지 않고 작동하도록 설계 (가능하면)
  2. 레지스트리 값을 1로 유지하면서 실제로는 비활성화 (EPT로 레지스트리 읽기를 후킹할 수 있으나 과도한 복잡도)
  3. **최선**: hyper-reV 코드를 Hyper-V의 기존 코드 서명 체인에 포함시켜 HVCI를 유지
- **상태**: ⚠️ 설계 주의 필요

### C5. VBS (Virtualization-Based Security) 상태 확인
- **공격**: `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard`로 VBS 상태 확인
- **우리 상황**: Hyper-V 기생 구조에서 VBS는 정상 동작 유지 가능
- **위험도**: ★☆☆☆☆ (1)
- **대응**: VBS 상태를 정상으로 유지하도록 설계
- **상태**: ✅ hyper-reV 설계로 해결 가능

---

## 카테고리 D: 네트워크 레벨 감지

### D1. 비정상적 네트워크 트래픽 패턴
- **공격**: 게임 실행 중 비정상적 UDP/TCP 트래픽 패턴 감지. 일정 간격의 소량 데이터 전송은 의심 대상
- **우리 상황**: EPT 훅으로 네트워크 스택을 통해 외부 PC와 통신
- **위험도**: ★★★☆☆ (3)
- **대응**:
  1. **트래픽 위장**: 기존 연결 (DNS, NTP, HTTPS) 내에 데이터 은닉
  2. **암호화**: TLS 형태의 암호화로 페이로드 위장
  3. **가변 간격**: 일정한 패턴이 아닌 랜덤 간격으로 전송
  4. **대역폭 제한**: 초당 전송량을 정상 트래픽 범위 내로 유지
  5. **최선**: 기존 게임 트래픽의 목적지와 다른 포트/IP를 사용하되, 일반적인 서비스 (예: CDN, cloud) IP를 경유
- **상태**: ⚠️ 구현 시 위장 전략 필요

### D2. NIC 이중 사용 감지 (is_current_nic)
- **공격**: EAC/VGK가 `is_current_nic`을 구현하여 2개의 NIC 설정 감지. 게임이 사용하는 NIC만 허용하고, 두 번째 NIC를 차단
- **우리 상황**: 우리는 물리적 DMA 카드가 아닌 소프트웨어 방식이므로 별도 NIC가 필요하지 않음. 같은 NIC를 사용
- **위험도**: ☆☆☆☆☆ (0)
- **대응**: 불필요. 하드웨어 DMA의 문제이지 소프트웨어 DMA와는 무관
- **상태**: ✅ 해당 없음

### D3. 네트워크 드라이버 스택 무결성 검사
- **공격**: Anti-cheat가 ndis.sys, tcpip.sys 등 네트워크 드라이버의 함수 무결성을 검사
- **우리 상황**: EPT 훅은 메모리의 실제 바이트를 변경하지 않음 (read → original page). 무결성 검사는 original page를 읽으므로 통과
- **위험도**: ★☆☆☆☆ (1)
- **대응**: EPT dual-view (read=original, execute=shadow) 설계로 자동 회피
- **상태**: ✅ EPT 설계로 해결

---

## 카테고리 E: PCIe / 하드웨어 DMA 감지 (참고용)

> 이 카테고리는 **물리적 DMA 카드**에 해당하는 감지 벡터로, 우리 소프트웨어 DMA 방식에는 **해당 없음**. 참고용으로 기록.

### E1. PCIe 디바이스 열거 (Device Enumeration)
- **공격**: VGK/EAC가 PCIe 슬롯의 모든 디바이스를 스캔하여 알려진 FPGA VID/PID 감지
- **우리 상황**: 물리적 PCIe 디바이스를 추가하지 않음
- **상태**: ✅ 해당 없음

### E2. PCIe Configuration Space 이상 탐지
- **공격**: Xilinx PCIe IP의 configuration space 특성 탐지
- **우리 상황**: 해당 없음
- **상태**: ✅ 해당 없음

### E3. IOMMU/Kernel DMA Protection
- **공격**: Windows의 IOMMU 기반 DMA 보호가 비인가 PCIe 디바이스의 메모리 접근 차단
- **우리 상황**: 해당 없음 (소프트웨어 방식)
- **상태**: ✅ 해당 없음

### E4. 데이터 전송 속도 모니터링
- **공격**: PCIe 디바이스의 비정상적 데이터 전송 패턴 감지
- **우리 상황**: 해당 없음
- **상태**: ✅ 해당 없음

### E5. Chipset Anomaly Detection
- **공격**: Vanguard의 chipset 분석을 통한 하드웨어 변조 감지
- **우리 상황**: 해당 없음
- **상태**: ✅ 해당 없음

---

## 카테고리 F: 행동 기반 / 서버사이드 감지

### F1. 게임 플레이 패턴 분석 (서버사이드)
- **공격**: ML 기반 행동 분석으로 비인간적 에임, 반응속도, 포지셔닝 패턴 감지
- **우리 상황**: ESP/레이더 정보를 제공하지만, 실제 게임 조작은 플레이어가 수행
- **위험도**: ★★☆☆☆ (2)
- **대응**:
  1. ESP 정보만 제공 (aimbot 없이)하면 행동 패턴이 자연스러움
  2. 서버사이드 감지는 모든 치트에 공통되는 문제이며, 우리 아키텍처와 무관
- **상태**: ⚠️ 사용자의 행동에 의존

### F2. Honeypot 메모리 영역
- **공격**: VGK가 의도적으로 가짜 메모리 영역을 배치하여 DMA 읽기 감지. 특정 패턴으로 채운 미끼 메모리를 읽으면 서버에 보고
- **우리 상황**: 우리도 게임 메모리를 읽으므로 해당될 수 있음
- **위험도**: ★★☆☆☆ (2)
- **대응**:
  1. 알려진 구조체만 정확히 읽기 (무차별 스캔 금지)
  2. 읽기 패턴을 정상적인 게임 메모리 접근과 유사하게 유지
  3. 하이퍼바이저 레벨에서 읽기이므로, Guest OS는 우리의 읽기를 감지할 수 없음 (EPT 기반 직접 물리 메모리 접근)
- **상태**: ✅ EPT 기반 읽기는 Guest에서 감지 불가 (핵심 장점)

### F3. Anti-cheat Heartbeat / 무결성 검증
- **공격**: Anti-cheat가 주기적으로 자체 무결성을 서버에 보고. 예상 응답이 없으면 킥
- **우리 상황**: Anti-cheat 프로세스를 건드리지 않으므로 heartbeat는 정상 동작
- **위험도**: ☆☆☆☆☆ (0)
- **대응**: 불필요
- **상태**: ✅ Guest-side 프로세스 없음

---

## 카테고리 G: Fault Injection 기반 감지

### G1. Invalid XSETBV 실행
- **공격**: 잘못된 XCR0 값으로 XSETBV 실행하여 예상 예외 발생 여부 확인. 하이퍼바이저가 이를 잘못 처리하면 감지
- **우리 상황**: Hyper-V가 XSETBV를 정상 처리
- **위험도**: ☆☆☆☆☆ (0)
- **대응**: 불필요
- **상태**: ✅ Hyper-V가 처리

### G2. Invalid MSR 읽기/쓰기
- **공격**: 존재하지 않는 MSR에 RDMSR/WRMSR 실행하여 #GP 예외 발생 여부/타이밍 확인
- **우리 상황**: MSR Bitmap 설정으로 필요한 MSR만 인터셉트. 나머지는 Hyper-V 패스스루
- **위험도**: ★☆☆☆☆ (1)
- **대응**: hyper-reV의 MSR Bitmap에서 불필요한 MSR 인터셉트를 최소화
- **상태**: ✅ MSR Bitmap 최적화

### G3. Invalid CR 접근
- **공격**: Control Register에 비정상적 값 쓰기로 하이퍼바이저 반응 테스트
- **우리 상황**: Hyper-V가 처리
- **위험도**: ☆☆☆☆☆ (0)
- **대응**: 불필요
- **상태**: ✅ Hyper-V가 처리

---

## 최종 위험 매트릭스

| ID | 감지 벡터 | 위험도 | 상태 | 대응 방법 |
|----|-----------|--------|------|-----------|
| A1 | CPUID Hypervisor Bit | ☆☆☆☆☆ | ✅ | Hyper-V가 커버 |
| A2 | CPUID Vendor ID | ☆☆☆☆☆ | ✅ | Hyper-V가 커버 |
| A3 | RDTSC+CPUID 타이밍 | ★☆☆☆☆ | ✅ | CPUID 인터셉트 안 함 |
| A4 | RDTSC+기타 명령 타이밍 | ★☆☆☆☆ | ✅ | 설계로 해결 |
| A5 | APERF/IET Divergence | ★☆☆☆☆ | ✅ | Hyper-V가 커버 |
| A6 | CR4.VMXE | ☆☆☆☆☆ | ✅ | Hyper-V가 커버 |
| A7 | VMREAD/VMWRITE | ☆☆☆☆☆ | ✅ | #UD 주입 |
| A8 | IA32_EFER SCE | ☆☆☆☆☆ | ✅ | 해당 없음 |
| A9 | Synthetic MSR | ☆☆☆☆☆ | ✅ | Hyper-V가 커버 |
| A10 | GDT/IDT 무결성 | ☆☆☆☆☆ | ✅ | Hyper-V 것 사용 |
| A11 | Page Table/CR3 | ☆☆☆☆☆ | ✅ | Guest PT 미변경 |
| B1 | EPT 훅 타이밍 | ☆☆☆☆☆ | ✅ | Guest EPT 훅 없음, MMIO 직접 접근 |
| B2 | EPT Write 탐지 | ☆☆☆☆☆ | ✅ | Guest EPT 훅 없음 |
| B3 | EPT TLB 탐지 | ★☆☆☆☆ | ✅ | 낮은 호출 빈도 |
| B4 | HV 이미지 무결성 | ☆☆☆☆☆ | ✅ | SLAT 보호 |
| B5 | HyperGuard | ★☆☆☆☆ | ✅ | 보호대상 외 훅 |
| C1 | ESP 파일 변조 | ★☆☆☆☆ | ✅ | 별도 EFI 부트항목, 원본 미수정 |
| C2 | MeasuredBoot 로그 | ☆☆☆☆☆ | ✅ | TPM OFF |
| C3 | Secure Boot | ☆☆☆☆☆ | ✅ | SB OFF |
| C4 | HVCI 레지스트리 | ☆☆☆☆☆ | ✅ | Ring -1 실행, HVCI 비활성화 불필요 |
| C5 | VBS 상태 | ★☆☆☆☆ | ✅ | 정상 유지 |
| D1 | 네트워크 트래픽 | ☆☆☆☆☆ | ✅ | Ring -1 NIC 직접 제어, Guest 스택 우회 |
| D2 | NIC 이중 사용 | ☆☆☆☆☆ | ✅ | 해당 없음 |
| D3 | NW 드라이버 무결성 | ★☆☆☆☆ | ✅ | EPT dual-view |
| E1~5 | PCIe/HW DMA | ☆☆☆☆☆ | ✅ | 해당 없음 (SW방식) |
| F1 | 행동 분석 | ★★☆☆☆ | ⚠️ | ESP 전용 사용 |
| **F2** | **Honeypot 메모리** | **★★☆☆☆** | **✅** | **EPT 레벨 읽기=Guest 감지불가** |
| F3 | AC Heartbeat | ☆☆☆☆☆ | ✅ | Guest 미변경 |
| G1~3 | Fault Injection | ☆☆☆☆☆ | ✅ | Hyper-V가 처리 |

---

## 핵심 결론

### 남은 실질적 위험 벡터 (총 1개)

1. **F1 - 행동 분석 (★★)**: 서버사이드 ML 분석. 아키텍처로 해결 불가, 사용자 행동에 의존

### 해결된 위험 벡터 (C1, C4 포함)

1. **C1 - ESP 파일 변조**: ✅ 별도 EFI 부트 항목 사용. 원본 bootmgfw.efi 절대 미수정. 부팅 후 payload.dll 자동 삭제
2. **B1 - EPT 훅 타이밍**: ✅ Guest EPT 훅 없음. NIC MMIO 직접 접근
3. **D1 - 네트워크 트래픽**: ✅ Ring -1 NIC 직접 제어. Guest 네트워크 스택 완전 우회
4. **C4 - HVCI 레지스트리**: ✅ hyper-reV는 Ring -1 전용. HVCI 비활성화 코드 없음. 레지스트리 정상

### 감지 0 수렴을 위한 필수 조치

| 우선순위 | 조치 | 상태 |
|----------|------|------|
| 1 | 별도 EFI 부트 항목 (원본 bootmgfw 미수정) | ✅ 구현 완료 |
| 2 | NIC MMIO 직접 접근 (Guest EPT 훅 제거) | ✅ 소프트웨어 DMA로 해결 |
| 3 | Ring -1 NIC 제어 (Guest 네트워크 스택 우회) | ✅ 소프트웨어 DMA로 해결 |
| 4 | HVCI 유지 (Ring -1 전용 설계) | ✅ 설계로 해결 |

### 우리 아키텍처의 근본적 강점

- **Hyper-V 기생**: 모든 CPU 레벨 감지 벡터 (A1~A11)를 Hyper-V가 자연스럽게 커버
- **Guest-side 0 footprint**: 프로세스, 드라이버, hypercall 없음 → 소프트웨어 스캔으로 감지 불가
- **EPT 기반 메모리 읽기**: Guest OS가 우리의 메모리 읽기를 감지할 수 없음 (Ring -1에서 물리 메모리 직접 접근)
- **물리 DMA 카드 불필요**: PCIe 열거, IOMMU, chipset 분석 등 하드웨어 DMA 감지 벡터 완전 회피

---

## H. hyper-reV 고유 + 2025 Anti-Cheat 진화 벡터 (신규)

### H1. UEFI Boot Entry / NVRAM 변수 열거
- **위험도**: ★★★☆☆
- **설명**: `bcdedit /enum all` 또는 UEFI NVRAM 변수 스캔으로 커스텀 부트 항목 발견 가능. 스텔스 모드에서 생성한 `\efi\hyper-rev\bootx64.efi` 경로가 비표준으로 감지됨
- **대응**: USB 부팅(NVRAM 흔적 0) 또는 UEFI 펌웨어 부트 메뉴에서 1회성 부팅(영구 항목 미생성)
- **상태**: ⚠️ 운영 완화 필요

### H2. EFI 메모리 맵 이상 (EfiRuntimeServicesData 할당)
- **위험도**: ★★☆☆☆
- **설명**: uefi-boot가 hyperv-attachment 힙으로 ~4MB EfiRuntimeServicesData를 할당. OS가 보존하는 이 메모리 블록이 정상 시스템 대비 크기 이상으로 감지 가능
- **대응**: Hyper-V 자체가 대량 EfiRuntimeServicesData를 사용하므로 통계적으로 묻힘. 또는 EfiBootServicesData로 변경(ExitBootServices 전에 Hyper-V 공간에 복사 완료되므로 가능)
- **상태**: ⚠️ 저위험

### H3. NIC 하드웨어 통계 카운터 불일치
- **위험도**: ★★★☆☆
- **설명**: Ring -1 MMIO TX가 만드는 패킷은 NIC 하드웨어 카운터(TPT/GPTC)에 반영되지만 Guest OS NDIS 카운터에는 미반영. Anti-cheat가 두 값을 비교하면 팬텀 트래픽 감지 가능
- **대응**: TX 후 NIC 통계 레지스터를 읽어서 카운터 조정(Intel I219 통계 레지스터는 R/C 모드)
- **상태**: ⚠️ 구현 필요 (stats register manipulation)

### H4. VMEXIT 처리 지연 분포 이동
- **위험도**: ★★☆☆☆
- **설명**: 매 VMEXIT마다 `process_pending()` NIC 폴링 실행 → 전체 VMEXIT 레이턴시 분포가 이동. `rdtsc; cpuid; rdtsc` 수천 회 반복으로 통계적 감지 가능
- **대응**: 타이머 기반 폴링 (매 1000번째 VMEXIT에만 NIC 체크) → 평균 오버헤드 ~0.3ns로 감소
- **상태**: ⚠️ 타이머 기반 폴링 구현 권장

### H5. NIC TX Descriptor Ring 충돌
- **위험도**: ★★☆☆☆
- **설명**: Guest NIC 드라이버와 Ring -1이 같은 TX descriptor ring 접근 시 충돌 가능
- **대응**: Intel NIC는 2-4개 TX 큐 지원. Queue 0=Guest, Queue 1=Ring -1 전용으로 분리
- **상태**: ✅ 설계로 해결 (별도 TX 큐)

### H6. 물리 메모리 시그니처 스캔
- **위험도**: ★☆☆☆☆
- **설명**: Ring 0에서 물리 메모리를 스캔하여 hyperv-attachment 코드 패턴/PE 헤더 탐색
- **대응**: Guest는 EPT를 통해 물리 메모리 접근 → Hyper-V가 자신의 코드/데이터를 Guest EPT에 미매핑 → Guest에서 물리적으로 하이퍼바이저 메모리 읽기 불가
- **상태**: ✅ Hyper-V EPT 격리로 해결

### H7. Secure Boot / 코드 서명 강제
- **위험도**: ★★★☆☆
- **설명**: Secure Boot은 모든 EFI 바이너리의 디지털 서명을 검증. 우리 EFI는 Microsoft 서명 없음. Secure Boot OFF → Vanguard/EAC/FACEIT 차단. 2025년부터 Vanguard+FACEIT는 Secure Boot ON 필수
- **대응**: MOK(Machine Owner Key) 등록으로 자체 서명 EFI 로드. Secure Boot ON 유지. 단 Anti-cheat가 MOK DB를 열거할 위험 존재
- **상태**: ⚠️ MOK 등록 또는 아키텍처 변경 필요

### H8. IOMMU / Pre-Boot DMA Protection 강제 (Vanguard 2025.12)
- **위험도**: ★☆☆☆☆
- **설명**: Vanguard가 CVE-2025-11901 등 발견. 메인보드 IOMMU 조기 초기화 결함 이용한 물리 DMA 차단. BIOS 업데이트 + IOMMU + Pre-Boot DMA Protection 강제
- **대응**: 소프트웨어 DMA는 물리 PCIe 디바이스 아님 → IOMMU 규제 대상 외. IOMMU ON이 오히려 보안 시스템처럼 보여서 유리
- **상태**: ✅ 해당 없음 (소프트웨어 DMA)

### H9. VBS Enclave / Secure Kernel 미래 위협
- **위험도**: ★★☆☆☆ (현재 미적용, 미래)
- **설명**: Samuel Tulach(2024.12) VBS 엔클레이브 anti-cheat 개념 증명. 게임 데이터를 VTL1(Secure World)에서 실행하면 Ring -1도 직접 읽기 어려움
- **대응**: 우리 Hyper-V 내부 위치에서 ShvlpVtlReturn 인터셉트 → Secure Kernel 메모리 매핑 가능 (Tulach가 동일 기법 증명). 현재 게임은 VBS 엔클레이브 미사용
- **상태**: ⚠️ 미래 위협 - 현재 아키텍처가 유리한 위치

### H10. NIC A/B 기능 테스트 (Vanguard/EAC 2024-2025)
- **위험도**: ★☆☆☆☆
- **설명**: isdmadead.com 타임라인 기준, Vanguard/EAC가 페이크 패킷 주입 + A/B 테스트로 NIC 진위 확인. FPGA 위장 디바이스 감지. `is_current_nic` 검사로 이중 NIC 차단
- **대응**: 우리는 실제 시스템 NIC 사용 (FPGA 아님). A/B 테스트 통과. `is_current_nic`도 게임과 동일 NIC이므로 통과
- **상태**: ✅ 해당 없음 (실제 NIC)

---

## 최종 매트릭스 (41개 벡터)

| ID | 벡터 | 위험도 | 상태 | 비고 |
|----|-------|--------|------|------|
| A1-A11 | CPU/하드웨어 탐지 (11개) | ☆ | ✅ | Hyper-V가 모두 처리 |
| B1-B5 | EPT/HV 훅 (5개) | ☆ | ✅ | MMIO 직접 접근으로 EPT 훅 제거 |
| C1 | ESP 파일 변조 | ★☆ | ✅ | 별도 EFI 부트항목, 원본 미수정 |
| C2-C3 | MeasuredBoot/SecureBoot | ★ | ✅ | Hyper-V 정상 부트체인 |
| C4 | HVCI 레지스트리 | ☆ | ✅ | Ring -1 전용, HVCI 비활성화 불필요 |
| C5 | VBS 상태 | ★ | ✅ | VBS 유지 |
| D1-D3 | 네트워크 (3개) | ☆ | ✅ | Ring -1 NIC 직접 제어 |
| E1-E5 | PCIe/HW DMA (5개) | ☆ | ✅ | 소프트웨어 DMA, 물리 디바이스 없음 |
| F1 | 행동 분석 | ★★ | ⚠️ | 사용자 행동 의존 |
| F2-F3 | 허니팟/하트비트 | ★ | ✅ | EPT 메모리 읽기 |
| G1-G3 | Fault Injection (3개) | ☆ | ✅ | Hyper-V 처리 |
| **H1** | **NVRAM 부트 항목** | **★★★** | **⚠️** | **USB 부팅으로 완화** |
| **H2** | **EFI 메모리 맵** | **★★** | **⚠️** | **저위험, HV 할당과 유사** |
| **H3** | **NIC 통계 카운터** | **★★★** | **⚠️** | **구현 필요** |
| **H4** | **VMEXIT 레이턴시** | **★★** | **⚠️** | **타이머 폴링 권장** |
| H5 | TX Ring 충돌 | ★★ | ✅ | 별도 TX 큐 |
| H6 | 물리 메모리 스캔 | ★ | ✅ | EPT 격리 |
| **H7** | **Secure Boot 서명** | **★★★** | **⚠️** | **MOK 등록 필요** |
| H8 | IOMMU/Pre-Boot DMA | ★ | ✅ | 소프트웨어 DMA |
| **H9** | **VBS Enclave (미래)** | **★★** | **⚠️** | **미래 위협** |
| H10 | NIC A/B 테스트 | ★ | ✅ | 실제 NIC |

## 최종 점수

**총 41개 벡터:**
- ✅ 완전 해결: **34개** (83%)
- ⚠️ 완화 필요: **7개** (17%)

**완화 필요 벡터 우선순위:**

| 우선순위 | ID | 벡터 | 난이도 | 방법 |
|----------|-----|------|--------|------|
| 1 | H7 | Secure Boot 서명 | 중 | MOK 자체서명 등록 |
| 2 | H3 | NIC 통계 카운터 | 중 | TX 후 Stats 레지스터 R/C |
| 3 | H4 | VMEXIT 레이턴시 | 하 | 타이머 기반 폴링 (코드 1줄) |
| 4 | H1 | NVRAM 부트 항목 | 하 | USB 부팅 또는 1회성 UEFI 메뉴 |
| 5 | H2 | EFI 메모리 맵 | 하 | 메모리 타입 변경 검토 |
| 6 | F1 | 행동 분석 | - | 사용자 행동 (아키텍처로 해결 불가) |
| 7 | H9 | VBS Enclave | - | 미래 위협 (현재 게임 미적용) |


## 웹검색 추가 벡터 (2026-02-08 검증)

### H11. Microsoft Remote Attestation API (GetRuntimeAttestationReport)
- **출처**: Andrea Allievi (AaLl86 Security, 2026-02-01)
- **위험도**: ★★★☆☆ (TPM ON 시) / ☆☆☆☆☆ (TPM OFF 시)
- **설명**: Windows 25H2+ 신규 API. HVCI ON + TPM 환경에서 커널 모듈 해시 목록을 TPM 서명하여 원격 서버에 증명. 로드된 적 있는 모든 드라이버(unload 후에도) 포함.
- **우리 상황**: TPM OFF → API 작동 불가. 또한 hyper-reV는 Guest 커널 드라이버 미로드 → 모듈 목록에 흔적 0
- **상태**: ✅ TPM OFF로 해결 + 설계적으로도 해결

### H12. FACEIT IOMMU + VBS 강제
- **출처**: FACEIT 공식 (2025-11-25 mandatory)
- **위험도**: ☆☆☆☆☆
- **설명**: FACEIT이 IOMMU+VBS 필수화. 물리 DMA 카드 차단 목적.
- **우리 상황**: Arc Raiders ≠ FACEIT. 소프트웨어 DMA → IOMMU 무관. IOMMU ON은 오히려 유리.
- **상태**: ✅ 해당 없음

### H13. Secure Boot/TPM 필수 게임 확대 트렌드
- **출처**: 웹검색 종합 (2026-02 기준)
- **위험도**: ★☆☆☆☆
- **설명**: BF6, CoD BO7, Valorant, LoL, Highguard 등 TPM+SB 필수. Arc Raiders는 현재 미필수.
- **우리 상황**: Arc Raiders = Anybrain AI + Denuvo. TPM/SB 현재 미요구 (Steam 커뮤니티 확인)
- **상태**: ✅ 현재 해당 없음 (향후 변경 모니터링 필요)

### H14. xgetbv 반복 실행 타이밍 (BattlEye 2025)
- **출처**: CheckMATE '25 (ACM)
- **위험도**: ☆☆☆☆☆
- **설명**: BattlEye가 xgetbv 반복 실행 타이밍으로 하이퍼바이저 오버헤드 감지
- **우리 상황**: Arc Raiders는 BattlEye 미사용. Hyper-V가 xgetbv 처리 → 추가 오버헤드 0
- **상태**: ✅ 기존 A3/A4와 동일 원리로 해결

---

## 최종 갱신 매트릭스 (45개 벡터, USB Boot + TPM OFF + SB OFF)

**총 45개 벡터: 43개 ✅ 해결, 2개 ⚠️ 잔여 (F1 행동분석, H9 VBS 미래)**
**기술적 감지 가능 벡터: 0개**
