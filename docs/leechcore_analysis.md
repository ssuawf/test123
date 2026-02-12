# LeechCore 아키텍처 분석
> 우리 hyper-reV 소프트웨어 DMA 플러그인 개발을 위한 핵심 레퍼런스
> 분석일: 2026-02-08

---

## 1. LeechCore 전체 구조

```
┌─────────────────────────────────────────────────┐
│  공격 PC (Attack PC)                              │
│                                                   │
│  ┌──────────────┐    ┌──────────────────────────┐│
│  │  MemProcFS   │───→│  LeechCore (leechcore.dll)││
│  │  (프로세스   │    │                          ││
│  │   분석엔진)  │    │  ┌─────────────────────┐ ││
│  └──────────────┘    │  │ Device Layer        │ ││
│                      │  │ ┌─────────────────┐ │ ││
│  ┌──────────────┐    │  │ │ pfnReadScatter  │ │ ││
│  │  PCILeech    │───→│  │ │ pfnWriteScatter │ │ ││
│  │  (직접 DMA   │    │  │ │ pfnClose        │ │ ││
│  │   명령도구)  │    │  │ └─────────────────┘ │ ││
│  └──────────────┘    │  └─────────────────────┘ ││
│                      └──────────────────────────┘│
└─────────────────────────────────────────────────┘
```

**핵심 포인트:**
- LeechCore는 **라이브러리** (.dll/.so) - 독립 실행 불가
- PCILeech, MemProcFS가 LeechCore를 로드해서 사용
- Device Layer가 실제 메모리 접근 담당 → **여기에 우리 플러그인 삽입**

---

## 2. Device Plugin 인터페이스

### 2.1 핵심 구조체

```c
// MEM_SCATTER - 메모리 읽기/쓰기의 기본 단위
// LeechCore의 모든 메모리 접근은 이 구조체 배열로 처리
typedef struct tdMEM_SCATTER {
    DWORD version;      // MEM_SCATTER_VERSION = 0xc0fe0002
    BOOL f;             // TRUE=성공, FALSE=실패/미읽음
    QWORD qwA;          // 읽을 물리 주소 (Physical Address)
    PBYTE pb;            // 데이터 버퍼 포인터
    DWORD cb;            // 읽을 바이트 수 (보통 0x1000 = 4KB)
    // ... stack, flags 등
} MEM_SCATTER, *PMEM_SCATTER, **PPMEM_SCATTER;
```

**MEM_SCATTER 규칙:**
- 최대 크기 = 0x1000 (4096 bytes) = 권장 크기
- 최소 크기 = 8 bytes (2 DWORDs)
- 4바이트 정렬 필수
- 0x1000 페이지 경계 넘기면 안됨

### 2.2 플러그인이 구현해야 할 함수들

```c
// 1. ReadScatter - 메모리 읽기 (가장 중요!)
VOID DeviceXXX_ReadScatter(
    _In_ PLC_CONTEXT ctxLC,     // LeechCore 컨텍스트
    _In_ DWORD cpMEMs,          // MEM_SCATTER 배열 개수
    _Inout_ PPMEM_SCATTER ppMEMs // MEM_SCATTER 포인터 배열
);
// 각 ppMEMs[i]의 qwA에서 cb바이트를 읽어 pb에 저장
// 성공시 ppMEMs[i]->f = TRUE

// 2. WriteScatter - 메모리 쓰기 (선택)
VOID DeviceXXX_WriteScatter(
    _In_ PLC_CONTEXT ctxLC,
    _In_ DWORD cpMEMs,
    _Inout_ PPMEM_SCATTER ppMEMs
);

// 3. Close - 디바이스 정리
VOID DeviceXXX_Close(
    _Inout_ PLC_CONTEXT ctxLC
);

// 4. Open - 디바이스 초기화 (export 함수)
// DLL export명: LcPluginCreate
_Success_(return)
BOOL LcPluginCreate(
    _Inout_ PLC_CONTEXT ctxLC,
    _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo
);
```

### 2.3 플러그인 등록 패턴 (Open 함수)

```c
BOOL LcPluginCreate(PLC_CONTEXT ctxLC, PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    // 1. 파라미터 파싱 (ctxLC->Config.szDevice에서 URL 파싱)
    //    예: "hyper-rev://192.168.1.100:28473"
    
    // 2. 디바이스 컨텍스트 할당
    PDEVICE_CONTEXT ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT));
    
    // 3. 연결 설정 (TCP 소켓 등)
    
    // 4. 콜백 함수 등록 ← 핵심!
    ctxLC->hDevice = ctx;                           // 디바이스 핸들
    ctxLC->pfnReadScatter = DeviceXXX_ReadScatter;  // 읽기 콜백
    ctxLC->pfnWriteScatter = DeviceXXX_WriteScatter;// 쓰기 콜백
    ctxLC->pfnClose = DeviceXXX_Close;              // 정리 콜백
    
    // 5. 설정
    ctxLC->Config.fVolatile = TRUE;   // 라이브 메모리
    ctxLC->Config.fWritable = TRUE;   // 쓰기 가능
    ctxLC->Config.paMax = 0x..;       // 최대 물리 주소
    
    return TRUE;
}
```

---

## 3. 기존 플러그인 비교 분석

### 우리에게 가장 관련있는 플러그인들:

| 플러그인 | 통신방식 | 특징 | 우리와의 관련성 |
|---------|---------|------|---------------|
| **rawtcp** | TCP 소켓 | iLO 등 원격 DMA | ★★★★ 네트워크 통신 패턴 참고 |
| **qemupcileech** | TCP 소켓 | QEMU 가상 PCILeech | ★★★★ PCILeech 프로토콜 구현 |
| **skeleton** | 없음 | 빈 템플릿 | ★★★ 플러그인 구조 참고 |
| **qemu** | 공유메모리 | /dev/shm 직접 접근 | ★★ 메모리 접근 패턴 |
| **devmem** | /dev/mem | 캐릭터 디바이스 | ★ 단순 읽기 |

### rawtcp 동작 방식 (가장 중요한 레퍼런스):
```
공격PC (LeechCore + rawtcp plugin)
    ↕ TCP 소켓
타겟PC (iLO 프록시)
    ↕ 물리 메모리 접근
타겟PC 물리 메모리
```

### qemupcileech 동작 방식:
```
공격PC (LeechCore + qemupcileech plugin)
    ↕ TCP 소켓 (port 6789)
QEMU (가상 PCILeech 디바이스)
    ↕ 게스트 물리 메모리 접근
QEMU 게스트 메모리
```

---

## 4. 우리 플러그인 설계: leechcore_device_hyperrev

### 4.1 아키텍처

```
┌──────────────── 공격 PC ─────────────────┐
│                                           │
│  MemProcFS / PCILeech                     │
│       ↓                                  │
│  LeechCore                                │
│       ↓                                  │
│  leechcore_device_hyperrev.dll ← 우리 것! │
│       ↓                                  │
│  TCP/TLS 소켓 (port ???)                  │
│       ↓                                  │
└───────╂───────────────────────────────────┘
        ↕ LAN (encrypted)
┌───────╂──────── 타겟 PC ─────────────────┐
│       ↓                                  │
│  EPT Hook (네트워크 드라이버)             │
│       ↓                                  │
│  Hypervisor (Ring -1)                     │
│       ↓ EPT GPA→HPA                      │
│  물리 메모리 직접 접근                    │
│                                           │
└───────────────────────────────────────────┘
```

### 4.2 프로토콜 설계

**옵션 A: PCILeech 프로토콜 호환 (권장)**
```
magic = 0xD042DE47 사용
장점: 기존 FPGA 프로토콜과 동일 → 검증된 안정성
단점: 불필요한 PCIe TLP 오버헤드 (우리는 PCIe 없음)
```

**옵션 B: 커스텀 경량 프로토콜 (대안)**
```c
// 우리만의 간단한 메시지 형식
typedef struct {
    DWORD magic;        // 0xHYPERREV (커스텀)
    DWORD cmd;          // READ=1, WRITE=2, RESPONSE=3
    QWORD pa;           // 물리주소
    DWORD cb;           // 바이트 수
    BYTE data[];        // 가변 데이터
} HYPERREV_MSG;
```

**옵션 C: ScatterRead 배치 프로토콜 (최적)**
```c
// Scatter 요청을 한 번에 묶어서 전송
typedef struct {
    DWORD magic;        // 0xD042DE47 (PCILeech 호환)
    DWORD count;        // MEM_SCATTER 개수
    struct {
        QWORD pa;       // 물리주소
        DWORD cb;       // 바이트 수
    } entries[];        // 배열
} SCATTER_REQUEST;

typedef struct {
    DWORD magic;
    DWORD count;
    struct {
        BOOL success;
        BYTE data[0x1000]; // 페이지 데이터
    } entries[];
} SCATTER_RESPONSE;
```

### 4.3 성능 예산

```
FPGA DMA:    ~1μs per read (USB-C 190MB/s)
LAN (1Gbps): ~0.5ms RTT (양호), ~1ms (보통)

ESP 60fps = 16.7ms per frame
Arc Raiders 1 frame 읽기 예상:
  - Player 수: ~50 actors
  - 각 actor: 위치(0x18) + HP(0x10) + 이름(0x20) = ~72 bytes
  - 추가: UWorld→GameInstance→Level→Actors 체인 ~10 reads
  
  총 = ~60 scatter reads × 0x1000 = ~240KB
  
  LAN 전송: 240KB @ 1Gbps = ~2ms
  + RTT 오버헤드: ~1ms × ceil(60/배치크기)
  
  배치크기=60이면: ~3ms total → 60fps 여유 충분! ✅
  배치크기=10이면: ~8ms total → 60fps 가능 ✅
  배치크기=1이면:  ~60ms total → 16fps ❌ 너무 느림
```

**결론: 반드시 ScatterRead 배치 전송 필요!**

### 4.4 디바이스 URL 형식

```
사용법: memprocfs -device 'hyperrev://192.168.1.100:28473'
또는:   pcileech -device 'hyperrev://192.168.1.100:28473'
```

---

## 5. 구현 단계

### Phase 1: 공격PC 플러그인 (leechcore_device_hyperrev.dll)
```
[ ] skeleton 기반 플러그인 구조 생성
[ ] LcPluginCreate - TCP 클라이언트 연결
[ ] ReadScatter - 배치 scatter read 요청 전송/응답 수신
[ ] WriteScatter - 배치 scatter write
[ ] Close - 소켓 정리
[ ] 빌드: Visual Studio, leechcore.dll 옆에 배치
```

### Phase 2: 타겟PC HV 서버
```
[ ] EPT hook 기반 covert channel 수신
[ ] Scatter read 요청 파싱
[ ] CR3 읽기 → Guest Page Table Walking → 물리주소 변환
[ ] 물리 메모리 읽기 → 응답 생성
[ ] covert channel로 응답 전송
```

### Phase 3: 통합
```
[ ] 공격PC: memprocfs -device 'hyperrev://...'
[ ] 프로세스 목록 나오는지 확인
[ ] Arc Raiders 프로세스 메모리 접근 테스트
```

---

## 6. 핵심 참조 코드

### LeechCore 소스 구조
```
LeechCore/
├── includes/
│   ├── leechcore.h            # 공개 API 헤더 (핵심!)
│   └── leechcore_device.h     # 플러그인 디바이스 헤더 (핵심!)
├── leechcore/
│   ├── leechcore.c            # 코어 구현 (ReadScatter 호출 체인)
│   ├── leechcore_internal.h   # 내부 헤더 (PLC_CONTEXT 정의)
│   ├── device_fpga.c          # FPGA 디바이스 (TLP 처리 참고)
│   ├── device_file.c          # 파일 디바이스 (ReadScatter 패턴)
│   └── device_vmware.c        # VMWare 디바이스
└── leechagent/                # LeechAgent (원격 접속)

LeechCore-plugins/
├── leechcore_device_skeleton/  # 빈 템플릿 ← 여기서 시작!
├── leechcore_device_rawtcp/    # TCP 기반 ← 네트워크 참고!
├── leechcore_device_qemupcileech/ # QEMU PCILeech ← 프로토콜 참고!
└── leechcore_device_devmem/    # /dev/mem 접근
```

### MEM_SCATTER 처리 흐름 (leechcore.c)
```
LcReadScatter() 호출
    ↓
1. TRANSLATE: MEM_SCATTER 주소 변환 (memmap)
    ↓
2. FETCH: ctxLC->pfnReadScatter() 호출 ← 우리 함수!
    ↓
3. RESTORE: 원래 주소 복원
```

---

## 7. 중요한 발견: 0xD042DE47 매직은 불필요할 수 있다

### LeechCore 플러그인 vs FPGA 프로토콜

```
FPGA 디바이스 (device_fpga.c):
  - USB/FT601 칩을 통해 FPGA와 통신
  - PCIe TLP 패킷으로 메모리 읽기/쓰기
  - 0xD042DE47 매직은 FPGA<->LeechCore 통신용
  - TLP 태그 기반 비동기 처리

커스텀 플러그인 (rawtcp, skeleton 등):
  - 자체 프로토콜 사용 가능
  - ReadScatter 콜백만 구현하면 됨
  - 0xD042DE47 사용 의무 없음!
```

**결론: 우리 플러그인은 0xD042DE47 매직 없이, 자체 경량 프로토콜로 구현 가능!**
→ 불필요한 FPGA 프로토콜 오버헤드 제거
→ 배치 scatter read에 최적화된 프로토콜 설계 가능

---

## 8. 남은 결정사항

1. **프로토콜 선택**: 커스텀 경량 vs PCILeech 호환
2. **암호화**: TLS? 커스텀 XOR? AES?
3. **포트**: 고정 vs 설정 가능
4. **배치 크기**: 최대 scatter read 개수
5. **타겟PC 서버**: covert channel vs 직접 TCP 리슨
