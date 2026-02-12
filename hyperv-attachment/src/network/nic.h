#pragma once
#include <cstdint>

// ============================================================================
// NIC Hardware Abstraction
// ============================================================================
// Intel: e1000e (I219 등) + igc (I225/I226)
// Realtek: RTL8168/8111 (1GbE), RTL8125/8126 (2.5GbE)
//
// [핵심] I225-V(igc)는 e1000e와 레지스터 오프셋이 다름!
//   e1000e: RDBAL=0x2800, RDH=0x2810, TDBAL=0x3800, TDH=0x3810
//   igc:    RDBAL=0xC000, RDH=0xC010, TDBAL=0xE000, TDH=0xE010
//   RDBAL/RDLEN은 미러링되어 old offset에서도 읽히지만
//   RDH/RDT/TDH/TDT는 igc 오프셋에서만 업데이트됨
// ============================================================================

namespace nic
{
    // ========================================================================
    // NIC Type
    // ========================================================================
    enum class nic_type_t : std::uint8_t
    {
        UNKNOWN = 0,
        INTEL = 1,
        REALTEK = 2
    };

    // [핵심] Intel NIC 서브타입 - 레지스터 오프셋 선택용
    enum class intel_gen_t : std::uint8_t
    {
        E1000E = 0,  // I219, I217, 82574L 등 (legacy offset)
        IGC = 1   // I225, I226 (new offset 0xC000/0xE000)
    };

    // ========================================================================
    // ECAM PCI Config Space
    // ========================================================================
    inline std::uint64_t ecam_base_detected = 0;

    constexpr std::uint64_t ECAM_CANDIDATES[] = {
        0xE0000000,     // Intel 대부분
        0xF0000000,     // AMD 일부
        0xC0000000,     // 구형 시스템
        0xB0000000,     // 레어 케이스
    };
    constexpr std::uint32_t ECAM_CANDIDATE_COUNT = 4;

    constexpr std::uint8_t PCI_CLASS_NETWORK = 0x02;
    constexpr std::uint8_t PCI_SUBCLASS_ETHERNET = 0x00;

    constexpr std::uint32_t PCI_VENDOR_ID = 0x00;
    constexpr std::uint32_t PCI_DEVICE_ID = 0x02;
    constexpr std::uint32_t PCI_COMMAND = 0x04;
    constexpr std::uint32_t PCI_STATUS = 0x06;
    constexpr std::uint32_t PCI_CLASS_CODE = 0x09;
    constexpr std::uint32_t PCI_HEADER_TYPE = 0x0E;
    constexpr std::uint32_t PCI_BAR0 = 0x10;
    constexpr std::uint32_t PCI_BAR1 = 0x14;

    inline std::uint64_t ecam_address(
        const std::uint8_t bus, const std::uint8_t dev,
        const std::uint8_t func, const std::uint32_t offset)
    {
        return ecam_base_detected
            + (static_cast<std::uint64_t>(bus) << 20)
            + (static_cast<std::uint64_t>(dev) << 15)
            + (static_cast<std::uint64_t>(func) << 12)
            + offset;
    }

    // ========================================================================
    // Vendor IDs
    // ========================================================================
    constexpr std::uint16_t INTEL_VENDOR_ID = 0x8086;
    constexpr std::uint16_t REALTEK_VENDOR_ID = 0x10EC;

    // ========================================================================
    // Intel Device IDs
    // ========================================================================
    constexpr std::uint16_t INTEL_I219_V = 0x15B8;
    constexpr std::uint16_t INTEL_I219_LM = 0x15B7;
    constexpr std::uint16_t INTEL_I225_V = 0x15F3;
    constexpr std::uint16_t INTEL_I225_LM = 0x15F2;
    constexpr std::uint16_t INTEL_I226_V = 0x125B;
    constexpr std::uint16_t INTEL_I226_LM = 0x125C;
    constexpr std::uint16_t INTEL_I210_T1 = 0x1533;
    constexpr std::uint16_t INTEL_I211_AT = 0x1539;
    constexpr std::uint16_t INTEL_I350_T1 = 0x1521;
    constexpr std::uint16_t INTEL_82574L = 0x10D3;

    // [핵심] I225/I226 판별 - igc 계열 레지스터 사용
    inline bool is_igc_nic(const std::uint16_t dev_id)
    {
        return dev_id == INTEL_I225_V || dev_id == INTEL_I225_LM
            || dev_id == INTEL_I226_V || dev_id == INTEL_I226_LM;
    }

    // ========================================================================
    // Intel e1000e Register Offsets (I219, I217, 82574L 등)
    // ========================================================================
    constexpr std::uint32_t INTEL_REG_CTRL = 0x0000;
    constexpr std::uint32_t INTEL_REG_STATUS = 0x0008;
    constexpr std::uint32_t INTEL_REG_CTRL_EXT = 0x0018;
    constexpr std::uint32_t INTEL_REG_ICR = 0x00C0;
    constexpr std::uint32_t INTEL_REG_IMS = 0x00D0;

    // e1000e RX (Queue 0)
    constexpr std::uint32_t INTEL_REG_RDBAL = 0x2800;
    constexpr std::uint32_t INTEL_REG_RDBAH = 0x2804;
    constexpr std::uint32_t INTEL_REG_RDLEN = 0x2808;
    constexpr std::uint32_t INTEL_REG_RDH = 0x2810;
    constexpr std::uint32_t INTEL_REG_RDT = 0x2818;
    constexpr std::uint32_t INTEL_REG_RCTL = 0x0100;

    // e1000e TX (Queue 0)
    constexpr std::uint32_t INTEL_REG_TDBAL = 0x3800;
    constexpr std::uint32_t INTEL_REG_TDBAH = 0x3804;
    constexpr std::uint32_t INTEL_REG_TDLEN = 0x3808;
    constexpr std::uint32_t INTEL_REG_TDH = 0x3810;
    constexpr std::uint32_t INTEL_REG_TDT = 0x3818;
    constexpr std::uint32_t INTEL_REG_TCTL = 0x0400;

    // ========================================================================
    // [핵심] Intel igc Register Offsets (I225-V, I226-V)
    // ========================================================================
    // igc는 0xC000/0xE000 계열 사용. RDH/TDH는 이 오프셋에서만 업데이트됨!
    // RDBAL/RDLEN은 legacy(0x2800)에서도 읽히지만 RDH는 안됨
    constexpr std::uint32_t IGC_REG_RDBAL = 0xC000;
    constexpr std::uint32_t IGC_REG_RDBAH = 0xC004;
    constexpr std::uint32_t IGC_REG_RDLEN = 0xC008;
    constexpr std::uint32_t IGC_REG_SRRCTL = 0xC00C;
    constexpr std::uint32_t IGC_REG_RDH = 0xC010;
    constexpr std::uint32_t IGC_REG_RDT = 0xC018;

    constexpr std::uint32_t IGC_REG_TDBAL = 0xE000;
    constexpr std::uint32_t IGC_REG_TDBAH = 0xE004;
    constexpr std::uint32_t IGC_REG_TDLEN = 0xE008;
    constexpr std::uint32_t IGC_REG_TDH = 0xE010;
    constexpr std::uint32_t IGC_REG_TDT = 0xE018;

    // ========================================================================
    // [핵심] IGC 전용 TX Queue 1 - OS Queue 0과 완전 격리
    // ========================================================================
    // OS 드라이버는 TX Q0(0xE000) 사용. 우리는 Q1(0xE040) 전용 사용.
    // → OS TDT 변경 0, OS 버퍼 덮어쓰기 0, stats 클리어 불필요
    //
    // TX Queue N = 0xE000 + N * 0x40:
    //   Q0: TDBAL=0xE000, TDH=0xE010, TDT=0xE018 (OS 전용 - 절대 건드리지 않음!)
    //   Q1: TDBAL=0xE040, TDH=0xE050, TDT=0xE058 (HV 전용)
    // ========================================================================

    constexpr std::uint32_t IGC_MAX_TX_QUEUES = 4;
    constexpr std::uint32_t IGC_TXQ_STRIDE = 0x40;
    constexpr std::uint32_t IGC_HV_TX_QUEUE = 1;  // 우리가 사용할 TX 큐 번호

    // TX Queue 1 레지스터 오프셋
    constexpr std::uint32_t IGC_TXQ1_TDBAL = 0xE040;
    constexpr std::uint32_t IGC_TXQ1_TDBAH = 0xE044;
    constexpr std::uint32_t IGC_TXQ1_TDLEN = 0xE048;
    constexpr std::uint32_t IGC_TXQ1_TDH = 0xE050;
    constexpr std::uint32_t IGC_TXQ1_TDT = 0xE058;

    // TX TXDCTL (Transmit Descriptor Control) per-queue
    // Q0: 0xE028, Q1: 0xE068, Q2: 0xE0A8, Q3: 0xE0E8
    constexpr std::uint32_t IGC_TXQ1_TXDCTL = 0xE068;
    constexpr std::uint32_t IGC_TXDCTL_ENABLE = (1u << 25);

    // HV 전용 TX 상태 (hidden page 기반)
    struct igc_hv_tx_state_t
    {
        std::uint64_t desc_ring_gpa;    // hidden page: TX descriptor ring GPA
        std::uint64_t data_buf_gpa;     // hidden page: TX data buffer GPA
        void* desc_ring_va;     // descriptor ring 가상주소
        void* data_buf_va;      // data buffer 가상주소
        std::uint32_t desc_count;       // descriptor 개수
        std::uint32_t our_tdt;          // 우리 TDT 인덱스
        std::uint32_t dbg_txdctl_val;   // TXDCTL 최종값 (bit25=ENABLE 확인용)
        std::uint8_t  initialized;      // 초기화 완료 여부

        // [진단 0xFB] TX 경로 디버깅 (struct 멤버 = TU간 공유 보장)
        // inline 스칼라/배열은 freestanding 링커에서 TU별 복사본 생성 → 깨짐
        // struct 멤버는 igc_hv_tx 인스턴스가 1개이므로 안전
        std::uint32_t diag_canary;      // 0xDEAD0000|frame_len (inject 진입 확인)
        std::uint32_t diag_buf_lo;      // data_buf_va low32
        std::uint32_t diag_buf_hi;      // data_buf_va high32
        std::uint32_t diag_gpa_lo;      // data_buf_gpa low32
        std::uint32_t diag_src_dw0;     // raw_frame[0:3] (source 확인)
        std::uint32_t diag_readback;    // buf[0:3] after copy (copy 확인)
        std::uint32_t diag_write_test;  // 0xAA write→read (VA 매핑 확인)

        // [0xFB+] TX 프레임 내용 진단 - 와이어에 나가는 실제 바이트
        // 공격PC에 도착 안 하면 DST MAC/IP/Port 확인 필수
        std::uint32_t diag_eth_dw0;     // frame[0:3]  = DST MAC 앞 4바이트
        std::uint32_t diag_eth_dw1;     // frame[4:7]  = DST MAC[4:5] + SRC MAC[0:1]
        std::uint32_t diag_eth_dw2;     // frame[8:11] = SRC MAC[2:5]
        std::uint32_t diag_ip_dst;      // frame[30:33] = DST IP (응답 대상)
        std::uint32_t diag_udp_ports;   // frame[34:37] = UDP src_port + dst_port
        std::uint32_t diag_our_port;    // our_src_port raw (expect 0x396F = 28473 NBO)
        std::uint32_t diag_atk_port;    // attack_src_port raw
        std::uint32_t diag_udp_raw8;    // frame[38:41] = UDP len + chksum
    };

    inline igc_hv_tx_state_t igc_hv_tx = {};

    // SRRCTL DESCTYPE bits [27:25]
    constexpr std::uint32_t IGC_SRRCTL_DESCTYPE_MASK = (7u << 25);
    constexpr std::uint32_t IGC_SRRCTL_DESCTYPE_LEGACY = (0u << 25);
    constexpr std::uint32_t IGC_SRRCTL_DESCTYPE_ADV = (1u << 25);

    // ========================================================================
    // [핵심] IGC 멀티큐 RX - 읽기 전용 폴링 (NIC 레지스터 수정 0)
    // ========================================================================
    // I225-V는 RSS로 4개 RX 큐에 패킷 분배. Queue 0만 읽으면 누락 발생.
    // 해결: 4개 큐 전부 폴링 (MRQC/RETA 수정 없이 읽기만!)
    //
    // Queue N 레지스터 = base(0xC000) + N * 0x40:
    //   Q0: RDBAL=0xC000, RDH=0xC010, RDT=0xC018
    //   Q1: RDBAL=0xC040, RDH=0xC050, RDT=0xC058
    //   Q2: RDBAL=0xC080, RDH=0xC090, RDT=0xC098
    //   Q3: RDBAL=0xC0C0, RDH=0xC0D0, RDT=0xC0D8
    // ========================================================================

    constexpr std::uint32_t IGC_MAX_RX_QUEUES = 4;
    constexpr std::uint32_t IGC_RXQ_STRIDE = 0x40;

    // 큐별 레지스터 오프셋 헬퍼 (읽기 전용!)
    inline std::uint32_t igc_rxq_rdbal(std::uint32_t q) { return 0xC000 + q * IGC_RXQ_STRIDE; }
    inline std::uint32_t igc_rxq_rdbah(std::uint32_t q) { return 0xC004 + q * IGC_RXQ_STRIDE; }
    inline std::uint32_t igc_rxq_rdlen(std::uint32_t q) { return 0xC008 + q * IGC_RXQ_STRIDE; }
    inline std::uint32_t igc_rxq_srrctl(std::uint32_t q) { return 0xC00C + q * IGC_RXQ_STRIDE; }
    inline std::uint32_t igc_rxq_rdh(std::uint32_t q) { return 0xC010 + q * IGC_RXQ_STRIDE; }
    inline std::uint32_t igc_rxq_rdt(std::uint32_t q) { return 0xC018 + q * IGC_RXQ_STRIDE; }

    // 큐별 RX 상태
    struct igc_rxq_state_t
    {
        std::uint64_t ring_gpa;         // RX ring 물리주소
        std::uint32_t count;            // descriptor 개수
        std::uint32_t our_index;        // 우리 추적 인덱스
        std::uint32_t last_known_rdt;   // 버퍼 캐시 갱신 추적용
        std::uint32_t scan_cursor;      // 0xFB: 회전 스캐너 위치 (전체 ring 순회)
        std::uint8_t  active;           // 이 큐가 유효한지
        std::uint8_t  buf_cache_valid;  // 버퍼 주소 캐시 완료 여부
    };

    inline igc_rxq_state_t  igc_rxq[IGC_MAX_RX_QUEUES] = {};
    inline std::uint32_t    igc_num_active_queues = 0;

    // 큐별 buffer address 캐시 (advanced descriptor write-back시 addr 소실 대비)
    constexpr std::uint32_t MAX_RXQ_BUF_CACHE = 1024;
    inline std::uint64_t igc_rxq_buf_cache[IGC_MAX_RX_QUEUES][MAX_RXQ_BUF_CACHE] = {};

    // MAC
    constexpr std::uint32_t INTEL_REG_RAL0 = 0x5400;
    constexpr std::uint32_t INTEL_REG_RAH0 = 0x5404;

    // ========================================================================
    // Intel TX Statistics (H3 Anti-Detection)
    // ========================================================================
    constexpr std::uint32_t INTEL_STAT_GPTC = 0x4080;
    constexpr std::uint32_t INTEL_STAT_GOTCL = 0x4090;
    constexpr std::uint32_t INTEL_STAT_GOTCH = 0x4094;
    constexpr std::uint32_t INTEL_STAT_TPT = 0x40D4;
    constexpr std::uint32_t INTEL_STAT_TOTL = 0x40D0;
    constexpr std::uint32_t INTEL_STAT_TOTH = 0x40C4;

    constexpr std::uint8_t INTEL_TX_CMD_EOP = 0x01;
    constexpr std::uint8_t INTEL_TX_CMD_IFCS = 0x02;
    constexpr std::uint8_t INTEL_TX_CMD_RS = 0x08;
    constexpr std::uint8_t INTEL_TX_STATUS_DD = 0x01;
    constexpr std::uint8_t INTEL_RX_STATUS_DD = 0x01;
    constexpr std::uint8_t INTEL_RX_STATUS_EOP = 0x02;

    // ========================================================================
    // Realtek Device IDs
    // ========================================================================
    constexpr std::uint16_t RTL8168 = 0x8168;  // RTL8111/8168 (1GbE)
    constexpr std::uint16_t RTL8136 = 0x8136;  // RTL8101/8102E (Fast Ethernet)
    constexpr std::uint16_t RTL8161 = 0x8161;  // RTL8168 variant
    constexpr std::uint16_t RTL8125 = 0x8125;  // RTL8125B (2.5GbE)
    constexpr std::uint16_t RTL8126 = 0x8126;  // RTL8126 (5GbE)

    // ========================================================================
    // Realtek Registers
    // ========================================================================

    constexpr std::uint32_t RTL_REG_IDR0 = 0x0000;
    constexpr std::uint32_t RTL_REG_IDR4 = 0x0004;
    constexpr std::uint32_t RTL_REG_TNPDS_LO = 0x0020;
    constexpr std::uint32_t RTL_REG_TNPDS_HI = 0x0024;
    constexpr std::uint32_t RTL_REG_CMD = 0x0037;
    constexpr std::uint32_t RTL_REG_TPPOLL = 0x0038;
    constexpr std::uint8_t  RTL_TPPOLL_NPQ = 0x40;
    constexpr std::uint32_t RTL_REG_TXCONFIG = 0x0040;
    constexpr std::uint32_t RTL_REG_RXCONFIG = 0x0044;
    constexpr std::uint32_t RTL_REG_IMR = 0x003C;
    constexpr std::uint32_t RTL_REG_ISR = 0x003E;
    constexpr std::uint32_t RTL_REG_RMS = 0x00DA;
    constexpr std::uint32_t RTL_REG_RDSAR_LO = 0x00E4;
    constexpr std::uint32_t RTL_REG_RDSAR_HI = 0x00E8;

    // ========================================================================
    // Realtek Descriptor Flags
    // ========================================================================
    constexpr std::uint32_t RTL_DESC_OWN = (1u << 31);
    constexpr std::uint32_t RTL_DESC_EOR = (1u << 30);
    constexpr std::uint32_t RTL_DESC_FS = (1u << 29);
    constexpr std::uint32_t RTL_DESC_LS = (1u << 28);
    constexpr std::uint32_t RTL_RX_LEN_MASK = 0x00003FFF;
    constexpr std::uint32_t RTL_TX_LEN_MASK = 0x0000FFFF;

    // ========================================================================
    // Intel Legacy Descriptors (16B) - e1000e용
    // ========================================================================
#pragma pack(push, 1)

    struct intel_rx_desc_t
    {
        std::uint64_t buffer_addr;
        std::uint16_t length;
        std::uint16_t checksum;
        std::uint8_t  status;       // bit0=DD, bit1=EOP
        std::uint8_t  errors;
        std::uint16_t special;
    };
    static_assert(sizeof(intel_rx_desc_t) == 16);

    struct intel_tx_desc_t
    {
        std::uint64_t buffer_addr;
        std::uint16_t length;
        std::uint8_t  cso;
        std::uint8_t  cmd;
        std::uint8_t  status;       // bit0=DD
        std::uint8_t  css;
        std::uint16_t special;
    };
    static_assert(sizeof(intel_tx_desc_t) == 16);

    // ========================================================================
    // [핵심] Intel Advanced RX Descriptor (16B) - I225/igc용
    // ========================================================================
    // Read Format (NIC 처리 전):
    //   [0-7]  Packet Buffer Address
    //   [8-15] Header Buffer Address
    //
    // Write-Back Format (NIC 처리 후):
    //   [0-3]  RSS Hash / Fragment Checksum
    //   [4-7]  Status/Error/PKT_TYPE info
    //   [8-11] Extended Status (bit0=DD, bit1=EOP) + Extended Error
    //   [12-15] Length[15:0] (upper 16 bits)
    //
    // buffer_addr는 write-back에서 덮어써지므로 사전 캐싱 필요!
    // ========================================================================

    // Read format - buffer address 캐싱용
    struct igc_rx_desc_read_t
    {
        std::uint64_t pkt_addr;     // Packet buffer address
        std::uint64_t hdr_addr;     // Header buffer address
    };
    static_assert(sizeof(igc_rx_desc_read_t) == 16);

    // Write-back format - 패킷 처리용
    struct igc_rx_desc_wb_t
    {
        std::uint32_t rss_hash;
        std::uint32_t info;         // SPH, HDR_LEN, PKT_TYPE etc.
        std::uint32_t staterr;      // bit0=DD, bit1=EOP, bits 4-7=errors
        std::uint16_t length;       // packet length
        std::uint16_t vlan;
    };
    static_assert(sizeof(igc_rx_desc_wb_t) == 16);

    // Advanced TX descriptor (I225/igc)
    struct igc_tx_desc_t
    {
        std::uint64_t buffer_addr;
        std::uint32_t cmd_type_len; // bit24=DEXT, bit25=RS, bit24=IFCS, bits 0-15=length
        std::uint32_t olinfo_status;
    };
    static_assert(sizeof(igc_tx_desc_t) == 16);

    // Advanced descriptor status bits
    constexpr std::uint32_t IGC_RXD_STAT_DD = 0x01;
    constexpr std::uint32_t IGC_RXD_STAT_EOP = 0x02;

    // Advanced TX cmd_type_len bits
    // [핵심] I225-V Advanced TX Data Descriptor 비트 정의
    // Linux igc_defines.h 참조: DEXT(bit29)가 반드시 1이어야 Advanced descriptor로 인식
    // DEXT=0이면 Legacy descriptor로 해석 → NIC가 DD는 세우지만 실제 전송 안 함!
    constexpr std::uint32_t IGC_TXD_DTYP_DATA = (3u << 20);  // bits[21:20]=11 = Data descriptor
    constexpr std::uint32_t IGC_TXD_CMD_EOP = (1u << 24);  // End of Packet
    constexpr std::uint32_t IGC_TXD_CMD_IFCS = (1u << 25);  // Insert FCS (CRC)
    constexpr std::uint32_t IGC_TXD_CMD_RS = (1u << 27);  // Report Status (DD 세움)
    constexpr std::uint32_t IGC_TXD_CMD_DEXT = (1u << 29);  // Descriptor Extension = Advanced!
    constexpr std::uint32_t IGC_TXD_STAT_DD = 0x01; // in olinfo_status

    // [핵심] Advanced TX descriptor의 olinfo_status 필드
    // bits[31:14] = PAYLEN: MAC이 wire에 보낼 총 패킷 크기
    // PAYLEN=0이면 NIC가 DMA read는 하지만 wire에 0바이트 전송 = 실질적 전송 안 됨!
    // Linux igc 드라이버: olinfo_status = size << IGC_ADVTXD_PAYLEN_SHIFT
    constexpr std::uint32_t IGC_TXD_PAYLEN_SHIFT = 14;

    // ========================================================================
    // Realtek Descriptors
    // ========================================================================
    struct rtl_rx_desc_t
    {
        std::uint32_t opts1;
        std::uint32_t opts2;
        std::uint32_t addr_lo;
        std::uint32_t addr_hi;
    };
    static_assert(sizeof(rtl_rx_desc_t) == 16);

    struct rtl_tx_desc_t
    {
        std::uint32_t opts1;
        std::uint32_t opts2;
        std::uint32_t addr_lo;
        std::uint32_t addr_hi;
    };
    static_assert(sizeof(rtl_tx_desc_t) == 16);

    struct rtl_rx_desc_32_t
    {
        std::uint32_t opts1;
        std::uint32_t opts2;
        std::uint32_t addr_lo;
        std::uint32_t addr_hi;
        std::uint32_t rss_lo;
        std::uint32_t rss_hi;
        std::uint32_t opts3;
        std::uint32_t opts4;
    };
    static_assert(sizeof(rtl_rx_desc_32_t) == 32);

    struct rtl_tx_desc_32_t
    {
        std::uint32_t opts1;
        std::uint32_t opts2;
        std::uint32_t addr_lo;
        std::uint32_t addr_hi;
        std::uint32_t opts3;
        std::uint32_t opts4;
        std::uint32_t reserved1;
        std::uint32_t reserved2;
    };
    static_assert(sizeof(rtl_tx_desc_32_t) == 32);

#pragma pack(pop)

    constexpr std::uint32_t RTL_MAX_RING_SCAN = 4096;

    // ========================================================================
    // NIC State
    // ========================================================================
    struct nic_state_t
    {
        nic_type_t    nic_type;
        intel_gen_t   intel_gen;    // [핵심] e1000e vs igc 구분

        std::uint8_t  bus;
        std::uint8_t  dev;
        std::uint8_t  func;
        std::uint16_t vendor_id;
        std::uint16_t device_id;

        std::uint64_t mmio_base_gpa;

        // RX ring
        std::uint64_t rx_ring_gpa;
        std::uint32_t rx_ring_len;
        std::uint32_t rx_count;

        // TX ring
        std::uint64_t tx_ring_gpa;
        std::uint32_t tx_ring_len;
        std::uint32_t tx_count;

        std::uint32_t our_rx_index;
        std::uint32_t our_tx_index;

        std::uint32_t rtl_desc_stride;  // 16 or 32

        // [핵심] igc advanced descriptor 여부
        std::uint8_t  use_adv_desc;     // 1=advanced(igc), 0=legacy(e1000e)

        // MAC
        std::uint8_t  mac[6];

        std::uint8_t  attack_mac[6];
        std::uint8_t  attack_mac_learned;
        std::uint32_t attack_ip;

        std::uint8_t  initialized;
    };

    // ========================================================================
    // [핵심] 레지스터 오프셋 헬퍼 - e1000e vs igc 자동 선택
    // ========================================================================
    inline std::uint32_t reg_rdh(const nic_state_t& s)
    {
        return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_RDH : INTEL_REG_RDH;
    }

    inline std::uint32_t reg_rdt(const nic_state_t& s)
    {
        return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_RDT : INTEL_REG_RDT;
    }

    inline std::uint32_t reg_tdh(const nic_state_t& s)
    {
        return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_TDH : INTEL_REG_TDH;
    }

    inline std::uint32_t reg_tdt(const nic_state_t& s)
    {
        return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_TDT : INTEL_REG_TDT;
    }

    inline std::uint32_t reg_rdbal(const nic_state_t& s)
    {
        return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_RDBAL : INTEL_REG_RDBAL;
    }

    inline std::uint32_t reg_rdbah(const nic_state_t& s)
    {
        return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_RDBAH : INTEL_REG_RDBAH;
    }

    inline std::uint32_t reg_rdlen(const nic_state_t& s)
    {
        return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_RDLEN : INTEL_REG_RDLEN;
    }

    inline std::uint32_t reg_tdbal(const nic_state_t& s)
    {
        return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_TDBAL : INTEL_REG_TDBAL;
    }

    inline std::uint32_t reg_tdbah(const nic_state_t& s)
    {
        return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_TDBAH : INTEL_REG_TDBAH;
    }

    inline std::uint32_t reg_tdlen(const nic_state_t& s)
    {
        return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_TDLEN : INTEL_REG_TDLEN;
    }

    // ========================================================================
    // [핵심] VA→GPA 변환 - 힙 할당 페이지의 물리주소 계산
    // ========================================================================
    // HV 힙은 연속 물리 메모리를 선형 매핑:
    //   map_host_physical(heap_phys_base) → heap_va_base
    //   offset = heap_va_base - heap_phys_base (상수)
    //   PA = VA - offset
    //
    // entry_point()에서 한번 계산 후 모든 힙 VA에 적용 가능.
    // 용도: TX Queue 1 전용 descriptor ring + data buffer의 GPA 계산
    //       → NIC TDBAL/TDBAH에 GPA를 써야 하므로 필수
    // ========================================================================
    inline std::int64_t  heap_va_to_pa_offset = 0;  // VA - PA
    inline std::uint8_t  heap_va_pa_valid = 0;       // 초기화 완료 여부

    // VA→GPA 변환 (힙 할당 페이지 전용)
    inline std::uint64_t va_to_gpa(const void* va)
    {
        return static_cast<std::uint64_t>(
            static_cast<std::int64_t>(reinterpret_cast<std::uint64_t>(va))
            - heap_va_to_pa_offset);
    }

    // Functions
    // ========================================================================
    std::uint32_t read_reg(const void* slat_cr3, std::uint32_t offset);
    void write_reg(const void* slat_cr3, std::uint32_t offset, std::uint32_t value);
    std::uint8_t read_reg8(const void* slat_cr3, std::uint32_t offset);
    void write_reg8(const void* slat_cr3, std::uint32_t offset, std::uint8_t value);

    inline bool is_rtl_25g_or_higher(const std::uint16_t dev_id)
    {
        return dev_id == RTL8125 || dev_id == RTL8126;
    }

    inline nic_state_t state = {};

    // ========================================================================
    // [핵심] RX buffer address cache - igc advanced descriptor용
    // ========================================================================
    // Advanced write-back에서 buffer_addr가 RSS hash로 덮어써지므로
    // read format에서 미리 캐싱해둬야 함. 최대 1024개.
    constexpr std::uint32_t MAX_RX_BUF_CACHE = 1024;
    inline std::uint64_t rx_buf_cache[MAX_RX_BUF_CACHE] = {};
    inline std::uint8_t rx_buf_cache_valid = 0;

    // ========================================================================
    // TX Stats Clear
    // ========================================================================
    inline void clear_tx_stats_intel(const void* slat_cr3_ptr)
    {
        (void)read_reg(slat_cr3_ptr, INTEL_STAT_GPTC);
        (void)read_reg(slat_cr3_ptr, INTEL_STAT_GOTCL);
        (void)read_reg(slat_cr3_ptr, INTEL_STAT_GOTCH);
        (void)read_reg(slat_cr3_ptr, INTEL_STAT_TPT);
        (void)read_reg(slat_cr3_ptr, INTEL_STAT_TOTL);
        (void)read_reg(slat_cr3_ptr, INTEL_STAT_TOTH);
    }

    constexpr std::uint32_t RTL_REG_DTCCR_LO = 0x0010;
    constexpr std::uint32_t RTL_REG_DTCCR_HI = 0x0014;

    inline void clear_tx_stats_realtek(const void* slat_cr3_ptr)
    {
        std::uint32_t dtccr_lo = read_reg(slat_cr3_ptr, RTL_REG_DTCCR_LO);
        std::uint32_t dtccr_hi = read_reg(slat_cr3_ptr, RTL_REG_DTCCR_HI);

        if ((dtccr_lo & ~0xFu) != 0 || dtccr_hi != 0)
        {
            write_reg(slat_cr3_ptr, RTL_REG_DTCCR_HI, dtccr_hi);
            write_reg(slat_cr3_ptr, RTL_REG_DTCCR_LO, (dtccr_lo & ~0xF) | 0x09);
        }
    }

    inline void clear_tx_stats(const void* slat_cr3_ptr)
    {
        if (state.nic_type == nic_type_t::INTEL)
            clear_tx_stats_intel(slat_cr3_ptr);
        else if (state.nic_type == nic_type_t::REALTEK)
            clear_tx_stats_realtek(slat_cr3_ptr);
    }

    std::uint8_t discover_nic(const void* slat_cr3);
    std::uint8_t read_ring_config(const void* slat_cr3);
    void read_mac(const void* slat_cr3);
    void cache_rx_buf_addrs(const void* slat_cr3); // [핵심] buffer address 캐싱

    // [핵심] IGC 멀티큐 초기화 - 4개 RX 큐 설정 로드 (읽기 전용!)
    std::uint8_t read_igc_multi_queue_config(const void* slat_cr3);
    void cache_igc_queue_buf_addrs(const void* slat_cr3, std::uint32_t queue_idx);
    void refresh_igc_queue_buf_cache(const void* slat_cr3, std::uint32_t queue_idx);

    // [핵심] IGC 전용 TX Queue 1 초기화 - hidden page 할당 + NIC 설정
    std::uint8_t setup_igc_hv_tx_queue(const void* slat_cr3);

    // [FIX] OPEN 수신 시 TX ring 리셋 - 취소 후 ring stuck 방지
    // 클라이언트 취소 → TX ring full (TDT==TDH, DD 미클리어) → 재연결 불가
    void reset_tx_ring(const void* slat_cr3);
}