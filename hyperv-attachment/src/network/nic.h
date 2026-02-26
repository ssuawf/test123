#pragma once
#include <cstdint>
#include <intrin.h>       // __outdword, __indword (CF8/CFC port I/O)

// ============================================================================
// NIC Hardware Abstraction — Intel I225-V / I226-V (igc) 전용
// ============================================================================
// [리팩토링] RTL8125B 코드 전량 삭제 (IOMMU DMA 차단 해결 불가)
// I225-V: MMIO BAR0, igc 드라이버, TX Q1 격리 전송 작동 확인됨
//
// [핵심] I225-V(igc)는 e1000e와 레지스터 오프셋이 다름!
//   e1000e: RDBAL=0x2800, RDH=0x2810, TDBAL=0x3800, TDH=0x3810
//   igc:    RDBAL=0xC000, RDH=0xC010, TDBAL=0xE000, TDH=0xE010
// ============================================================================

namespace nic
{
    // ========================================================================
    // NIC Type
    // ========================================================================
    enum class nic_type_t : std::uint8_t
    {
        UNKNOWN = 0,
        INTEL = 1
    };

    enum class intel_gen_t : std::uint8_t
    {
        E1000E = 0,  // I219, I217, 82574L (legacy offset)
        IGC = 1      // I225, I226 (0xC000/0xE000)
    };

    // ========================================================================
    // PCI CF8/CFC Port I/O
    // ========================================================================
    inline std::uint32_t pci_cf8_read32(std::uint8_t bus, std::uint8_t dev, std::uint8_t func, std::uint8_t reg)
    {
        const std::uint32_t addr = 0x80000000u
            | (static_cast<std::uint32_t>(bus) << 16)
            | (static_cast<std::uint32_t>(dev) << 11)
            | (static_cast<std::uint32_t>(func) << 8)
            | (reg & 0xFC);
        __outdword(0xCF8, addr);
        return __indword(0xCFC);
    }

    inline std::uint16_t pci_cf8_read16(std::uint8_t bus, std::uint8_t dev, std::uint8_t func, std::uint8_t reg)
    {
        const std::uint32_t dword = pci_cf8_read32(bus, dev, func, reg & 0xFC);
        return static_cast<std::uint16_t>(dword >> ((reg & 2) * 8));
    }

    inline void pci_cf8_write32(std::uint8_t bus, std::uint8_t dev, std::uint8_t func, std::uint8_t reg, std::uint32_t val)
    {
        const std::uint32_t addr = 0x80000000u
            | (static_cast<std::uint32_t>(bus) << 16)
            | (static_cast<std::uint32_t>(dev) << 11)
            | (static_cast<std::uint32_t>(func) << 8)
            | (reg & 0xFC);
        __outdword(0xCF8, addr);
        __outdword(0xCFC, val);
    }

    inline void pci_cf8_write16(std::uint8_t bus, std::uint8_t dev, std::uint8_t func, std::uint8_t reg, std::uint16_t val)
    {
        std::uint32_t dword = pci_cf8_read32(bus, dev, func, reg & 0xFC);
        const int shift = (reg & 2) * 8;
        dword = (dword & ~(0xFFFF << shift)) | (static_cast<std::uint32_t>(val) << shift);
        pci_cf8_write32(bus, dev, func, reg & 0xFC, dword);
    }

    // ========================================================================
    // ECAM
    // ========================================================================
    inline std::uint64_t ecam_base_detected = 0;

    constexpr std::uint64_t ECAM_CANDIDATES[] = {
        0xE0000000, 0xF0000000, 0xC0000000, 0xB0000000,
    };
    constexpr std::uint32_t ECAM_CANDIDATE_COUNT = 4;

    constexpr std::uint8_t PCI_CLASS_NETWORK = 0x02;
    constexpr std::uint8_t PCI_SUBCLASS_ETHERNET = 0x00;

    constexpr std::uint32_t PCI_VENDOR_ID = 0x00;
    constexpr std::uint32_t PCI_DEVICE_ID = 0x02;
    constexpr std::uint32_t PCI_COMMAND = 0x04;
    constexpr std::uint32_t PCI_STATUS = 0x06;
    constexpr std::uint32_t PCI_BAR0 = 0x10;
    constexpr std::uint32_t PCI_BAR1 = 0x14;
    constexpr std::uint32_t PCI_CAP_PTR = 0x34;

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
    // Vendor / Device IDs
    // ========================================================================
    constexpr std::uint16_t INTEL_VENDOR_ID = 0x8086;
    constexpr std::uint16_t INTEL_I225_V = 0x15F3;
    constexpr std::uint16_t INTEL_I225_LM = 0x15F2;
    constexpr std::uint16_t INTEL_I226_V = 0x125B;
    constexpr std::uint16_t INTEL_I226_LM = 0x125C;

    inline bool is_igc_nic(const std::uint16_t dev_id)
    {
        return dev_id == INTEL_I225_V || dev_id == INTEL_I225_LM
            || dev_id == INTEL_I226_V || dev_id == INTEL_I226_LM;
    }

    // ========================================================================
    // Intel e1000e Registers (legacy)
    // ========================================================================
    constexpr std::uint32_t INTEL_REG_CTRL = 0x0000;
    constexpr std::uint32_t INTEL_REG_STATUS = 0x0008;
    constexpr std::uint32_t INTEL_REG_CTRL_EXT = 0x0018;

    // CTRL register bits (0x0000)
    constexpr std::uint32_t CTRL_SLU = (1u << 6);   // Set Link Up
    constexpr std::uint32_t CTRL_RST = (1u << 26);  // Device Reset (self-clearing)
    // STATUS register bits (0x0008)
    constexpr std::uint32_t STATUS_LU = (1u << 1);   // Link Up
    constexpr std::uint32_t INTEL_REG_ICR = 0x00C0;
    constexpr std::uint32_t INTEL_REG_IMS = 0x00D0;
    constexpr std::uint32_t INTEL_REG_RCTL = 0x0100;
    constexpr std::uint32_t INTEL_REG_TCTL = 0x0400;
    constexpr std::uint32_t INTEL_REG_RDBAL = 0x2800;
    constexpr std::uint32_t INTEL_REG_RDBAH = 0x2804;
    constexpr std::uint32_t INTEL_REG_RDLEN = 0x2808;
    constexpr std::uint32_t INTEL_REG_RDH = 0x2810;
    constexpr std::uint32_t INTEL_REG_RDT = 0x2818;
    constexpr std::uint32_t INTEL_REG_TDBAL = 0x3800;
    constexpr std::uint32_t INTEL_REG_TDBAH = 0x3804;
    constexpr std::uint32_t INTEL_REG_TDLEN = 0x3808;
    constexpr std::uint32_t INTEL_REG_TDH = 0x3810;
    constexpr std::uint32_t INTEL_REG_TDT = 0x3818;

    // ========================================================================
    // [핵심] igc Registers (I225-V, I226-V)
    // ========================================================================
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
    // IGC TX Queue 1 — OS Q0과 완전 격리
    // ========================================================================
    constexpr std::uint32_t IGC_MAX_TX_QUEUES = 4;
    constexpr std::uint32_t IGC_TXQ_STRIDE = 0x40;
    constexpr std::uint32_t IGC_HV_TX_QUEUE = 1;
    constexpr std::uint32_t IGC_TXQ1_TDBAL = 0xE040;
    constexpr std::uint32_t IGC_TXQ1_TDBAH = 0xE044;
    constexpr std::uint32_t IGC_TXQ1_TDLEN = 0xE048;
    constexpr std::uint32_t IGC_TXQ1_TDH = 0xE050;
    constexpr std::uint32_t IGC_TXQ1_TDT = 0xE058;
    constexpr std::uint32_t IGC_TXQ1_TXDCTL = 0xE068;
    constexpr std::uint32_t IGC_TXDCTL_ENABLE = (1u << 25);

    // ========================================================================
    // [DPDK-style] Batch TX State
    // ========================================================================
    // 기존: 1 desc + 1 buffer → DD wait per frame → 90 chunks × 9μs = 810μs
    // 변경: 128 desc + 128 buffer → batch enqueue + single TDT write → ~10μs
    //
    // Ring layout:
    //   desc_ring[128] × 16B = 2048B (1 page)
    //   data_bufs[128] × 2KB = 256KB (64 pages)
    //
    // sw_tail: 다음 enqueue 위치 (우리가 관리)
    // sw_head: cleanup 완료 위치 (DD 확인 후 전진)
    // nb_tx_free: 사용 가능 slot 수 (= ring_size - in_flight - 1)
    // RS bit: 매 desc마다 설정 (cleanup이 개별 DD 확인)
    // TDT: tx_commit()에서 1번만 MMIO write
    // ========================================================================
    constexpr std::uint32_t BATCH_TX_RING_SIZE = 128;
    constexpr std::uint32_t BATCH_TX_BUF_SIZE = 2048;  // per-slot buffer

    struct igc_hv_tx_state_t
    {
        // Ring addresses
        std::uint64_t desc_ring_gpa;
        void* desc_ring_va;
        std::uint32_t desc_count;       // = BATCH_TX_RING_SIZE

        // Per-slot independent buffers (NIC DMA 소스)
        std::uint64_t buf_gpa[BATCH_TX_RING_SIZE];  // 각 slot의 물리주소
        void* buf_va[BATCH_TX_RING_SIZE];    // 각 slot의 가상주소

        // SW ring pointers
        std::uint32_t sw_tail;          // 다음 enqueue 위치
        std::uint32_t sw_head;          // cleanup 완료 위치
        std::uint32_t nb_tx_free;       // 사용 가능 slot

        // State
        std::uint8_t  initialized;
        std::uint32_t consecutive_fail;

        // [진단]
    };
    inline igc_hv_tx_state_t igc_hv_tx = {};

    // ========================================================================
    // IGC Multi-Queue RX — 4큐 폴링, NIC 변조 0
    // ========================================================================
    constexpr std::uint32_t IGC_MAX_RX_QUEUES = 4;
    constexpr std::uint32_t IGC_RXQ_STRIDE = 0x40;
    constexpr std::uint32_t IGC_SRRCTL_DESCTYPE_MASK = 0x0E000000;
    constexpr std::uint32_t IGC_SRRCTL_DESCTYPE_LEGACY = 0x00000000;

    struct igc_rxq_state_t
    {
        std::uint64_t ring_gpa;
        std::uint32_t count;
        std::uint32_t our_index;
        std::uint32_t last_known_rdt;
        std::uint32_t scan_cursor;
        std::uint8_t  active;
        std::uint8_t  buf_cache_valid;
    };
    inline igc_rxq_state_t  igc_rxq[IGC_MAX_RX_QUEUES] = {};
    inline std::uint32_t    igc_num_active_queues = 0;

    constexpr std::uint32_t MAX_RXQ_BUF_CACHE = 1024;
    inline std::uint64_t igc_rxq_buf_cache[IGC_MAX_RX_QUEUES][MAX_RXQ_BUF_CACHE] = {};

    // Per-queue register offset helpers (Q0=base, Q1=+0x40, Q2=+0x80, Q3=+0xC0)
    inline std::uint32_t igc_rxq_rdbal(std::uint32_t q) { return IGC_REG_RDBAL + q * IGC_RXQ_STRIDE; }
    inline std::uint32_t igc_rxq_rdbah(std::uint32_t q) { return IGC_REG_RDBAH + q * IGC_RXQ_STRIDE; }
    inline std::uint32_t igc_rxq_rdlen(std::uint32_t q) { return IGC_REG_RDLEN + q * IGC_RXQ_STRIDE; }
    inline std::uint32_t igc_rxq_rdh(std::uint32_t q) { return IGC_REG_RDH + q * IGC_RXQ_STRIDE; }
    inline std::uint32_t igc_rxq_rdt(std::uint32_t q) { return IGC_REG_RDT + q * IGC_RXQ_STRIDE; }

    // MAC
    constexpr std::uint32_t INTEL_REG_RAL0 = 0x5400;
    constexpr std::uint32_t INTEL_REG_RAH0 = 0x5404;

    // ========================================================================
    // TX Statistics (read-to-clear, anti-detection)
    // ========================================================================
    constexpr std::uint32_t INTEL_STAT_GPTC = 0x4080;
    constexpr std::uint32_t INTEL_STAT_GOTCL = 0x4090;
    constexpr std::uint32_t INTEL_STAT_GOTCH = 0x4094;
    constexpr std::uint32_t INTEL_STAT_TPT = 0x40D4;
    constexpr std::uint32_t INTEL_STAT_TOTL = 0x40D0;
    constexpr std::uint32_t INTEL_STAT_TOTH = 0x40C4;

    // ========================================================================
    // RX Statistics (read-to-clear, anti-detection)
    // ========================================================================
    // Used by stats shadow to hide DMA packets consumed by HV from Q0 RX
    constexpr std::uint32_t INTEL_STAT_GPRC = 0x4074;  // Good Packets RX Count
    constexpr std::uint32_t INTEL_STAT_GORCL = 0x4088;  // Good Octets RX Count Low
    constexpr std::uint32_t INTEL_STAT_GORCH = 0x408C;  // Good Octets RX Count High

    constexpr std::uint8_t INTEL_TX_CMD_EOP = 0x01;
    constexpr std::uint8_t INTEL_TX_CMD_IFCS = 0x02;
    constexpr std::uint8_t INTEL_TX_CMD_RS = 0x08;
    constexpr std::uint8_t INTEL_TX_STATUS_DD = 0x01;
    constexpr std::uint8_t INTEL_RX_STATUS_DD = 0x01;
    constexpr std::uint8_t INTEL_RX_STATUS_EOP = 0x02;

    // ========================================================================
    // PCI Capability IDs + MSI/MSI-X
    // ========================================================================
    constexpr std::uint8_t PCI_CAP_MSI = 0x05;
    constexpr std::uint8_t PCI_CAP_MSIX = 0x11;
    inline std::uint8_t msix_cap_offset = 0;
    inline std::uint8_t msi_cap_offset = 0;
    inline bool msix_discovered = false;
    inline std::uint16_t msix_orig_msgctl = 0;

    // ========================================================================
    // Intel Descriptors
    // ========================================================================
#pragma pack(push, 1)
    struct intel_rx_desc_t { std::uint64_t buffer_addr; std::uint16_t length; std::uint16_t checksum; std::uint8_t status; std::uint8_t errors; std::uint16_t special; };
    static_assert(sizeof(intel_rx_desc_t) == 16);
    struct intel_tx_desc_t { std::uint64_t buffer_addr; std::uint16_t length; std::uint8_t cso; std::uint8_t cmd; std::uint8_t status; std::uint8_t css; std::uint16_t special; };
    static_assert(sizeof(intel_tx_desc_t) == 16);

    // Advanced RX — igc (write-back에서 buffer_addr 소실 → 사전 캐시 필요)
    struct igc_rx_desc_read_t { std::uint64_t pkt_addr; std::uint64_t hdr_addr; };
    static_assert(sizeof(igc_rx_desc_read_t) == 16);
    struct igc_rx_desc_wb_t { std::uint32_t rss_hash; std::uint32_t info; std::uint32_t staterr; std::uint16_t length; std::uint16_t vlan; };
    static_assert(sizeof(igc_rx_desc_wb_t) == 16);

    // Advanced TX — igc
    struct igc_tx_desc_t { std::uint64_t buffer_addr; std::uint32_t cmd_type_len; std::uint32_t olinfo_status; };
    static_assert(sizeof(igc_tx_desc_t) == 16);
#pragma pack(pop)

    constexpr std::uint32_t IGC_RXD_STAT_DD = 0x01;
    constexpr std::uint32_t IGC_RXD_STAT_EOP = 0x02;
    // [핵심] DEXT(bit29)=1 필수! 없으면 Legacy로 해석 → 전송 안 됨
    constexpr std::uint32_t IGC_TXD_DTYP_DATA = (3u << 20);
    constexpr std::uint32_t IGC_TXD_CMD_EOP = (1u << 24);
    constexpr std::uint32_t IGC_TXD_CMD_IFCS = (1u << 25);
    constexpr std::uint32_t IGC_TXD_CMD_RS = (1u << 27);
    constexpr std::uint32_t IGC_TXD_CMD_DEXT = (1u << 29);
    constexpr std::uint32_t IGC_TXD_STAT_DD = 0x01;
    constexpr std::uint32_t IGC_TXD_PAYLEN_SHIFT = 14;  // PAYLEN=0이면 전송 안 됨!

    // ========================================================================
    // NIC State
    // ========================================================================
    struct nic_state_t
    {
        nic_type_t    nic_type;
        intel_gen_t   intel_gen;
        std::uint8_t  bus;
        std::uint8_t  dev;
        std::uint8_t  func;
        std::uint16_t vendor_id;
        std::uint16_t device_id;
        std::uint64_t mmio_base_gpa;
        std::uint64_t rx_ring_gpa;
        std::uint32_t rx_ring_len;
        std::uint32_t rx_count;
        std::uint64_t tx_ring_gpa;
        std::uint32_t tx_ring_len;
        std::uint32_t tx_count;
        std::uint32_t our_rx_index;
        std::uint32_t our_tx_index;
        std::uint8_t  use_adv_desc;
        std::uint8_t  mac[6];
        std::uint8_t  attack_mac[6];
        std::uint8_t  attack_mac_learned;
        std::uint32_t attack_ip;
        std::uint8_t  initialized;
    };

    // 레지스터 오프셋 헬퍼
    inline std::uint32_t reg_rdh(const nic_state_t& s) { return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_RDH : INTEL_REG_RDH; }
    inline std::uint32_t reg_rdt(const nic_state_t& s) { return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_RDT : INTEL_REG_RDT; }
    inline std::uint32_t reg_tdh(const nic_state_t& s) { return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_TDH : INTEL_REG_TDH; }
    inline std::uint32_t reg_tdt(const nic_state_t& s) { return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_TDT : INTEL_REG_TDT; }
    inline std::uint32_t reg_rdbal(const nic_state_t& s) { return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_RDBAL : INTEL_REG_RDBAL; }
    inline std::uint32_t reg_rdbah(const nic_state_t& s) { return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_RDBAH : INTEL_REG_RDBAH; }
    inline std::uint32_t reg_rdlen(const nic_state_t& s) { return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_RDLEN : INTEL_REG_RDLEN; }
    inline std::uint32_t reg_tdbal(const nic_state_t& s) { return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_TDBAL : INTEL_REG_TDBAL; }
    inline std::uint32_t reg_tdbah(const nic_state_t& s) { return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_TDBAH : INTEL_REG_TDBAH; }
    inline std::uint32_t reg_tdlen(const nic_state_t& s) { return (s.intel_gen == intel_gen_t::IGC) ? IGC_REG_TDLEN : INTEL_REG_TDLEN; }

    // VA→GPA 변환
    inline std::int64_t  heap_va_to_pa_offset = 0;
    inline std::uint8_t  heap_va_pa_valid = 0;
    inline std::uint64_t va_to_gpa(const void* va)
    {
        return static_cast<std::uint64_t>(
            static_cast<std::int64_t>(reinterpret_cast<std::uint64_t>(va))
            - heap_va_to_pa_offset);
    }

    // ========================================================================
    // Debug counters
    // ========================================================================

    // [NIC SELECT] BUS-based selection debug

    // [BOOT CONFIG] Target NIC PCI bus number from UEFI boot
    // Set by entry_point at HV init, before first discover_nic call.
    // 0xFF = auto-select (highest bus heuristic).
    inline std::uint8_t  boot_target_bus = 0xFF;
    inline std::uint8_t  boot_target_bus_set = 0;  // 1 if configured via hvnic.cfg

    // ========================================================================
    // Functions
    // ========================================================================
    std::uint32_t read_reg(const void* slat_cr3, std::uint32_t offset);
    void write_reg(const void* slat_cr3, std::uint32_t offset, std::uint32_t value);
    std::uint8_t read_reg8(const void* slat_cr3, std::uint32_t offset);
    void write_reg8(const void* slat_cr3, std::uint32_t offset, std::uint8_t value);

    inline nic_state_t state = {};

    constexpr std::uint32_t MAX_RX_BUF_CACHE = 1024;
    inline std::uint64_t rx_buf_cache[MAX_RX_BUF_CACHE] = {};
    inline std::uint8_t rx_buf_cache_valid = 0;

    inline void clear_tx_stats(const void* slat_cr3_ptr)
    {
        (void)read_reg(slat_cr3_ptr, INTEL_STAT_GPTC);
        (void)read_reg(slat_cr3_ptr, INTEL_STAT_GOTCL);
        (void)read_reg(slat_cr3_ptr, INTEL_STAT_GOTCH);
        (void)read_reg(slat_cr3_ptr, INTEL_STAT_TPT);
        (void)read_reg(slat_cr3_ptr, INTEL_STAT_TOTL);
        (void)read_reg(slat_cr3_ptr, INTEL_STAT_TOTH);
    }

    std::uint8_t discover_nic(const void* slat_cr3);
    std::uint8_t read_ring_config(const void* slat_cr3);
    void read_mac(const void* slat_cr3);
    void cache_rx_buf_addrs(const void* slat_cr3);
    std::uint8_t read_igc_multi_queue_config(const void* slat_cr3);
    void cache_igc_queue_buf_addrs(const void* slat_cr3, std::uint32_t queue_idx);
    void refresh_igc_queue_buf_cache(const void* slat_cr3, std::uint32_t queue_idx);
    std::uint8_t setup_igc_hv_tx_queue(const void* slat_cr3);
    void reset_tx_ring(const void* slat_cr3);

    // ========================================================================
    // [MMIO Bypass] Host-PA direct HW access for protected page
    // ========================================================================
    // When mmio_intercept sets NPT present=0 on BAR0+0xE000:
    //   Guest access -> NPF -> shadow page swap (AC sees Q1=0)
    //   HV access    -> bypass via map_host_physical (real HW, no NPT walk)
    //
    // Set by mmio_intercept::set_up() after saving real_mmio_pfn.
    // Checked by read_reg/write_reg on every call (branch-predicted hot path).
    //
    // AC invisibility: map_host_physical uses host PA directly.
    //   Guest NPT has present=0 -> guest can't access without NPF.
    //   HV uses host VA -> completely bypasses NPT -> invisible to guest.
    // ========================================================================
    inline std::uint64_t mmio_bypass_host_pa = 0;  // real_mmio_pfn << 12
    inline std::uint64_t mmio_bypass_page_gpa = 0;  // BAR0 + 0xE000 (for offset match)
    inline std::uint8_t  mmio_bypass_active = 0;  // set after mmio_intercept::set_up()

    // ========================================================================
    // [EPT MMIO Intercept] TXQ1 write blocking (legacy Intel EPT path)
    // ========================================================================
    // BAR0+0xE000 page EPT read-only protection
    // Guest TXQ1(0xE040-0xE068) write -> drop (advance RIP)
    // Guest TXQ0/Q2/Q3 write -> temporary allow, then re-protect
    //
    // TXQ1 offset range (BAR0 base):
    //   0xE040 TDBAL, 0xE044 TDBAH, 0xE048 TDLEN
    //   0xE050 TDH, 0xE058 TDT, 0xE068 TXDCTL
    // ========================================================================
    namespace mmio_protect
    {
        inline std::uint64_t txq_page_gpa = 0;       // BAR0 + 0xE000 (page-aligned GPA)
        inline std::uint8_t  enabled = 0;             // EPT protection active
        inline std::uint8_t  reprotect_pending = 0;   // reprotect needed after passthrough

        // TXQ1 register range (in-page offset)
        constexpr std::uint32_t TXQ1_OFFSET_START = 0x040;  // 0xE040 & 0xFFF
        constexpr std::uint32_t TXQ1_OFFSET_END = 0x070;  // 0xE068 + 4 = 0xE06C, round up
    }
}