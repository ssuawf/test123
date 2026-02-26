#pragma once
#include <cstdint>

// ============================================================================
// Network Module - NIC Ring-1 DMA Communication (Production)
// ============================================================================
// UDP-based DMA protocol over onboard NIC.
// HV polls RX ring for DMA requests, sends responses via TX Q1.
// All diagnostic/debug variables removed for zero AC detection surface.
//
// Stats Shadow: hv_tx_interval_* track Q1 TX contribution since last
// stats page refresh. mmio_intercept subtracts these from NIC global
// stats registers (GPTC, GOTCL etc) so OS/AC sees only Q0 traffic.
// ============================================================================

namespace network
{
    // NIC discovery + RX/TX ring setup
    void set_up();

    // Per-VMEXIT: poll RX ring for DMA requests, process and respond
    std::uint8_t process_pending();

    // Send DMA response via TX ring
    std::uint8_t send_response(const std::uint8_t* dma_response, std::uint32_t size);

    // Send raw packet
    std::uint8_t send_packet(const std::uint8_t* data, std::uint32_t size);

    // Core state
    inline std::uint8_t is_initialized = 0;
    inline std::uint64_t attack_pc_identifier = 0;

    // Packet counters (functional, not debug)
    inline std::uint64_t packets_received = 0;
    inline std::uint64_t packets_sent = 0;
    inline std::uint64_t packets_dropped = 0;

    // ========================================================================
    // Stats Shadow Tracking
    // ========================================================================
    // Tracks Q1 TX and HV-consumed RX contribution since last shadow refresh.
    // On NPF for BAR0+0x4000 page, mmio_intercept reads real NIC stats,
    // subtracts these values, then resets to 0.
    // This hides HV DMA traffic from OS/AC monitoring NIC stats.
    //
    // TX tracking (Q1 packets sent by HV):
    //   hv_tx_interval_packets -> subtracted from GPTC, TPT
    //   hv_tx_interval_bytes   -> subtracted from GOTCL/H, TOTL/H
    //
    // RX tracking (DMA packets consumed by HV from Q0):
    //   hv_rx_interval_packets -> subtracted from GPRC, TPR
    //   hv_rx_interval_bytes   -> subtracted from GORCL/H, TORL/H
    // ========================================================================
    inline volatile std::uint32_t hv_tx_interval_packets = 0;
    inline volatile std::uint64_t hv_tx_interval_bytes = 0;
    inline volatile std::uint32_t hv_rx_interval_packets = 0;
    inline volatile std::uint64_t hv_rx_interval_bytes = 0;
}