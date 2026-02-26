#pragma once
#include <cstdint>

// ============================================================================
// Ethernet/IP/UDP  
// ============================================================================
//
// [ ]
// [Ethernet 14B] [IP 20B] [UDP 8B] [DMA Payload ...]
//
//  : 14 + 20 + 8 = 42
// DMA  UDP   (: 28473)
//
// [ UDP?]
// -    (TCP     )
// - :   
// - DMA   / 
//
// [] LeechCore (PC) TCP ,
// HV  PC  UDP .
//  UDP  ! (TCP  Ring -1  )
// ============================================================================

namespace packet
{
    //    (Ethernet MTU )
    // : jumbo frame .  MTU 1500 .
    constexpr std::uint32_t MAX_PACKET_SIZE = 1514;     // ETH(14) + MTU(1500)
    constexpr std::uint32_t MAX_PAYLOAD_SIZE = 1458;     // MTU(1500) - IP(20) - UDP(8) - ETH excluded
    constexpr std::uint32_t HEADER_SIZE = 42;       // ETH(14) + IP(20) + UDP(8)

    // ========================================================================
    // Ethernet Header (14B)
    // ========================================================================
#pragma pack(push, 1)

    struct eth_hdr_t
    {
        std::uint8_t  dst_mac[6];       //  MAC
        std::uint8_t  src_mac[6];       //  MAC
        std::uint16_t ethertype;        // 0x0800 = IPv4
    };
    static_assert(sizeof(eth_hdr_t) == 14);

    constexpr std::uint16_t ETHERTYPE_IPV4 = 0x0008;    //    ()

    // ========================================================================
    // IPv4 Header (20B,  )
    // ========================================================================
    struct ip_hdr_t
    {
        std::uint8_t  ver_ihl;          // version(4) + IHL(4) = 0x45
        std::uint8_t  tos;              // Type of Service
        std::uint16_t total_length;     //  IP   ()
        std::uint16_t identification;   // 
        std::uint16_t flags_frag;       // flags + fragment offset
        std::uint8_t  ttl;              // Time to Live
        std::uint8_t  protocol;         // 17 = UDP
        std::uint16_t checksum;         //  
        std::uint32_t src_ip;           //  IP
        std::uint32_t dst_ip;           //  IP
    };
    static_assert(sizeof(ip_hdr_t) == 20);

    constexpr std::uint8_t IP_PROTO_UDP = 17;

    // ========================================================================
    // UDP Header (8B)
    // ========================================================================
    struct udp_hdr_t
    {
        std::uint16_t src_port;         //   ()
        std::uint16_t dst_port;         //   ()
        std::uint16_t length;           // UDP  +   ()
        std::uint16_t checksum;         //  (0=)
    };
    static_assert(sizeof(udp_hdr_t) == 8);

    // ========================================================================
    //    ()
    // ========================================================================
    struct full_packet_t
    {
        eth_hdr_t eth;
        ip_hdr_t  ip;
        udp_hdr_t udp;
        // : DMA payload (dma_protocol.h msg_hdr_t)
    };
    static_assert(sizeof(full_packet_t) == 42);

#pragma pack(pop)

    // ========================================================================
    //    (  )
    // ========================================================================
    // : x86 ,  .  .

    inline std::uint16_t bswap16(const std::uint16_t v)
    {
        return static_cast<std::uint16_t>((v >> 8) | (v << 8));
    }

    inline std::uint32_t bswap32(const std::uint32_t v)
    {
        return ((v >> 24) & 0xFF)
            | ((v >> 8) & 0xFF00)
            | ((v << 8) & 0xFF0000)
            | ((v << 24) & 0xFF000000);
    }

    //   
    inline std::uint16_t ntohs(const std::uint16_t v) { return bswap16(v); }
    inline std::uint32_t ntohl(const std::uint32_t v) { return bswap32(v); }

    //   
    inline std::uint16_t htons(const std::uint16_t v) { return bswap16(v); }
    inline std::uint32_t htonl(const std::uint32_t v) { return bswap32(v); }

    // ========================================================================
    // IP  
    // ========================================================================
    // : IP  . UDP  0  (DMA   )
    inline std::uint16_t ip_checksum(const void* data, std::uint32_t len)
    {
        const auto* ptr = static_cast<const std::uint16_t*>(data);
        std::uint32_t sum = 0;

        while (len > 1)
        {
            sum += *ptr++;
            len -= 2;
        }

        if (len == 1)
        {
            sum += *reinterpret_cast<const std::uint8_t*>(ptr);
        }

        //  
        while (sum >> 16)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return static_cast<std::uint16_t>(~sum);
    }

    // ========================================================================
    //   
    // ========================================================================
    //   src/dst     
    // payload_size: DMA   
    // :    ( + )
    inline std::uint32_t build_response_headers(
        std::uint8_t* out_packet,
        const std::uint8_t* src_mac,       //  NIC MAC
        const std::uint8_t* dst_mac,       // PC MAC
        const std::uint32_t src_ip,        //  IP (NIC IP)
        const std::uint32_t dst_ip,        // PC IP
        const std::uint16_t src_port,      //   ()
        const std::uint16_t dst_port,      //   ()
        const std::uint32_t payload_size)
    {
        auto* pkt = reinterpret_cast<full_packet_t*>(out_packet);

        // Ethernet
        for (int i = 0; i < 6; i++)
        {
            pkt->eth.dst_mac[i] = dst_mac[i];
            pkt->eth.src_mac[i] = src_mac[i];
        }
        pkt->eth.ethertype = ETHERTYPE_IPV4;

        // IP
        pkt->ip.ver_ihl = 0x45;            // IPv4, IHL=5 (20)
        pkt->ip.tos = 0;
        pkt->ip.total_length = htons(static_cast<std::uint16_t>(20 + 8 + payload_size));
        pkt->ip.identification = 0;
        pkt->ip.flags_frag = htons(0x4000); // Don't Fragment
        pkt->ip.ttl = 128;             // Windows default (OS TTL과 일치시켜 포렌식 회피)
        pkt->ip.protocol = IP_PROTO_UDP;
        pkt->ip.checksum = 0;
        pkt->ip.src_ip = src_ip;
        pkt->ip.dst_ip = dst_ip;

        // IP  
        pkt->ip.checksum = ip_checksum(&pkt->ip, 20);

        // UDP
        pkt->udp.src_port = src_port;
        pkt->udp.dst_port = dst_port;
        pkt->udp.length = htons(static_cast<std::uint16_t>(8 + payload_size));
        pkt->udp.checksum = 0;             // UDP   (DMA  )

        return HEADER_SIZE + payload_size;
    }

    // ========================================================================
    //   :  DMA  
    // ========================================================================
    // : 1= , 0=
    // dma_payload_out: DMA   
    // dma_payload_size_out: DMA  
    // Port-agnostic DMA packet validation
    // Checks: IPv4 + UDP + protocol magic (0x48564430)
    // No hardcoded port check = AC cannot DPI-match on fixed port
    // Port is learned from first valid DMA packet for response routing
    inline std::uint8_t is_dma_packet(
        const std::uint8_t* raw_packet,
        const std::uint32_t packet_len,
        const std::uint8_t** dma_payload_out,
        std::uint32_t* dma_payload_size_out)
    {
        // Min size: ETH(14) + IP(20) + UDP(8) + DMA_HDR(16) = 58
        if (packet_len < HEADER_SIZE + 16) return 0;

        const auto* pkt = reinterpret_cast<const full_packet_t*>(raw_packet);

        // IPv4
        if (pkt->eth.ethertype != ETHERTYPE_IPV4) return 0;

        // UDP
        if (pkt->ip.protocol != IP_PROTO_UDP) return 0;

        // DMA protocol magic validation (primary identifier)
        const std::uint8_t* payload = raw_packet + HEADER_SIZE;
        const auto magic = *reinterpret_cast<const std::uint32_t*>(payload);
        if (magic != 0x48564430) return 0;

        *dma_payload_out = payload;
        *dma_payload_size_out = packet_len - HEADER_SIZE;

        return 1;
    }
}