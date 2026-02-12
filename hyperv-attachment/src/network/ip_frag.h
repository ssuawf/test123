#pragma once
#include <cstdint>
#include <intrin.h>       // __rdtsc() for IP ID randomization
#include "packet.h"
#include "../crt/crt.h"

// ============================================================================
// IP Fragmentation / Reassembly (Ring -1 )
// ============================================================================
//
// [ ]
// HV NIC TX ring    , RX ring  .
// OS    raw   .
// MTU = 1500B (ETH )  IP   1480B
//
// ReadScatter : 64 entries * 4KB = ~260KB  IP  
// WriteScatter : 1 entry * 4KB = ~4KB  IP  
//
// [IP Fragmentation ]
// - IP  MF(More Fragments)  Fragment Offset 
// - Fragment Offset = 8 
// -  : IP+UDP   (UDP  )
// -  : IP  + 
// -   IP   = 8  (  )
//
// [IP Reassembly ]
// -  Identification + src/dst IP   
// - Fragment Offset  
// - MF=0     
// -     
//
// [ ]
// - VMEXIT     
// -    
// -     1 (  -)
// ============================================================================

namespace ip_frag
{
    // MTU  
    // ETH(14) + IP(20) = 34B. MTU=1500이면 IP payload 최대 1480B
    // [해결완료] WiFi fragment drop 문제 → 유선 직결로 해결
    constexpr std::uint32_t ETH_MTU = 1500;     // 표준 MTU
    constexpr std::uint32_t IP_HDR_SIZE = 20;
    constexpr std::uint32_t ETH_HDR_SIZE = 14;
    constexpr std::uint32_t MAX_IP_PAYLOAD = ETH_MTU - IP_HDR_SIZE;   // 1480
    constexpr std::uint32_t FRAG_ALIGN = 8;        // fragment offset 단위

    // 첫 fragment: UDP(8) 포함 = 1480-8 = 1472
    constexpr std::uint32_t FIRST_FRAG_DATA = MAX_IP_PAYLOAD - 8;      // 1472
    // 후속 fragment: IP payload만 = 1480
    constexpr std::uint32_t NEXT_FRAG_DATA = MAX_IP_PAYLOAD;          // 1480

    // IP flags
    constexpr std::uint16_t IP_FLAG_MF = 0x2000;   // More Fragments ( )
    constexpr std::uint16_t IP_FLAG_DF = 0x4000;   // Don't Fragment

    // IP Identification (TSC 기반 pseudo-random, OS IP ID와 충돌 방지)
    inline std::uint16_t next_ip_id()
    {
        // TSC 하위 비트 + 카운터 XOR로 예측 불가능한 ID 생성
        static std::uint16_t counter = 0;
        counter++;
        return static_cast<std::uint16_t>(__rdtsc() ^ (counter * 0x9E37));
    }

    // ========================================================================
    // TX: IP Fragmentation (HV  Plugin)
    // ========================================================================
    //
    //  UDP  MTU    .
    //   tx_inject_func  NIC TX ring .
    //
    // udp_payload:      DMA   ( )
    // udp_payload_size:  
    // src/dst_mac, src/dst_ip, src/dst_port:   
    // tx_inject_func:      (raw_frame, frame_size)  1=
    //
    // :    (0=)

    // ========================================================================
    // TX: Multi-UDP Chunked Send (IP fragmentation 대체)
    // ========================================================================
    //
    // IP fragmentation 문제:
    //   62KB 응답 → 43 IP fragments → 1개 손실시 전체 실패 → 300ms timeout
    //   실효 처리량 5-10 MB/s
    //
    // Multi-UDP 해결:
    //   62KB 응답 → 43 독립 UDP 패킷 (각 chunk_hdr 8B + data ≤1464B)
    //   각 패킷 완전한 ETH+IP+UDP 헤더 → IP fragmentation 없음
    //   1개 손실해도 나머지 42개 정상 수신
    //   수신측: chunk_hdr로 조립, 빠진 chunk만 실패 처리
    //
    // 리턴: 전송한 chunk 수 (0=실패)
    // ========================================================================

    typedef std::uint8_t(*tx_inject_fn)(const std::uint8_t* frame, std::uint32_t size);

    inline std::uint32_t chunked_udp_send(
        const std::uint8_t* payload,
        std::uint32_t payload_size,
        const std::uint8_t* src_mac,
        const std::uint8_t* dst_mac,
        std::uint32_t src_ip,
        std::uint32_t dst_ip,
        std::uint16_t src_port,
        std::uint16_t dst_port,
        std::uint8_t* frame_buf,        // 작업 버퍼 (≥1514B)
        tx_inject_fn inject)
    {
        // chunk 계산
        // UDP payload = chunk_hdr(12) + data(≤1460) = ≤1472
        // IP packet = IP(20) + UDP(8) + 1472 = 1500 = MTU (no fragmentation)
        constexpr std::uint32_t CHUNK_HDR_SIZE = 12;  // sizeof(dma::chunk_hdr_t)
        constexpr std::uint32_t CHUNK_DATA_MAX = 1460;

        // [핵심] 응답 시퀀스 번호: HV가 VMEXIT 재진입으로 같은 요청 여러번 처리시
        // 수신측이 같은 seq chunk만 조립 → 크로스 오염 방지
        static std::uint32_t s_response_seq = 0;
        const std::uint32_t cur_seq = s_response_seq++;

        const std::uint32_t chunk_total = (payload_size + CHUNK_DATA_MAX - 1) / CHUNK_DATA_MAX;
        // payload_size==0이면 chunk 1개 (빈 응답도 전송)
        const std::uint32_t total_chunks = (chunk_total == 0) ? 1 : chunk_total;

        std::uint32_t data_sent = 0;
        std::uint32_t chunks_sent = 0;

        for (std::uint32_t ci = 0; ci < total_chunks; ci++)
        {
            // 이 chunk의 데이터 크기
            std::uint32_t remaining = payload_size - data_sent;
            std::uint32_t chunk_data = (remaining > CHUNK_DATA_MAX) ? CHUNK_DATA_MAX : remaining;

            // UDP payload = chunk_hdr + chunk_data
            std::uint32_t udp_payload_size = CHUNK_HDR_SIZE + chunk_data;

            // 프레임 구성: ETH(14) + IP(20) + UDP(8) + chunk_hdr(12) + data
            auto* eth = reinterpret_cast<packet::eth_hdr_t*>(frame_buf);
            auto* ip = reinterpret_cast<packet::ip_hdr_t*>(frame_buf + ETH_HDR_SIZE);
            auto* udp = reinterpret_cast<packet::udp_hdr_t*>(frame_buf + ETH_HDR_SIZE + IP_HDR_SIZE);

            // chunk header (UDP payload 시작 위치, 12 bytes)
            auto* chdr = reinterpret_cast<std::uint16_t*>(
                frame_buf + ETH_HDR_SIZE + IP_HDR_SIZE + 8);
            chdr[0] = static_cast<std::uint16_t>(ci);             // chunk_index
            chdr[1] = static_cast<std::uint16_t>(total_chunks);   // chunk_total
            auto* chdr32 = reinterpret_cast<std::uint32_t*>(chdr + 2);
            chdr32[0] = payload_size;                              // total_size
            chdr32[1] = cur_seq;                                   // response_seq

            // 데이터 복사
            if (chunk_data > 0) {
                crt::copy_memory(
                    frame_buf + ETH_HDR_SIZE + IP_HDR_SIZE + 8 + CHUNK_HDR_SIZE,
                    payload + data_sent, chunk_data);
            }

            // ETH header
            for (int i = 0; i < 6; i++) {
                eth->dst_mac[i] = dst_mac[i];
                eth->src_mac[i] = src_mac[i];
            }
            eth->ethertype = packet::ETHERTYPE_IPV4;

            // IP header (DF=1: Don't Fragment!)
            ip->ver_ihl = 0x45;
            ip->tos = 0;
            ip->total_length = packet::htons(
                static_cast<std::uint16_t>(IP_HDR_SIZE + 8 + udp_payload_size));
            ip->identification = packet::htons(next_ip_id());
            ip->flags_frag = packet::htons(IP_FLAG_DF);  // DF=1: 절대 fragmentation 안함
            ip->ttl = 128;
            ip->protocol = packet::IP_PROTO_UDP;
            ip->checksum = 0;
            ip->src_ip = src_ip;
            ip->dst_ip = dst_ip;
            ip->checksum = packet::ip_checksum(ip, IP_HDR_SIZE);

            // UDP header
            udp->src_port = src_port;
            udp->dst_port = dst_port;
            udp->length = packet::htons(static_cast<std::uint16_t>(8 + udp_payload_size));
            udp->checksum = 0;

   
            std::uint32_t frame_size = ETH_HDR_SIZE + IP_HDR_SIZE + 8 + udp_payload_size;
            std::uint8_t ok = inject(frame_buf, frame_size);
            if (!ok) {
                // ring full recovery: NIC DMA 처리 시간 확보
                for (int w = 0; w < 1000; w++) _mm_pause(); // ~10µs
                ok = inject(frame_buf, frame_size);
            }
            if (ok) chunks_sent++;
            // inject 실패해도 나머지 chunk 계속 전송 (partial > nothing)

            data_sent += chunk_data;
        }

        return chunks_sent;
    }

    // ========================================================================
    // RX: IP Reassembly (Plugin  HV)
    // ========================================================================
    //
    // [ ]
    //    datagram  (- )
    //  : 256KB (WriteScatter 16 entries * 4KB + )
    //
    // []
    // 1. IP    fragment 
    // 2. fragment reassembly  
    // 3.      UDP payload 
    // 4. -fragment  

    constexpr std::uint32_t REASM_BUF_SIZE = 256 * 1024;  // 256KB
    constexpr std::uint32_t REASM_TIMEOUT = 1000;         //    (VMEXIT )

    //  
    struct reasm_state_t
    {
        std::uint8_t  active;           //   
        std::uint16_t ip_id;            //   IP ID
        std::uint32_t src_ip;           //  IP ()
        std::uint32_t total_size;       //    (0= )
        std::uint32_t received_size;    //   
        std::uint32_t highest_offset;   //   offset + 
        std::uint8_t  last_received;    //    (MF=0)
        std::uint32_t age;              //  
        // :    
        // :  highest_offset last_received 
        //           , LAN   
    };

    //    (network::set_up )
    inline std::uint8_t* reasm_buffer = nullptr;
    inline reasm_state_t reasm_state = {};

    //  
    inline void reasm_init(std::uint8_t* buffer)
    {
        reasm_buffer = buffer;
        crt::set_memory(&reasm_state, 0, sizeof(reasm_state));
    }

    //  
    inline void reasm_reset()
    {
        reasm_state.active = 0;
        reasm_state.ip_id = 0;
        reasm_state.received_size = 0;
        reasm_state.highest_offset = 0;
        reasm_state.last_received = 0;
        reasm_state.total_size = 0;
        reasm_state.age = 0;
    }

    // IP  : fragment   
    //
    // ip_packet:    IP    (ETH  )
    // ip_packet_len: IP  
    // out_payload:  [OUT]  UDP   (reasm_buffer )
    // out_size:     [OUT]  
    //
    // :
    //   0 =   (  )
    //   1 = ! out_payload/out_size 
    //   2 = -fragment  (ip_packet    )

    inline std::uint8_t process_ip_packet(
        const std::uint8_t* ip_packet,
        std::uint32_t ip_packet_len,
        const std::uint8_t** out_payload,
        std::uint32_t* out_size)
    {
        if (ip_packet_len < IP_HDR_SIZE) return 0;

        const auto* ip = reinterpret_cast<const packet::ip_hdr_t*>(ip_packet);

        // IP   (IHL * 4)
        std::uint32_t ihl = (ip->ver_ihl & 0x0F) * 4;
        if (ihl < 20 || ihl > ip_packet_len) return 0;

        std::uint16_t flags_frag = packet::ntohs(ip->flags_frag);
        std::uint16_t frag_offset = (flags_frag & 0x1FFF) * FRAG_ALIGN;    //  
        std::uint8_t  mf = (flags_frag & 0x2000) ? 1 : 0;                  // More Fragments

        // -fragment : DF  (MF=0, offset=0)
        if (!mf && frag_offset == 0)
        {
            // UDP 
            if (ip->protocol != packet::IP_PROTO_UDP) return 0;

            *out_payload = ip_packet + ihl + 8;     // UDP (8) 
            std::uint32_t ip_total = packet::ntohs(ip->total_length);
            if (ip_total < ihl + 8) return 0;
            *out_size = ip_total - ihl - 8;
            return 2;   //   
        }

        // Fragment 
        if (!reasm_buffer) return 0;

        std::uint16_t ip_id = packet::ntohs(ip->identification);
        std::uint32_t src_ip = ip->src_ip;

        //  datagram 
        if (!reasm_state.active || reasm_state.ip_id != ip_id || reasm_state.src_ip != src_ip)
        {
            reasm_reset();
            reasm_state.active = 1;
            reasm_state.ip_id = ip_id;
            reasm_state.src_ip = src_ip;
        }

        //   
        std::uint32_t ip_total = packet::ntohs(ip->total_length);
        std::uint32_t data_len = ip_total - ihl;
        const std::uint8_t* data = ip_packet + ihl;

        //   (offset=0): UDP  
        // : UDP      .  .
        if (frag_offset + data_len > REASM_BUF_SIZE) return 0;  //  

        //   
        crt::copy_memory(reasm_buffer + frag_offset, data, data_len);
        reasm_state.received_size += data_len;

        //  offset 
        std::uint32_t this_end = frag_offset + data_len;
        if (this_end > reasm_state.highest_offset) {
            reasm_state.highest_offset = this_end;
        }

        //  ?
        if (!mf) {
            reasm_state.last_received = 1;
            reasm_state.total_size = this_end;  //  IP payload 
        }

        //  :    &&   
        // : LAN   .     .
        if (reasm_state.last_received && reasm_state.received_size >= reasm_state.total_size)
        {
            // ! UDP (8B)   
            *out_payload = reasm_buffer + 8;
            *out_size = reasm_state.total_size - 8;
            reasm_reset();
            return 1;
        }

        reasm_state.age = 0;    //  
        return 0;   //   
    }

    //   ( )
    inline void reasm_tick()
    {
        if (reasm_state.active) {
            if (++reasm_state.age > REASM_TIMEOUT) {
                reasm_reset();  //   
            }
        }
    }
}