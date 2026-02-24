#pragma once
#include <cstdint>

// ============================================================================
// PCILeech-compatible Software DMA Protocol
// ============================================================================
//
// [ ]
// PC (LeechCore ) UDP/LAN PC (HV NIC EPT hook)
//
// HV  " "  :
//   - ReadScatter:  Guest PA   
//   - WriteScatter: Guest PA   
//   -  // = 0% (  PC )
//
// [ ]
//  : [msg_hdr_t (16B)] + [type-specific payload]
//
// ReadScatter:
//   REQ: [HDR type=0x07] + [scatter_hdr_t] + [scatter_entry_t  N]
//   RSP: [HDR type=0x08] + [scatter_hdr_t] + [scatter_entry_t  N] + [data]
//
// WriteScatter:
//   REQ: [HDR type=0x09] + [scatter_hdr_t] + [scatter_entry_t  N] + [data]
//   RSP: [HDR type=0x0A] + [scatter_hdr_t] + [write_result_t  N]
//
// [LeechCore  ]
// pfnReadScatter   read_scatter_req   HV EPT read   read_scatter_rsp
// pfnWriteScatter  write_scatter_req  HV EPT write  write_scatter_rsp
// ============================================================================

namespace dma
{
    // : "HVD0" - NIC    
    constexpr std::uint32_t PROTOCOL_MAGIC = 0x48564430;

    //  
    constexpr std::uint16_t PROTOCOL_VERSION = 0x0001;

    //  scatter   (PCILeech MEM_SCATTER : max 4KB,   )
    constexpr std::uint32_t MAX_SCATTER_SIZE = 0x1000;

    //   Scatter     
    // LeechRPC 0x1000  (leechrpcclient.c:521 )
    constexpr std::uint32_t MAX_SCATTER_COUNT = 0x1000;

    // ========================================================================
    //   (LeechRPC MSGTYPE   : 7=Read, 9=Write)
    // ========================================================================
    enum class msg_type_t : std::uint16_t
    {
        ping_req = 0x01,
        ping_rsp = 0x02,
        open_req = 0x03,
        open_rsp = 0x04,
        close_req = 0x05,
        close_rsp = 0x06,

        read_scatter_req = 0x07,     // :  
        read_scatter_rsp = 0x08,
        write_scatter_req = 0x09,     // :  
        write_scatter_rsp = 0x0A,

        get_option_req = 0x0B,
        get_option_rsp = 0x0C,
        set_option_req = 0x0D,
        set_option_rsp = 0x0E,

        keepalive_req = 0x11,
        keepalive_rsp = 0x12,
    };

    // ========================================================================
    //   (packed,  )
    // ========================================================================
#pragma pack(push, 1)

//    (16B) -  DMA  
    struct msg_hdr_t
    {
        std::uint32_t magic;            // PROTOCOL_MAGIC (0x48564430)
        std::uint32_t cb_msg;           //     
        msg_type_t    type;             //  
        std::uint16_t version;          // PROTOCOL_VERSION
        std::uint32_t session_id;       //  ID
    };
    static_assert(sizeof(msg_hdr_t) == 16);

    // Scatter   (8B) - msg_hdr_t  
    struct scatter_hdr_t
    {
        std::uint32_t count;            // scatter_entry_t 
        std::uint32_t cb_total;         //    ()
    };
    static_assert(sizeof(scatter_hdr_t) == 8);

    // Scatter  (16B) - PCILeech MEM_SCATTER 1:1 
    // : qw_addr=, cb=, f=0
    // : qw_addr=echo, cb=, f=1()/0()
    struct scatter_entry_t
    {
        std::uint64_t qw_addr;          // Guest Physical Address
        std::uint32_t cb;               //   (max 0x1000)
        std::uint32_t f;                //   (RSP 1=)
    };
    static_assert(sizeof(scatter_entry_t) == 16);

    // Open  
    struct open_rsp_data_t
    {
        std::uint64_t pa_max;           // Guest  
        std::uint32_t success;          //  
        std::uint32_t flags;            // LC_OPT  (writable )
    };
    static_assert(sizeof(open_rsp_data_t) == 16);

    // Write  
    struct write_result_t
    {
        std::uint32_t f;                // =1, =0
    };
    static_assert(sizeof(write_result_t) == 4);

    // Option /
    struct option_data_t
    {
        std::uint64_t option;           // LC_OPT_* ID
        std::uint64_t value;            // 
    };
    static_assert(sizeof(option_data_t) == 16);

    // ========================================================================
    // Multi-UDP Chunked Response Header (12B)
    // ========================================================================
    // IP fragmentation ��� ���� UDP ��Ŷ���� ���� ����
    // �� UDP ��Ŷ = [chunk_hdr_t 12B] + [data ��1460B]
    // response_seq: HV�� �� ���丶�� ������Ű�� ������ ��ȣ
    //   �� �������� ���� seq�� chunk�� ����, �ٸ� seq�� skip
    //   �� HV�� ���� ��û�� VMEXIT ���������� ������ ó���ص� ���� ����
    // ========================================================================
    struct chunk_hdr_t
    {
        std::uint16_t chunk_index;      // 0-based chunk ��ȣ
        std::uint16_t chunk_total;      // �� chunk ��
        std::uint32_t total_size;       // ��ü ���� ũ�� (chunk header ������)
        std::uint32_t response_seq;     // ���� ������ ��ȣ (�� ���� ����)
    };
    static_assert(sizeof(chunk_hdr_t) == 12);

    // chunk�� �ִ� ������: UDP payload(1472) - chunk_hdr(12) = 1460
    constexpr std::uint32_t CHUNK_DATA_MAX = 1460;

#pragma pack(pop)

    // ========================================================================
    //   
    // ========================================================================
    constexpr std::uint32_t read_req_size(const std::uint32_t count)
    {
        return sizeof(msg_hdr_t) + sizeof(scatter_hdr_t)
            + count * sizeof(scatter_entry_t);
    }

    constexpr std::uint32_t read_rsp_size(const std::uint32_t count,
        const std::uint32_t cb_data)
    {
        return sizeof(msg_hdr_t) + sizeof(scatter_hdr_t)
            + count * sizeof(scatter_entry_t) + cb_data;
    }

    constexpr std::uint32_t write_req_size(const std::uint32_t count,
        const std::uint32_t cb_data)
    {
        return sizeof(msg_hdr_t) + sizeof(scatter_hdr_t)
            + count * sizeof(scatter_entry_t) + cb_data;
    }

    constexpr std::uint32_t write_rsp_size(const std::uint32_t count)
    {
        return sizeof(msg_hdr_t) + sizeof(scatter_hdr_t)
            + count * sizeof(write_result_t);
    }
}