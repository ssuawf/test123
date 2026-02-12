#include "dma_handler.h"
#include "dma_protocol.h"

#include "../memory_manager/memory_manager.h"
#include "../memory_manager/heap_manager.h"
#include "../slat/slat.h"
#include "../slat/cr3/cr3.h"
#include "../crt/crt.h"
#include "../network/nic.h"  // [FIX] TX ring reset on OPEN

// ============================================================================
// DMA Handler 
// ============================================================================
//  :   DMA  ,
// EPT(SLAT)  Guest  /,   .
//
//  hyper-reV memory_manager   :
//   - map_guest_physical(slat_cr3, GPA)  HV   HVA 
//   -  EPT   
//
// : network  process()  handle_xxx()  memory_manager  EPT  
// ============================================================================

namespace
{
    //   ID ( )
    std::uint32_t next_session_id = 0x1000;

    // ========================================================================
    // :   
    // ========================================================================
    void build_response_header(dma::msg_hdr_t* hdr,
        const dma::msg_type_t type,
        const std::uint32_t cb_msg,
        const std::uint32_t session_id)
    {
        hdr->magic = dma::PROTOCOL_MAGIC;
        hdr->cb_msg = cb_msg;
        hdr->type = type;
        hdr->version = dma::PROTOCOL_VERSION;
        hdr->session_id = session_id;
    }

    // ========================================================================
    // Ping 
    // ========================================================================
    std::uint32_t handle_ping(const dma::msg_hdr_t* req_hdr,
        std::uint8_t* response,
        const std::uint32_t response_capacity)
    {
        constexpr std::uint32_t rsp_size = sizeof(dma::msg_hdr_t);

        if (response_capacity < rsp_size)
        {
            return 0;
        }

        auto* rsp_hdr = reinterpret_cast<dma::msg_hdr_t*>(response);
        build_response_header(rsp_hdr, dma::msg_type_t::ping_rsp,
            rsp_size, req_hdr->session_id);

        return rsp_size;
    }

    // ========================================================================
    // Open  -  , MemProcFS  pa_max 
    // ========================================================================
    std::uint32_t handle_open(const dma::msg_hdr_t* req_hdr,
        std::uint8_t* response,
        const std::uint32_t response_capacity)
    {
        constexpr std::uint32_t rsp_size = sizeof(dma::msg_hdr_t)
            + sizeof(dma::open_rsp_data_t);

        if (response_capacity < rsp_size)
        {
            return 0;
        }

        //  
        dma::current_session_id = next_session_id++;
        dma::is_session_open = 1;

        // [FIX] TX ring 리셋: 이전 세션 취소 후 ring stuck 방지
        // 클라이언트가 중간에 끊으면 TX descriptor ring이 소진된 상태로 남음
        // 새 OPEN 시 리셋해야 응답 전송 가능
        {
            const cr3 slat_cr3 = slat::hyperv_cr3();
            nic::reset_tx_ring(&slat_cr3);
        }

        //  
        auto* rsp_hdr = reinterpret_cast<dma::msg_hdr_t*>(response);
        build_response_header(rsp_hdr, dma::msg_type_t::open_rsp,
            rsp_size, dma::current_session_id);

        //  : pa_max, flags
        // MemProcFS  pa_max    
        auto* rsp_data = reinterpret_cast<dma::open_rsp_data_t*>(
            response + sizeof(dma::msg_hdr_t));

        rsp_data->pa_max = dma::guest_pa_max;
        rsp_data->success = 1;
        rsp_data->flags = 0x01;  // writable

        return rsp_size;
    }

    // ========================================================================
    // Close 
    // ========================================================================
    std::uint32_t handle_close(const dma::msg_hdr_t* req_hdr,
        std::uint8_t* response,
        const std::uint32_t response_capacity)
    {
        constexpr std::uint32_t rsp_size = sizeof(dma::msg_hdr_t);

        if (response_capacity < rsp_size)
        {
            return 0;
        }

        dma::is_session_open = 0;

        auto* rsp_hdr = reinterpret_cast<dma::msg_hdr_t*>(response);
        build_response_header(rsp_hdr, dma::msg_type_t::close_rsp,
            rsp_size, req_hdr->session_id);

        return rsp_size;
    }

    // ========================================================================
    // ReadScatter  ()
    // ========================================================================
    // PC  Guest PA  EPT    .
    //
    //  :
    //   [msg_hdr_t] [scatter_hdr_t] [scatter_entry_t  count]
    //
    //  :
    //   [msg_hdr_t] [scatter_hdr_t] [scatter_entry_t  count] [ ]
    //
    //  :     
    //   - f=1   
    //   - PC  f     
    // ========================================================================
    std::uint32_t handle_read_scatter(const std::uint8_t* request,
        const std::uint32_t request_size,
        std::uint8_t* response,
        const std::uint32_t response_capacity)
    {
        //   
        constexpr std::uint32_t min_req = sizeof(dma::msg_hdr_t)
            + sizeof(dma::scatter_hdr_t);
        if (request_size < min_req)
        {
            return 0;
        }

        const auto* req_hdr = reinterpret_cast<const dma::msg_hdr_t*>(request);
        const auto* scatter_hdr = reinterpret_cast<const dma::scatter_hdr_t*>(
            request + sizeof(dma::msg_hdr_t));

        const std::uint32_t count = scatter_hdr->count;

        //  
        if (count == 0 || count > dma::MAX_SCATTER_COUNT)
        {
            return 0;
        }

        const std::uint32_t expected_req = dma::read_req_size(count);
        if (request_size < expected_req)
        {
            return 0;
        }

        //  scatter   
        const auto* req_entries = reinterpret_cast<const dma::scatter_entry_t*>(
            request + sizeof(dma::msg_hdr_t) + sizeof(dma::scatter_hdr_t));

        //   
        const std::uint32_t entries_offset = sizeof(dma::msg_hdr_t)
            + sizeof(dma::scatter_hdr_t);
        const std::uint32_t data_offset = entries_offset
            + count * sizeof(dma::scatter_entry_t);

        // [Multi-UDP] IP fragmentation 제거됨 → UDP_SAFE_LIMIT 불필요
        // 각 chunk가 독립 UDP 패킷(≤1472B)으로 전송되므로 응답 크기 제한 없음
        const std::uint32_t safe_capacity = response_capacity;

        //  scatter  
        auto* rsp_entries = reinterpret_cast<dma::scatter_entry_t*>(
            response + entries_offset);

        //    
        std::uint8_t* data_cursor = response + data_offset;
        std::uint32_t cb_data_written = 0;

        // SLAT CR3: EPT  - Guest PA  Host PA  
        const cr3 slat_cr3 = slat::hyperv_cr3();

        //  scatter  
        for (std::uint32_t i = 0; i < count; i++)
        {
            rsp_entries[i].qw_addr = req_entries[i].qw_addr;
            rsp_entries[i].cb = req_entries[i].cb;
            rsp_entries[i].f = 0;     // : 

            const std::uint64_t gpa = req_entries[i].qw_addr;
            const std::uint32_t cb = req_entries[i].cb;

            //  
            if (cb == 0 || cb > dma::MAX_SCATTER_SIZE)
            {
                continue;
            }

            //    
            if (data_offset + cb_data_written + cb > safe_capacity)
            {
                break;
            }

            // EPT  Guest PA Host VA 
            // map_guest_physical: GPA  SLAT   HPA  HVA 
            std::uint64_t size_left_of_page = 0;
            const void* mapped = memory_manager::map_guest_physical(
                slat_cr3, gpa, &size_left_of_page);

            if (mapped == nullptr || size_left_of_page == UINT64_MAX)
            {
                continue;
            }

            //     (PCILeech    )
            const std::uint32_t safe_cb = static_cast<std::uint32_t>(
                crt::min(static_cast<std::uint64_t>(cb), size_left_of_page));

            // EPT     
            crt::copy_memory(data_cursor + cb_data_written, mapped, safe_cb);

            rsp_entries[i].f = 1;      // 
            rsp_entries[i].cb = safe_cb;
            cb_data_written += safe_cb;
        }

        //   
        const std::uint32_t rsp_size = data_offset + cb_data_written;

        auto* rsp_hdr = reinterpret_cast<dma::msg_hdr_t*>(response);
        build_response_header(rsp_hdr, dma::msg_type_t::read_scatter_rsp,
            rsp_size, req_hdr->session_id);

        auto* rsp_scatter_hdr = reinterpret_cast<dma::scatter_hdr_t*>(
            response + sizeof(dma::msg_hdr_t));
        rsp_scatter_hdr->count = count;
        rsp_scatter_hdr->cb_total = cb_data_written;

        return rsp_size;
    }

    // ========================================================================
    // WriteScatter 
    // ========================================================================
    //  :
    //   [msg_hdr_t] [scatter_hdr_t] [scatter_entry_t  count] [ ]
    //
    //  :
    //   [msg_hdr_t] [scatter_hdr_t] [write_result_t  count]
    //
    //  :   cb   
    //         (  )
    // ========================================================================
    std::uint32_t handle_write_scatter(const std::uint8_t* request,
        const std::uint32_t request_size,
        std::uint8_t* response,
        const std::uint32_t response_capacity)
    {
        constexpr std::uint32_t min_req = sizeof(dma::msg_hdr_t)
            + sizeof(dma::scatter_hdr_t);
        if (request_size < min_req)
        {
            return 0;
        }

        const auto* req_hdr = reinterpret_cast<const dma::msg_hdr_t*>(request);
        const auto* scatter_hdr = reinterpret_cast<const dma::scatter_hdr_t*>(
            request + sizeof(dma::msg_hdr_t));

        const std::uint32_t count = scatter_hdr->count;

        if (count == 0 || count > dma::MAX_SCATTER_COUNT)
        {
            return 0;
        }

        //  scatter 
        const auto* req_entries = reinterpret_cast<const dma::scatter_entry_t*>(
            request + sizeof(dma::msg_hdr_t) + sizeof(dma::scatter_hdr_t));

        //    
        const std::uint32_t data_start = sizeof(dma::msg_hdr_t)
            + sizeof(dma::scatter_hdr_t)
            + count * sizeof(dma::scatter_entry_t);
        const std::uint8_t* data_cursor = request + data_start;

        //  
        const std::uint32_t rsp_size = dma::write_rsp_size(count);
        if (response_capacity < rsp_size)
        {
            return 0;
        }

        auto* rsp_results = reinterpret_cast<dma::write_result_t*>(
            response + sizeof(dma::msg_hdr_t) + sizeof(dma::scatter_hdr_t));

        const cr3 slat_cr3 = slat::hyperv_cr3();

        std::uint32_t data_consumed = 0;

        for (std::uint32_t i = 0; i < count; i++)
        {
            rsp_results[i].f = 0;  // : 

            const std::uint64_t gpa = req_entries[i].qw_addr;
            const std::uint32_t cb = req_entries[i].cb;

            if (cb == 0 || cb > dma::MAX_SCATTER_SIZE)
            {
                data_consumed += cb;
                continue;
            }

            //    
            if (data_start + data_consumed + cb > request_size)
            {
                break;
            }

            std::uint64_t size_left_of_page = 0;
            void* mapped = memory_manager::map_guest_physical(
                slat_cr3, gpa, &size_left_of_page);

            if (mapped == nullptr || size_left_of_page == UINT64_MAX)
            {
                data_consumed += cb;
                continue;
            }

            const std::uint32_t safe_cb = static_cast<std::uint32_t>(
                crt::min(static_cast<std::uint64_t>(cb), size_left_of_page));

            //    EPT  
            crt::copy_memory(mapped, data_cursor + data_consumed, safe_cb);

            rsp_results[i].f = 1;  // 
            data_consumed += cb;
        }

        //  
        auto* rsp_hdr = reinterpret_cast<dma::msg_hdr_t*>(response);
        build_response_header(rsp_hdr, dma::msg_type_t::write_scatter_rsp,
            rsp_size, req_hdr->session_id);

        auto* rsp_scatter_hdr = reinterpret_cast<dma::scatter_hdr_t*>(
            response + sizeof(dma::msg_hdr_t));
        rsp_scatter_hdr->count = count;
        rsp_scatter_hdr->cb_total = data_consumed;

        return rsp_size;
    }

    // ========================================================================
    // Keepalive 
    // ========================================================================
    std::uint32_t handle_keepalive(const dma::msg_hdr_t* req_hdr,
        std::uint8_t* response,
        const std::uint32_t response_capacity)
    {
        constexpr std::uint32_t rsp_size = sizeof(dma::msg_hdr_t);

        if (response_capacity < rsp_size)
        {
            return 0;
        }

        auto* rsp_hdr = reinterpret_cast<dma::msg_hdr_t*>(response);
        build_response_header(rsp_hdr, dma::msg_type_t::keepalive_rsp,
            rsp_size, req_hdr->session_id);

        return rsp_size;
    }

    // ========================================================================
    // GetOption 
    // ========================================================================
    // MemProcFS/LeechCore     .
    //  :
    //   LC_OPT_MEMORYINFO_VALID (0x02000000)  1
    //   LC_OPT_MEMORYINFO_ADDR_MAX (0x02000004)  guest_pa_max
    //   LC_OPT_MEMORYINFO_FLAG_32BIT (0x02000001)  0 (64bit)
    // ========================================================================
    std::uint32_t handle_get_option(const std::uint8_t* request,
        const std::uint32_t request_size,
        std::uint8_t* response,
        const std::uint32_t response_capacity)
    {
        constexpr std::uint32_t min_req = sizeof(dma::msg_hdr_t)
            + sizeof(dma::option_data_t);
        constexpr std::uint32_t rsp_size = sizeof(dma::msg_hdr_t)
            + sizeof(dma::option_data_t);

        if (request_size < min_req || response_capacity < rsp_size)
        {
            return 0;
        }

        const auto* req_hdr = reinterpret_cast<const dma::msg_hdr_t*>(request);
        const auto* req_opt = reinterpret_cast<const dma::option_data_t*>(
            request + sizeof(dma::msg_hdr_t));

        auto* rsp_hdr = reinterpret_cast<dma::msg_hdr_t*>(response);
        auto* rsp_opt = reinterpret_cast<dma::option_data_t*>(
            response + sizeof(dma::msg_hdr_t));

        rsp_opt->option = req_opt->option;
        rsp_opt->value = 0;  // :   0

        // LC_OPT  (LeechCore.h )
        constexpr std::uint64_t LC_OPT_MEMORYINFO_VALID = 0x02000000;
        constexpr std::uint64_t LC_OPT_MEMORYINFO_FLAG_32BIT = 0x02000001;
        constexpr std::uint64_t LC_OPT_MEMORYINFO_FLAG_PAE = 0x02000002;
        constexpr std::uint64_t LC_OPT_MEMORYINFO_ADDR_MAX = 0x02000004;
        constexpr std::uint64_t LC_OPT_CORE_VOLATILE = 0x01000000;

        switch (req_opt->option)
        {
        case LC_OPT_MEMORYINFO_VALID:
            rsp_opt->value = 1;
            break;
        case LC_OPT_MEMORYINFO_ADDR_MAX:
            rsp_opt->value = dma::guest_pa_max;
            break;
        case LC_OPT_MEMORYINFO_FLAG_32BIT:
            rsp_opt->value = 0;  // 64bit
            break;
        case LC_OPT_MEMORYINFO_FLAG_PAE:
            rsp_opt->value = 0;  // x64 = no PAE
            break;
        case LC_OPT_CORE_VOLATILE:
            rsp_opt->value = 1;  //   = volatile
            break;
        default:
            break;
        }

        build_response_header(rsp_hdr, dma::msg_type_t::get_option_rsp,
            rsp_size, req_hdr->session_id);

        return rsp_size;
    }

    // ========================================================================
    // SetOption 
    // ========================================================================
    //      .
    //      .
    // ========================================================================
    std::uint32_t handle_set_option(const std::uint8_t* request,
        const std::uint32_t request_size,
        std::uint8_t* response,
        const std::uint32_t response_capacity)
    {
        constexpr std::uint32_t min_req = sizeof(dma::msg_hdr_t)
            + sizeof(dma::option_data_t);
        constexpr std::uint32_t rsp_size = sizeof(dma::msg_hdr_t)
            + sizeof(dma::option_data_t);

        if (request_size < min_req || response_capacity < rsp_size)
        {
            return 0;
        }

        const auto* req_hdr = reinterpret_cast<const dma::msg_hdr_t*>(request);
        const auto* req_opt = reinterpret_cast<const dma::option_data_t*>(
            request + sizeof(dma::msg_hdr_t));

        auto* rsp_hdr = reinterpret_cast<dma::msg_hdr_t*>(response);
        auto* rsp_opt = reinterpret_cast<dma::option_data_t*>(
            response + sizeof(dma::msg_hdr_t));

        // echo back:   
        rsp_opt->option = req_opt->option;
        rsp_opt->value = req_opt->value;

        build_response_header(rsp_hdr, dma::msg_type_t::set_option_rsp,
            rsp_size, req_hdr->session_id);

        return rsp_size;
    }
}

// ============================================================================
// Public API
// ============================================================================

void dma::set_up()
{
    current_session_id = 0;
    is_session_open = 0;

    // ========================================================================
    // guest_pa_max : EPT 
    // ========================================================================
    // Hyper-V EPT  Guest PA    .
    // 1GB      GPA    1GB  pa_max .
    //    128GB .
    //
    //  : MemProcFS open   pa_max   .
    //     ,    .
    // ========================================================================
    const cr3 slat_cr3 = slat::hyperv_cr3();

    // 256GB 1GB   
    constexpr std::uint64_t PROBE_START = 0x4000000000ull;  // 256GB
    constexpr std::uint64_t PROBE_STEP = 0x40000000ull;    // 1GB
    constexpr std::uint64_t PROBE_MIN = 0x100000000ull;   // 4GB (  )

    std::uint64_t detected_max = 0;

    for (std::uint64_t probe = PROBE_START; probe >= PROBE_MIN;
        probe -= PROBE_STEP)
    {
        //  GB    EPT  
        std::uint64_t size_left = 0;
        const void* mapped = memory_manager::map_guest_physical(
            slat_cr3, probe - 0x1000, &size_left);

        if (mapped != nullptr && size_left != UINT64_MAX)
        {
            detected_max = probe;
            break;
        }
    }

    if (detected_max > 0)
    {
        guest_pa_max = detected_max;
    }
    // else:  128GB 
}

std::uint32_t dma::process(const std::uint8_t* request,
    const std::uint32_t request_size,
    std::uint8_t* response,
    const std::uint32_t response_capacity)
{
    //    
    if (request_size < sizeof(msg_hdr_t) || response == nullptr)
    {
        return 0;
    }

    const auto* hdr = reinterpret_cast<const msg_hdr_t*>(request);

    //   -    
    if (hdr->magic != PROTOCOL_MAGIC)
    {
        return 0;
    }

    //  
    if (hdr->version != PROTOCOL_VERSION)
    {
        return 0;
    }

    //   
    if (hdr->cb_msg > request_size)
    {
        return 0;
    }

    //   
    switch (hdr->type)
    {
    case msg_type_t::ping_req:
        return handle_ping(hdr, response, response_capacity);

    case msg_type_t::open_req:
        return handle_open(hdr, response, response_capacity);

    case msg_type_t::close_req:
        return handle_close(hdr, response, response_capacity);

    case msg_type_t::read_scatter_req:
        return handle_read_scatter(request, request_size,
            response, response_capacity);

    case msg_type_t::write_scatter_req:
        return handle_write_scatter(request, request_size,
            response, response_capacity);

    case msg_type_t::keepalive_req:
        return handle_keepalive(hdr, response, response_capacity);

    case msg_type_t::get_option_req:
        return handle_get_option(request, request_size,
            response, response_capacity);

    case msg_type_t::set_option_req:
        return handle_set_option(request, request_size,
            response, response_capacity);

    default:
        return 0;
    }
}