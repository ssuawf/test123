#pragma once
#include <cstdint>

// ============================================================================
// DMA Handler -   
// ============================================================================
// network   raw    .
//     EPT  R/W    .
//
// process()  :
//   :    ( )
//   :   (response_buffer )
//   :   (0  )
//
//   memory_manager :
//   - map_guest_physical()  EPT  Guest PA 
//   - translate_guest_virtual_address()  VAPA 
// ============================================================================

namespace dma
{
    // :    (heap_manager)
    void set_up();

    //    
    // request:         DMA  (msg_hdr_t + payload)
    // request_size:    
    // response:       [OUT]    
    // response_capacity:    
    // :           (0=, )
    std::uint32_t process(
        const std::uint8_t* request,
        std::uint32_t request_size,
        std::uint8_t* response,
        std::uint32_t response_capacity
    );

    //  
    inline std::uint32_t current_session_id = 0;
    inline std::uint8_t  is_session_open = 0;

    // Guest    (open  , MemProcFS  )
    //  128GB -   UEFI memory map 
    inline std::uint64_t guest_pa_max = 0x2000000000ull;
}
