#include "interrupts.h"
#include "../memory_manager/heap_manager.h"
#include "../slat/cr3/cr3.h"

#include "ia32-doc/ia32.hpp"
#include <intrin.h>

extern "C"
{
    std::uint64_t original_nmi_handler = 0;

    void nmi_standalone_entry();
    void nmi_entry();
}

namespace
{
    crt::bitmap_t processor_nmi_states = { };
}

void set_up_nmi_handling()
{
    segment_descriptor_register_64 idtr = { };

    __sidt(&idtr);

    if (idtr.base_address == 0)
    {
        return;
    }

    const auto interrupt_gates = reinterpret_cast<segment_descriptor_interrupt_gate_64*>(idtr.base_address);
    segment_descriptor_interrupt_gate_64* const nmi_gate = &interrupt_gates[2];
    segment_descriptor_interrupt_gate_64 new_gate = *nmi_gate;

    std::uint64_t new_handler = reinterpret_cast<std::uint64_t>(nmi_entry);

    if (new_gate.present == 0)
    {
        constexpr segment_selector gate_segment_selector = { .index = 1 };

        new_gate.segment_selector = gate_segment_selector.flags;
        new_gate.type = SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE;
        new_gate.present = 1;

        new_handler = reinterpret_cast<std::uint64_t>(nmi_standalone_entry);
    }
    else
    {
        original_nmi_handler = nmi_gate->offset_low | (nmi_gate->offset_middle << 16) | (static_cast<uint64_t>(nmi_gate->offset_high) << 32);
    }

    new_gate.offset_low = new_handler & 0xFFFF;
    new_gate.offset_middle = (new_handler >> 16) & 0xFFFF;
    new_gate.offset_high = (new_handler >> 32) & 0xFFFFFFFF;

    *nmi_gate = new_gate;
}

void interrupts::set_up()
{
    constexpr std::uint64_t processor_nmi_state_count = 0x1000 / sizeof(crt::bitmap_t::size_type);

    processor_nmi_states.set_value(static_cast<crt::bitmap_t::pointer>(heap_manager::allocate_page()));
    processor_nmi_states.set_count(processor_nmi_state_count);

    apic = apic_t::create_instance();

#ifdef _INTELMACHINE
    set_up_nmi_handling();
#endif
}

void interrupts::set_all_nmi_ready()
{
    processor_nmi_states.set_all();
}

void interrupts::set_nmi_ready(const std::uint64_t apic_id)
{
    processor_nmi_states.set(apic_id);
}

void interrupts::clear_nmi_ready(const std::uint64_t apic_id)
{
    processor_nmi_states.clear(apic_id);
}

crt::bitmap_t::bit_type interrupts::is_nmi_ready(const std::uint64_t apic_id)
{
    return processor_nmi_states.is_set(apic_id);
}

void interrupts::process_nmi()
{
    const std::uint64_t current_apic_id = apic_t::current_apic_id();

    if (is_nmi_ready(current_apic_id) == 1)
    {
        slat::flush_current_logical_processor_cache();

        clear_nmi_ready(current_apic_id);
    }
}

void interrupts::send_nmi_all_but_self()
{
    apic->send_nmi(icr_destination_shorthand_t::all_but_self);
}
