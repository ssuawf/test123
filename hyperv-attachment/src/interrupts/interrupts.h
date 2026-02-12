#pragma once
#include "../apic/apic.h"
#include "../crt/crt.h"

namespace interrupts
{
	void set_up();

	void set_all_nmi_ready();
	void set_nmi_ready(uint64_t apic_id);
	void clear_nmi_ready(uint64_t apic_id);

	crt::bitmap_t::bit_type is_nmi_ready(uint64_t apic_id);

	void process_nmi();
	void send_nmi_all_but_self();

	inline apic_t* apic = nullptr;
}
