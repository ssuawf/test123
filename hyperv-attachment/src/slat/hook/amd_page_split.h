#pragma once
#ifndef _INTELMACHINE
#include "hook_entry.h"
#include <ia32-doc/ia32.hpp>

union virtual_address_t;

namespace slat::hook
{
	void fix_split_instructions(cr3 slat_cr3, virtual_address_t target_guest_address);
	void unfix_split_instructions(const entry_t* hook_entry, cr3 slat_cr3, virtual_address_t target_guest_address);
}
#endif
