#pragma once
#include <ia32-doc/ia32.hpp>
#include <cstdint>

union virtual_address_t;

namespace slat
{
	void set_up();
	void process_first_vmexit();

	std::uint64_t translate_guest_physical_address(cr3 slat_cr3, virtual_address_t guest_physical_address, std::uint64_t* size_left_of_page = nullptr);

	std::uint8_t hide_heap_pages(cr3 slat_cr3);

	std::uint64_t hide_physical_page_from_guest(cr3 slat_cr3, virtual_address_t guest_physical_address);
	std::uint64_t hide_physical_page_from_guest(virtual_address_t guest_physical_address);
}
