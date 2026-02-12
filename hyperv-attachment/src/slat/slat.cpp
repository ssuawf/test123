#include "slat.h"
#include "../memory_manager/memory_manager.h"
#include "../memory_manager/heap_manager.h"
#include "../crt/crt.h"
#include <ia32-doc/ia32.hpp>

#include "cr3/cr3.h"
#include "cr3/pte.h"
#include "hook/hook.h"
#include "slat_def.h"

namespace
{
	std::uint64_t dummy_page_pfn = 0;
}

void set_up_dummy_page()
{
	void* const dummy_page_allocation = heap_manager::allocate_page();

	const std::uint64_t dummy_page_physical_address = memory_manager::unmap_host_physical(dummy_page_allocation);

	dummy_page_pfn = dummy_page_physical_address >> 12;

	crt::set_memory(dummy_page_allocation, 0, 0x1000);
}

void slat::set_up()
{
	hook::set_up_entries();
	set_up_dummy_page();
}

void slat::process_first_vmexit()
{
	set_up_hyperv_cr3();
}

std::uint64_t slat::translate_guest_physical_address(const cr3 slat_cr3, const virtual_address_t guest_physical_address, std::uint64_t* const size_left_of_page)
{
	return memory_manager::translate_host_virtual_address(slat_cr3, guest_physical_address, size_left_of_page);
}

std::uint8_t slat::hide_heap_pages(const cr3 slat_cr3)
{
	const std::uint64_t heap_physical_address = heap_manager::initial_physical_base;
	const std::uint64_t heap_physical_end = heap_physical_address + heap_manager::initial_size;

	std::uint64_t current_physical_address = heap_physical_address;

	while (current_physical_address < heap_physical_end)
	{
		hide_physical_page_from_guest(slat_cr3, { .address = current_physical_address });

		current_physical_address += 0x1000;
	}

	return 1;
}

std::uint64_t slat::hide_physical_page_from_guest(const cr3 slat_cr3, const virtual_address_t guest_physical_address)
{
	slat_pte* const target_pte = get_pte(slat_cr3, guest_physical_address, 1);

	if (target_pte == nullptr)
	{
		return 0;
	}

	target_pte->page_frame_number = dummy_page_pfn;

	return 1;
}

std::uint64_t slat::hide_physical_page_from_guest(const virtual_address_t guest_physical_address)
{
	return hide_physical_page_from_guest(hyperv_cr3(), guest_physical_address) && hide_physical_page_from_guest(hook_cr3(), guest_physical_address);
}
