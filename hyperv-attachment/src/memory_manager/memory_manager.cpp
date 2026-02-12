#include "memory_manager.h"

#include "../crt/crt.h"
#include "../slat/slat.h"

constexpr std::uint64_t host_physical_memory_access_base = 255ull << 39;

void* memory_manager::map_host_physical(const std::uint64_t host_physical_address)
{
	return reinterpret_cast<void*>(host_physical_memory_access_base + host_physical_address);
}

std::uint64_t memory_manager::unmap_host_physical(const void* const host_mapped_address)
{
	return reinterpret_cast<std::uint64_t>(host_mapped_address) - host_physical_memory_access_base;
}

void* memory_manager::map_guest_physical(const cr3 slat_cr3, const std::uint64_t guest_physical_address, std::uint64_t* const size_left_of_page)
{
	const virtual_address_t guest_physical_address_to_map = { .address = guest_physical_address };

	const std::uint64_t host_physical_address = slat::translate_guest_physical_address(slat_cr3, guest_physical_address_to_map, size_left_of_page);

	if (!host_physical_address)
	{
		return nullptr;
	}

	return reinterpret_cast<void*>(host_physical_memory_access_base + host_physical_address);
}

std::uint64_t memory_manager::translate_guest_virtual_address(const cr3 guest_cr3, const cr3 slat_cr3, const virtual_address_t guest_virtual_address, std::uint64_t* const size_left_of_page)
{
	const auto pml4 = static_cast<const pml4e_64*>(map_guest_physical(slat_cr3, guest_cr3.address_of_page_directory << 12));
	const pml4e_64 pml4e = pml4[guest_virtual_address.pml4_idx];

	if (pml4e.present == 0)
	{
		return 0;
	}

	const auto pdpt = static_cast<const pdpte_64*>(map_guest_physical(slat_cr3, pml4e.page_frame_number << 12));
	const pdpte_64 pdpte = pdpt[guest_virtual_address.pdpt_idx];

	if (pdpte.present == 0)
	{
		return 0;
	}

	if (pdpte.large_page == 1)
	{
		const pdpte_1gb_64 large_pdpte = { .flags = pdpte.flags };
		const std::uint64_t page_offset = (guest_virtual_address.pd_idx << 21) + (guest_virtual_address.pt_idx << 12) + guest_virtual_address.offset;

		if (size_left_of_page != nullptr)
		{
			*size_left_of_page = (1ull << 30) - page_offset;
		}

		return (large_pdpte.page_frame_number << 30) + page_offset;
	}

	const auto pd = static_cast<const pde_64*>(map_guest_physical(slat_cr3, pdpte.page_frame_number << 12));
	const pde_64 pde = pd[guest_virtual_address.pd_idx];

	if (pde.present == 0)
	{
		return 0;
	}

	if (pde.large_page == 1)
	{
		const pde_2mb_64 large_pde = { .flags = pde.flags };
		const std::uint64_t page_offset = (guest_virtual_address.pt_idx << 12) + guest_virtual_address.offset;

		if (size_left_of_page != nullptr)
		{
			*size_left_of_page = (1ull << 21) - page_offset;
		}

		return (large_pde.page_frame_number << 21) + page_offset;
	}

	const auto pt = static_cast<const pte_64*>(map_guest_physical(slat_cr3, pde.page_frame_number << 12));
	const pte_64 pte = pt[guest_virtual_address.pt_idx];

	if (pte.present == 0)
	{
		return 0;
	}

	const std::uint64_t page_offset = guest_virtual_address.offset;

	if (size_left_of_page != nullptr)
	{
		*size_left_of_page = (1ull << 12) - page_offset;
	}

	return (pte.page_frame_number << 12) + page_offset;
}

std::uint64_t memory_manager::translate_host_virtual_address(const cr3 host_cr3, const virtual_address_t host_virtual_address, std::uint64_t* const size_left_of_page)
{
	const auto pml4 = static_cast<const pml4e_64*>(map_host_physical(host_cr3.address_of_page_directory << 12));
	const pml4e_64 pml4e = pml4[host_virtual_address.pml4_idx];

	if (pml4e.present == 0)
	{
		return 0;
	}

	const auto pdpt = static_cast<const pdpte_64*>(map_host_physical(pml4e.page_frame_number << 12));
	const pdpte_64 pdpte = pdpt[host_virtual_address.pdpt_idx];

	if (pdpte.present == 0)
	{
		return 0;
	}

	if (pdpte.large_page == 1)
	{
		const pdpte_1gb_64 large_pdpte = { .flags = pdpte.flags };

		const std::uint64_t page_offset = (host_virtual_address.pd_idx << 21) + (host_virtual_address.pt_idx << 12) + host_virtual_address.offset;

		if (size_left_of_page != nullptr)
		{
			*size_left_of_page = (1ull << 30) - page_offset;
		}

		return (large_pdpte.page_frame_number << 30) + page_offset;
	}

	const auto pd = static_cast<const pde_64*>(map_host_physical(pdpte.page_frame_number << 12));
	const pde_64 pde = pd[host_virtual_address.pd_idx];

	if (pde.present == 0)
	{
		return 0;
	}

	if (pde.large_page == 1)
	{
		const pde_2mb_64 large_pde = { .flags = pde.flags };
		const std::uint64_t page_offset = (host_virtual_address.pt_idx << 12) + host_virtual_address.offset;

		if (size_left_of_page != nullptr)
		{
			*size_left_of_page = (1ull << 21) - page_offset;
		}

		return (large_pde.page_frame_number << 21) + page_offset;
	}

	const auto pt = static_cast<const pte_64*>(map_host_physical(pde.page_frame_number << 12));
	const pte_64 pte = pt[host_virtual_address.pt_idx];

	if (pte.present == 0)
	{
		return 0;
	}

	const std::uint64_t page_offset = host_virtual_address.offset;

	if (size_left_of_page != nullptr)
	{
		*size_left_of_page = (1ull << 12) - page_offset;
	}

	return (pte.page_frame_number << 12) + page_offset;
}

std::uint64_t memory_manager::operate_on_guest_virtual_memory(const cr3 slat_cr3, void* const host_buffer, const std::uint64_t guest_virtual_address, const cr3 guest_cr3, const std::uint64_t total_size, const memory_operation_t operation)
{
	std::uint64_t size_left_to_read = total_size;
	std::uint64_t bytes_read = 0;

	while (size_left_to_read != 0)
	{
		std::uint64_t size_left_of_virtual_page = 0;
		std::uint64_t size_left_of_slat_page = 0;

		const std::uint64_t guest_physical_address = translate_guest_virtual_address(guest_cr3, slat_cr3, { .address = guest_virtual_address + bytes_read }, &size_left_of_virtual_page);

		if (guest_physical_address == 0)
		{
			break;
		}

		void* guest_physical_mapped = map_guest_physical(slat_cr3, guest_physical_address, &size_left_of_slat_page);
		std::uint8_t* current_host_buffer = static_cast<std::uint8_t*>(host_buffer) + bytes_read;

		const std::uint64_t size_left_of_pages = crt::min(size_left_of_virtual_page, size_left_of_slat_page);
		const std::uint64_t copy_size = crt::min(size_left_to_read, size_left_of_pages);

		if (operation == memory_operation_t::write_operation)
		{
			crt::copy_memory(guest_physical_mapped, current_host_buffer, copy_size);
		}
		else
		{
			crt::copy_memory(current_host_buffer, guest_physical_mapped, copy_size);
		}

		size_left_to_read -= copy_size;
		bytes_read += copy_size;
	}

	return bytes_read;
}
