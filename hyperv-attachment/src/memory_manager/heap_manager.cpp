#include "heap_manager.h"
#include "../crt/crt.h"
#include <intrin.h>

#include "memory_manager.h"

namespace
{
	constexpr std::uint64_t heap_block_size = 0x1000;

	heap_manager::heap_entry_t* free_block_list_head = nullptr;

	crt::mutex_t allocation_mutex = { };
}

void heap_manager::set_up(void* const heap_base, const std::uint64_t heap_size)
{
	free_block_list_head = static_cast<heap_entry_t*>(heap_base);

	const std::uint64_t heap_entries = heap_size / heap_block_size;

	heap_entry_t* entry = free_block_list_head;

	for (std::uint64_t i = 1; i < heap_entries - 1; i++)
	{
		entry->set_next(reinterpret_cast<heap_entry_t*>(reinterpret_cast<std::uint8_t*>(entry) + heap_block_size));

		entry = entry->next();
	}

	entry->set_next(nullptr);
}

void* heap_manager::allocate_page()
{
	allocation_mutex.lock();

	heap_entry_t* const entry = free_block_list_head;

	if (entry == nullptr)
	{
		allocation_mutex.release();

		return nullptr;
	}

	free_block_list_head = entry->next();

	allocation_mutex.release();

	return entry;
}

std::uint64_t heap_manager::allocate_physical_page()
{
	const void* const allocation = allocate_page();

	if (allocation == nullptr)
	{
		return 0;
	}

	return memory_manager::unmap_host_physical(allocation);
}

void heap_manager::free_page(void* const allocation_base)
{
	if (allocation_base == nullptr)
	{
		return;
	}

	allocation_mutex.lock();

	const auto entry = static_cast<heap_entry_t*>(allocation_base);

	entry->set_next(free_block_list_head);
	free_block_list_head = entry;

	allocation_mutex.release();
}

std::uint64_t heap_manager::get_free_page_count()
{
	allocation_mutex.lock();

	std::uint64_t count = 0;

	const heap_entry_t* entry = free_block_list_head;

	while (entry != nullptr)
	{
		count++;

		entry = entry->next();
	}

	allocation_mutex.release();

	return count;
}

heap_manager::heap_entry_t* heap_manager::heap_entry_t::next() const
{
	return next_;
}

void heap_manager::heap_entry_t::set_next(heap_entry_t* const next)
{
	next_ = next;
}
