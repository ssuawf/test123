#include "hook_entry.h"
#include "../../crt/crt.h"

slat::hook::entry_t* slat::hook::entry_t::next() const
{
	return reinterpret_cast<entry_t*>(next_);
}

void slat::hook::entry_t::set_next(entry_t* const next_entry)
{
	next_ = reinterpret_cast<std::uint64_t>(next_entry);
}

std::uint64_t slat::hook::entry_t::original_pfn() const
{
	return original_pfn_;
}

void slat::hook::entry_t::set_original_pfn(const std::uint64_t original_pfn)
{
	original_pfn_ = original_pfn;
}

std::uint64_t slat::hook::entry_t::original_read_access() const
{
	return original_read_access_;
}

std::uint64_t slat::hook::entry_t::original_write_access() const
{
	return original_write_access_;
}

std::uint64_t slat::hook::entry_t::original_execute_access() const
{
	return original_execute_access_;
}

std::uint64_t slat::hook::entry_t::paging_split_state() const
{
	return paging_split_state_;
}

void slat::hook::entry_t::set_original_read_access(const std::uint64_t original_read_access)
{
	original_read_access_ = original_read_access;
}

void slat::hook::entry_t::set_original_write_access(const std::uint64_t original_write_access)
{
	original_write_access_ = original_write_access;
}

void slat::hook::entry_t::set_original_execute_access(const std::uint64_t original_execute_access)
{
	original_execute_access_ = original_execute_access;
}

void slat::hook::entry_t::set_paging_split_state(const std::uint64_t paging_split_state)
{
	paging_split_state_ = paging_split_state;
}

slat::hook::entry_t* slat::hook::entry_t::find(const std::uint64_t target_original_4kb_pfn, entry_t** const previous_entry_out)
{
	entry_t* current_entry = used_hook_list_head;
	entry_t* previous_entry = nullptr;

	while (current_entry != nullptr)
	{
		if (current_entry->original_pfn() == target_original_4kb_pfn)
		{
			if (previous_entry_out != nullptr)
			{
				*previous_entry_out = previous_entry;
			}

			return current_entry;
		}

		previous_entry = current_entry;
		current_entry = current_entry->next();
	}

	return nullptr;
}

slat::hook::entry_t* slat::hook::entry_t::find_in_2mb_range(const std::uint64_t target_original_4kb_pfn, const entry_t* const excluding_hook)
{
	entry_t* current_entry = used_hook_list_head;

	const std::uint64_t target_2mb_pfn = target_original_4kb_pfn >> 9;

	while (current_entry != nullptr)
	{
		const std::uint64_t current_hook_2mb_pfn = current_entry->original_pfn() >> 9;

		if (excluding_hook != current_entry && current_hook_2mb_pfn == target_2mb_pfn)
		{
			return current_entry;
		}

		current_entry = current_entry->next();
	}

	return nullptr;
}

slat::hook::entry_t* slat::hook::entry_t::find_closest_in_2mb_range(const std::uint64_t target_original_4kb_pfn, const entry_t* const excluding_hook)
{
	entry_t* current_entry = used_hook_list_head;

	const std::uint64_t target_2mb_pfn = target_original_4kb_pfn >> 9;

	entry_t* closest_entry = nullptr;
	std::int64_t closest_difference = INT64_MAX;

	while (current_entry != nullptr)
	{
		const std::uint64_t current_hook_4kb_pfn = current_entry->original_pfn();
		const std::uint64_t current_hook_2mb_pfn = current_hook_4kb_pfn >> 9;

		if (excluding_hook != current_entry && current_hook_2mb_pfn == target_2mb_pfn)
		{
			const std::int64_t current_difference = crt::abs(static_cast<std::int64_t>(current_hook_4kb_pfn) - static_cast<std::int64_t>(target_original_4kb_pfn));

			if (current_difference < closest_difference)
			{
				closest_difference = current_difference;
				closest_entry = current_entry;
			}
		}

		current_entry = current_entry->next();
	}

	return closest_entry;
}
