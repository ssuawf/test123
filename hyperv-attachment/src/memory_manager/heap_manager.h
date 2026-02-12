#pragma once
#include <cstdint>

namespace heap_manager
{
	void set_up(void* heap_base, std::uint64_t heap_size);

	void* allocate_page();
	std::uint64_t allocate_physical_page();

	void free_page(void* allocation_base);

	std::uint64_t get_free_page_count();

	class heap_entry_t
	{
	public:
		[[nodiscard]] heap_entry_t* next() const;
		void set_next(heap_entry_t* next);

	protected:
		heap_entry_t* next_ = nullptr;
	};

	inline std::uint64_t initial_physical_base = 0;
	inline std::uint64_t initial_size = 0;
}
