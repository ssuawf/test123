#pragma once
#include <cstdint>
#include "../slat_def.h"

namespace slat
{
	void make_pml4_copy(const slat_pml4e* hyperv_pml4, slat_pml4e* hook_pml4, std::uint8_t make_non_executable);
}
