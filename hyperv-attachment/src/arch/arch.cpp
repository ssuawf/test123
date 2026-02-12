#include "arch.h"
#include "../crt/crt.h"

#include <intrin.h>

#ifdef _INTELMACHINE
#include <ia32-doc/ia32.hpp>

std::uint64_t vmread(const std::uint64_t field)
{
	std::uint64_t value = 0;

	__vmx_vmread(field, &value);

	return value;
}

void vmwrite(const std::uint64_t field, const std::uint64_t value)
{
	__vmx_vmwrite(field, value);
}

std::uint64_t get_vmexit_instruction_length()
{
	return vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH);
}

vmx_exit_qualification_ept_violation arch::get_exit_qualification()
{
	return { .flags = vmread(VMCS_EXIT_QUALIFICATION) };
}

std::uint64_t arch::get_guest_physical_address()
{
	return vmread(VMCS_GUEST_PHYSICAL_ADDRESS);
}

#else
std::uint8_t get_vmcb_routine_bytes[27];

typedef vmcb_t*(*get_vmcb_routine_t)();

vmcb_t* arch::get_vmcb()
{
	get_vmcb_routine_t get_vmcb_routine = reinterpret_cast<get_vmcb_routine_t>(&get_vmcb_routine_bytes[0]);

	return get_vmcb_routine();
}

void arch::parse_vmcb_gadget(const std::uint8_t* const get_vmcb_gadget)
{
	constexpr std::uint32_t final_needed_opcode_offset = 23;

	crt::copy_memory(&get_vmcb_routine_bytes[0], get_vmcb_gadget, final_needed_opcode_offset);

	if (get_vmcb_gadget[25] == 8) // needs to be dereffed once more
	{
		constexpr std::uint8_t return_bytes[4] = {
			0x48, 0x8B, 0x00, // mov rax, [rax]
			0xC3 // ret
		};

		crt::copy_memory(&get_vmcb_routine_bytes[final_needed_opcode_offset], &return_bytes[0], sizeof(return_bytes));
	}
	else
	{
		get_vmcb_routine_bytes[final_needed_opcode_offset] = 0xC3;
	}
}
#endif

std::uint64_t arch::get_vmexit_reason()
{
#ifdef _INTELMACHINE
	return vmread(VMCS_EXIT_REASON);
#else
	const vmcb_t* const vmcb = get_vmcb();

	return vmcb->control.vmexit_reason;
#endif
}

std::uint8_t arch::is_cpuid(const std::uint64_t vmexit_reason)
{
#ifdef _INTELMACHINE
	return vmexit_reason == VMX_EXIT_REASON_EXECUTE_CPUID;
#else
	return vmexit_reason == SVM_EXIT_REASON_CPUID;
#endif
}

std::uint8_t arch::is_slat_violation(const std::uint64_t vmexit_reason)
{
#ifdef _INTELMACHINE
	return vmexit_reason == VMX_EXIT_REASON_EPT_VIOLATION;
#else
	return vmexit_reason == SVM_EXIT_REASON_NPF;
#endif
}

std::uint8_t arch::is_non_maskable_interrupt_exit(const std::uint64_t vmexit_reason)
{
#ifdef _INTELMACHINE
	if (vmexit_reason != VMX_EXIT_REASON_EXCEPTION_OR_NMI)
	{
		return 0;
	}

	const std::uint64_t raw_interruption_information = vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION);

	const vmexit_interrupt_information interrupt_information = { .flags = static_cast<std::uint32_t>(raw_interruption_information) };

	return interrupt_information.interruption_type == interruption_type::non_maskable_interrupt;
#else
	return vmexit_reason == SVM_EXIT_REASON_PHYSICAL_NMI;
#endif
}

cr3 arch::get_guest_cr3()
{
	cr3 guest_cr3;

#ifdef _INTELMACHINE
	guest_cr3.flags = vmread(VMCS_GUEST_CR3);
#else
	const vmcb_t* const vmcb = get_vmcb();

	guest_cr3.flags = vmcb->save_state.cr3;
#endif

	return guest_cr3;
}

cr3 arch::get_slat_cr3()
{
	cr3 slat_cr3;

#ifdef _INTELMACHINE
	slat_cr3.flags = vmread(VMCS_CTRL_EPT_POINTER);
#else
	const vmcb_t* const vmcb = arch::get_vmcb();

	slat_cr3 = vmcb->control.nested_cr3;
#endif

	return slat_cr3;
}

void arch::set_slat_cr3(const cr3 slat_cr3)
{
#ifdef _INTELMACHINE
	vmwrite(VMCS_CTRL_EPT_POINTER, slat_cr3.flags);
#else
	vmcb_t* const vmcb = arch::get_vmcb();

	vmcb->control.nested_cr3 = slat_cr3;
#endif
}

std::uint64_t arch::get_guest_rsp()
{
#ifdef _INTELMACHINE
	return vmread(VMCS_GUEST_RSP);
#else
	const vmcb_t* const vmcb = get_vmcb();

	return vmcb->save_state.rsp;
#endif
}

void arch::set_guest_rsp(const std::uint64_t guest_rsp)
{
#ifdef _INTELMACHINE
	vmwrite(VMCS_GUEST_RSP, guest_rsp);
#else
	vmcb_t* const vmcb = get_vmcb();

	vmcb->save_state.rsp = guest_rsp;
#endif
}

std::uint64_t arch::get_guest_rip()
{
#ifdef _INTELMACHINE
	return vmread(VMCS_GUEST_RIP);
#else
	const vmcb_t* const vmcb = get_vmcb();

	return vmcb->save_state.rip;
#endif
}

void arch::set_guest_rip(const std::uint64_t guest_rip)
{
#ifdef _INTELMACHINE
	vmwrite(VMCS_GUEST_RIP, guest_rip);
#else
	vmcb_t* const vmcb = get_vmcb();

	vmcb->save_state.rip = guest_rip;
#endif
}

void arch::advance_guest_rip()
{
#ifdef _INTELMACHINE
	const std::uint64_t guest_rip = get_guest_rip();
	const std::uint64_t instruction_length = get_vmexit_instruction_length();

	const std::uint64_t next_rip = guest_rip + instruction_length;
#else
	const vmcb_t* const vmcb = get_vmcb();

	const std::uint64_t next_rip = vmcb->control.next_rip;
#endif

	set_guest_rip(next_rip);
}
