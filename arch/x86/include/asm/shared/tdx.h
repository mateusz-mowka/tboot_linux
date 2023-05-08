/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_SHARED_TDX_H
#define _ASM_X86_SHARED_TDX_H

#include <linux/bits.h>
#include <linux/types.h>

#define TDX_HYPERCALL_STANDARD  0

#define TDX_HCALL_HAS_OUTPUT	BIT(0)
#define TDX_HCALL_ISSUE_STI	BIT(1)

#define TDX_CPUID_LEAF_ID	0x21
#define TDX_IDENT		"IntelTDX    "

/* TDX module Call Leaf IDs */
#define TDX_GET_INFO			1
#define TDX_EXTEND_RTMR			2
#define TDX_GET_VEINFO			3
#define TDX_GET_REPORT			4
#define TDX_ACCEPT_PAGE			6
#define TDX_VERIFYREPORT		22

/* TDX hypercall Leaf IDs */
#define TDVMCALL_MAP_GPA		0x10001
#define TDVMCALL_SETUP_NOTIFY_INTR	0x10004
#define TDVMCALL_GET_QUOTE		0x10002

#define TDX_MODULECALL_RETRY_MAX	10000
#define TDX_MODULECALL_STATUS_MASK	0xFFFFFFFF00000000ULL

#define TDX_OPERAND_BUSY		0x8000020000000000ULL
#define TDX_OPERAND_BUSY_HOST_PRIORITY	0x8000020400000000ULL

#ifndef __ASSEMBLY__

/*
 * Used in __tdx_hypercall() to pass down and get back registers' values of
 * the TDCALL instruction when requesting services from the VMM.
 *
 * This is a software only structure and not part of the TDX module/VMM ABI.
 */
struct tdx_hypercall_args {
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
};

/* Used to request services from the VMM */
u64 __tdx_hypercall(struct tdx_hypercall_args *args, unsigned long flags);

/*
 * Wrapper for standard use of __tdx_hypercall with no output aside from
 * return code.
 */
static inline u64 _tdx_hypercall(u64 fn, u64 r12, u64 r13, u64 r14, u64 r15)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = fn,
		.r12 = r12,
		.r13 = r13,
		.r14 = r14,
		.r15 = r15,
	};

	return __tdx_hypercall(&args, 0);
}

/* Called from __tdx_hypercall() for unrecoverable failure */
void __tdx_hypercall_failed(void);

/*
 * Used in __tdx_module_call() to gather the output registers' values of the
 * TDCALL instruction when requesting services from the TDX module. This is a
 * software only structure and not part of the TDX module/VMM ABI
 */
struct tdx_module_output {
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
};

/* Used to communicate with the TDX module */
u64 __tdx_module_call_asm(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
			  u64 r10, u64 r11, u64 r12, u64 r13,
			  struct tdx_module_output *out);

static inline u64 __tdx_module_call(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
				    u64 r10, u64 r11, u64 r12, u64 r13,
				    struct tdx_module_output *out)
{
	u64 err, err_masked, retries = 0;

	do {
		err = __tdx_module_call_asm(fn, rcx, rdx, r8, r9,
					    r10, r11, r12, r13, out);
		if (likely(!err) || retries++ > TDX_MODULECALL_RETRY_MAX)
			break;

		err_masked = err & TDX_MODULECALL_STATUS_MASK;
	} while (err_masked == TDX_OPERAND_BUSY ||
		 err_masked == TDX_OPERAND_BUSY_HOST_PRIORITY);

	return err;
}

u64 __tdx_module_call_io_asm(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10,
			     u64 r11, u64 r12, u64 r13, u64 r14, u64 r15,
			     struct tdx_module_output *out);

static inline u64
__tdx_module_call_io(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10,
		     u64 r11, u64 r12, u64 r13, u64 r14, u64 r15,
		     struct tdx_module_output *out)
{
	u64 err, err_masked, retries = 0;

	do {
		err = __tdx_module_call_io_asm(fn, rcx, rdx, r8, r9, r10,
					       r11, r12, r13, r14, r15, out);
		if (likely(!err) || retries++ > TDX_MODULECALL_RETRY_MAX)
			break;

		err_masked = err & TDX_MODULECALL_STATUS_MASK;
	} while (err_masked == TDX_OPERAND_BUSY ||
		 err_masked == TDX_OPERAND_BUSY_HOST_PRIORITY);

	return err;
}

void tdx_accept_memory(phys_addr_t start, phys_addr_t end);

bool early_is_tdx_guest(void);

#endif /* !__ASSEMBLY__ */
#endif /* _ASM_X86_SHARED_TDX_H */
