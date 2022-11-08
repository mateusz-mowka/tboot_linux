/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_MSR_LIST_H
#define _ASM_X86_MSR_LIST_H

#ifndef __ASSEMBLY__

#include <asm/msr.h>

#include <linux/static_call.h>

#define X86_MSRLIST_SIZE	64
#define X86_MSRLIST_NR		1
#define X86_MSRLIST_MAX		(X86_MSRLIST_NR * X86_MSRLIST_SIZE)

extern u64 x86_msrlist_msrs[X86_MSRLIST_MAX] __read_mostly;
DECLARE_PER_CPU(u64, x86_msrlist_data[X86_MSRLIST_MAX]);
DECLARE_PER_CPU(unsigned long, x86_msrlist_mask[BITS_TO_LONGS(X86_MSRLIST_MAX)]);

#ifdef CONFIG_X86_64
static inline void rdmsrlist(u64 data_list, u64 msr_list, u64 msr_mask)
{
	asm volatile (".byte 0xf2,0x0f,0x01,0xc6;"
		      :
		      : "D" (data_list), "S" (msr_list), "c" (msr_mask)
		      : "memory");
}

static inline void wrmsrlist(u64 data_list, u64 msr_list, u64 msr_mask)
{
	asm volatile (".byte 0xf3,0x0f,0x01,0xc6;"
		      :
		      : "D" (data_list), "S" (msr_list), "c" (msr_mask)
		      : "memory");
}

static inline void wrmsrns(unsigned int msr, u32 low, u32 high)
{
	asm volatile (".byte 0x0f,0x01,0xc6;"
		      : : "c" (msr), "a"(low), "d" (high) : "memory");
}

#else
static inline void rdmsrlist(u64 data_list, u64 msr_list, u64 msr_mask)
{
}

static inline void wrmsrlist(u64 data_list, u64 msr_list, u64 msr_mask)
{
}

static inline void wrmsrns(unsigned int msr, u32 low, u32 high)
{
}
#endif

static inline void wrmsrnsl(unsigned int msr, u64 val)
{
	wrmsrns(msr, (u32)(val & 0xffffffffULL), (u32)(val >> 32));
}

static __always_inline void x86_rdmsrl(int idx, u64 *val)
{
	rdmsrl(x86_msrlist_msrs[idx], *val);
}

static __always_inline void intel_rdmsrl(int idx, u64 *val)
{
	*val = this_cpu_read(x86_msrlist_data[idx]);
}

static __always_inline void x86_wrmsrl(int idx, u64 val)
{
	wrmsrl(x86_msrlist_msrs[idx], val);
}

static __always_inline void intel_wrmsrl(int idx, u64 val)
{
	set_bit(idx, this_cpu_ptr(x86_msrlist_mask));
	this_cpu_write(x86_msrlist_data[idx], val);
}

DECLARE_STATIC_CALL(msrlist_rdmsrl, x86_rdmsrl);
DECLARE_STATIC_CALL(msrlist_wrmsrl, x86_wrmsrl);

static inline void intel_msrlist(int start, int end, bool wr)
{
	int idx;

	if (end > X86_MSRLIST_NR)
		end = X86_MSRLIST_NR;

	for (int i = start; i < end; i++) {
		if (bitmap_empty(this_cpu_ptr(&x86_msrlist_mask[i]), X86_MSRLIST_SIZE))
			continue;
		idx = i * X86_MSRLIST_SIZE;
		if (wr) {
			wrmsrlist((uintptr_t)this_cpu_ptr(&x86_msrlist_data[idx]),
				  (uintptr_t)&x86_msrlist_msrs[idx],
				  *(u64 *)this_cpu_ptr(&x86_msrlist_mask[i]));
		} else {
			rdmsrlist((uintptr_t)this_cpu_ptr(&x86_msrlist_data[idx]),
				  (uintptr_t)&x86_msrlist_msrs[idx],
				  *(u64 *)this_cpu_ptr(&x86_msrlist_mask[i]));
		}
		bitmap_clear(this_cpu_ptr(&x86_msrlist_mask[i]), 0, X86_MSRLIST_SIZE);
	}
}

DECLARE_STATIC_CALL(msrlist_msrlist, intel_msrlist);

void init_msrlist(void);

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_MSR_LIST_H */
