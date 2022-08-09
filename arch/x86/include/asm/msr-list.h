/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_MSR_LIST_H
#define _ASM_X86_MSR_LIST_H

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/percpu.h>

#ifdef CONFIG_X86_64

/* Size of a msrlist batch */
#define MSRLIST_SIZE		64

struct msrlist {
	u64		msrs[MSRLIST_SIZE];
	u64		val[MSRLIST_SIZE];
	unsigned int	size;
};

/*
 * The global per-cpu msrlist is only used in the critical path,
 * e.g., context switch, interrupt, where the preemption is disabled.
 */
DECLARE_PER_CPU(struct msrlist, msrlist);

/* Read requested list of MSRs, and store the read value to memory */
#define RDMSRLIST	".byte 0xf2,0x0f,0x01,0xc6;"

/* Write requested list of MSRs with the values specified in memory */
#define WRMSRLIST	".byte 0xf3,0x0f,0x01,0xc6;"


static inline void rdmsrlistl(u64 data_list, u64 msr_list, u64 msr_mask)
{
	asm volatile (RDMSRLIST
		      : "+c" (msr_mask)
		      : "D" (data_list), "S" (msr_list), "c" (msr_mask)
		      : "memory");
}

static inline void wrmsrlistl(u64 data_list, u64 msr_list, u64 msr_mask)
{
	asm volatile (WRMSRLIST
		      : "+c" (msr_mask)
		      : "D" (data_list), "S" (msr_list), "c" (msr_mask)
		      : "memory");
}

static __always_inline void msrlist_writel(void)
{
	unsigned int size;

	if (!static_cpu_has(X86_FEATURE_MSRLIST))
		return;

	size = raw_cpu_read(msrlist.size);
	switch (size) {
		case 0:
			return;
		/*
		 * The WRMSRLIST has a better performance,
		 * when the number of MSRs is larger than 2.
		 * Fallback to WRMSRL for size 1 and 2.
		 */
		case 2:
			wrmsrl(raw_cpu_read(msrlist.msrs[1]), raw_cpu_read(msrlist.val[1]));
			fallthrough;
		case 1:
			wrmsrl(raw_cpu_read(msrlist.msrs[0]), raw_cpu_read(msrlist.val[0]));
			break;
		default:
			wrmsrlistl((uintptr_t)raw_cpu_ptr(msrlist.val),
				   (uintptr_t)raw_cpu_ptr(msrlist.msrs),
				   (1ULL << size) - 1);
	}
	raw_cpu_write(msrlist.size, 0);
}

static __always_inline void wrmsrl_batch(unsigned int msr, u64 val)
{
	if (static_cpu_has(X86_FEATURE_MSRLIST)) {
		unsigned int size = raw_cpu_read(msrlist.size);

		raw_cpu_write(msrlist.msrs[size], msr);
		raw_cpu_write(msrlist.val[size], val);
		raw_cpu_inc(msrlist.size);

		if (size == (MSRLIST_SIZE - 1))
			msrlist_writel();
	} else
		wrmsrl(msr, val);
}

#else /* !CONFIG_X86_64 */

static __always_inline void wrmsrl_batch(unsigned int msr, u64 val)
{
	wrmsrl(msr, val);
}

static __always_inline void msrlist_writel(void) {}

#endif /* CONFIG_X86_64 */

static inline void wrmsrns(unsigned int msr, u32 low, u32 high)
{
	asm volatile (".byte 0x0f,0x01,0xc6;"
		      : : "c" (msr), "a"(low), "d" (high) : "memory");
}

static inline void wrmsrnsl(unsigned int msr, u64 val)
{
	wrmsrns(msr, (u32)(val & 0xffffffffULL), (u32)(val >> 32));
}

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_MSR_LIST_H */
