/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_MSR_LIST_H
#define _ASM_X86_MSR_LIST_H

#ifndef __ASSEMBLY__

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

static inline void wrmsrnsl(unsigned int msr, u64 val)
{
	wrmsrns(msr, (u32)(val & 0xffffffffULL), (u32)(val >> 32));
}

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_MSR_LIST_H */
