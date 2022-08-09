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

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_MSR_LIST_H */
