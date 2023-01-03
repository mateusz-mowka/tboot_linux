/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_MSR_LIST_H
#define _ASM_X86_MSR_LIST_H

#ifndef __ASSEMBLY__

#ifdef CONFIG_X86_64

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

#endif /* CONFIG_X86_64 */
#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_MSR_LIST_H */
