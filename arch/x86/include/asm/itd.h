/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_EHFI_H
#define _ASM_X86_EHFI_H

#include <linux/bits.h>

#include <asm/cpufeatures.h>
#include <asm/msr-index.h>

#define ITD_CHAR_VALID			BIT(31)

#ifdef CONFIG_SCHED_TASK_CLASSES
.macro	ITD_SAVE_CURR_TASK_CLASS
		/*
		 * Task classification:
		 * A) read the classification result of the current task.
		 * B) call HRESET to reset the classification hardware.
		 *
		 */
		ALTERNATIVE "jmp 1f", "", X86_FEATURE_ITD
		push %rdx
		push %rcx
		push %rax
		movl	$MSR_IA32_HW_FEEDBACK_CHAR, %ecx
		rdmsr
		/*
		 * Only update the classification result if it is valid (i.e.,
		 * MSR_IA32_HW_FEEDBACK_CHAR[63]). Such valid bit is loaded in
		 * %edx[31].
		 */
		test	$ITD_CHAR_VALID, %edx
		jz 2f
		movq	PER_CPU_VAR(current_task), %rdx
		mov	%al, TASK_class_raw(%rdx)
	2:
		pop %rax
		pop %rcx
		pop %rdx
	1:
.endm
#else /* CONFIG_X86_64 */
#define ITD_SAVE_CURR_TASK_CLASS
#endif /* CONFIG_X86_64 */
#endif /* _ASM_X86_EHFI_H */
