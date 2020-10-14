/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_EHFI_H
#define _ASM_X86_EHFI_H

#include <linux/bits.h>

#include <asm/cpufeatures.h>
#include <asm/percpu.h>
#include <asm/msr-index.h>

#define ITD_CHAR_VALID			BIT(31)

#ifdef CONFIG_IPC_CLASSES
.macro	ITD_SAVE_CURR_TASK_CLASS
		/*
		 * Read the classification result of the current task.
		 */
		ALTERNATIVE "jmp 1f", "", X86_FEATURE_ITD
		push	%rdx
		push	%rcx
		push	%rbx
		push	%rax
		mov	$0, %rbx
		movl	$MSR_IA32_HW_FEEDBACK_CHAR, %ecx
		rdmsr
		/*
		 * Set ipcc_raw as unclassified if  the classification is
		 * invalid (i.e., MSR_IA32_HW_FEEDBACK_CHAR[63] is not set).
		 * Such valid bit is loaded in %edx[31].
		 */
		test	$ITD_CHAR_VALID, %edx
		jz	2f
		/* rdmsr loaded the classificaiton in %al */
		mov	%al, %bl
		/* IPCC classes start at 1. */
		inc	%bl
	2:
		movq	PER_CPU_VAR(pcpu_hot + X86_current_task), %rdx
		mov	%bl, TASK_ipcc_raw(%rdx)
		pop	%rax
		pop	%rbx
		pop	%rcx
		pop	%rdx
	1:
.endm
#else /* CONFIG_X86_64 */
#define ITD_SAVE_CURR_TASK_CLASS
#endif /* CONFIG_X86_64 */
#endif /* _ASM_X86_EHFI_H */
