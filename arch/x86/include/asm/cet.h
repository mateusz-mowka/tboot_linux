/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CET_H
#define _ASM_X86_CET_H

#ifndef __ASSEMBLY__
#include <linux/types.h>

struct task_struct;

#ifdef CONFIG_X86_SHADOW_STACK
long cet_prctl(struct task_struct *task, int option,
		      unsigned long features);
#else
long cet_prctl(struct task_struct *task, int option,
	       unsigned long features) { return -EINVAL; }
#endif /* CONFIG_X86_SHADOW_STACK */

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_CET_H */
