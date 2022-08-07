/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CET_H
#define _ASM_X86_CET_H

#ifndef __ASSEMBLY__
#include <linux/types.h>

struct task_struct;

struct thread_shstk {
	u64	base;
	u64	size;
};

#ifdef CONFIG_X86_SHADOW_STACK
long cet_prctl(struct task_struct *task, int option,
		      unsigned long features);
int shstk_setup(void);
int shstk_alloc_thread_stack(struct task_struct *p, unsigned long clone_flags,
			     unsigned long stack_size,
			     unsigned long *shstk_addr);
void shstk_free(struct task_struct *p);
int shstk_disable(void);
void reset_thread_shstk(void);
int setup_signal_shadow_stack(void __user *restorer);
int restore_signal_shadow_stack(void);
int wrss_control(bool enable);
#else
static inline long cet_prctl(struct task_struct *task, int option,
	       unsigned long features) { return -EINVAL; }
static inline int shstk_setup(void) { return -EOPNOTSUPP; }
static inline int shstk_alloc_thread_stack(struct task_struct *p,
					   unsigned long clone_flags,
					   unsigned long stack_size,
					   unsigned long *shstk_addr) { return 0; }
static inline void shstk_free(struct task_struct *p) {}
static inline int shstk_disable(void) { return -EOPNOTSUPP; }
static inline void reset_thread_shstk(void) {}
static inline int setup_signal_shadow_stack(void __user *restorer) { return 0; }
static inline int restore_signal_shadow_stack(void) { return 0; }
static inline int wrss_control(bool enable) { return -EOPNOTSUPP; }
#endif /* CONFIG_X86_SHADOW_STACK */

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_CET_H */
