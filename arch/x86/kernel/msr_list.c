// SPDX-License-Identifier: GPL-2.0-only
#include <asm/msr-list.h>

#ifdef CONFIG_X86_64
DEFINE_PER_CPU(struct msrlist, msrlist) = { 0 };
#endif /* CONFIG_X86_64 */
