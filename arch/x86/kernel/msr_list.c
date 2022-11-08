// SPDX-License-Identifier: GPL-2.0-only
#include <asm/msr.h>
#include <asm/msr-list.h>
#include <asm/perf_event.h>

u64 x86_msrlist_msrs[X86_MSRLIST_MAX] __read_mostly = {
	/*
	 * The perf_event related MSRs are initialized in the perf_event subsystem.
	 * See init_perf_msrlist().
	 */
};

DEFINE_PER_CPU(u64, x86_msrlist_data[X86_MSRLIST_MAX]);
DEFINE_PER_CPU(unsigned long, x86_msrlist_mask[BITS_TO_LONGS(X86_MSRLIST_MAX)]) = { 0 };

DEFINE_STATIC_CALL(msrlist_rdmsrl, x86_rdmsrl);
DEFINE_STATIC_CALL(msrlist_wrmsrl, x86_wrmsrl);
DEFINE_STATIC_CALL_NULL(msrlist_msrlist, intel_msrlist);

void init_msrlist(void)
{
	if (!cpu_feature_enabled(X86_FEATURE_MSRLIST))
		return;

#ifdef CONFIG_X86_64
	static_call_update(msrlist_rdmsrl, intel_rdmsrl);
	static_call_update(msrlist_wrmsrl, intel_wrmsrl);
	static_call_update(msrlist_msrlist, intel_msrlist);
#endif
}
EXPORT_SYMBOL(init_msrlist);
