// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kexec.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/pfn.h>
#include <linux/spinlock.h>
#include <linux/set_memory.h>

#include <asm/io.h>
#include <asm/setup.h>
#include <asm/shared/tdx.h>
#include <asm/unaccepted_memory.h>

/* Protects unaccepted memory bitmap */
static DEFINE_SPINLOCK(unaccepted_memory_lock);

void accept_memory(phys_addr_t start, phys_addr_t end)
{
	unsigned long range_start, range_end;
	unsigned long *bitmap;
	unsigned long flags;

	if (!boot_params.unaccepted_memory)
		return;

	bitmap = __va(boot_params.unaccepted_memory);
	range_start = start / PMD_SIZE;

	/*
	 * load_unaligned_zeropad() can lead to unwanted loads across page
	 * boundaries. The unwanted loads are typically harmless. But, they
	 * might be made to totally unrelated or even unmapped memory.
	 * load_unaligned_zeropad() relies on exception fixup (#PF, #GP and now
	 * #VE) to recover from these unwanted loads.
	 *
	 * But, this approach does not work for unaccepted memory. For TDX, a
	 * load from unaccepted memory will not lead to a recoverable exception
	 * within the guest. The guest will exit to the VMM where the only
	 * recourse is to terminate the guest.
	 *
	 * There are three parts to fix this issue and comprehensively avoid
	 * access to unaccepted memory. Together these ensure that an extra
	 * "guard" page is accepted in addition to the memory that needs to be
	 * used:
	 *
	 * 1. Implicitly extend the range_contains_unaccepted_memory(start, end)
	 *    checks up to end+2M if 'end' is aligned on a 2M boundary.
	 *
	 * 2. Implicitly extend accept_memory(start, end) to end+2M if 'end' is
	 *    aligned on a 2M boundary. (immediately following this comment)
	 *
	 * 3. Set PageUnaccepted() on both memory that itself needs to be
	 *    accepted *and* memory where the next page needs to be accepted.
	 *    Essentially, make PageUnaccepted(page) a marker for whether work
	 *    needs to be done to make 'page' usable. That work might include
	 *    accepting pages in addition to 'page' itself.
	 */
	if (!(end % PMD_SIZE))
		end += PMD_SIZE;

	spin_lock_irqsave(&unaccepted_memory_lock, flags);
	for_each_set_bitrange_from(range_start, range_end, bitmap,
				   DIV_ROUND_UP(end, PMD_SIZE)) {
		unsigned long len = range_end - range_start;

		/* Platform-specific memory-acceptance call goes here */
		if (cpu_feature_enabled(X86_FEATURE_TDX_GUEST)) {
			tdx_accept_memory(range_start * PMD_SIZE,
					  range_end * PMD_SIZE);
		} else {
			panic("Cannot accept memory: unknown platform\n");
		}

		bitmap_clear(bitmap, range_start, len);
	}
	spin_unlock_irqrestore(&unaccepted_memory_lock, flags);
}

bool unaccept_memory(phys_addr_t start, phys_addr_t end)
{
	unsigned long *bitmap;
	unsigned long flags;
	unsigned long long i;
	int accepted = 0;

	if (!boot_params.unaccepted_memory)
		return false;

	if (!IS_ALIGNED(start, PMD_SIZE) || !IS_ALIGNED(end, PMD_SIZE)) {
		pr_err("Error: requested memory range isn't 2MB aligned\n");
		return false;
	}

	spin_lock_irqsave(&unaccepted_memory_lock, flags);
	bitmap = __va(boot_params.unaccepted_memory);
	for (i = start / PMD_SIZE; i < DIV_ROUND_UP(end, PMD_SIZE); i++) {
		if (!test_bit(i, bitmap)) {
			accepted++;
			pr_err("IO TLB: found %llx accepted\n", i * PMD_SIZE);
			set_memory_decrypted((unsigned long)__va(i * PMD_SIZE),
					     PMD_SIZE >> PAGE_SHIFT);
			set_bit(i, bitmap);
		}
	}

	/*
	 * To avoid load_unaligned_zeropad() stepping into unaccepted memory,
	 * the next 2MB page of the memory range supplied to accept_memory()
	 * may be accepted.
	 *
	 * But if the next 2MB page is unaccepted because it is converted to
	 * shared directly, trying to accept it would block shared accesses.
	 * Some failure is observed because the first 2MB page of swiotlb pool
	 * is converted to private at runtime when kernel tries to accept the
	 * preceding 2MB page.
	 *
	 * Mark the first page as accepted to avoid it being accepted due to
	 * the quirk of accept_memory().
	 */
	clear_bit(start / PMD_SIZE, bitmap);

	spin_unlock_irqrestore(&unaccepted_memory_lock, flags);
	pr_err("IO TLB: %llx-%llx accepted %d\n", start, end, accepted);

	return true;
}

bool range_contains_unaccepted_memory(phys_addr_t start, phys_addr_t end)
{
	unsigned long *bitmap;
	unsigned long flags;
	bool ret = false;

	if (!boot_params.unaccepted_memory)
		return 0;

	bitmap = __va(boot_params.unaccepted_memory);

	/*
	 * Also consider the unaccepted state of the *next* page. See fix #1 in
	 * the comment on load_unaligned_zeropad() in accept_memory().
	 */
	if (!(end % PMD_SIZE))
		end += PMD_SIZE;

	spin_lock_irqsave(&unaccepted_memory_lock, flags);
	while (start < end) {
		if (test_bit(start / PMD_SIZE, bitmap)) {
			ret = true;
			break;
		}

		start += PMD_SIZE;
	}
	spin_unlock_irqrestore(&unaccepted_memory_lock, flags);

	return ret;
}

#ifdef CONFIG_KEXEC_CORE
int arch_kexec_load(void)
{
	if (!boot_params.unaccepted_memory)
		return 0;

	/*
	 * TODO: Information on memory acceptance status has to be communicated
	 * between kernel.
	 */
	pr_warn_once("Disable kexec: not yet supported on systems with unaccepted memory\n");
	return -EOPNOTSUPP;
}
#endif
