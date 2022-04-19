// SPDX-License-Identifier: GPL-2.0
/* Load and initialize TDX-module. */

#define pr_fmt(fmt) "tdx: " fmt

#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include <asm/msr.h>
#include <asm/tdx.h>
#include <asm/virtext.h>

/* Support Intel Secure Arbitration Mode Range Registers (SEAMRR) */
#define MTRR_CAP_SEAMRR			BIT(15)

/* Core-scope Intel SEAMRR base and mask registers. */
#define MSR_IA32_SEAMRR_PHYS_BASE	0x00001400
#define MSR_IA32_SEAMRR_PHYS_MASK	0x00001401

#define MSR_IA32_SEAMRR_PHYS_BASE_CONFIGURED    BIT_ULL(3)
#define MSR_IA32_SEAMRR_PHYS_MASK_ENABLED       BIT_ULL(11)
#define MSR_IA32_SEAMRR_PHYS_MASK_LOCKED        BIT_ULL(10)

/*
 * is_seamrr_enabled - check if seamrr is supported.
 */
static bool __init is_seamrr_enabled(void)
{
	u64 mtrrcap, seamrr_base, seamrr_mask;

	if (!boot_cpu_has(X86_FEATURE_MTRR))
		return false;

	/* MTRRcap.SEAMRR indicates the support of SEAMRR_PHYS_{BASE, MASK} */
	rdmsrl(MSR_MTRRcap, mtrrcap);
	if (!(mtrrcap & MTRR_CAP_SEAMRR))
		return false;

	rdmsrl(MSR_IA32_SEAMRR_PHYS_BASE, seamrr_base);
	if (!(seamrr_base & MSR_IA32_SEAMRR_PHYS_BASE_CONFIGURED)) {
		pr_info("SEAMRR base is not configured by BIOS\n");
		return false;
	}

	rdmsrl(MSR_IA32_SEAMRR_PHYS_MASK, seamrr_mask);
	if (!(seamrr_mask & MSR_IA32_SEAMRR_PHYS_MASK_ENABLED)) {
		pr_info("SEAMRR is not enabled by BIOS\n");
		return false;
	}

	return true;
}

struct vmcs_hdr {
	u32 revision_id:31;
	u32 shadow_vmcs:1;
};

struct vmcs {
	struct vmcs_hdr hdr;
	u32 abort;
	char data[];
};

static u32 seam_vmxon_version_id __initdata;
static DEFINE_PER_CPU(struct vmcs *, seam_vmxon_region);

/*
 * This function must be called before init_ia32_feat_ctl() that sets
 * X86_FEATURE_VMX.
 */
static int __init __seam_init_vmx_early(void)
{
	u64 msr;
	u32 vmx_msr_low, vmx_msr_high;

	/*
	 * Can't enable TDX if VMX is unsupported or disabled by BIOS.
	 * cpu_has(X86_FEATURE_VMX) can't be relied on as the BSP calls this
	 * before the kernel has configured feat_ctl().
	 */
	if (!cpu_has_vmx())
		return -EOPNOTSUPP;

	if (rdmsrl_safe(MSR_IA32_FEAT_CTL, &msr) ||
		!(msr & FEAT_CTL_LOCKED) ||
		!(msr & FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX))
		return -EOPNOTSUPP;

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	/*
	 * IA-32 SDM Vol 3C: VMCS size is never greater than 4kB.  The size of
	 * VMXON region is same to VMCS size.
	 */
	if ((vmx_msr_high & 0x1fff) > PAGE_SIZE)
		return -EIO;

	seam_vmxon_version_id = vmx_msr_low;

	return 0;
}

/*
 * This function must be called after init_ia32_feat_ctl() that sets
 * X86_FEATURE_VMX.
 */
static int __init seam_init_vmx_early(void)
{
	u32 vmx_msr_low, vmx_msr_high;

	if (!this_cpu_has(X86_FEATURE_VMX))
		return -EOPNOTSUPP;

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	/*
	 * IA-32 SDM Vol 3C: VMCS size is never greater than 4kB.  The size of
	 * VMXON region is same to VMCS size.
	 */
	if ((vmx_msr_high & 0x1fff) > PAGE_SIZE)
		return -EIO;

	seam_vmxon_version_id = vmx_msr_low;

	return 0;
}

/*
 * seam_init_vmxon_vmcs - initialize VMXON region with version id for this CPU.
 * @vmcs: vmxon region to initialize.  zero it before call.
 *
 * VMXON region has the same header format as the vmcs region.  It is assumed
 * that all CPUs have the same vmcs version.  The KVM kernel module has this
 * same assumption.  Even if the version differs, VMXON fails with
 * seam_vmxon_on_each_cpu() to catch it.
 */
static void __init seam_init_vmxon_vmcs(struct vmcs *vmcs)
{
	vmcs->hdr.revision_id = seam_vmxon_version_id;
}

static void __init seam_free_vmcs_tmp_set(void)
{
	int cpu;

	for_each_online_cpu(cpu) {
		/* It's safe to pass NULL to free_page() that ignores NULL. */
		free_page((unsigned long)per_cpu(seam_vmxon_region, cpu));
		per_cpu(seam_vmxon_region, cpu) = NULL;
	}
}

/*
 * seam_alloc_init_vmcs_tmp_set -
 *	allocate temporary one page for VMXON region for each CPU and stash
 *	pages to the per-cpu variable, seam_vmxon_region, and initialize those
 *	regions on each CPU for later VMXON.
 * @return: 0 on success, -ENOMEM on failure.
 *
 * Call this function before use of seam_vmxon_on_each_cpu() and
 * seam_vmxoff_on_each_cpu().
 *
 * Disable cpu hotplug by cpus_read_lock() and cpus_read_unlock() until
 * seam_free_vmcs_tmp_set().
 */
static int __init seam_alloc_init_vmcs_tmp_set(void)
{
	int cpu;
	struct vmcs *vmxon_region;

	if (!this_cpu_has(X86_FEATURE_VMX))
		return -EOPNOTSUPP;

	for_each_online_cpu(cpu) {
		/* VMXON region must be 4K-aligned. */
		vmxon_region = (struct vmcs *)get_zeroed_page(GFP_KERNEL);
		if (!vmxon_region)
			goto err;
		seam_init_vmxon_vmcs(vmxon_region);
		per_cpu(seam_vmxon_region, cpu) = vmxon_region;
	}

	return 0;

err:
	seam_free_vmcs_tmp_set();
	return -ENOMEM;
}

/*
 * cpu_vmxon() - Enable VMX on the current CPU
 *
 * Set CR4.VMXE and enable VMX
 */
static inline int cpu_vmxon(u64 vmxon_pointer)
{
	u64 msr;

	cr4_set_bits(X86_CR4_VMXE);

	asm_volatile_goto("1: vmxon %[vmxon_pointer]\n\t"
			_ASM_EXTABLE(1b, %l[fault])
			: : [vmxon_pointer] "m"(vmxon_pointer)
			: : fault);
	return 0;

fault:
	WARN_ONCE(1, "VMXON faulted, MSR_IA32_FEAT_CTL (0x3a) = 0x%llx\n",
		rdmsrl_safe(MSR_IA32_FEAT_CTL, &msr) ? 0xdeadbeef : msr);
	cr4_clear_bits(X86_CR4_VMXE);

	return -EFAULT;
}

static void __init seam_vmxon(void *data)
{
	atomic_t *error = data;
	int r;

	r = cpu_vmxon(__pa(this_cpu_read(seam_vmxon_region)));
	if (r)
		atomic_set(error, r);
}

static int __init seam_vmxon_on_each_cpu(void)
{
	atomic_t error;

	atomic_set(&error, 0);
	on_each_cpu(seam_vmxon, &error, 1);

	/*
	 * Check if any of the CPUs fail.  Don't care how many CPUs failed and
	 * about the exact error code.
	 */
	return atomic_read(&error);
}

static void __init seam_vmxoff(void *data)
{
	atomic_t *error = data;
	int r;

	r = cpu_vmxoff();
	if (r)
		atomic_set(error, r);
}

static int __init seam_vmxoff_on_each_cpu(void)
{
	atomic_t error;

	atomic_set(&error, 0);
	on_each_cpu(seam_vmxoff, &error, 1);

	/*
	 * Check if any of the CPUs fail.  Don't care how many CPUs failed and
	 * about the exact error code.
	 */
	return atomic_read(&error);
}
/*
 * Early system wide initialization of the TDX module. Check if the TDX firmware
 * loader and the TDX firmware module are available and log their version.
 */
static int __init tdx_arch_init(void)
{
	int vmxoff_err;
	int ret;

	/* TDX requires SEAM mode. */
	if (!is_seamrr_enabled())
		return -EOPNOTSUPP;

	/* TDX requires VMX. */
	ret = seam_init_vmx_early();
	if (ret)
		return ret;

	/*
	 * Prevent potential concurrent CPU online/offline because smp is
	 * enabled.
	 * - Make seam_vmx{on, off}_on_each_cpu() work.  Otherwise concurrently
	 *   onlined CPU has VMX disabled and the SEAM operation on that CPU
	 *   fails.
	 * - Ensure all present CPUs are online during this initialization after
	 *   the check.
	 */
	cpus_read_lock();

	/*
	 * Initialization of TDX module needs to involve all CPUs.  Ensure all
	 * CPUs are online.  All CPUs are required to be initialized by
	 * TDH.SYS.LP.INIT otherwise TDH.SYS.CONFIG fails.
	 */
	if (!cpumask_equal(cpu_present_mask, cpu_online_mask)) {
		ret = -EINVAL;
		goto out_err;
	}

	/* SEAMCALL requires to enable VMX on CPUs. */
	ret = seam_alloc_init_vmcs_tmp_set();
	if (ret)
		goto out_err;
	ret = seam_vmxon_on_each_cpu();
	if (ret)
		goto out;

	ret = tdx_init();
	if (ret)
		pr_err("Failed to initialize TDX module %d\n", ret);

out:
	/*
	 * Other codes (especially kvm_intel) expect that they're the first to
	 * use VMX.  That is, VMX is off on their initialization as a reset
	 * state.  Maintain the assumption to keep them working.
	 */
	vmxoff_err = seam_vmxoff_on_each_cpu();
	if (vmxoff_err) {
		pr_info("Failed to VMXOFF.\n");
		if (!ret)
			ret = vmxoff_err;
	}
	seam_free_vmcs_tmp_set();

out_err:
	cpus_read_unlock();

	if (ret)
		pr_err("Failed to find the TDX module. %d\n", ret);

	return ret;
}
arch_initcall(tdx_arch_init);
