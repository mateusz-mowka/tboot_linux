// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * CPU Microcode Update Driver for Linux
 *
 * Copyright (C) 2000-2006 Tigran Aivazian <aivazian.tigran@gmail.com>
 *	      2006	Shaohua Li <shaohua.li@intel.com>
 *	      2013-2016	Borislav Petkov <bp@alien8.de>
 *
 * X86 CPU microcode early update for Linux:
 *
 *	Copyright (C) 2012 Fenghua Yu <fenghua.yu@intel.com>
 *			   H Peter Anvin" <hpa@zytor.com>
 *		  (C) 2015 Borislav Petkov <bp@alien8.de>
 *
 * This driver allows to upgrade microcode on x86 processors.
 */

#define DEBUG
#define pr_fmt(fmt) "microcode: " fmt

#include <linux/platform_device.h>
#include <linux/stop_machine.h>
#include <linux/syscore_ops.h>
#include <linux/miscdevice.h>
#include <linux/capability.h>
#include <linux/firmware.h>
#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/cpu.h>
#include <linux/nmi.h>
#include <linux/fs.h>
#include <linux/mm.h>

#include <asm/microcode_intel.h>
#include <asm/cpu_device_id.h>
#include <asm/microcode_amd.h>
#include <asm/perf_event.h>
#include <asm/microcode.h>
#include <asm/processor.h>
#include <asm/cmdline.h>
#include <asm/setup.h>
#include <asm/sgx.h>
#include <asm/apic.h>
#include <asm/mce.h>

#define DRIVER_VERSION	"2.2"

static struct microcode_ops	*microcode_ops;
static struct dentry		*dentry_ucode;
static bool dis_ucode_ldr = true;
bool override_minrev;
bool ucode_load_same;

bool initrd_gone;

LIST_HEAD(microcode_cache);

/*
 * Synchronization.
 *
 * All non cpu-hotplug-callback call sites use:
 *
 * - microcode_mutex to synchronize with each other;
 * - cpus_read_lock/unlock() to synchronize with
 *   the cpu-hotplug-callback call sites.
 *
 * We guarantee that only a single cpu is being
 * updated at any particular moment of time.
 */
static DEFINE_MUTEX(microcode_mutex);

struct ucode_cpu_info		ucode_cpu_info[NR_CPUS];

struct cpu_info_ctx {
	struct cpu_signature	*cpu_sig;
	int			err;
};

/*
 * Those patch levels cannot be updated to newer ones and thus should be final.
 */
static u32 final_levels[] = {
	0x01000098,
	0x0100009f,
	0x010000af,
	0, /* T-101 terminator */
};

/*
 * Check the current patch level on this CPU.
 *
 * Returns:
 *  - true: if update should stop
 *  - false: otherwise
 */
static bool amd_check_current_patch_level(void)
{
	u32 lvl, dummy, i;
	u32 *levels;

	native_rdmsr(MSR_AMD64_PATCH_LEVEL, lvl, dummy);

	if (IS_ENABLED(CONFIG_X86_32))
		levels = (u32 *)__pa_nodebug(&final_levels);
	else
		levels = final_levels;

	for (i = 0; levels[i]; i++) {
		if (lvl == levels[i])
			return true;
	}
	return false;
}

static bool __init check_loader_disabled_bsp(void)
{
	static const char *__dis_opt_str = "dis_ucode_ldr";

#ifdef CONFIG_X86_32
	const char *cmdline = (const char *)__pa_nodebug(boot_command_line);
	const char *option  = (const char *)__pa_nodebug(__dis_opt_str);
	bool *res = (bool *)__pa_nodebug(&dis_ucode_ldr);

#else /* CONFIG_X86_64 */
	const char *cmdline = boot_command_line;
	const char *option  = __dis_opt_str;
	bool *res = &dis_ucode_ldr;
#endif

	/*
	 * CPUID(1).ECX[31]: reserved for hypervisor use. This is still not
	 * completely accurate as xen pv guests don't see that CPUID bit set but
	 * that's good enough as they don't land on the BSP path anyway.
	 */
	if (native_cpuid_ecx(1) & BIT(31))
		return *res;

	if (x86_cpuid_vendor() == X86_VENDOR_AMD) {
		if (amd_check_current_patch_level())
			return *res;
	}

	if (cmdline_find_option_bool(cmdline, option) <= 0)
		*res = false;

	return *res;
}

void __init load_ucode_bsp(void)
{
	unsigned int cpuid_1_eax;
	bool intel = true;

	if (!have_cpuid_p())
		return;

	cpuid_1_eax = native_cpuid_eax(1);

	switch (x86_cpuid_vendor()) {
	case X86_VENDOR_INTEL:
		if (x86_family(cpuid_1_eax) < 6)
			return;
		break;

	case X86_VENDOR_AMD:
		if (x86_family(cpuid_1_eax) < 0x10)
			return;
		intel = false;
		break;

	default:
		return;
	}

	if (check_loader_disabled_bsp())
		return;

	if (intel)
		load_ucode_intel(true);
	else
		load_ucode_amd_bsp(cpuid_1_eax);
}

static bool check_loader_disabled_ap(void)
{
#ifdef CONFIG_X86_32
	return *((bool *)__pa_nodebug(&dis_ucode_ldr));
#else
	return dis_ucode_ldr;
#endif
}

void load_ucode_ap(void)
{
	unsigned int cpuid_1_eax;

	if (check_loader_disabled_ap())
		return;

	cpuid_1_eax = native_cpuid_eax(1);

	switch (x86_cpuid_vendor()) {
	case X86_VENDOR_INTEL:
		if (x86_family(cpuid_1_eax) >= 6)
			load_ucode_intel(false);
		break;
	case X86_VENDOR_AMD:
		if (x86_family(cpuid_1_eax) >= 0x10)
			load_ucode_amd_ap(cpuid_1_eax);
		break;
	default:
		break;
	}
}

static int __init save_microcode_in_initrd(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;
	int ret = -EINVAL;

	switch (c->x86_vendor) {
	case X86_VENDOR_INTEL:
		if (c->x86 >= 6)
			ret = save_microcode_in_initrd_intel();
		break;
	case X86_VENDOR_AMD:
		if (c->x86 >= 0x10)
			ret = save_microcode_in_initrd_amd(cpuid_eax(1));
		break;
	default:
		break;
	}

	initrd_gone = true;

	return ret;
}

struct cpio_data find_microcode_in_initrd(const char *path, bool use_pa)
{
#ifdef CONFIG_BLK_DEV_INITRD
	unsigned long start = 0;
	size_t size;

#ifdef CONFIG_X86_32
	struct boot_params *params;

	if (use_pa)
		params = (struct boot_params *)__pa_nodebug(&boot_params);
	else
		params = &boot_params;

	size = params->hdr.ramdisk_size;

	/*
	 * Set start only if we have an initrd image. We cannot use initrd_start
	 * because it is not set that early yet.
	 */
	if (size)
		start = params->hdr.ramdisk_image;

# else /* CONFIG_X86_64 */
	size  = (unsigned long)boot_params.ext_ramdisk_size << 32;
	size |= boot_params.hdr.ramdisk_size;

	if (size) {
		start  = (unsigned long)boot_params.ext_ramdisk_image << 32;
		start |= boot_params.hdr.ramdisk_image;

		start += PAGE_OFFSET;
	}
# endif

	/*
	 * Fixup the start address: after reserve_initrd() runs, initrd_start
	 * has the virtual address of the beginning of the initrd. It also
	 * possibly relocates the ramdisk. In either case, initrd_start contains
	 * the updated address so use that instead.
	 *
	 * initrd_gone is for the hotplug case where we've thrown out initrd
	 * already.
	 */
	if (!use_pa) {
		if (initrd_gone)
			return (struct cpio_data){ NULL, 0, "" };
		if (initrd_start)
			start = initrd_start;
	} else {
		/*
		 * The picture with physical addresses is a bit different: we
		 * need to get the *physical* address to which the ramdisk was
		 * relocated, i.e., relocated_ramdisk (not initrd_start) and
		 * since we're running from physical addresses, we need to access
		 * relocated_ramdisk through its *physical* address too.
		 */
		u64 *rr = (u64 *)__pa_nodebug(&relocated_ramdisk);
		if (*rr)
			start = *rr;
	}

	return find_cpio_data(path, (void *)start, size, NULL);
#else /* !CONFIG_BLK_DEV_INITRD */
	return (struct cpio_data){ NULL, 0, "" };
#endif
}

void reload_early_microcode(void)
{
	int vendor, family;

	vendor = x86_cpuid_vendor();
	family = x86_cpuid_family();

	switch (vendor) {
	case X86_VENDOR_INTEL:
		if (family >= 6)
			load_ucode_intel(false);
		break;
	case X86_VENDOR_AMD:
		if (family >= 0x10)
			reload_ucode_amd();
		break;
	default:
		break;
	}
}

/* fake device for request_firmware */
static struct platform_device	*microcode_pdev;

#ifdef CONFIG_MICROCODE_LATE_LOADING
static atomic_t ucode_updating;
static atomic_t mce_in_progress;

static enum ucode_load_scope load_scope;

static enum ucode_load_scope get_load_scope(void)
{
	if (!load_scope) {
		load_scope = microcode_ops->get_load_scope ?
				microcode_ops->get_load_scope() : CORE_SCOPE;
		pr_info_once("Load Scope: 0x%x", load_scope);
	}

	return load_scope;
}

/*
 * Late loading dance. Why the heavy-handed stomp_machine effort?
 *
 * - HT siblings must be idle and not execute other code while the other sibling
 *   is loading microcode in order to avoid any negative interactions caused by
 *   the loading.
 *
 * - In addition, microcode update on the cores must be serialized until this
 *   requirement can be relaxed in the future. Right now, this is conservative
 *   and good.
 */
#define SPINUNIT 100 /* 100 nsec */

static int check_online_cpus(void)
{
	unsigned int cpu;

	/*
	 * Make sure all CPUs are online.  It's fine for SMT to be disabled if
	 * all the primary threads are still online.
	 */
	for_each_present_cpu(cpu) {
		if (topology_is_primary_thread(cpu) && !cpu_online(cpu)) {
			pr_err("Not all CPUs online, aborting microcode update.\n");
			return -EBUSY;
		}
	}

	return 0;
}

#ifdef CONFIG_SMP
static atomic_t late_cpus_in;
static atomic_t late_cpus_out;

static int __wait_for_cpus(atomic_t *t, long long timeout)
{
	int all_cpus = num_online_cpus();

	atomic_inc(t);

	while (atomic_read(t) < all_cpus) {
		if (timeout < SPINUNIT) {
			pr_err("Timeout while waiting for CPUs rendezvous, remaining: %d\n",
				all_cpus - atomic_read(t));
			return 1;
		}

		ndelay(SPINUNIT);
		timeout -= SPINUNIT;

		touch_nmi_watchdog();
	}
	return 0;
}

/*
 * Empty stub to mark NMI as handled. The real work to block further NMIs
 * until microcode update finishes happens in hold_sibling_in_nmi()
 */
static int ucode_nmi_cb(unsigned int val, struct pt_regs *regs)
{
	return NMI_HANDLED;
}

static int get_target_cpu(int cpu)
{
	switch (load_scope) {
		case CORE_SCOPE:
			return cpumask_first(topology_sibling_cpumask(cpu));
		case PACKAGE_SCOPE:
			return cpumask_first(topology_core_cpumask(cpu));
		case PLATFORM_SCOPE:
			return cpumask_first(cpu_online_mask);
		default:
			return 0;
	}
}

static int get_target_num_cpus(int cpu)
{
	switch (load_scope) {
		case CORE_SCOPE:
			return cpumask_weight(topology_sibling_cpumask(cpu));
		case PACKAGE_SCOPE:
			return cpumask_weight(topology_core_cpumask(cpu));
		case PLATFORM_SCOPE:
			return cpumask_weight(cpu_online_mask);
		default:
			return 0;
	}
}

/*
 * Primary thread waits for all siblings to report that they have entered
 * the NMI handler
 */
static int __wait_for_core_siblings(struct core_rendez *rendez)
{
	long timeout = NSEC_PER_MSEC;
	atomic_t *t = &rendez->siblings_left;
	int cpu = smp_processor_id();

	while (atomic_read(t)) {
		cpu_relax();
		ndelay(SPINUNIT);
		touch_nmi_watchdog();
		timeout -= SPINUNIT;
		if (timeout < SPINUNIT) {
			pr_err("CPU%d timedout waiting for siblings\n", cpu);
			atomic_inc(&rendez->failed);
			return 1;
		}
	}
	return 0;
}

/*
 * Setup for the primary CPU of the core
 * - Number of siblings to wait before updating the microcode.
 * - Clear the core_done flag to indicate secondary CPUs
 * - Clear the failed counter to record any failures that may be noticed
 */
static int prepare_for_update(void)
{
	int ret, cpu, first_cpu;
	struct core_rendez *pcpu_core;

	ret = register_nmi_handler(NMI_LOCAL, ucode_nmi_cb, NMI_FLAG_FIRST,
				   "ucode_nmi");
	if (ret) {
		pr_err("Unable to register NMI handler\n");
		return -ENOSPC;
	}

	for_each_online_cpu(cpu) {
		first_cpu = get_target_cpu(cpu);
		if (cpu != first_cpu)
			continue;

		pcpu_core = &per_cpu(core_sync, first_cpu);
		atomic_set(&pcpu_core->siblings_left,
			   get_target_num_cpus(cpu) - 1);
		atomic_set(&pcpu_core->core_done, 0);
		atomic_set(&pcpu_core->failed, 0);
	}

	atomic_set(&late_cpus_in,  0);
	atomic_set(&late_cpus_out, 0);

	return 0;
}

/*
 * Returns:
 * < 0 - on error
 *   0 - success (no update done or microcode was updated)
 */
static int __reload_late(void *info)
{
	struct cpuinfo_x86 *bsp_info = &boot_cpu_data;
	struct cpuinfo_x86 *this_cpu_info;
	int first_cpu, cpu = smp_processor_id();
	struct ucode_cpu_info *uci;
	struct core_rendez *pcpu_core;
	enum ucode_state err;
	int ret = 0;

	/*
	 * Wait for all CPUs to arrive. A load will not be attempted unless all
	 * CPUs show up.
	 * */
	if (__wait_for_cpus(&late_cpus_in, NSEC_PER_SEC))
		return -1;

	/*
	 * On an SMT system, it suffices to load the microcode on one sibling of
	 * the core because the microcode engine is shared between the threads.
	 * Synchronization still needs to take place so that no concurrent
	 * loading attempts happen on multiple threads of an SMT core. See
	 * below.
	 */
	first_cpu = get_target_cpu(cpu);
	pcpu_core = &per_cpu(core_sync, first_cpu);

	/*
	 * Set the CPUs that we should hold in NMI until the primary has
	 * completed the microcode update.
	 */
	if (first_cpu == cpu) {
		/*
		 * Wait for all siblings to enter
		 * NMI before performing the update
		 */
		ret = __wait_for_core_siblings(pcpu_core);
		if (ret || atomic_read(&pcpu_core->failed)) {
			pr_err("CPU %d core lead timeout waiting for siblings\n", cpu);
			ret = -1;
		}
		pr_debug("Primary CPU %d proceeding with update\n", cpu);
		err = microcode_ops->apply_microcode(cpu);
		atomic_set(&pcpu_core->core_done, 1);
	} else {
		/*
		 * Update the secondary CPU of the core with a pointer to
		 * the primary CPUs control structure. This is needed in
		 * the NMI handler to:
		 *     - Update the sibling reached count to allow primary
		 *       CPU so start performing the microcode update.
		 *     - Also wait in the NMI until primary CPU has
		 *     indicated its complete the update.
		 * Now send the secondary CPU to NMI handler to wait.
		 */
		this_cpu_write(nmi_primary_ptr, pcpu_core);
		apic->send_IPI_self(NMI_VECTOR);
		goto wait_for_siblings;
	}

	if (ret || err >= UCODE_NFOUND) {
		if (err == UCODE_ERROR ||
		    (err == UCODE_NFOUND && !ucode_load_same)) {
			pr_warn("Error reloading microcode on CPU %d\n", cpu);
			ret = -1;
		}
	}

wait_for_siblings:
	if (__wait_for_cpus(&late_cpus_out, NSEC_PER_SEC))
		panic("Timeout during microcode update!\n");

	/*
	 * At least one thread has completed update on each core.
	 * For siblings, collect the cpuinfo and update the
	 * per-cpu cpuinfo with the current microcode revision.
	 */
	if (cpumask_first(topology_sibling_cpumask(cpu)) != cpu) {
		uci = ucode_cpu_info + cpu;
		microcode_ops->collect_cpu_info(cpu, &uci->cpu_sig);
	}

	this_cpu_info = &cpu_data(cpu);
	if (this_cpu_info->microcode != bsp_info->microcode)
		panic("Microcode Revision for CPU %d = 0x%x doesn't match BSP rev 0x%x\n",
		      cpu, this_cpu_info->microcode, bsp_info->microcode);

	return ret;
}

static void cleanup_after_update(void)
{
	unregister_nmi_handler(NMI_LOCAL, "ucode_nmi");
}

static int do_load_microcode(void)
{
	return stop_machine_cpuslocked(__reload_late, NULL, cpu_online_mask);
}
#else
static int prepare_for_update(void)
{
	return 0;
}

#define cleanup_after_update() { }
static int do_load_microcode(void)
{
	return microcode_ops->apply_microcode(0);
}
#endif

void noinstr inform_ucode_mce_in_progress(void)
{
	if (arch_atomic_read(&ucode_updating))
		arch_atomic_set(&mce_in_progress, 1);
}

/*
 * Reload microcode late on all CPUs. Wait for a sec until they
 * all gather together.
 */
static int microcode_reload_late(void)
{
	int old = boot_cpu_data.microcode, ret;

	ret = prepare_for_update();

	if (ret)
		goto done;

	atomic_set(&ucode_updating, 1);
	ret = do_load_microcode();
	atomic_set(&ucode_updating, 0);

	if (atomic_read(&mce_in_progress))
		pr_warn("MCE occured while microcode update was in progress\n");

	atomic_set(&mce_in_progress, 0);

	cleanup_after_update();
done:

	if (ret == 0) {
		pr_info("Reload completed, microcode revision: 0x%x -> 0x%x\n",
			old, boot_cpu_data.microcode);
		microcode_check();
▸       } else {
▸       ▸       pr_info("Reload failed, current microcode revision: 0x%x\n",
▸       ▸       ▸       boot_cpu_data.microcode);¬
▸       }

	return ret;
}

static ssize_t reload_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf, size_t size)
{
	enum ucode_state tmp_ret = UCODE_OK;
	int bsp = boot_cpu_data.cpu_index;
	enum ucode_load_scope load_scope;
	unsigned long val;
	bool safe_late_load = false;
	ssize_t ret;

	ret = kstrtoul(buf, 0, &val);
	if (ret)
		return ret;

	if (val != 1)
		return size;

	tmp_ret = microcode_ops->request_microcode_fw(bsp, &microcode_pdev->dev);
	if (tmp_ret != UCODE_NEW) {
		if (tmp_ret == UCODE_ERROR)
			return -EINVAL;

		if (!ucode_load_same)
			return size;

		pr_info("Force loading ucode\n");
	}

	load_scope = get_load_scope();
	if (load_scope == NO_LATE_UPDATE) {
		pr_err_once("Platform doesn't support late loading\n");
		pr_err_once("Please contact your BIOS vendor\n");
		return size;
	}

	cpus_read_lock();

	ret = check_online_cpus();
	if (ret)
		goto unlock;

	safe_late_load = microcode_ops->safe_late_load;

	/*
	 * If safe loading indication isn't present, bail out.
	 */
	if (!safe_late_load) {
		pr_err("Attempting late microcode loading - it is dangerous and taints the kernel.\n");
		pr_err("You should switch to early loading, if possible.\n");
		ret = -EINVAL;

		if (!override_minrev)
			goto unlock;

		pr_info("Overriding minrev\n");
	}

	mutex_lock(&microcode_mutex);
	ret = microcode_reload_late();
	mutex_unlock(&microcode_mutex);

	if (ret == 0) {
		ret = size;
		if (!safe_late_load || override_minrev) {
			add_taint(TAINT_CPU_OUT_OF_SPEC, LOCKDEP_STILL_OK);
			pr_warn("Microcode late loading tainted the kernel\n");
		}
	}

unlock:
	cpus_read_unlock();

	return ret;
}

static DEVICE_ATTR_WO(reload);
#endif

static ssize_t version_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct ucode_cpu_info *uci = ucode_cpu_info + dev->id;

	return sprintf(buf, "0x%x\n", uci->cpu_sig.rev);
}

static ssize_t pf_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct ucode_cpu_info *uci = ucode_cpu_info + dev->id;

	return sprintf(buf, "0x%x\n", uci->cpu_sig.pf);
}

static DEVICE_ATTR(version, 0444, version_show, NULL);
static DEVICE_ATTR(processor_flags, 0444, pf_show, NULL);

static struct attribute *mc_default_attrs[] = {
	&dev_attr_version.attr,
	&dev_attr_processor_flags.attr,
	NULL
};

static const struct attribute_group mc_attr_group = {
	.attrs			= mc_default_attrs,
	.name			= "microcode",
};

static void microcode_fini_cpu(int cpu)
{
	if (microcode_ops->microcode_fini_cpu)
		microcode_ops->microcode_fini_cpu(cpu);
}

static enum ucode_state microcode_init_cpu(int cpu)
{
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;

	memset(uci, 0, sizeof(*uci));

	microcode_ops->collect_cpu_info(cpu, &uci->cpu_sig);

	return microcode_ops->apply_microcode(cpu);
}

/**
 * microcode_bsp_resume - Update boot CPU microcode during resume.
 */
void microcode_bsp_resume(void)
{
	int cpu = smp_processor_id();
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;

	if (uci->mc)
		microcode_ops->apply_microcode(cpu);
	else
		reload_early_microcode();
}

static struct syscore_ops mc_syscore_ops = {
	.resume	= microcode_bsp_resume,
};

static int mc_cpu_starting(unsigned int cpu)
{
	enum ucode_state err = microcode_ops->apply_microcode(cpu);

	pr_debug("%s: CPU%d, err: %d\n", __func__, cpu, err);

	return err == UCODE_ERROR;
}

static int mc_cpu_online(unsigned int cpu)
{
	struct device *dev = get_cpu_device(cpu);

	if (sysfs_create_group(&dev->kobj, &mc_attr_group))
		pr_err("Failed to create group for CPU%d\n", cpu);
	return 0;
}

static int mc_cpu_down_prep(unsigned int cpu)
{
	struct device *dev;

	dev = get_cpu_device(cpu);

	microcode_fini_cpu(cpu);

	/* Suspend is in progress, only remove the interface */
	sysfs_remove_group(&dev->kobj, &mc_attr_group);
	pr_debug("%s: CPU%d\n", __func__, cpu);

	return 0;
}

static void setup_online_cpu(struct work_struct *work)
{
	int cpu = smp_processor_id();
	enum ucode_state err;

	err = microcode_init_cpu(cpu);
	if (err == UCODE_ERROR) {
		pr_err("Error applying microcode on CPU%d\n", cpu);
		return;
	}

	mc_cpu_online(cpu);
}

static ssize_t svnupdate_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf, size_t size)
{
	unsigned long val;
	ssize_t ret = 0;

	ret = kstrtoul(buf, 0, &val);
	if (ret)
		return ret;

	if (val == 1) {
		mutex_lock(&microcode_mutex);
		sgx_update_cpusvn_intel();
		mutex_unlock(&microcode_mutex);
	}

	return size;
}
static DEVICE_ATTR_WO(svnupdate);

static struct attribute *cpu_root_microcode_attrs[] = {
#ifdef CONFIG_MICROCODE_LATE_LOADING
	&dev_attr_reload.attr,
#endif
	NULL
};

static const struct attribute_group cpu_root_microcode_group = {
	.name  = "microcode",
	.attrs = cpu_root_microcode_attrs,
};

static int __init microcode_init(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;
	unsigned int cpuid_level;
	int error;

	if (dis_ucode_ldr)
		return -EINVAL;

	if (c->x86_vendor == X86_VENDOR_INTEL)
		microcode_ops = init_intel_microcode();
	else if (c->x86_vendor == X86_VENDOR_AMD)
		microcode_ops = init_amd_microcode();
	else
		pr_err("no support for this CPU vendor\n");

	if (!microcode_ops)
		return -ENODEV;

	microcode_pdev = platform_device_register_simple("microcode", -1, NULL, 0);
	if (IS_ERR(microcode_pdev))
		return PTR_ERR(microcode_pdev);

	error = sysfs_create_group(&cpu_subsys.dev_root->kobj, &cpu_root_microcode_group);
	if (error) {
		pr_err("Error creating microcode group!\n");
		goto out_pdev;
	}

	/*
	 * Check CPUID directly. If SGX support bit is on
	 * in CPUID level 0x00000007:0 (EBX), and EUPDAESVN
	 * is enabled, allow svnupdate to occur even if
	 * X86/FEATURE_SGX is clear. Future kexec()'s kernels
	 * may want to use SGX.
	 */
	cpuid_level = cpuid_eax(0);
	if (sysfs_svnupdate_enabled() && (cpuid_level >= 7) &&
	    (cpuid_ebx(7) & (X86_FEATURE_SGX % 32)) &&
	    (cpuid_eax(SGX_CPUID) & SGX_CPUID_EUPDATESVN)) {
		error = sysfs_add_file_to_group(&cpu_subsys.dev_root->kobj,
						&dev_attr_svnupdate.attr,
						"microcode");

		if (error)
			pr_err("Error creating microcode svnupdate file!\n");
	}

	/* Do per-CPU setup */
	schedule_on_each_cpu(setup_online_cpu);

	register_syscore_ops(&mc_syscore_ops);
	cpuhp_setup_state_nocalls(CPUHP_AP_MICROCODE_LOADER, "x86/microcode:starting",
				  mc_cpu_starting, NULL);
	cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN, "x86/microcode:online",
				  mc_cpu_online, mc_cpu_down_prep);

	dentry_ucode = debugfs_create_dir("microcode", NULL);
	debugfs_create_bool("override_minrev", 0644, dentry_ucode, &override_minrev);
	debugfs_create_bool("load_same", 0644, dentry_ucode, &ucode_load_same);

	pr_info("Microcode Update Driver: v%s.", DRIVER_VERSION);
	pr_info("Override minrev %s\n", override_minrev ? "enabled" : "disabled");
	pr_info("ucode_load_same is %s\n",
		ucode_load_same ? "enabled" : "disabled");

	return 0;

 out_pdev:
	platform_device_unregister(microcode_pdev);
	return error;

}
fs_initcall(save_microcode_in_initrd);
late_initcall(microcode_init);
