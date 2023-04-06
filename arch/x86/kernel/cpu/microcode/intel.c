// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Intel CPU Microcode Update Driver for Linux
 *
 * Copyright (C) 2000-2006 Tigran Aivazian <aivazian.tigran@gmail.com>
 *		 2006 Shaohua Li <shaohua.li@intel.com>
 *
 * Intel CPU microcode early update for Linux
 *
 * Copyright (C) 2012 Fenghua Yu <fenghua.yu@intel.com>
 *		      H Peter Anvin" <hpa@zytor.com>
 */

/*
 * This needs to be before all headers so that pr_debug in printk.h doesn't turn
 * printk calls into no_printk().
 *
 *#define DEBUG
 */
#define DEBUG
#define pr_fmt(fmt) "microcode: " fmt


#include <linux/earlycpio.h>
#include <linux/firmware.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/initrd.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/uio.h>
#include <linux/mm.h>

#include <asm/microcode_intel.h>
#include <asm/intel-family.h>
#include <asm/msr-index.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>
#include <asm/setup.h>
#include <asm/msr.h>
#include <asm/cpu.h>

static const char ucode_path[] = "kernel/x86/microcode/GenuineIntel.bin";

/* Current microcode patch used in early patching on the APs. */

struct ucode_info {
	struct microcode_intel *ucode;
	int size;
};

static struct ucode_info intel_ucode;

/* last level cache size per core */
static int llc_size_per_core;

enum scope {
	UNIFORM_CORE     = 0x02, // Core Scope
	UNIFORM_PACKAGE  = 0x80, // Package Scope
	UNIFORM_PLATFORM = 0xC0, // Platform Scope
};

union mcu_enumeration {
	u64	data;
	struct {
		u64	valid:1;
		u64	required:1;
		u64	cfg_done:1;
		u64	rollback:1;
		u64	reserved:4;
		u64	scope:8;
	};
};

union mcu_status {
	u64	data;
	struct {
		u64	partial:1;
		u64	auth_fail:1;
		u64	rsvd:1;
		u64	post_bios_mcu:1;
	};
};

#define MSR_MCU_ENUM		(0x7b)
#define MSR_MCU_STATUS		(0x7c)

#define META_TYPE_ROLLBACK	(0x2)

static union mcu_enumeration mcu_cap;

/*
 * MSR's related to deferred commit architecture
 */
#define MSR_MCU_CONFIG		(0x7a0)
#define MSR_MCU_COMMIT		(0x7a1)
#define MSR_MCU_INFO		(0x7a2)

#define NUM_ROLLBACK_MSRS	(16)
#define MSR_ROLLBACK_SIGN_BASE	(0x7b0)
#define MSR_ROLLBACK_SIGN_ID(x)	(MSR_ROLLBACK_SIGN_BASE+(x))

struct rb_svn_info {
	u32	rb_min_svn:16;
	u32	rb_mcu_svn:16;
};

/* MSR_MCU_CONFIG */
union svn_config {
	u64	data;
	struct {
		u64	defer_svn:1;
		u64	lock:1;
	};
};

/* MSR_MCU_COMMIT */
union svn_commit {
	u64	data;
	struct {
		u64	commit_svn:1;
	};
};

#define NUM_RB_INFO	16
struct ucode_meta {
	struct	metadata_header	rb_hdr;
	struct  rb_svn_info svn_info;
	u32	rollback_id[NUM_RB_INFO];
	u16	rollback_svn[NUM_RB_INFO];
};

union min_svn {
	u64	data;
	struct {
		u64	mcu_svn:16;
		u64	pending_mcu_svn:16;
	};
};

union rb_sign_id {
	u64	data;
	struct {
		u64	rb_id:32;
		u64	rb_mcu_svn:16;
	};
};

struct rb_info {
	union	min_svn min_svn;
	union	rb_sign_id rb_sign_id[NUM_RB_INFO];
};

static struct rb_info bsp_rb_info;

static void dump_rollback_meta(struct ucode_meta *rb)
{
	int i;

	pr_debug("Type    : 0x%x\n", rb->rb_hdr.type);
	pr_debug("Block SZ: 0x%x\n", rb->rb_hdr.blk_size);
	pr_debug("Min SVN : 0x%x\n", rb->svn_info.rb_min_svn);
	pr_debug("MCU SVN : 0x%x\n", rb->svn_info.rb_mcu_svn);

	for (i = 0; i < NUM_RB_INFO; i++) {
		if (!rb->rollback_id[i])
			break;
		pr_debug("Rollback[%d]: ID: 0x%x SVN 0x%x\n", i, rb->rollback_id[i], rb->rollback_svn[i]);
	}
}

static struct microcode_ops microcode_intel_ops;
static atomic_t pending_commits;
static atomic_t commit_status;

static void read_commit_status(struct work_struct *work)
{
	union	svn_commit commit;
	int	cpu = smp_processor_id();

	if (!mcu_cap.rollback)
		return;

	rdmsrl(MSR_MCU_COMMIT, commit.data);
	if (commit.commit_svn) {
		atomic_inc(&pending_commits);
		pr_debug("CPU%d pending commit\n", cpu);
	}
}

static int check_pending(void)
{
	int rv = 0;

	if (!mcu_cap.rollback)
		return rv;

	atomic_set(&pending_commits, 0);

	rv = schedule_on_each_cpu(read_commit_status);

	if (!rv && atomic_read(&pending_commits))
		rv = -EBUSY;

	return rv;
}

static bool check_pending_commits(void)
{
	int rv = check_pending();

	return (rv == 0 ? false : true);
}

static void do_commit(struct work_struct *work)
{
	union	svn_commit commit;
	int	cpu = smp_processor_id();

	if (!mcu_cap.rollback)
		return;

	commit.data = 0;
	commit.commit_svn = 1;

	wrmsrl(MSR_MCU_COMMIT, commit.data);

	commit.data = 0;
	rdmsrl(MSR_MCU_COMMIT, commit.data);

	if (commit.commit_svn) {
		atomic_inc(&commit_status);
		pr_debug("CPU%d pending commit\n", cpu);
	}
}
static int perform_commit(void)
{
	int rv;

	rv = schedule_on_each_cpu(do_commit);

	if (!rv && !atomic_read(&commit_status))
		return rv;

	return -EBUSY;
}

static void write_auto_commit(struct work_struct *work)
{
	union svn_config cfg;

	cfg.data = 0;
	wrmsrl(MSR_MCU_CONFIG, cfg.data);
}

static int switch_to_auto_commit(void)
{
	union	svn_config cfg;
	int	rv;

	rv = check_pending();

	if (rv) {
		pr_err("Pending commit, Please commit before proceeding\n");
		return rv;
	}


	/*
	 * We know this is per-core MSR, but its enough to check just this
	 * CPU, since we expect the system to be consistent with this
	 * value across all cores.
	 */
	rdmsrl(MSR_MCU_CONFIG, cfg.data);

	/*
	 * Already with auto-commit
	 */
	if (!cfg.defer_svn)
		return 0;

	/*
	 * Admin has locked with manual commit, its not a preferred
	 * setting since booting a legacy kernel via kexec() will not
	 * know how to deal with manual commit.
	 */
	if (cfg.lock && cfg.defer_svn) {
		pr_err_once("Manual commit locked, can't switch to auto commit\n");
		return -EBUSY;
	}

	rv = schedule_on_each_cpu(write_auto_commit);

	pr_info("Switching to auto commit %s\n", rv ? "Failed" : "Succeeded");

	return rv;
}

static void write_manual_commit(struct work_struct *work)
{
	union svn_config cfg;

	cfg.data = 0;
	cfg.defer_svn = 1;
	wrmsrl(MSR_MCU_CONFIG, cfg.data);
}

static int switch_to_manual_commit(void)
{
	union	svn_config cfg;
	int	rv;

	/*
	 * If there are any pending commits, inform user to commit before
	 * proceeding.
	 */
	rv = check_pending();

	if (rv) {
		pr_err("Pending commit, Please commit before proceeding\n");
		return rv;
	}

	/*
	 * We know this is per-core MSR, but its enough to check just this
	 * CPU, since we expect the system to be consistent with this
	 * value across all cores.
	 */
	rdmsrl(MSR_MCU_CONFIG, cfg.data);

	/* Already manual commit is default */
	if (cfg.defer_svn)
		return 0;

	if (cfg.lock) {
		pr_info_once("SVN config locked with auto commit\n");
		return -EBUSY;
	}

	rv = schedule_on_each_cpu(write_manual_commit);

	pr_info("Switching to manual commit %s\n", rv ? "Failed" : "Succeeded");

	return rv;
}

static void save_bsp_rollback_info(void)
{
	int i;

	/*
	 * Always clear everything since a new MCU can have more entries
	 * populated in RB_INFO.
	 */
	memset(&bsp_rb_info, 0, sizeof(struct rb_info));

	rdmsrl(MSR_MCU_INFO, bsp_rb_info.min_svn.data);
	pr_debug("mcu_min_svn: 0x%x pending_svn: 0x%x\n",
		 bsp_rb_info.min_svn.mcu_svn, bsp_rb_info.min_svn.pending_mcu_svn);
	for (i = 0; i < NUM_RB_INFO; i++) {
		rdmsrl(MSR_ROLLBACK_SIGN_ID(i), bsp_rb_info.rb_sign_id[i].data);

		/*
		 * If this entry is clear, stop looking further.
		 */
		if (!bsp_rb_info.rb_sign_id[i].data)
			break;

		pr_debug("rollback_sign_id[%d]: patch Id: 0x%x mcu_svn: 0x%x\n",
			 i, bsp_rb_info.rb_sign_id[i].rb_id,
			 bsp_rb_info.rb_sign_id[i].rb_mcu_svn);
	}
}

static void setup_mcu_enumeration(void)
{
	u64 arch_cap;

	microcode_intel_ops.need_nmi_lateload = true;
	arch_cap = x86_read_arch_cap_msr();

	if (!(arch_cap & ARCH_CAP_MCU_ENUM))
		return;

	rdmsrl(MSR_MCU_ENUM, mcu_cap.data);

	if (mcu_cap.valid) {
		microcode_intel_ops.need_nmi_lateload = false;
		pr_info_once("Uniform Loading: Required: %s Configured: %s\n",
			     mcu_cap.required ? "Yes" : "No",
			     mcu_cap.cfg_done ? "Yes" : "No");
	}

	if (mcu_cap.rollback) {
		pr_info_once("Microcode Rollback Capability detected\n");
		save_bsp_rollback_info();
	}
}

static enum ucode_load_scope get_load_scope(void)
{

	/*
	 * If no capability is found, default to CORE scope
	 */
	if (!mcu_cap.valid)
		return CORE_SCOPE;

	/*
	 * If enumeration requires UNIFORM and the platform configuration
	 * is not complete, disable any further attempt to late loading.
	 */
	if (mcu_cap.required && !mcu_cap.cfg_done) {
		pr_info_once("Late loading disabled, check uniform config with BIOS vendor\n");
		return NO_LATE_UPDATE;
	}

	if (mcu_cap.scope == UNIFORM_PLATFORM) {
		pr_info_once("Platform Scope\n");
		return PLATFORM_SCOPE;
	}

	if(mcu_cap.scope == UNIFORM_PACKAGE) {
		pr_info_once("Package Scope\n");
		return PACKAGE_SCOPE;
	}

	return CORE_SCOPE;
}

/*
 * Returns 1 if update has been found, 0 otherwise.
 */
static int has_newer_microcode(void *mc, unsigned int csig, int cpf, int new_rev)
{
	struct microcode_header_intel *mc_hdr = mc;

	if (mc_hdr->rev <= new_rev)
		return 0;

	return intel_find_matching_signature(mc, csig, cpf);
}

static void save_microcode_patch(struct ucode_info *info, struct ucode_cpu_info *uci, void *data, unsigned int size)
{
	struct microcode_header_intel *mc_hdr, *p;

	if (!(info && data))
		return;

	mc_hdr = (struct microcode_header_intel *)data;

	if (info->ucode) {
		kfree(info->ucode);
		info->ucode = NULL;
		info->size = 0;
	}

	p = kmemdup(data, size, GFP_KERNEL);
	if (!p) {
		pr_err("Error allocating buffer for %p\n", data);
		return;
	}

	/*
	 * Save for early loading. On 32-bit, that needs to be a physical
	 * address as the APs are running from physical addresses, before
	 * paging has been enabled.
	 */
	if (IS_ENABLED(CONFIG_X86_32))
		info->ucode = (struct microcode_intel *)__pa_nodebug(p);
	else
		info->ucode = (struct microcode_intel *)p;

	info->size = size;
}

static int is_lateload_safe(struct microcode_header_intel *mc_header)
{
	struct ucode_cpu_info uci;

	/*
	 * If minrev is bypassed via debugfs, then allow late-load.
	 */
	if (override_minrev) {
		pr_info("Bypassing minrev enforcement via debugfs\n");
		return 0;
	}

	/*
	 * When late-loading, ensure the header declares a minimum revision
	 * required to perform a late-load.
	 */
	if (!mc_header->min_req_ver) {
		pr_warn("Late loading denied: Microcode header does not specify a required min version\n");
		return -EINVAL;
	}

	intel_cpu_collect_info(&uci);

	if (uci.cpu_sig.rev > mc_header->rev) {
		pr_warn("Current microcode rev 0x%x greater than 0x%x, aborting\n",
			uci.cpu_sig.rev, mc_header->rev);
		return -EINVAL;
	}
	/*
	 * Enforce the minimum revision specified in the header is either
	 * greater or equal to the current revision.
	 */
	if (uci.cpu_sig.rev < mc_header->min_req_ver) {
		pr_warn("Late loading denied: Current revision 0x%x too old to update, must be at 0x%x or higher. Use early loading instead\n",
			uci.cpu_sig.rev, mc_header->min_req_ver);
		return -EINVAL;
	}
	return 0;
}

static bool is_ucode_listed(struct ucode_meta *umeta)
{
	int i, cpu = smp_processor_id();
	struct ucode_cpu_info *uci;
	int rev;

	uci = ucode_cpu_info + cpu;
	rev = uci->cpu_sig.rev;

	for (i = 0; i < NUM_RB_INFO; i++) {
		if (!umeta->rollback_id[i])
			return false;
		if (umeta->rollback_id[i] == rev)
			return true;
	}
	return false;
}

static bool can_do_nocommit(struct microcode_header_intel *mch,
			    struct ucode_meta *umeta)
{
	if (!mcu_cap.rollback)
		return false;

	if (check_pending())
		return false;

	if (!is_ucode_listed(umeta))
		return false;
}

/*
 * Get microcode matching with BSP's model. Only CPUs with the same model as
 * BSP can stay in the platform.
 */
static struct microcode_intel *
scan_microcode(void *data, size_t size, struct ucode_cpu_info *uci, bool save)
{
	struct microcode_header_intel *mc_header;
	struct microcode_intel *patch = NULL;
	struct ucode_meta *rb_meta;
	unsigned int mc_size;

	while (size) {
		if (size < sizeof(struct microcode_header_intel))
			break;

		mc_header = (struct microcode_header_intel *)data;

		mc_size = get_totalsize(mc_header);
		if (!mc_size ||
		    mc_size > size ||
		    intel_microcode_sanity_check(data, false, MC_HEADER_TYPE_MICROCODE) < 0)
			break;

		size -= mc_size;

		if (!intel_find_matching_signature(data, uci->cpu_sig.sig,
						   uci->cpu_sig.pf)) {
			data += mc_size;
			continue;
		}

		rb_meta = (struct ucode_meta *)intel_microcode_find_meta_data(data, META_TYPE_ROLLBACK);
		if (rb_meta)
			dump_rollback_meta(rb_meta);

		if (save) {
			save_microcode_patch(&intel_ucode, uci, data, mc_size);
			goto next;
		}


		if (!patch) {
			if (!has_newer_microcode(data,
						 uci->cpu_sig.sig,
						 uci->cpu_sig.pf,
						 uci->cpu_sig.rev))
				goto next;

		} else {
			struct microcode_header_intel *phdr = &patch->hdr;

			if (!has_newer_microcode(data,
						 phdr->sig,
						 phdr->pf,
						 phdr->rev))
				goto next;
		}

		/* We have a newer patch, save it. */
		patch = data;
		pr_info("Setting patch at 0x%p val = 0x%lx \n", patch, (unsigned long) patch);

next:
		data += mc_size;
	}

	if (size) {
		pr_info("size = 0x%lx returning NULL\n", size);
		return NULL;
	}
	pr_info("Returning patch at 0x%p val = 0x%lxn", patch, (unsigned long) patch);

	return patch;
}

static void show_saved_mc(void *mc)
{
#ifdef DEBUG
	struct microcode_intel *ucode = mc;
	unsigned int sig, pf, rev, total_size, data_size, date;
	struct extended_sigtable *ext_header;
	struct extended_signature *ext_sig;
	struct ucode_meta *rb_meta;
	struct ucode_cpu_info uci;
	int j, ext_sigcount;

	if (!ucode) {
		pr_debug("no microcode data saved.\n");
		return;
	}

	intel_cpu_collect_info(&uci);

	sig	= uci.cpu_sig.sig;
	pf	= uci.cpu_sig.pf;
	rev	= uci.cpu_sig.rev;
	pr_debug("CPU: sig=0x%x, pf=0x%x, rev=0x%x\n", sig, pf, rev);

	sig	= ucode->hdr.sig;
	pf	= ucode->hdr.pf;
	rev	= ucode->hdr.rev;
	date	= ucode->hdr.date;

	total_size	= get_totalsize(ucode);
	data_size	= get_datasize(ucode);

	pr_debug("mc_saved: sig=0x%x, pf=0x%x, rev=0x%x, total size=0x%x, date = %04x-%02x-%02x\n",
		 sig, pf, rev, total_size, date & 0xffff,
		 date >> 24, (date >> 16) & 0xff);

	/* Look for ext. headers: */
	if (total_size <= data_size + MC_HEADER_SIZE)
		return;

	ext_header = (void *)ucode + data_size + MC_HEADER_SIZE;
	ext_sigcount = ext_header->count;
	ext_sig = (void *)ext_header + EXT_HEADER_SIZE;

	for (j = 0; j < ext_sigcount; j++) {
		sig = ext_sig->sig;
		pf = ext_sig->pf;

		pr_debug("\tExtended[%d]: sig=0x%x, pf=0x%x\n",
			 j, sig, pf);

		ext_sig++;
	}

	rb_meta = (struct ucode_meta *)intel_microcode_find_meta_data(mc, META_TYPE_ROLLBACK);
	if (rb_meta)
		dump_rollback_meta(rb_meta);
#endif
}

/*
 * Save this microcode patch. It will be loaded early when a CPU is
 * hot-added or resumes.
 */
static void save_mc_for_early(struct ucode_cpu_info *uci, u8 *mc, unsigned int size)
{
	/* Synchronization during CPU hotplug. */
	static DEFINE_MUTEX(x86_cpu_microcode_mutex);

	mutex_lock(&x86_cpu_microcode_mutex);

	save_microcode_patch(&intel_ucode, uci, mc, size);
	show_saved_mc(mc);

	mutex_unlock(&x86_cpu_microcode_mutex);
}

static bool load_builtin_intel_microcode(struct cpio_data *cp)
{
	unsigned int eax = 1, ebx, ecx = 0, edx;
	struct firmware fw;
	char name[30];

	if (IS_ENABLED(CONFIG_X86_32))
		return false;

	native_cpuid(&eax, &ebx, &ecx, &edx);

	sprintf(name, "intel-ucode/%02x-%02x-%02x",
		      x86_family(eax), x86_model(eax), x86_stepping(eax));

	if (firmware_request_builtin(&fw, name)) {
		cp->size = fw.size;
		cp->data = (void *)fw.data;
		return true;
	}

	return false;
}

/*
 * Print ucode update info.
 */
static void
print_ucode_info(struct ucode_cpu_info *uci, unsigned int date)
{
	pr_info_once("microcode updated early to revision 0x%x, date = %04x-%02x-%02x\n",
		     uci->cpu_sig.rev,
		     date & 0xffff,
		     date >> 24,
		     (date >> 16) & 0xff);
}

#ifdef CONFIG_X86_32

static int delay_ucode_info;
static int current_mc_date;

/*
 * Print early updated ucode info after printk works. This is delayed info dump.
 */
void show_ucode_info_early(void)
{
	struct ucode_cpu_info uci;

	if (delay_ucode_info) {
		intel_cpu_collect_info(&uci);
		print_ucode_info(&uci, current_mc_date);
		delay_ucode_info = 0;
	}
}

/*
 * At this point, we can not call printk() yet. Delay printing microcode info in
 * show_ucode_info_early() until printk() works.
 */
static void print_ucode(struct ucode_cpu_info *uci)
{
	struct microcode_intel *mc;
	int *delay_ucode_info_p;
	int *current_mc_date_p;

	mc = uci->mc;
	if (!mc)
		return;

	delay_ucode_info_p = (int *)__pa_nodebug(&delay_ucode_info);
	current_mc_date_p = (int *)__pa_nodebug(&current_mc_date);

	*delay_ucode_info_p = 1;
	*current_mc_date_p = mc->hdr.date;
}
#else

static inline void print_ucode(struct ucode_cpu_info *uci)
{
	struct microcode_intel *mc;

	mc = uci->mc;
	if (!mc)
		return;

	print_ucode_info(uci, mc->hdr.date);
}
#endif

static noinline void prof_native_wrmsr(unsigned long bits)
{
	native_wrmsrl(MSR_IA32_UCODE_WRITE, bits);
}

static noinline void prof_wrmsrl(unsigned long bits)
{
	wrmsrl(MSR_IA32_UCODE_WRITE, bits);
}

static struct microcode_intel *find_patch(void)
{
	return intel_ucode.ucode;
}

static int apply_microcode_early(struct ucode_cpu_info *uci, bool early)
{
	struct microcode_intel *mc;
	u32 rev;

	mc = uci->mc;
	if (!mc)
		return 0;

	/*
	 * Save us the MSR write below - which is a particular expensive
	 * operation - when the other hyperthread has updated the microcode
	 * already.
	 */
	rev = intel_get_microcode_revision();
	if (rev >= mc->hdr.rev) {
		uci->cpu_sig.rev = rev;
		return UCODE_OK;
	}

	/* write microcode via MSR 0x79 */
	prof_native_wrmsr((unsigned long)mc->bits);

	rev = intel_get_microcode_revision();
	if (rev != mc->hdr.rev)
		return -1;

	uci->cpu_sig.rev = rev;

	if (early)
		print_ucode(uci);
	else
		print_ucode_info(uci, mc->hdr.date);

	return 0;
}

int __init save_microcode_in_initrd_intel(void)
{
	struct ucode_cpu_info uci;
	struct cpio_data cp;

	/*
	 * initrd is going away, clear patch ptr. We will scan the microcode one
	 * last time before jettisoning and save a patch, if found. Then we will
	 * update that pointer too, with a stable patch address to use when
	 * resuming the cores.
	 */
	intel_ucode.ucode = NULL;

	if (!load_builtin_intel_microcode(&cp))
		cp = find_microcode_in_initrd(ucode_path, false);

	if (!(cp.data && cp.size))
		return 0;

	intel_cpu_collect_info(&uci);

	scan_microcode(cp.data, cp.size, &uci, true);

	show_saved_mc(intel_ucode.ucode);

	return 0;
}

/*
 * @res_patch, output: a pointer to the patch we found.
 */
static struct microcode_intel *__load_ucode_intel(struct ucode_cpu_info *uci)
{
	static const char *path;
	struct cpio_data cp;
	bool use_pa;

	if (IS_ENABLED(CONFIG_X86_32)) {
		path	  = (const char *)__pa_nodebug(ucode_path);
		use_pa	  = true;
	} else {
		path	  = ucode_path;
		use_pa	  = false;
	}

	/* try built-in microcode first */
	if (!load_builtin_intel_microcode(&cp))
		cp = find_microcode_in_initrd(path, use_pa);

	pr_info("%s: cp_data = 0x%p cp_size = 0x%lx\n", __func__, cp.data, cp.size);
	if (!(cp.data && cp.size))
		return NULL;

	intel_cpu_collect_info(uci);
	pr_info("Proceeding with scan_microcode\n");

	return scan_microcode(cp.data, cp.size, uci, false);
}

static void load_ucode_intel_bsp(void)
{
	struct microcode_intel *patch;
	struct ucode_cpu_info uci;

	patch = __load_ucode_intel(&uci);
	if (!patch)
		return;

	uci.mc = patch;

	apply_microcode_early(&uci, true);
}

static void load_ucode_intel_ap(void)
{
	struct microcode_intel *patch, **iup;
	struct ucode_cpu_info uci;

	if (IS_ENABLED(CONFIG_X86_32))
		iup = (struct microcode_intel **) __pa_nodebug(&intel_ucode.ucode);
	else
		iup = &intel_ucode.ucode;

	if (!*iup) {
		patch = __load_ucode_intel(&uci);
		if (!patch)
			return;

		*iup = patch;
	}

	uci.mc = *iup;

	apply_microcode_early(&uci, true);
}

void load_ucode_intel(bool bsp)
{
	pr_info("Load ucode for %s\n", bsp ? "BSP" : "AP");

	if (bsp)
		load_ucode_intel_bsp();
	else
		load_ucode_intel_ap();
}

void reload_ucode_intel(void)
{
	struct microcode_intel *p;
	struct ucode_cpu_info uci;

	intel_cpu_collect_info(&uci);

	p = find_patch();
	if (!p)
		return;

	apply_microcode_early(&uci, false);
}

static int collect_cpu_info(int cpu_num, struct cpu_signature *csig)
{
	struct cpuinfo_x86 *c = &cpu_data(cpu_num);
	unsigned int val[2];
	int rev;

	/*
	 * intel_get_microcode_revision() reads a per-core MSR
	 * to read the revision (MSR_IA32_UCODE_REV).
	 */
	WARN_ON_ONCE(cpu_num != smp_processor_id());

	memset(csig, 0, sizeof(*csig));

	csig->sig = cpuid_eax(0x00000001);

	if ((c->x86_model >= 5) || (c->x86 > 6)) {
		/* get processor flags from MSR 0x17 */
		rdmsr(MSR_IA32_PLATFORM_ID, val[0], val[1]);
		csig->pf = 1 << ((val[1] >> 18) & 7);
	}

	rev = intel_get_microcode_revision();
	c->microcode = rev;
	csig->rev = rev;

	return 0;
}

static enum ucode_state get_apply_status(void)
{
	enum ucode_state ret = UCODE_OK;
	union mcu_status status;

	if (!mcu_cap.data)
		return UCODE_UPDATED;

	status.data = 0;
	rdmsrl(MSR_MCU_STATUS, status.data);

	/*
	 * AUTH_FAIL is evil, best to trigger reset
	 * PARTIAL update is ok, but OS policy is TBD.
	 */
	if (status.auth_fail)
		ret = UCODE_UPDATED_AUTH;
	else if (status.partial)
		ret = UCODE_UPDATED_PART;

	return ret;
}

static enum ucode_state apply_microcode_intel(int cpu)
{
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;
	struct cpuinfo_x86 *c = &cpu_data(cpu);
	bool bsp = c->cpu_index == boot_cpu_data.cpu_index;
	struct microcode_intel *mc;
	enum ucode_state ret;
	static int prev_rev;
	u32 rev;

	/* We should bind the task to the CPU */
	if (WARN_ON(raw_smp_processor_id() != cpu))
		return UCODE_ERROR;

	/* Look for a newer patch in our cache: */
	mc = find_patch();
	if (!mc) {
		mc = uci->mc;
		if (!mc)
			return UCODE_NFOUND;
	}

	/*
	 * Save us the MSR write below - which is a particular expensive
	 * operation - when the other hyperthread has updated the microcode
	 * already.
	 */
	rev = intel_get_microcode_revision();
	if (rev >= mc->hdr.rev && !ucode_load_same) {
		ret = UCODE_OK;
		goto out;
	}

	/* write microcode via MSR 0x79 */
	prof_wrmsrl((unsigned long)mc->bits);

	rev = intel_get_microcode_revision();

	if (rev != mc->hdr.rev) {
		pr_err("CPU%d update to revision 0x%x failed\n",
		       cpu, mc->hdr.rev);
		return UCODE_ERROR;
	}

	if (bsp && rev != prev_rev) {
		pr_info("updated to revision 0x%x, date = %04x-%02x-%02x\n",
			rev,
			mc->hdr.date & 0xffff,
			mc->hdr.date >> 24,
			(mc->hdr.date >> 16) & 0xff);
		prev_rev = rev;
	}

	ret = UCODE_UPDATED;

out:
	uci->cpu_sig.rev = rev;
	c->microcode	 = rev;

	/* Update boot_cpu_data's revision too, if we're on the BSP: */
	if (bsp)
		boot_cpu_data.microcode = rev;

	ret = get_apply_status();

	return ret;
}

static enum ucode_state generic_load_microcode(int cpu, struct iov_iter *iter, enum reload_type type)
{
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;
	unsigned int curr_mc_size = 0, new_mc_size = 0;
	enum ucode_state ret = UCODE_OK;
	int new_rev = uci->cpu_sig.rev;
	u8 *new_mc = NULL, *mc = NULL;
	unsigned int csig, cpf;

	while (iov_iter_count(iter)) {
		struct microcode_header_intel mc_header;
		unsigned int mc_size, data_size;
		u8 *data;

		if (!copy_from_iter_full(&mc_header, sizeof(mc_header), iter)) {
			pr_err("error! Truncated or inaccessible header in microcode data file\n");
			break;
		}

		mc_size = get_totalsize(&mc_header);
		if (mc_size < sizeof(mc_header)) {
			pr_err("error! Bad data in microcode data file (totalsize too small)\n");
			break;
		}
		data_size = mc_size - sizeof(mc_header);
		if (data_size > iov_iter_count(iter)) {
			pr_err("error! Bad data in microcode data file (truncated file?)\n");
			break;
		}

		/* For performance reasons, reuse mc area when possible */
		if (!mc || mc_size > curr_mc_size) {
			vfree(mc);
			mc = vmalloc(mc_size);
			if (!mc)
				break;
			curr_mc_size = mc_size;
		}

		memcpy(mc, &mc_header, sizeof(mc_header));
		data = mc + sizeof(mc_header);
		if (!copy_from_iter_full(data, data_size, iter) ||
		    intel_microcode_sanity_check(mc, true, MC_HEADER_TYPE_MICROCODE) < 0 ||
		    is_lateload_safe(&mc_header)) {
			ret = UCODE_ERROR;
			break;
		}

		csig = uci->cpu_sig.sig;
		cpf = uci->cpu_sig.pf;
		if (has_newer_microcode(mc, csig, cpf, new_rev)) {
			vfree(new_mc);
			new_rev = mc_header.rev;
			new_mc  = mc;
			new_mc_size = mc_size;
			mc = NULL;	/* trigger new vmalloc */
			ret = UCODE_NEW;
		}
	}

	vfree(mc);

	if (iov_iter_count(iter)) {
		vfree(new_mc);
		return UCODE_ERROR;
	}

	if (ret == UCODE_ERROR)
		return ret;

	if (!new_mc)
		return UCODE_NFOUND;

	vfree(uci->mc);
	uci->mc = (struct microcode_intel *)new_mc;

	/*
	 * If early loading microcode is supported, save this mc into
	 * permanent memory. So it will be loaded early when a CPU is hot added
	 * or resumes.
	 */
	save_mc_for_early(uci, new_mc, new_mc_size);

	pr_debug("CPU%d found a matching microcode update with version 0x%x (current=0x%x)\n",
		 cpu, new_rev, uci->cpu_sig.rev);

	return ret;
}

static bool is_blacklisted(unsigned int cpu)
{
	struct cpuinfo_x86 *c = &cpu_data(cpu);

	/*
	 * Late loading on model 79 with microcode revision less than 0x0b000021
	 * and LLC size per core bigger than 2.5MB may result in a system hang.
	 * This behavior is documented in item BDF90, #334165 (Intel Xeon
	 * Processor E7-8800/4800 v4 Product Family).
	 */
	if (c->x86 == 6 &&
	    c->x86_model == INTEL_FAM6_BROADWELL_X &&
	    c->x86_stepping == 0x01 &&
	    llc_size_per_core > 2621440 &&
	    c->microcode < 0x0b000021) {
		pr_err_once("Erratum BDF90: late loading with revision < 0x0b000021 (0x%x) disabled.\n", c->microcode);
		pr_err_once("Please consider either early loading through initrd/built-in or a potential BIOS update.\n");
		return true;
	}

	return false;
}

static int prepare_to_apply_intel(enum reload_type type)
{
	int rv = -EINVAL;

	if (type == RELOAD_COMMIT) {
		/*
		 * This is a legacy CPU so nothing to prepare. Otherwise
		 * check if the configuration is currently in manual commit
		 * then switch to auto-commit.
		 */
		if (!mcu_cap.rollback)
			return 0;
		rv = switch_to_auto_commit();
	}
	else if (type == RELOAD_NO_COMMIT) {
		if (!mcu_cap.rollback)
			return rv;
		rv = switch_to_manual_commit();
	}

	return rv;
}

static enum ucode_state request_microcode_fw(int cpu, struct device *device, enum reload_type type)
{
	struct cpuinfo_x86 *c = &cpu_data(cpu);
	const struct firmware *firmware;
	struct iov_iter iter;
	enum ucode_state ret;
	struct kvec kvec;
	char name[30];

	if (is_blacklisted(cpu))
		return UCODE_NFOUND;

	if (type == RELOAD_NO_COMMIT && !check_pending()) {
		pr_err("Pending commit, Please commit before proceeding\n");
		return UCODE_ERROR;
	}

	sprintf(name, "intel-ucode/%02x-%02x-%02x",
		c->x86, c->x86_model, c->x86_stepping);

	if (request_firmware_direct(&firmware, name, device)) {
		pr_debug("data file %s load failed\n", name);
		return UCODE_NFOUND;
	}

	kvec.iov_base = (void *)firmware->data;
	kvec.iov_len = firmware->size;
	iov_iter_kvec(&iter, WRITE, &kvec, 1, firmware->size);

	ret = generic_load_microcode(cpu, &iter, type);

	release_firmware(firmware);

	return ret;
}

static struct microcode_ops microcode_intel_ops = {
	.safe_late_load			  = true,
	.get_load_scope			  = get_load_scope,
	.check_pending_commits		  = check_pending_commits,
	.perform_commit			  = perform_commit,
	.request_microcode_fw             = request_microcode_fw,
	.collect_cpu_info                 = collect_cpu_info,
	.prepare_to_apply		  = prepare_to_apply_intel,
	.apply_microcode                  = apply_microcode_intel,
};

static int __init calc_llc_size_per_core(struct cpuinfo_x86 *c)
{
	u64 llc_size = c->x86_cache_size * 1024ULL;

	do_div(llc_size, c->x86_max_cores);

	return (int)llc_size;
}

struct microcode_ops * __init init_intel_microcode(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;

	if (c->x86_vendor != X86_VENDOR_INTEL || c->x86 < 6 ||
	    cpu_has(c, X86_FEATURE_IA64)) {
		pr_err("Intel CPU family 0x%x not supported\n", c->x86);
		return NULL;
	}

	llc_size_per_core = calc_llc_size_per_core(c);
	setup_mcu_enumeration();

	return &microcode_intel_ops;
}
