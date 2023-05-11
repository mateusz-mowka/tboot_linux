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
#include <linux/debugfs.h>
#include <linux/vmalloc.h>
#include <linux/initrd.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/uio.h>
#include <linux/mm.h>
#include <linux/bitops.h>

#include <asm/microcode_intel.h>
#include <asm/intel-family.h>
#include <asm/msr-index.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>
#include <asm/setup.h>
#include <asm/msr.h>
#include <asm/cpu.h>

#include "doe.h"

static const char ucode_path[] = "kernel/x86/microcode/GenuineIntel.bin";
static bool ucode_staging = true;
extern struct dentry *dentry_ucode;
int post_bios_mcu_rev;

/* Current microcode patch used in early patching on the APs. */

struct ucode_info {
	struct microcode_intel *ucode;
	int size;
};


/*
 * Holds the previous applied microcode before a reload_nc is successful.
 */
static struct ucode_info rollback_ucode;

/*
 * Always hold the currently applied microcode in the CPU. mc->hdr.rev
 * should match whats in the CPU revision MSR.
 */
static struct ucode_info intel_ucode;

/*
 * Holds the value of microcode read from the file system and is yet to be
 * applied to the CPU. This allows post_apply() to free it in case the
 * application to CPU fails.
 */
static struct ucode_info unapplied_ucode;

/*
 * When performing a rollback, we do the following to allow the
 * apply_microcode() to do the right thing.
 *
 * pre_rollback = intel_ucode
 * intel_ucode = rollback_ucode
 *
 * Now if everything goes good:
 *
 * free pre_rollback
 *
 * if apply_fails:
 * rollback_ucode = intel_ucode
 * intel_ucode = pre_rollback
 * clear pre_rollback
 */
static struct ucode_info pre_rollback;

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
		u64	staging_supported:1;
		u64	reserved:3;
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
#define MSR_MCU_MBOX_ADDR	(0x7a5)

#define META_TYPE_ROLLBACK	(0x2)

static union mcu_enumeration mcu_cap;

/*
 * MSR's related to deferred commit architecture
 */
#define MSR_MCU_CONFIG		(0x7a0)
#define MSR_MCU_COMMIT		(0x7a1)
#define MSR_MCU_INFO		(0x7a2)
#define MSR_MCU_ROLLBACK_MIN	(0x7a4)

#define NUM_ROLLBACK_MSRS	(16)
#define MSR_ROLLBACK_SIGN_BASE	(0x7b0)
#define MSR_ROLLBACK_SIGN_ID(x)	(MSR_ROLLBACK_SIGN_BASE+(x))

union svn_info {
	u64     data;
	struct {
		u64     cpu_svn:16;
		u64     pending_svn:16;
	};
};


struct rb_svn_info {
	u32	rb_mcu_svn:16;
	u32	rb_min_svn:16;
};

/* MSR_MCU_CONFIG */
union svn_config {
	u64	data;
	struct {
		u64	lock:1;
		u64	defer_svn:1;
	};
};

/* MSR_MCU_COMMIT */
union svn_commit {
	u64	data;
	struct {
		u64	commit_svn:1;
	};
};

/**
 * struct mcu_staging -  Information of per package staging mailbox instances
 *
 * @mboxes    : Array of per package staging mailbox instances
 * @work      : Work to stage microcode
 * @scheduled : Whether the work to stage microcode is scheduled
 * @creating  : Whether the mailbox instance is being created
 * @result    : Result of microcode staging by @work
 * @mbox_num  : Number of staging mailbox instances
 */
struct mcu_staging {
	struct {
		struct uc_doe_mbox *mbox;
		struct work_struct work;
		bool scheduled;
		unsigned long creating;
		enum ucode_state result;
	} *mboxes;
	int mbox_num;
};

#define NUM_RB_INFO	16
struct ucode_meta {
	struct	metadata_header	rb_hdr;
	struct  rb_svn_info svn_info;
	u32	rollback_id[NUM_RB_INFO];
	u16	rollback_svn[NUM_RB_INFO];
};

union rb_sign_id {
	u64	data;
	struct {
		u64	rb_id:32;
		u64	rb_mcu_svn:16;
	};
};

struct rb_info {
	union	svn_info svn_info;
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
static struct mcu_staging mcu_staging;

static void read_commit_status(struct work_struct *work)
{
	union	svn_commit commit;
	int	cpu = raw_smp_processor_id();

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

	rv = schedule_on_each_cpu_locked(read_commit_status);

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

static void clear_ucode_store(struct ucode_info *ucode)
{
	ucode->ucode = NULL;
	ucode->size = 0;
}

static void free_ucode_store(struct ucode_info *ucode)
{
	if (ucode->ucode)
		kfree(ucode->ucode);
	clear_ucode_store(ucode);
}

static int perform_commit(void)
{
	int rv;

	free_ucode_store(&rollback_ucode);
	rv = schedule_on_each_cpu_locked(do_commit);

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

#if 0
	/*
	 * Skip this, since we don't need any enforcement for auto-commit
	 */

	if (rv) {
		pr_err("Pending commit, Please commit before proceeding\n");
		return rv;
	}
#endif

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

	rv = schedule_on_each_cpu_locked(write_auto_commit);

	pr_info("Switching to auto commit %s\n", rv ? "Failed" : "Succeeded");

	return rv;
}

static void write_manual_commit(struct work_struct *work)
{
	union svn_config cfg;

	cfg.data = 0;
	cfg.defer_svn = 1;
	pr_debug("OSPL: %s:%d\n", __FILE__,__LINE__);
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

	pr_debug("OSPL: %s:%d\n", __FILE__,__LINE__);
	rv = check_pending();

#if 0
	/*
	 * Its ok to not do this, since officially the can_do_nocommit should
	 * check all constraints. As long as we don't hurt going back to what
	 * was originally loaded we can permit a nc reload.
	 */

	if (rv) {
		pr_err("Pending commit, Please commit before proceeding\n");
		return rv;
	}
#endif

	/*
	 * We know this is per-core MSR, but its enough to check just this
	 * CPU, since we expect the system to be consistent with this
	 * value across all cores.
	 */
	rdmsrl(MSR_MCU_CONFIG, cfg.data);
	pr_debug("OSPL: %s:%d\n", __FILE__,__LINE__);

	/* Already manual commit is default */
	if (cfg.defer_svn)
	{
		pr_debug("OSPL: %s:%d\n", __FILE__,__LINE__);
		return 0;
	}


	pr_debug("OSPL: %s:%d\n", __FILE__,__LINE__);

	if (cfg.lock) {
		pr_info_once("SVN config locked with auto commit\n");
		pr_debug("OSPL: %s:%d\n", __FILE__,__LINE__);
		return -EBUSY;
	}

	pr_debug("OSPL: %s:%d\n", __FILE__,__LINE__);
	rv = schedule_on_each_cpu_locked(write_manual_commit);

	pr_info("Switching to manual commit %s\n", rv ? "Failed" : "Succeeded");

	return rv;
}

static void save_bsp_rollback_info(void)
{
	int i;

	if (!mcu_cap.rollback)
		return;

	/*
	 * Always clear everything since a new MCU can have more entries
	 * populated in RB_INFO.
	 */
	memset(&bsp_rb_info, 0, sizeof(struct rb_info));

	rdmsrl(MSR_MCU_INFO, bsp_rb_info.svn_info.data);
	pr_debug("mcu_min_svn: 0x%x pending_svn: 0x%x\n",
		 bsp_rb_info.svn_info.cpu_svn, bsp_rb_info.svn_info.pending_svn);
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
	union mcu_status status;

	microcode_intel_ops.need_nmi_lateload = true;
	arch_cap = x86_read_arch_cap_msr();

	if (!(arch_cap & ARCH_CAP_MCU_ENUM))
		return;

	rdmsrl(MSR_MCU_ENUM, mcu_cap.data);
	pr_debug("OSPL: MCU_ENUM is %llx\n", mcu_cap.data);

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

	if (mcu_cap.staging_supported) {
		pr_info_once("Microcode Staging Capability detected\n");

		mcu_staging.mbox_num = topology_max_packages();
		mcu_staging.mboxes   = kcalloc(mcu_staging.mbox_num,
					       sizeof(*mcu_staging.mboxes),
					       GFP_KERNEL);
		if (!dentry_ucode)
			dentry_ucode = debugfs_create_dir("microcode", NULL);

		debugfs_create_bool("ucode_staging", 0644, dentry_ucode, &ucode_staging);
	}

	status.data = 0;
	rdmsrl(MSR_MCU_STATUS, status.data);
	if (!status.post_bios_mcu)
		pr_info("WARNING: Contact BIOS Vendor: POST_BIOS_MCU not set\n");
	else {
		u32 dummy;
		native_rdmsr(MSR_MCU_ROLLBACK_MIN, dummy, post_bios_mcu_rev);
		pr_info("post_bios_mcu_rev: 0x%x\n", post_bios_mcu_rev);
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
	struct microcode_header_intel *p;

	if (!(info && data))
		return;

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
	int i, cpu = raw_smp_processor_id();
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

static bool check_update_reqs(struct microcode_header_intel *mch)
{
	struct ucode_meta *rb_meta;
	union	svn_commit commit;

	if (!mcu_cap.rollback)
		return true;

	if (mch->rev < post_bios_mcu_rev) {
		pr_err("Revision 0x%x less than 0x%x (Post BIOS rev)\n",
			mch->rev, post_bios_mcu_rev);
		return false;
	}

	rb_meta = (struct ucode_meta *)intel_microcode_find_meta_data(mch, META_TYPE_ROLLBACK);
	if (!rb_meta)
		return false;

	if (rb_meta->svn_info.rb_mcu_svn < bsp_rb_info.svn_info.cpu_svn) {
		pr_err("MCU SVN 0x%x less than CPU SVN 0x%x, can't update\n",
				rb_meta->svn_info.rb_mcu_svn, bsp_rb_info.svn_info.cpu_svn);
		return false;
	}

	rdmsrl(MSR_MCU_COMMIT, commit.data);
	if (!commit.commit_svn)
		return true;

	if (rb_meta->svn_info.rb_mcu_svn > bsp_rb_info.svn_info.pending_svn) {
		pr_err("Can't load MCU_SVN 0x%x with pending commit SVN 0x%x\n",
				rb_meta->svn_info.rb_mcu_svn, bsp_rb_info.svn_info.pending_svn);
		return false;
	}

	return true;
}

static bool can_do_nocommit(struct microcode_header_intel *mch)
{
	struct ucode_meta *rb_meta;

	if (!mcu_cap.rollback)
		return false;

	if (!check_update_reqs(mch))
		return false;

	rb_meta = (struct ucode_meta *)intel_microcode_find_meta_data(mch, META_TYPE_ROLLBACK);
	if (!rb_meta)
		return false;

	if (!is_ucode_listed(rb_meta))
		return false;

	/*
	 * Check if MCU min_svn == CPU min_svn
	 */
	if (rb_meta->svn_info.rb_min_svn > bsp_rb_info.svn_info.cpu_svn) {
		pr_debug("svn check fails\n");
		pr_debug("min_svn = 0x%x cpu_svn = 0x%x\n",
			rb_meta->svn_info.rb_min_svn, bsp_rb_info.svn_info.cpu_svn);
		return false;
	}

	return true;
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

#if 0
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
#endif

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

static void print_ucode_info(int old_rev, int new_rev, unsigned int date)
{
	pr_info_once("updated early: 0x%x -> 0x%x, date = %04x-%02x-%02x\n",
		     old_rev,
		     new_rev,
		     date & 0xffff,
		     date >> 24,
		     (date >> 16) & 0xff);
}

#ifdef CONFIG_X86_32

static int delay_ucode_info;
static int current_mc_date;
static int early_old_rev;

/*
 * Print early updated ucode info after printk works. This is delayed info dump.
 */
void show_ucode_info_early(void)
{
	struct ucode_cpu_info uci;

	if (delay_ucode_info) {
		intel_cpu_collect_info(&uci);
		print_ucode_info(early_old_rev, uci.cpu_sig.rev, current_mc_date);
		delay_ucode_info = 0;
	}
}

/*
 * At this point, we can not call printk() yet. Delay printing microcode info in
 * show_ucode_info_early() until printk() works.
 */
static void print_ucode(int old_rev, int new_rev, int date)
{
	int *delay_ucode_info_p;
	int *current_mc_date_p;
	int *early_old_rev_p;

	delay_ucode_info_p = (int *)__pa_nodebug(&delay_ucode_info);
	current_mc_date_p = (int *)__pa_nodebug(&current_mc_date);
	early_old_rev_p = (int *)__pa_nodebug(&early_old_rev);

	*delay_ucode_info_p = 1;
	*current_mc_date_p = date;
	*early_old_rev_p = old_rev;
}
#else

static inline void print_ucode(int old_rev, int new_rev, int date)
{
	print_ucode_info(old_rev, new_rev, date);
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
	return (unapplied_ucode.ucode ? unapplied_ucode.ucode : intel_ucode.ucode);
}

static int apply_microcode_early(struct ucode_cpu_info *uci, bool early)
{
	struct microcode_intel *mc;
	u32 rev, old_rev;

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

	old_rev = rev;

	/* write microcode via MSR 0x79 */
	prof_native_wrmsr((unsigned long)mc->bits);

	rev = intel_get_microcode_revision();
	if (rev != mc->hdr.rev)
		return -1;

	uci->cpu_sig.rev = rev;

	if (early)
		print_ucode(old_rev, uci->cpu_sig.rev, mc->hdr.date);
	else
		print_ucode_info(old_rev, uci->cpu_sig.rev, mc->hdr.date);

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

static void collect_staging_mailbox(int cpu)
{
	struct uc_doe_mbox *mbox;
	u64 mbox_addr;
	int i;

	if (!mcu_cap.staging_supported)
		return;

	i = topology_physical_package_id(cpu);

	/* Avoid multiple mailbox instances per package */
	if (test_and_set_bit(0, &mcu_staging.mboxes[i].creating))
		return;

	if (mcu_staging.mboxes[i].mbox)
		goto out;

	rdmsrl(MSR_MCU_MBOX_ADDR, mbox_addr);
	if (!mbox_addr) {
		/*
		 * REVERTME: If the 0x7a5 MSR enumeration isn't officially
		 *           supported, hardcode it for testing purpose.
		 */
		if (i == 0) {
			/* The 1st package DOE mailbox address */
			mbox_addr = 0x90110000;
		} else if (i == 1) {
			/* The 2nd package DOE mailbox address */
			mbox_addr = 0xc3910000;
		} else {
			pr_err("No hardcoded DOE mailbox address for package %d\n", i);
			goto out;
		}

		pr_debug("Temporarily hardcode DOE mailbox address 0x%llx for package %d\n", mbox_addr, i);
		/* goto out; */
	}

	mbox = uc_doe_create_mbox(mbox_addr);
	if (!mbox)
		goto out;

	mcu_staging.mboxes[i].mbox = mbox;
out:
	clear_bit(0, &mcu_staging.mboxes[i].creating);
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

	collect_staging_mailbox(cpu_num);

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

static enum ucode_state apply_microcode_intel(int cpu, enum reload_type type)
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
	if ((rev >= mc->hdr.rev && type != RELOAD_ROLLBACK) && !ucode_load_same) {
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
		save_bsp_rollback_info();
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
		if (ucode_load_same || (type == RELOAD_SAME &&
					uci->cpu_sig.rev == mc_header.rev) ||
				has_newer_microcode(mc, csig, cpf, new_rev)) {
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

	/*
	 * TBD: need to remove uci->mc for future...
	 */
	// uci->mc = (struct microcode_intel *)new_mc;
	save_microcode_patch(&unapplied_ucode, uci, new_mc, new_mc_size);

	/*
	 * If early loading microcode is supported, save this mc into
	 * permanent memory. So it will be loaded early when a CPU is hot added
	 * or resumes.
	 */
	// save_mc_for_early(uci, new_mc, new_mc_size);

	pr_debug("CPU%d found a matching microcode update with version 0x%x (current=0x%x)\n",
		 cpu, new_rev, uci->cpu_sig.rev);

	return ret;
}

static void post_apply_intel(enum reload_type type, bool apply_state)
{
	pr_debug("OSPL: apply_state is %x type = 0x%x\n",
		apply_state, type);

	switch (type) {
		case RELOAD_COMMIT:
			/*
			 * If apply was successful, then move from
			 * unapplied to intel_ucode
			 */
			if(apply_state) {
				kfree(intel_ucode.ucode);
				intel_ucode = unapplied_ucode;
				free_ucode_store(&rollback_ucode);
			}
			break;

		case RELOAD_NO_COMMIT:
			/*
			 * Preserve the original patch in case we need for
			 * rollback before its commited
			 */
			if (apply_state) {
				pr_debug("OSPL: reload_nc: Old ucode revision is \n");
				show_saved_mc(intel_ucode.ucode);

				rollback_ucode = intel_ucode;

				intel_ucode = unapplied_ucode;
				pr_debug("OSPL: reload_nc: Unapplied ucode revision is \n");
				show_saved_mc(unapplied_ucode.ucode);
			}
			break;
		case RELOAD_ROLLBACK:
			if (apply_state) {
				show_saved_mc(intel_ucode.ucode);
			} else {
				pr_info("Rollback failed\n");
				rollback_ucode = intel_ucode;
				intel_ucode = pre_rollback;
				clear_ucode_store(&pre_rollback);
			}
			break;
		default:
			pr_debug("Got unknown commit type, returning\n");
			return;
	}
	/*
	 * Free if microcode didn't apply successfully
	 */
	if (!apply_state)
		free_ucode_store(&unapplied_ucode);
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

static void do_staging(struct work_struct *work)
{
	int i, cpu = smp_processor_id();
	struct ucode_cpu_info *uci;
	struct microcode_intel *mc;
	struct uc_doe_mbox *mbox;

	uci = ucode_cpu_info + cpu;
	i = topology_physical_package_id(cpu);

	mc = find_patch();
	if (!mc) {
		mc = uci->mc;
		if (!mc) {
			mcu_staging.mboxes[i].result = UCODE_NFOUND;
			return;
		}
	}

	if (uci->cpu_sig.rev >= mc->hdr.rev) {
		/*
		mcu_staging.mboxes[i].result  = UCODE_OK;
		return;
		*/
		pr_debug("Drop the rev check before staging\n");
	}

	mbox = mcu_staging.mboxes[i].mbox;

	/* Need to include the external header */
	if (uc_doe_stage_ucode(mbox, mc, mc->hdr.totalsize)) {
		mcu_staging.mboxes[i].result = UCODE_ERROR;
		return;
	}

	mcu_staging.mboxes[i].result = UCODE_OK;

	pr_info("Microcode is staged for package %d\n", i);
}

static enum ucode_state perform_staging(void)
{
	enum ucode_state ret = UCODE_OK;
	struct work_struct *work;
	int cpu, i;

	if (!mcu_cap.staging_supported || !ucode_staging)
		return UCODE_OK;

	for (i = 0; i < mcu_staging.mbox_num; i++) {
		mcu_staging.mboxes[i].scheduled = false;
		mcu_staging.mboxes[i].result = UCODE_OK;
	}

	for_each_online_cpu(cpu) {
		i = topology_physical_package_id(cpu);

		if (!mcu_staging.mboxes[i].mbox)
			continue;

		if (mcu_staging.mboxes[i].scheduled)
			continue;

		mcu_staging.mboxes[i].scheduled = true;

		work = &mcu_staging.mboxes[i].work;
		INIT_WORK(work, do_staging);
		schedule_work_on(cpu, work);
	}

	for (i = 0; i < mcu_staging.mbox_num; i++) {
		if (!mcu_staging.mboxes[i].scheduled)
			continue;

		work = &mcu_staging.mboxes[i].work;
		flush_work(work);

		if (ret < mcu_staging.mboxes[i].result)
			ret = mcu_staging.mboxes[i].result;

		mcu_staging.mboxes[i].scheduled = false;
	}

	return ret;
}

static int map_ucode_to_errno(enum ucode_state error)
{
	switch (error) {
		case UCODE_NEW:
		case UCODE_UPDATED:
		case UCODE_OK:
			return 0;
		case UCODE_ERROR:
			return -EBADF;
		case UCODE_NFOUND:
			return -ENOENT;
		case UCODE_UPDATED_PART:
		case UCODE_UPDATED_AUTH:
			return -ENXIO;
		default:
			return -EINVAL;
	}
}

static int prepare_to_apply_intel(enum reload_type type)
{
	int rv = 0;
	enum ucode_state ret;

	pr_debug("OSPL: %s:%d, type:%d\n", __FILE__,__LINE__, type);
	switch (type) {
		case RELOAD_COMMIT:
			pr_debug("OSPL: reload: %s:%d\n", __FILE__,__LINE__);
			if (!mcu_cap.rollback)
			{
				pr_debug("OSPL: %s:%d\n", __FILE__,__LINE__);
				break;
			}

			free_ucode_store(&rollback_ucode);
			rv = switch_to_auto_commit();
			if (rv)
				return rv;
			break;
		case RELOAD_NO_COMMIT:
			pr_debug("OSPL: %s:%d\n", __FILE__,__LINE__);
			if (!mcu_cap.rollback) {
				pr_debug("OSPL: No rollback cap: %s:%d\n", __FILE__,__LINE__);
				return -EINVAL;
			}

			if (!intel_ucode.ucode) {
				pr_info("Defer Commit, No prior microcode, can't continue...\n");
				return -ENOENT;
			}

			rv = switch_to_manual_commit();
			if (rv)
				return rv;
			pr_debug("Switched manual for reload_nocommit\n");
			break;
		case RELOAD_ROLLBACK:
			pr_debug("OSPL: %s:%d\n", __FILE__,__LINE__);
			if (!mcu_cap.rollback) {
				pr_debug("OSPL: No rollback cap: %s:%d\n", __FILE__,__LINE__);
				return -EINVAL;
			}

			if (!intel_ucode.ucode || !rollback_ucode.ucode) {
				if (!intel_ucode.ucode)
					pr_info("No saved ucode found, exiting...\n");
				if (!rollback_ucode.ucode)
					pr_info("No rollback ucode found, exiting...\n");
				return -ENOENT;
			}

			/*
			 * Switch intel_code to rollback.
			 */
			pr_debug("OSPL: Rollback revision is\n");
			show_saved_mc(rollback_ucode.ucode);

			/*
			 * Free previous intel_ucode, and clear
			 * rollback_ucode
			 * TBD: Move these freeing to post call, in case
			 * rollback fails during staging etc.
				kfree(intel_ucode.ucode);
				intel_ucode = rollback_ucode;
				rollback_ucode.ucode = NULL;
				rollback_ucode.size = 0;
			 */
			pre_rollback = intel_ucode;
			intel_ucode = rollback_ucode;
			clear_ucode_store(&rollback_ucode);
			break;
		default:
			pr_debug("OSPL: %s:%d\n", __FILE__,__LINE__);
	}

	pr_debug("OSPL: %s:%d\n", __FILE__,__LINE__);

	ret = perform_staging();
	if (ret == UCODE_ERROR ||
	    (ret == UCODE_NFOUND && !ucode_load_same)) {
		pr_err("Error staging microcode\n");
		return map_ucode_to_errno(ret);
	}

	return 0;
}

static enum ucode_state request_microcode_fw(int cpu, struct device *device, enum reload_type type)
{
	/* Hack for nocommit WA */
	bool nocommit, fetch_orig = false;
	struct cpuinfo_x86 *c = &cpu_data(cpu);
	const struct firmware *firmware;
	enum reload_type tmp_type;
	struct iov_iter iter;
	enum ucode_state ret;
	struct kvec kvec;
	char name[30];

	if (is_blacklisted(cpu))
		return UCODE_NFOUND;

	if (type == RELOAD_NO_COMMIT && check_pending()) {
		pr_err("Pending commit, Please commit before proceeding\n");
		return UCODE_ERROR;
	}

reget:
	sprintf(name, "intel-ucode/%02x-%02x-%02x",
		c->x86, c->x86_model, c->x86_stepping);

	if (type == RELOAD_NO_COMMIT) {
		/*
		 * If we don't have a current ucode try to fetch it
		 */
		if (intel_ucode.ucode) {
			sprintf(name, "intel-ucode/stage/%02x-%02x-%02x",
				c->x86, c->x86_model, c->x86_stepping);
		} else {
			fetch_orig = true;
			pr_info("No current ucode found, fetching\n");
		}
	}

	if (request_firmware_direct(&firmware, name, device)) {
		pr_debug("data file %s load failed\n", name);
		return UCODE_NFOUND;
	}

	kvec.iov_base = (void *)firmware->data;
	kvec.iov_len = firmware->size;
	iov_iter_kvec(&iter, WRITE, &kvec, 1, firmware->size);

	tmp_type = (type == RELOAD_NO_COMMIT && !intel_ucode.ucode) ?
				RELOAD_SAME : type;

	ret = generic_load_microcode(cpu, &iter, tmp_type);

	if (!fetch_orig && ret == UCODE_NEW && type == RELOAD_NO_COMMIT) {
		nocommit = can_do_nocommit((struct microcode_header_intel *)unapplied_ucode.ucode);
		nocommit = true; // hack since metadata is messed up now
		if (!nocommit) {
			ret = UCODE_ERROR;
			if (unapplied_ucode.ucode)
				kfree(unapplied_ucode.ucode);
			unapplied_ucode.ucode = NULL;
			unapplied_ucode.size = 0;
		}
	} else if (!fetch_orig && ret == UCODE_NEW && type == RELOAD_COMMIT) {
		if (!check_update_reqs((struct microcode_header_intel *)unapplied_ucode.ucode)) {
			ret = UCODE_ERROR;
			if (unapplied_ucode.ucode)
				kfree (unapplied_ucode.ucode);
			unapplied_ucode.ucode = NULL;
			unapplied_ucode.size = 0;
		}
	}

	release_firmware(firmware);

	pr_debug("type = 0x%x fetch_orig = 0x%x ret = 0x%x\n",
		type, fetch_orig, ret);

	if (fetch_orig) {
		if (unapplied_ucode.ucode) {
			if (unapplied_ucode.ucode->hdr.rev == c->microcode) {
				intel_ucode = unapplied_ucode;
				unapplied_ucode.ucode = NULL;
				unapplied_ucode.size = 0;
			} else {
				kfree (unapplied_ucode.ucode);
				unapplied_ucode.ucode = NULL;
				unapplied_ucode.size = 0;
				pr_info("Orig ucode not found\n");
				return UCODE_NFOUND;
			}
		} else {
			pr_info("Can't find currently loaded microcode, please copy rev 0x%x and retry\n",
				c->microcode);
			return UCODE_NFOUND;
		}

		fetch_orig = false;
		pr_debug ("Trying to fetch new no commit ucode now\n");
		goto reget;
	}

	return ret;
}

static void release_staging_mailbox(int cpu)
{
	struct uc_doe_mbox *mbox;
	int i, cpus;

	if (!mcu_cap.staging_supported)
		return;

	i = topology_physical_package_id(cpu);
	mbox = mcu_staging.mboxes[i].mbox;
	if (!mbox)
		return;

	/* The number of online CPUs of current package */
	cpus = cpumask_weight_and(topology_core_cpumask(cpu), cpu_online_mask);

	/*
	 * If current CPU is the last online CPU of current package,
	 * release the staging mailbox instance.
	 */
	if (cpus == 1) {
		uc_doe_destroy_mbox(mbox);
		mcu_staging.mboxes[i].mbox = NULL;
	}
}

static void microcode_fini_cpu_intel(int cpu)
{
	release_staging_mailbox(cpu);
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
	.post_apply			  = post_apply_intel,
	.microcode_fini_cpu               = microcode_fini_cpu_intel,
};

static int __init calc_llc_size_per_core(struct cpuinfo_x86 *c)
{
	u64 llc_size = c->x86_cache_size * 1024ULL;

	do_div(llc_size, c->x86_max_cores);

	return (int)llc_size;
}

struct microcode_ops * __init init_intel_microcode(struct microcode_capability *mcap)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;

	if (c->x86_vendor != X86_VENDOR_INTEL || c->x86 < 6 ||
	    cpu_has(c, X86_FEATURE_IA64)) {
		pr_err("Intel CPU family 0x%x not supported\n", c->x86);
		return NULL;
	}

	llc_size_per_core = calc_llc_size_per_core(c);
	setup_mcu_enumeration();
	mcap->rollback = mcu_cap.rollback;

	return &microcode_intel_ops;
}
