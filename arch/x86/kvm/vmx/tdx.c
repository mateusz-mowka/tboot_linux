// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/firmware.h>
#include <linux/mmu_context.h>
#include <linux/misc_cgroup.h>
#include <linux/percpu-rwsem.h>
#include <linux/platform_device.h>

#include <asm/fpu/xcr.h>
#include <asm/virtext.h>
#include <asm/cpu.h>
#include <asm/tdx.h>

#include "capabilities.h"
#include "x86_ops.h"
#include "common.h"
#include "mmu.h"
#include "tdx.h"
#include "vmx.h"
#include "x86.h"

#include <trace/events/kvm.h>
#include "trace.h"

#include "tdx_mig.c"

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

#define pr_err_skip_ud(_x) \
	pr_err_once("Skip #UD injection for " _x " due to it's not supported in TDX 1.0\n")

static u64 hkid_mask __ro_after_init;
static u8 hkid_start_pos __ro_after_init;

/* Protect 3 variables right below */
static DEFINE_SPINLOCK(tdx_update_lock);
static unsigned int created_tds;
static bool tdx_in_update;
static RAW_NOTIFIER_HEAD(tdx_update_chain);

#ifdef CONFIG_INTEL_TDX_MODULE_UPDATE
/* Fake device for request_firmware */
static struct platform_device *tdx_pdev;
DEFINE_STATIC_PERCPU_RWSEM(tdx_update_percpu_rwsem);
DEFINE_STATIC_PERCPU_RWSEM(tdx_update_percpu_rwsem_mn_invalidate);
static DEFINE_RWLOCK(tdx_update_rwlock);

void tdx_svmm_get(int event)
{
	switch (event) {
	case SVMM_EVENT_BASIC:
		percpu_down_read(&tdx_update_percpu_rwsem);
		break;
	case SVMM_EVENT_MN_INVD:
		percpu_down_read(&tdx_update_percpu_rwsem_mn_invalidate);
		break;
	case SVMM_EVENT_MN_INVD_NONBLOCK:
		read_lock(&tdx_update_rwlock);
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}

}

void tdx_svmm_put(int event)
{
	switch (event) {
	case SVMM_EVENT_BASIC:
		percpu_up_read(&tdx_update_percpu_rwsem);
		break;
	case SVMM_EVENT_MN_INVD:
		percpu_up_read(&tdx_update_percpu_rwsem_mn_invalidate);
		break;
	case SVMM_EVENT_MN_INVD_NONBLOCK:
		read_unlock(&tdx_update_rwlock);
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
}
#endif /* CONFIG_INTEL_TDX_MODULE_UPDATE */

#define TDX_MAX_NR_CPUID_CONFIGS					\
	((sizeof(struct tdsysinfo_struct) -				\
		offsetof(struct tdsysinfo_struct, cpuid_configs))	\
		/ sizeof(struct tdx_cpuid_config))

struct tdx_capabilities {
	u8 tdcs_nr_pages;
	u8 tdvpx_nr_pages;
	u8 sys_rd;
	u32 max_servtds;

	u64 attrs_fixed0;
	u64 attrs_fixed1;
	u64 xfam_fixed0;
	u64 xfam_fixed1;

	u32 nr_cpuid_configs;
	struct tdx_cpuid_config cpuid_configs[TDX_MAX_NR_CPUID_CONFIGS];
};

/*
 * Key id globally used by TDX module: TDX module maps TDR with this TDX global
 * key id.  TDR includes key id assigned to the TD.  Then TDX module maps other
 * TD-related pages with the assigned key id.  TDR requires this TDX global key
 * id for cache flush unlike other TD-related pages.
 */
static u32 tdx_global_keyid __read_mostly;

/* Capabilities of KVM + the TDX module. */
static struct tdx_capabilities tdx_caps;

/*
 * Some TDX SEAMCALLs (TDH.MNG.CREATE, TDH.PHYMEM.CACHE.WB,
 * TDH.MNG.KEY.RECLAIMID, TDH.MNG.KEY.FREEID etc) tries to acquire a global lock
 * internally in TDX module.  If failed, TDX_OPERAND_BUSY is returned without
 * spinning or waiting due to a constraint on execution time.  It's caller's
 * responsibility to avoid race (or retry on TDX_OPERAND_BUSY).  Use this mutex
 * to avoid race in TDX module because the kernel knows better about scheduling.
 */
static DEFINE_MUTEX(tdx_lock);
static struct mutex *tdx_mng_key_config_lock;

/*
 * A per-CPU list of TD vCPUs associated with a given CPU.  Used when a CPU
 * is brought down to invoke TDH_VP_FLUSH on the approapriate TD vCPUS.
 * Protected by interrupt mask.  This list is manipulated in process context
 * of vcpu and IPI callback.  See tdx_flush_vp_on_cpu().
 */
static DEFINE_PER_CPU(struct list_head, associated_tdvcpus);

static int tdx_emulate_inject_bp_end(struct kvm_vcpu *vcpu, unsigned long dr6);

static enum {
	TD_PROFILE_NONE = 0,
	TD_PROFILE_ENABLE,
	TD_PROFILE_DISABLE,
} td_profile_state;

/*
 * Currently, host is allowed to get TD's profile only if this TD is debuggable
 * and cannot use PMU.
 */
static inline bool td_profile_allowed(struct kvm_tdx *kvm_tdx)
{
	u64 attributes = kvm_tdx->attributes;

	if ((td_profile_state == TD_PROFILE_ENABLE) &&
	    (attributes & TDX_TD_ATTRIBUTE_DEBUG) &&
	    !(attributes & TDX_TD_ATTRIBUTE_PERFMON))
		return true;

	return false;
}

static __always_inline hpa_t set_hkid_to_hpa(hpa_t pa, u16 hkid)
{
	pa &= ~hkid_mask;
	pa |= (u64)hkid << hkid_start_pos;

	return pa;
}

static __always_inline unsigned long tdexit_exit_qual(struct kvm_vcpu *vcpu)
{
	return kvm_rcx_read(vcpu);
}

static __always_inline unsigned long tdexit_ext_exit_qual(struct kvm_vcpu *vcpu)
{
	return kvm_rdx_read(vcpu);
}

static __always_inline unsigned long tdexit_gpa(struct kvm_vcpu *vcpu)
{
	return kvm_r8_read(vcpu);
}

static __always_inline unsigned long tdexit_intr_info(struct kvm_vcpu *vcpu)
{
	return kvm_r9_read(vcpu);
}

#define BUILD_TDVMCALL_ACCESSORS(param, gpr)				\
static __always_inline							\
unsigned long tdvmcall_##param##_read(struct kvm_vcpu *vcpu)		\
{									\
	return kvm_##gpr##_read(vcpu);					\
}									\
static __always_inline void tdvmcall_##param##_write(struct kvm_vcpu *vcpu, \
						     unsigned long val)	\
{									\
	kvm_##gpr##_write(vcpu, val);					\
}
BUILD_TDVMCALL_ACCESSORS(a0, r12);
BUILD_TDVMCALL_ACCESSORS(a1, r13);
BUILD_TDVMCALL_ACCESSORS(a2, r14);
BUILD_TDVMCALL_ACCESSORS(a3, r15);

#define TDX_VMCALL_REG_MASK_RBX	BIT_ULL(2)
#define TDX_VMCALL_REG_MASK_RDX	BIT_ULL(3)
#define TDX_VMCALL_REG_MASK_RBP	BIT_ULL(5)
#define TDX_VMCALL_REG_MASK_RSI	BIT_ULL(6)
#define TDX_VMCALL_REG_MASK_RDI	BIT_ULL(7)
#define TDX_VMCALL_REG_MASK_R8	BIT_ULL(8)
#define TDX_VMCALL_REG_MASK_R9	BIT_ULL(9)
#define TDX_VMCALL_REG_MASK_R12	BIT_ULL(12)
#define TDX_VMCALL_REG_MASK_R13	BIT_ULL(13)
#define TDX_VMCALL_REG_MASK_R14	BIT_ULL(14)
#define TDX_VMCALL_REG_MASK_R15	BIT_ULL(15)

static __always_inline unsigned long tdvmcall_exit_type(struct kvm_vcpu *vcpu)
{
	return kvm_r10_read(vcpu);
}
static __always_inline unsigned long tdvmcall_leaf(struct kvm_vcpu *vcpu)
{
	return kvm_r11_read(vcpu);
}
static __always_inline void tdvmcall_set_return_code(struct kvm_vcpu *vcpu,
						     long val)
{
	kvm_r10_write(vcpu, val);
}
static __always_inline void tdvmcall_set_return_val(struct kvm_vcpu *vcpu,
						    unsigned long val)
{
	kvm_r11_write(vcpu, val);
}

static inline bool is_td_vcpu_created(struct vcpu_tdx *tdx)
{
	return tdx->tdvpr.added;
}

static inline bool is_td_created(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->tdr.added;
}

#define TDX_UPDATE_START	0
#define TDX_UPDATE_END		1

static int tdx_update_notifier_call(struct notifier_block *nb,
				    unsigned long action, void *data)
{
	struct vcpu_tdx *tdx = container_of(nb, struct vcpu_tdx, update_nb);

	if (action == TDX_UPDATE_START) {
		kvm_make_request(KVM_REQ_TDX_UPDATE, &tdx->vcpu);
		kvm_vcpu_kick(&tdx->vcpu);
	} else if (action == TDX_UPDATE_END) {
		kvm_clear_request(KVM_REQ_TDX_UPDATE, &tdx->vcpu);
	} else {
		WARN_ON_ONCE(1);
	}

	return NOTIFY_OK;
}

static int register_tdx_update(struct notifier_block *nb)
{
	int ret;

	spin_lock(&tdx_update_lock);
	ret = raw_notifier_chain_register(&tdx_update_chain, nb);
	if (!ret && tdx_in_update)
		tdx_update_notifier_call(nb, TDX_UPDATE_START, NULL);
	spin_unlock(&tdx_update_lock);
	return ret;
}

static int unregister_tdx_update(struct notifier_block *nb)
{
	int ret;

	spin_lock(&tdx_update_lock);
	ret = raw_notifier_chain_unregister(&tdx_update_chain, nb);
	if (!ret && tdx_in_update)
		tdx_update_notifier_call(nb, TDX_UPDATE_END, NULL);
	spin_unlock(&tdx_update_lock);
	return ret;
}

int tdx_update_notifier_call_chain(int update)
{
	int ret;

	if (update != TDX_UPDATE_START && update != TDX_UPDATE_END)
		return -EINVAL;

	ret = raw_notifier_call_chain(&tdx_update_chain, update, NULL);

	return notifier_to_errno(ret);
}

static inline int created_tds_inc(void)
{
	int ret = 0;

	spin_lock(&tdx_update_lock);
	if (tdx_in_update)
		/*
		 * Don't need to make userspace VMMs aware of TDX module
		 * update. return -EINTR to let them retry.
		 */
		ret = -EINTR;
	else
		created_tds++;
	spin_unlock(&tdx_update_lock);

	return ret;
}

static inline void created_tds_dec(void)
{
	spin_lock(&tdx_update_lock);
	created_tds--;
	spin_unlock(&tdx_update_lock);
}

/* Block TD creation and return the number of created TDs */
static inline unsigned int td_creation_block(void)
{
	unsigned int ret;

	spin_lock(&tdx_update_lock);
	tdx_in_update = true;
	WARN_ON_ONCE(tdx_update_notifier_call_chain(TDX_UPDATE_START));
	ret = created_tds;
	spin_unlock(&tdx_update_lock);

	return ret;
}

static inline void td_creation_unblock(void)
{
	spin_lock(&tdx_update_lock);
	tdx_in_update = false;
	WARN_ON_ONCE(tdx_update_notifier_call_chain(TDX_UPDATE_END));
	spin_unlock(&tdx_update_lock);
}

static inline void tdx_hkid_free(struct kvm_tdx *kvm_tdx)
{
	tdx_keyid_free(kvm_tdx->hkid);
	kvm_tdx->hkid = -1;
	misc_cg_uncharge(MISC_CG_RES_TDX, kvm_tdx->misc_cg, 1);
	put_misc_cg(kvm_tdx->misc_cg);
	kvm_tdx->misc_cg = NULL;
}

static inline bool is_hkid_assigned(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->hkid > 0;
}

static inline bool is_td_finalized(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->finalized;
}

static inline void tdx_disassociate_vp(struct kvm_vcpu *vcpu)
{
	list_del(&to_tdx(vcpu)->cpu_list);

	/*
	 * Ensure tdx->cpu_list is updated is before setting vcpu->cpu to -1,
	 * otherwise, a different CPU can see vcpu->cpu = -1 and add the vCPU
	 * to its list before its deleted from this CPUs list.
	 */
	smp_wmb();

	vcpu->cpu = -1;
}

void tdx_hardware_enable(void)
{
	INIT_LIST_HEAD(&per_cpu(associated_tdvcpus, raw_smp_processor_id()));
}

static void tdx_clear_page(unsigned long page, int size)
{
	const void *zero_page = (const void *) __va(page_to_phys(ZERO_PAGE(0)));
	unsigned long i;

	WARN_ON_ONCE(size % 64);

	/*
	 * Zeroing the page is only necessary for systems with MKTME-i:
	 * when re-assign one page from old keyid to a new keyid, MOVDIR64B is
	 * required to clear/write the page with new keyid to prevent integrity
	 * error when read on the page with new keyid.
	 */
	if (!static_cpu_has(X86_FEATURE_MOVDIR64B))
		return;

	for (i = 0; i < size; i += 64)
		/* MOVDIR64B [rdx], es:rdi */
		asm (".byte 0x66, 0x0f, 0x38, 0xf8, 0x3a"
		     : : "d" (zero_page), "D" (page + i) : "memory");
}

static int tdx_reclaim_page(unsigned long va, hpa_t pa, enum pg_level level,
			    bool do_wb, u16 hkid)
{
	struct tdx_module_output out;
	u64 err;

	/*
	 * Don't print warning here, and let callers decide if warning messages
	 * are needed. This prevents false alarms from TDX modules, such as
	 * reclaiming pages that are not added to TDX modules.
	 */
	err = tdh_phymem_page_reclaim(pa, &out);
	if (err & TDX_SEAMCALL_STATUS_MASK)
		return -EIO;
	/* out.r8 == tdx sept page level */
	WARN_ON_ONCE(out.r8 != pg_level_to_tdx_sept_level(level));

	/* only TDR page gets into this path */
	if (do_wb && level == PG_LEVEL_4K) {
		err = tdh_phymem_page_wbinvd(set_hkid_to_hpa(pa, hkid));
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
			return -EIO;
		}
	}

	tdx_clear_page(va, KVM_HPAGE_SIZE(level));
	return 0;
}

int tdx_alloc_td_page(struct tdx_td_page *page)
{
	page->va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!page->va)
		return -ENOMEM;

	page->pa = __pa(page->va);
	return 0;
}

void tdx_mark_td_page_added(struct tdx_td_page *page)
{
	WARN_ON_ONCE(page->added);
	page->added = true;
}

void tdx_reclaim_td_page(struct tdx_td_page *page)
{
	if (page->added) {
		/*
		 * TDCX are being reclaimed.  TDX module maps TDCX with HKID
		 * assigned to the TD.  Here the cache associated to the TD
		 * was already flushed by TDH.PHYMEM.CACHE.WB before here, So
		 * cache doesn't need to be flushed again.
		 */
		if (tdx_reclaim_page(page->va, page->pa, PG_LEVEL_4K, false, 0))
			return;

		page->added = false;
	}
	free_page(page->va);
}

struct tdx_flush_vp_arg {
	struct kvm_vcpu *vcpu;
	u64 err;
};

static void tdx_flush_vp(void *arg_)
{
	struct tdx_flush_vp_arg *arg = arg_;
	struct kvm_vcpu *vcpu = arg->vcpu;
	u64 err;

	arg->err = 0;
	lockdep_assert_irqs_disabled();

	/* Task migration can race with CPU offlining. */
	if (vcpu->cpu != raw_smp_processor_id())
		return;

	/*
	 * No need to do TDH_VP_FLUSH if the vCPU hasn't been initialized.  The
	 * list tracking still needs to be updated so that it's correct if/when
	 * the vCPU does get initialized.
	 */
	if (is_td_vcpu_created(to_tdx(vcpu))) {
		err = tdh_vp_flush(to_tdx(vcpu)->tdvpr.pa);
		if (unlikely(err && err != TDX_VCPU_NOT_ASSOCIATED)) {
			/*
			 * This function is called in IPI context. Do not use
			 * printk to avoid console semaphore.
			 * The caller prints out the error message, instead.
			 */
			if (err)
				arg->err = err;
		}
	}

	tdx_disassociate_vp(vcpu);
}

void tdx_flush_vp_on_cpu(struct kvm_vcpu *vcpu)
{
	struct tdx_flush_vp_arg arg = {
		.vcpu = vcpu,
	};

	if (unlikely(vcpu->cpu == -1))
		return;

	smp_call_function_single(vcpu->cpu, tdx_flush_vp, &arg, 1);
	if (WARN_ON_ONCE(arg.err)) {
		pr_err("cpu: %d ", vcpu->cpu);
		pr_tdx_error(TDH_VP_FLUSH, arg.err, NULL);
	}
}

void tdx_hardware_disable(void)
{
	int cpu = raw_smp_processor_id();
	struct list_head *tdvcpus = &per_cpu(associated_tdvcpus, cpu);
	struct tdx_flush_vp_arg arg;
	struct vcpu_tdx *tdx, *tmp;
	unsigned long flags;

	local_irq_save(flags);
	/* Safe variant needed as tdx_disassociate_vp() deletes the entry. */
	list_for_each_entry_safe(tdx, tmp, tdvcpus, cpu_list) {
		arg.vcpu = &tdx->vcpu;
		tdx_flush_vp(&arg);
	}
	local_irq_restore(flags);
}

static int tdx_do_tdh_phymem_cache_wb(void *param)
{
	u64 err = 0;

	do {
		err = tdh_phymem_cache_wb(!!err);
	} while (err == TDX_INTERRUPTED_RESUMABLE);

	/* Other thread may have done for us. */
	if (err == TDX_NO_HKID_READY_TO_WBCACHE)
		err = TDX_SUCCESS;
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_PHYMEM_CACHE_WB, err, NULL);
		return -EIO;
	}

	return 0;
}

void tdx_mmu_release_hkid(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	cpumask_var_t packages;
	bool cpumask_allocated;
	struct kvm_vcpu *vcpu;
	u64 err;
	int ret;
	int i;
	unsigned long j;

	if (!is_hkid_assigned(kvm_tdx))
		return;

	if (!is_td_created(kvm_tdx))
		goto free_hkid;

	kvm_for_each_vcpu(j, vcpu, kvm)
		tdx_flush_vp_on_cpu(vcpu);

	mutex_lock(&tdx_lock);
	err = tdh_mng_vpflushdone(kvm_tdx->tdr.pa);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_VPFLUSHDONE, err, NULL);
		pr_err("tdh_mng_vpflushdone failed. HKID %d is leaked.\n",
			kvm_tdx->hkid);
		return;
	}

	cpumask_allocated = zalloc_cpumask_var(&packages, GFP_KERNEL);
	cpus_read_lock();
	for_each_online_cpu(i) {
		if (cpumask_allocated &&
			cpumask_test_and_set_cpu(topology_physical_package_id(i),
						packages))
			continue;

		/*
		 * We can destroy multiple the guest TDs simultaneously.
		 * Prevent tdh_phymem_cache_wb from returning TDX_BUSY by
		 * serialization.
		 */
		mutex_lock(&tdx_lock);
		ret = smp_call_on_cpu(i, tdx_do_tdh_phymem_cache_wb, NULL, 1);
		mutex_unlock(&tdx_lock);
		if (ret)
			break;
	}
	cpus_read_unlock();
	free_cpumask_var(packages);

	mutex_lock(&tdx_lock);
	err = tdh_mng_key_freeid(kvm_tdx->tdr.pa);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_FREEID, err, NULL);
		pr_err("tdh_mng_key_freeid failed. HKID %d is leaked.\n",
			kvm_tdx->hkid);
		return;
	}

free_hkid:
	tdx_hkid_free(kvm_tdx);
}

static void tdx_binding_slots_cleanup(struct kvm_tdx *kvm_tdx)
{
	struct tdx_binding_slot *slot;
	struct kvm_tdx *servtd_tdx;
	uint16_t req_id;
	int i;

	/* Being a user TD, disconnect from the related servtds */
	for (i = 0; i < KVM_TDX_SERVTD_TYPE_MAX; i++) {
		slot = &kvm_tdx->binding_slots[i];
		servtd_tdx = slot->servtd_tdx;
		if (!servtd_tdx)
			continue;
		spin_lock(&servtd_tdx->binding_slot_lock);
		req_id = slot->req_id;
		/*
		 * Sanity check: servtd should have the slot pointer
		 * to this slot.
		 */
		if (servtd_tdx->usertd_binding_slots[req_id] != slot) {
			pr_err("%s: unexpected slot %d pointer\n",
				__func__, i);
				continue;
		}
		servtd_tdx->usertd_binding_slots[req_id] = NULL;
		spin_unlock(&servtd_tdx->binding_slot_lock);
	}

	/* Being a service TD, disconnect from the related user TDs */
	spin_lock(&kvm_tdx->binding_slot_lock);
	for (i = 0; i < SERVTD_SLOTS_MAX; i++) {
		slot = kvm_tdx->usertd_binding_slots[i];
		if (!slot)
			continue;

		/*
		 * Reset everything, and the slot (of the user TD) is availale
		 * for a new usage.
		 */
		memset(slot, 0, sizeof(struct tdx_binding_slot));
	}
	spin_unlock(&kvm_tdx->binding_slot_lock);
}

void tdx_vm_free(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	int i;

	/* Can't reclaim or free TD pages if teardown failed. */
	if (is_hkid_assigned(kvm_tdx))
		return;

	tdx_binding_slots_cleanup(kvm_tdx);
	tdx_mig_state_cleanup(kvm_tdx);

	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++)
		tdx_reclaim_td_page(&kvm_tdx->tdcs[i]);
	kfree(kvm_tdx->tdcs);

	/*
	 * TDX module maps TDR with TDX global HKID.  TDX module may access TDR
	 * while operating on TD (Especially reclaiming TDCS).  Cache flush with
	 * TDX global HKID is needed.
	 */
	if (kvm_tdx->tdr.added &&
		tdx_reclaim_page(kvm_tdx->tdr.va, kvm_tdx->tdr.pa, PG_LEVEL_4K,
				 true, tdx_global_keyid))
		return;

	free_page(kvm_tdx->tdr.va);
	created_tds_dec();
}

static int tdx_do_tdh_mng_key_config(void *param)
{
	hpa_t *tdr_p = param;
	u64 err;

	do {
		err = tdh_mng_key_config(*tdr_p);

		/*
		 * If it failed to generate a random key, retry it because this
		 * is typically caused by an entropy error of the CPU's random
		 * number generator.
		 */
	} while (err == TDX_KEY_GENERATION_FAILED);

	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_CONFIG, err, NULL);
		return -EIO;
	}

	return 0;
}

static void tdx_binding_slot_set_status(struct tdx_binding_slot *slot,
					enum tdx_binding_slot_status status)
{
	atomic_xchg(&slot->status, status);
}

static enum tdx_binding_slot_status
tdx_binding_slot_get_status(struct tdx_binding_slot *slot)
{
	return atomic_read(&slot->status);
}

int tdx_vm_init(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	cpumask_var_t packages;
	int ret, i;
	u64 err;

	/*
	 * Because guest TD is protected, VMM can't parse the instruction in TD.
	 * Instead, guest uses MMIO hypercall.  For unmodified device driver,
	 * #VE needs to be injected for MMIO and #VE handler in TD converts MMIO
	 * instruction into MMIO hypercall.
	 *
	 * SPTE value for MMIO needs to be setup so that #VE is injected into
	 * TD instead of triggering EPT MISCONFIG.
	 * - RWX=0 so that EPT violation is triggered.
	 * - suppress #VE bit is cleared to inject #VE.
	 */
	kvm_mmu_set_mmio_spte_mask(kvm, 0, VMX_EPT_RWX_MASK, 0);

	/* TODO: test 1GB support and remove tdp_max_page_level */
	kvm->arch.tdp_max_page_level = PG_LEVEL_2M;
	/* vCPUs can't be created until after KVM_TDX_INIT_VM. */
	kvm->max_vcpus = 0;

	kvm_tdx->hkid = tdx_keyid_alloc();
	if (kvm_tdx->hkid < 0)
		return -EBUSY;
       kvm_tdx->misc_cg = get_current_misc_cg();
       ret = misc_cg_try_charge(MISC_CG_RES_TDX, kvm_tdx->misc_cg, 1);
       if (ret)
	       goto free_hkid;

	ret = tdx_alloc_td_page(&kvm_tdx->tdr);
	if (ret)
		goto free_hkid;

	kvm_tdx->tdcs = kcalloc(tdx_caps.tdcs_nr_pages, sizeof(*kvm_tdx->tdcs),
				GFP_KERNEL_ACCOUNT);
	if (!kvm_tdx->tdcs)
		goto free_tdr;
	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++) {
		ret = tdx_alloc_td_page(&kvm_tdx->tdcs[i]);
		if (ret)
			goto free_tdcs;
	}

	ret = created_tds_inc();
	if (ret)
		goto free_tdcs;

	/*
	 * Acquire global lock to avoid TDX_OPERAND_BUSY:
	 * TDH.MNG.CREATE and other APIs try to lock the global Key Owner
	 * Table (KOT) to track the assigned TDX private HKID.  It doesn't spin
	 * to acquire the lock, returns TDX_OPERAND_BUSY instead, and let the
	 * caller to handle the contention.  This is because of time limitation
	 * usable inside the TDX module and OS/VMM knows better about process
	 * scheduling.
	 *
	 * APIs to acquire the lock of KOT:
	 * TDH.MNG.CREATE, TDH.MNG.KEY.FREEID, TDH.MNG.VPFLUSHDONE, and
	 * TDH.PHYMEM.CACHE.WB.
	 */
	mutex_lock(&tdx_lock);
	err = tdh_mng_create(kvm_tdx->tdr.pa, kvm_tdx->hkid);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_CREATE, err, NULL);
		ret = -EIO;
		goto free_tdcs;
	}
	tdx_mark_td_page_added(&kvm_tdx->tdr);

	if (!zalloc_cpumask_var(&packages, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto free_tdcs;
	}
	cpus_read_lock();
	for_each_online_cpu(i) {
		int pkg = topology_physical_package_id(i);

		if (cpumask_test_and_set_cpu(pkg, packages))
			continue;

		/*
		 * Program the memory controller in the package with an
		 * encryption key associated to a TDX private host key id
		 * assigned to this TDR.  Concurrent operations on same memory
		 * controller results in TDX_OPERAND_BUSY.  Avoid this race by
		 * mutex.
		 */
		mutex_lock(&tdx_mng_key_config_lock[pkg]);
		ret = smp_call_on_cpu(i, tdx_do_tdh_mng_key_config,
				      &kvm_tdx->tdr.pa, true);
		mutex_unlock(&tdx_mng_key_config_lock[pkg]);
		if (ret)
			break;
	}
	cpus_read_unlock();
	free_cpumask_var(packages);
	if (ret)
		goto teardown;

	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++) {
		err = tdh_mng_addcx(kvm_tdx->tdr.pa, kvm_tdx->tdcs[i].pa);
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_MNG_ADDCX, err, NULL);
			ret = -EIO;
			goto teardown;
		}
		tdx_mark_td_page_added(&kvm_tdx->tdcs[i]);
	}

	spin_lock_init(&kvm_tdx->seamcall_lock);
	spin_lock_init(&kvm_tdx->binding_slot_lock);
	kvm_tdx->has_range_blocked = false;

	/*
	 * Note, TDH_MNG_INIT cannot be invoked here.  TDH_MNG_INIT requires a dedicated
	 * ioctl() to define the configure CPUID values for the TD.
	 */
	return 0;

	/*
	 * The sequence for freeing resources from a partially initialized TD
	 * varies based on where in the initialization flow failure occurred.
	 * Simply use the full teardown and destroy, which naturally play nice
	 * with partial initialization.
	 */
teardown:
	tdx_mmu_release_hkid(kvm);
	tdx_vm_free(kvm);
	return ret;

free_tdcs:
	/* @i points at the TDCS page that failed allocation. */
	for (--i; i >= 0; i--)
		free_page(kvm_tdx->tdcs[i].va);
	kfree(kvm_tdx->tdcs);
free_tdr:
	free_page(kvm_tdx->tdr.va);
free_hkid:
	tdx_hkid_free(kvm_tdx);
	return ret;
}

int tdx_vcpu_create(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	int ret, i;

	/* TDX only supports x2APIC, which requires an in-kernel local APIC. */
	if (!vcpu->arch.apic)
		return -EINVAL;

	fpstate_set_confidential(&vcpu->arch.guest_fpu);
	vcpu->arch.apic->guest_apic_protected = true;
	INIT_LIST_HEAD(&tdx->pi_wakeup_list);

	ret = tdx_alloc_td_page(&tdx->tdvpr);
	if (ret)
		return ret;

	tdx->tdvpx = kcalloc(tdx_caps.tdvpx_nr_pages, sizeof(*tdx->tdvpx),
			GFP_KERNEL_ACCOUNT);
	if (!tdx->tdvpx) {
		ret = -ENOMEM;
		goto free_tdvpr;
	}
	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++) {
		ret = tdx_alloc_td_page(&tdx->tdvpx[i]);
		if (ret)
			goto free_tdvpx;
	}

	vcpu->arch.efer = EFER_SCE | EFER_LME | EFER_LMA | EFER_NX;

	vcpu->arch.switch_db_regs = KVM_DEBUGREG_AUTO_SWITCH;
	/*
	 * kvm_arch_vcpu_reset(init_event=false) reads cr0 to reset MMU.
	 * Prevent to read CR0 via SEAMCALL.
	 */
	vcpu->arch.cr0_guest_owned_bits = 0ul;
	vcpu->arch.cr4_guest_owned_bits = -1ul;
	vcpu->arch.root_mmu.no_prefetch = true;

	vcpu->arch.tsc_offset = to_kvm_tdx(vcpu->kvm)->tsc_offset;
	vcpu->arch.l1_tsc_offset = vcpu->arch.tsc_offset;
	vcpu->arch.guest_state_protected =
		!(to_kvm_tdx(vcpu->kvm)->attributes & TDX_TD_ATTRIBUTE_DEBUG);

	if ((kvm_tdx->xfam & XFEATURE_MASK_XTILE) == XFEATURE_MASK_XTILE)
		vcpu->arch.xfd_no_write_intercept = true;

	tdx->pi_desc.nv = POSTED_INTR_VECTOR;
	tdx->pi_desc.sn = 1;

	tdx->host_state_need_save = true;
	tdx->host_state_need_restore = false;

	tdx->update_nb.notifier_call = tdx_update_notifier_call;
	WARN_ON(register_tdx_update(&tdx->update_nb));

	tdx->tdvmcall.regs_mask = 0xffffffff;
	return 0;

free_tdvpx:
	/* @i points at the TDVPX page that failed allocation. */
	for (--i; i >= 0; i--)
		free_page(tdx->tdvpx[i].va);
	kfree(tdx->tdvpx);
free_tdvpr:
	free_page(tdx->tdvpr.va);

	return ret;
}

void tdx_add_vcpu_association(struct vcpu_tdx *tdx, int cpu)
{
	local_irq_disable();
	/*
	 * Pairs with the smp_wmb() in tdx_disassociate_vp() to ensure
	 * vcpu->cpu is read before tdx->cpu_list.
	 */
	smp_rmb();

	list_add(&tdx->cpu_list, &per_cpu(associated_tdvcpus, cpu));
	local_irq_enable();
}

void tdx_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	vmx_vcpu_pi_load(vcpu, cpu);
	if (vcpu->cpu == cpu)
		return;

	tdx_flush_vp_on_cpu(vcpu);
	tdx_add_vcpu_association(tdx, cpu);
}

bool tdx_protected_apic_has_interrupt(struct kvm_vcpu *vcpu)
{
	bool ret = pi_has_pending_interrupt(vcpu);
	union tdx_vcpu_state_details details;
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (ret || vcpu->arch.mp_state != KVM_MP_STATE_HALTED)
		return true;

	if (tdx->interrupt_disabled_hlt)
		return false;

	/*
	 * This is for the case where the virtual interrupt is recognized,
	 * i.e. set in vmcs.RVI, between the STI and "HLT".  KVM doesn't have
	 * access to RVI and the interrupt is no longer in the PID (because it
	 * was "recognized".  It doesn't get delivered in the guest because the
	 * TDCALL completes before interrupts are enabled.
	 *
	 * TDX modules sets RVI while in an STI interrupt shadow.
	 * - TDExit(typically TDG.VP.VMCALL<HLT>) from the guest to TDX module.
	 *   The interrupt shadow at this point is gone.
	 * - It knows that there is an interrupt that can be delivered
	 *   (RVI > PPR && EFLAGS.IF=1, the other conditions of 29.2.2 don't
	 *    matter)
	 * - It forwards the TDExit nevertheless, to a clueless hypervisor that
	 *   has no way to glean either RVI or PPR.
	 */
	if (xchg(&tdx->buggy_hlt_workaround, 0))
		return true;

	/*
	 * This is needed for device assignment. Interrupts can arrive from
	 * the assigned devices.  Because tdx.buggy_hlt_workaround can't be set
	 * by VMM, use TDX SEAMCALL to query pending interrupts.
	 */
	details.full = td_state_non_arch_read64(
		tdx, TD_VCPU_STATE_DETAILS_NON_ARCH);
	return !!details.vmxip;
}

void tdx_prepare_switch_to_guest(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (!tdx->host_state_need_save)
		return;

	if (likely(is_64bit_mm(current->mm)))
		tdx->msr_host_kernel_gs_base = current->thread.gsbase;
	else
		tdx->msr_host_kernel_gs_base = read_msr(MSR_KERNEL_GS_BASE);

	tdx->host_state_need_save = false;
}

static void tdx_prepare_switch_to_host(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	tdx->host_state_need_save = true;
	if (!tdx->host_state_need_restore)
		return;

	wrmsrl(MSR_KERNEL_GS_BASE, tdx->msr_host_kernel_gs_base);
	tdx->host_state_need_restore = false;
}

void tdx_vcpu_put(struct kvm_vcpu *vcpu)
{
	vmx_vcpu_pi_put(vcpu);
	tdx_prepare_switch_to_host(vcpu);
}

void tdx_vcpu_free(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int i;

	/* Can't reclaim or free pages if teardown failed. */
	if (is_hkid_assigned(to_kvm_tdx(vcpu->kvm)))
		return;

	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++)
		tdx_reclaim_td_page(&tdx->tdvpx[i]);
	kfree(tdx->tdvpx);
	tdx_reclaim_td_page(&tdx->tdvpr);

	/*
	 * kvm_free_vcpus()
	 *   -> kvm_unload_vcpu_mmu()
	 *
	 * does vcpu_load() for every vcpu after they already disassociated
	 * from the per cpu list when tdx_vm_teardown(). So we need to
	 * disassociate them again, otherwise the freed vcpu data will be
	 * accessed when do list_{del,add}() on associated_tdvcpus list
	 * later.
	 */
	tdx_flush_vp_on_cpu(vcpu);
	WARN_ON(vcpu->cpu != -1);
	unregister_tdx_update(&tdx->update_nb);
}

void tdx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct msr_data apic_base_msr;
	u64 err;
	int i;

	if (!kvm_tdx->initialized)
		return;

	/* TDX doesn't support INIT event. */
	if (WARN_ON(init_event))
		goto td_bugged;
	if (WARN_ON(is_td_vcpu_created(tdx)))
		goto td_bugged;

	err = tdh_vp_create(kvm_tdx->tdr.pa, tdx->tdvpr.pa);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_VP_CREATE, err, NULL);
		goto td_bugged;
	}
	tdx_mark_td_page_added(&tdx->tdvpr);

	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++) {
		err = tdh_vp_addcx(tdx->tdvpr.pa, tdx->tdvpx[i].pa);
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_VP_ADDCX, err, NULL);
			goto td_bugged;
		}
		tdx_mark_td_page_added(&tdx->tdvpx[i]);
	}

	if (!vcpu->arch.cpuid_entries) {
		/*
		 * On cpu creation, cpuid entry is blank.  Forcibly enable
		 * X2APIC feature to allow X2APIC.
		 */
		struct kvm_cpuid_entry2 *e;

		e = kvmalloc_array(1, sizeof(*e), GFP_KERNEL_ACCOUNT);
		*e  = (struct kvm_cpuid_entry2) {
			.function = 1,	/* Features for X2APIC */
			.index = 0,
			.eax = 0,
			.ebx = 0,
			.ecx = 1ULL << 21,	/* X2APIC */
			.edx = 0,
		};
		vcpu->arch.cpuid_entries = e;
		vcpu->arch.cpuid_nent = 1;
	}
	apic_base_msr.data = APIC_DEFAULT_PHYS_BASE | LAPIC_MODE_X2APIC;
	if (kvm_vcpu_is_reset_bsp(vcpu))
		apic_base_msr.data |= MSR_IA32_APICBASE_BSP;
	apic_base_msr.host_initiated = true;
	if (WARN_ON(kvm_set_apic_base(vcpu, &apic_base_msr)))
		goto td_bugged;

	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	vcpu->arch.cr0_guest_owned_bits = -1ul;

	/*
	 * tdx_vcpu_run()  load GPRs from KVM's internal cache
	 * into TDX guest for DEBUG TDX guest, but this should
	 * NOT happen before the 1st time VCPU start to run,
	 * to avoid break VCPU INIT state set by TDX module
	 */
	if (is_debug_td(vcpu))
		vcpu->arch.regs_dirty = 0;
	tdx->dr6 = vcpu->arch.dr6;

	return;

td_bugged:
	vcpu->kvm->vm_bugged = true;
}

static void tdx_complete_interrupts(struct kvm_vcpu *vcpu)
{
	/* Avoid costly SEAMCALL if no nmi was injected */
	if (vcpu->arch.nmi_injected)
		vcpu->arch.nmi_injected = td_management_read8(to_tdx(vcpu),
							      TD_VCPU_PEND_NMI);

	if (is_debug_td(vcpu))
		kvm_clear_exception_queue(vcpu);
}

struct tdx_uret_msr {
	u32 msr;
	unsigned int slot;
	u64 defval;
};

static struct tdx_uret_msr tdx_uret_msrs[] = {
	{.msr = MSR_SYSCALL_MASK,},
	{.msr = MSR_STAR,},
	{.msr = MSR_LSTAR,},
	{.msr = MSR_TSC_AUX,},
};

static void tdx_user_return_update_cache(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tdx_uret_msrs); i++)
		kvm_user_return_update_cache(tdx_uret_msrs[i].slot,
					     tdx_uret_msrs[i].defval);
}

static void tdx_restore_host_xsave_state(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);

	if (static_cpu_has(X86_FEATURE_XSAVE) &&
	    host_xcr0 != (kvm_tdx->xfam & kvm_caps.supported_xcr0))
		xsetbv(XCR_XFEATURE_ENABLED_MASK, host_xcr0);
	if (static_cpu_has(X86_FEATURE_XSAVES) &&
	    /* PT can be exposed to TD guest regardless of KVM's XSS support */
	    host_xss != (kvm_tdx->xfam &
			 (kvm_caps.supported_xss | XFEATURE_MASK_PT | TDX_TD_XFAM_CET)))
		wrmsrl(MSR_IA32_XSS, host_xss);
	if (static_cpu_has(X86_FEATURE_PKU) &&
	    (kvm_tdx->xfam & XFEATURE_MASK_PKRU))
		write_pkru(vcpu->arch.host_pkru);
}

static void tdx_reset_regs_cache(struct kvm_vcpu *vcpu)
{
	vcpu->arch.regs_avail = 0;
	vcpu->arch.regs_dirty = 0;
}

static void tdx_load_gprs(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int i;

	for (i = 0; i < NR_VCPU_REGS; i++) {
		if (!kvm_register_is_dirty(vcpu, i))
			continue;

		if (i == VCPU_REGS_RSP) {
			td_vmcs_write64(tdx, GUEST_RSP, vcpu->arch.regs[i]);
			continue;
		}
		if (i == VCPU_REGS_RIP) {
			td_vmcs_write64(tdx, GUEST_RIP, vcpu->arch.regs[i]);
			continue;
		}
		td_gpr_write64(tdx, i, vcpu->arch.regs[i]);
	}
}

/*
 * Update TD VMCS to enable PMU counters when this TD vCPU is running.
 */
static void tdx_switch_perf_msrs(struct kvm_vcpu *vcpu)
{
	int i, nr_msrs;
	struct perf_guest_switch_msr *msrs;
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	/*
	 * TODO: pass tdx version of vcpu_to_pmu(&vmx->vcpu) instead of NULL.
	 * See intel_guest_get_msr() in arch/x86/events/intel/core.c
	 */
	msrs = perf_guest_get_msrs(&nr_msrs, NULL);
	if (!msrs)
		return;

	for (i = 0; i < nr_msrs; i++) {
		switch (msrs[i].msr) {
		case MSR_CORE_PERF_GLOBAL_CTRL:
			if (tdx->guest_perf_global_ctrl != msrs[i].guest) {
				td_vmcs_write64(tdx,
						GUEST_IA32_PERF_GLOBAL_CTRL,
						msrs[i].guest);
				tdx->guest_perf_global_ctrl = msrs[i].guest;
			}
			break;

		default:
			WARN_ONCE(1, "Cannot switch msrs other than IA32_PERF_GLOBAL_CTRL");
		}
	}
}

u64 __tdx_vcpu_run(hpa_t tdvpr, void *regs, u32 regs_mask);

static noinstr void tdx_vcpu_enter_exit(struct kvm_vcpu *vcpu,
					struct vcpu_tdx *tdx)
{
	u64 err, retries = 0;

	guest_enter_irqoff();
	do {
		tdx->exit_reason.full = __tdx_vcpu_run(tdx->tdvpr.pa,
						     vcpu->arch.regs,
					    tdx->tdvmcall.regs_mask);
		err = tdx->exit_reason.full & TDX_SEAMCALL_STATUS_MASK;

		if (retries++ > TDX_SEAMCALL_RETRY_MAX) {
			KVM_BUG_ON(err, vcpu->kvm);
			pr_tdx_error(TDH_VP_ENTER, err, NULL);
			break;
		}
	} while (err == TDX_OPERAND_BUSY ||
		 err == TDX_OPERAND_BUSY_HOST_PRIORITY);
	guest_exit_irqoff();
}

fastpath_t tdx_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	u64 tsx_ctrl;

	if (unlikely(vcpu->kvm->vm_bugged)) {
		tdx->exit_reason.full = TDX_NON_RECOVERABLE_VCPU;
		return EXIT_FASTPATH_NONE;
	}

	trace_kvm_entry(vcpu);

	if (pi_test_on(&tdx->pi_desc)) {
		apic->send_IPI_self(POSTED_INTR_VECTOR);

		kvm_wait_lapic_expire(vcpu);
	}

	if (is_debug_td(vcpu)) {
		tdx_load_gprs(vcpu);
		/*
		 * Clear corresponding interruptibility bits for STI
		 * and MOV SS as legacy guest, refer vmx_vcpu_run()
		 * for more informaiton
		 */
		if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
			tdx_set_interrupt_shadow(vcpu, 0);
	}

	/*
	 * Always do PMU context switch here because SEAM module
	 * unconditionally clear MSR_IA32_DS_AREA, otherwise CPU
	 * may start to write data into DS area immediately after
	 * SEAMRET to KVM, which cause PANIC with NULL access.
	 */
	intel_pmu_save();
	if (!(kvm_tdx->attributes & TDX_TD_ATTRIBUTE_PERFMON) &&
		td_profile_allowed(kvm_tdx))
		tdx_switch_perf_msrs(vcpu);

	/*
	 * This is safe only when host PMU is disabled, e.g.
	 * the intel_pmu_save() is called before.
	 */
	if (kvm_tdx->attributes & TDX_TD_ATTRIBUTE_PERFMON)
		apic_write(APIC_LVTPC, TDX_GUEST_PMI_VECTOR);

	/*
	 * TDH.VP.ENTER has special environment requirements that
	 * RTM_DISABLE(bit 0) and TSX_CPUID_CLEAR(bit 1) of IA32_TSX_CTRL must
	 * be 0 if it's supported.
	 */
	tsx_ctrl = tsx_ctrl_clear();
	tdx_vcpu_enter_exit(vcpu, tdx);
	tsx_ctrl_restore(tsx_ctrl);

	tdx_user_return_update_cache();

	/*
	 * This is safe only when host PMU is disabled, e.g.
	 * the intel_pmu_save() is called before.
	 */
	if (kvm_tdx->attributes & TDX_TD_ATTRIBUTE_PERFMON)
		apic_write(APIC_LVTPC, APIC_DM_NMI);

	perf_restore_debug_store();
	tdx_restore_host_xsave_state(vcpu);
	tdx->host_state_need_restore = true;

	/*
	 * See the comments above for intel_pmu_save() for why
	 * always do PMU context switch here
	 *
	 * Restoring PMU must be after DS area because PMU may start to log
	 * records in DS area.
	 */
	intel_pmu_restore();

	if (is_debug_td(vcpu))
		tdx_reset_regs_cache(vcpu);
	else
		vcpu->arch.regs_avail &= ~VMX_REGS_LAZY_LOAD_SET;

	trace_kvm_exit(vcpu, KVM_ISA_VMX);

	tdx_complete_interrupts(vcpu);

	if (tdx->exit_reason.basic == EXIT_REASON_TDCALL)
		tdx->tdvmcall.rcx = vcpu->arch.regs[VCPU_REGS_RCX];
	else
		tdx->tdvmcall.rcx = 0;

	return EXIT_FASTPATH_NONE;
}

void tdx_inject_nmi(struct kvm_vcpu *vcpu)
{
	td_management_write8(to_tdx(vcpu), TD_VCPU_PEND_NMI, 1);
}

void tdx_handle_exit_irqoff(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	u16 exit_reason = tdx->exit_reason.basic;

	if (exit_reason == EXIT_REASON_EXCEPTION_NMI) {
		kvm_before_interrupt(vcpu, KVM_HANDLING_NMI);
		vmx_handle_exception_nmi_irqoff(vcpu,
						tdexit_intr_info(vcpu));
		kvm_after_interrupt(vcpu);
	} else if (exit_reason == EXIT_REASON_EXTERNAL_INTERRUPT)
		vmx_handle_external_interrupt_irqoff(vcpu,
						     tdexit_intr_info(vcpu));
	else if (unlikely(tdx->exit_reason.non_recoverable ||
		 tdx->exit_reason.error)) {
		/*
		 * The only reason it gets EXIT_REASON_OTHER_SMI is there is an
		 * #MSMI(Machine Check System Management Interrupt) in TD
		 * guest. The #MSMI is delivered right after SEAMCALL returns,
		 * and an #MC is delivered to host kernel after SMI handler
		 * returns.
		 *
		 * The #MC right after SEAMCALL is fixed up and skipped in #MC
		 * handler because it's an #MC happens in TD guest we cannot
		 * handle it with host's context.
		 *
		 * Call KVM's machine check handler explicitly here.
		 */
		if (tdx->exit_reason.basic == EXIT_REASON_OTHER_SMI)
			kvm_machine_check();
	}
}

static bool tdx_kvm_use_dr(struct kvm_vcpu *vcpu)
{
	return !!(vcpu->guest_debug &
		  (KVM_GUESTDBG_USE_HW_BP | KVM_GUESTDBG_SINGLESTEP));
}

static int tdx_handle_exception(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	u32 ex_no;
	u32 intr_info = tdexit_intr_info(vcpu);

	if (is_nmi(intr_info) || is_machine_check(intr_info))
		return 1;

	ex_no = intr_info & INTR_INFO_VECTOR_MASK;
	switch (ex_no) {
	case DB_VECTOR: {
		unsigned long dr6 = tdexit_exit_qual(vcpu);

		if (tdx_emulate_inject_bp_end(vcpu, dr6))
			return 1;

		if (!tdx_kvm_use_dr(vcpu)) {
			if (is_icebp(intr_info))
				WARN_ON(!tdx_skip_emulated_instruction(vcpu));

			kvm_queue_exception_p(vcpu, DB_VECTOR, dr6);
			return 1;
		}

		vcpu->run->debug.arch.dr6 = dr6 | DR6_ACTIVE_LOW;
		vcpu->run->debug.arch.dr7 = td_vmcs_read64(tdx, GUEST_DR7);
	}
		fallthrough;
	case BP_VECTOR:
		vcpu->arch.event_exit_inst_len =
			td_vmcs_read32(tdx, VM_EXIT_INSTRUCTION_LEN);
		vcpu->run->exit_reason = KVM_EXIT_DEBUG;
		vcpu->run->debug.arch.pc = kvm_get_linear_rip(vcpu);
		vcpu->run->debug.arch.exception = ex_no;
		return 0;
	default:
		break;
	}

	kvm_pr_unimpl("unexpected exception 0x%x(exit_reason 0x%llx qual 0x%lx)\n",
		      intr_info,
		      to_tdx(vcpu)->exit_reason.full, tdexit_exit_qual(vcpu));
	return -EFAULT;
}

void tdx_set_dr7(struct kvm_vcpu *vcpu, unsigned long val)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (!is_debug_td(vcpu) || !tdx->initialized)
		return;

	td_vmcs_write64(tdx, GUEST_DR7, val);
}

bool tdx_check_apicv_inhibit_reasons(struct kvm *kvm, ulong bit)
{
	ulong supported = BIT(APICV_INHIBIT_REASON_ABSENT);

	return supported & BIT(bit);
}


static void tdx_emulate_inject_bp_begin(struct kvm_vcpu *vcpu)
{
	unsigned long rflags;
	unsigned long guest_debug_old;

	/*
	 * Set the flag firstly because tdx_update_exception_bitmap()
	 * checkes it for deciding intercept #DB or not.
	 */
	to_tdx(vcpu)->emulate_inject_bp = true;

	/*
	 * Disable #BP intercept and enable single stepping
	 * so the int3 will execute normally in guest and
	 * return to KVM due to single stepping enabled,
	 * this emulates the #BP injection.
	 */
	guest_debug_old = vcpu->guest_debug;
	vcpu->guest_debug &= ~KVM_GUESTDBG_USE_SW_BP;
	tdx_update_exception_bitmap(vcpu);
	vcpu->guest_debug = guest_debug_old;

	rflags = tdx_get_rflags(vcpu);
	rflags |= X86_EFLAGS_TF;
	tdx_set_rflags(vcpu, rflags);
}

static int tdx_emulate_inject_bp_end(struct kvm_vcpu *vcpu, unsigned long dr6)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (!tdx->emulate_inject_bp)
		return  0;

	if (!(dr6 & DR6_BS))
		return 0;

	tdx->emulate_inject_bp = false;

	/* Check if we need enable #BP interception again */
	tdx_update_exception_bitmap(vcpu);

	/* No guest debug single step request, so clear it */
	if (!(vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)) {
		unsigned long rflags;

		rflags = tdx_get_rflags(vcpu);
		rflags &= ~X86_EFLAGS_TF;
		tdx_set_rflags(vcpu, rflags);
		kvm_make_request(KVM_REQ_EVENT, vcpu);
	}

	return 1;
}

static int tdx_handle_external_interrupt(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.irq_exits;
	return 1;
}

static int tdx_handle_triple_fault(struct kvm_vcpu *vcpu)
{
	if (to_kvm_tdx(vcpu->kvm)->attributes & TDX_TD_ATTRIBUTE_DEBUG)
		pr_err("triple fault at 0x%lx\n", kvm_rip_read(vcpu));
	vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
	vcpu->mmio_needed = 0;
	return 0;
}

static int tdx_emulate_vmcall(struct kvm_vcpu *vcpu)
{
	unsigned long nr, a0, a1, a2, a3, ret;

#define TDX_HYPERCALL_VENDOR_KVM		0x4d564b2e584454 /* TDX.KVM */
	nr = kvm_r10_read(vcpu);
	if (nr == TDX_HYPERCALL_VENDOR_KVM) {
		/*
		 * TODO: once the guest ABI change is done, remove this ABI
		 * support.
		 *
		 * ABI for KVM tdvmcall argument:
		 * magic number: R10 (0x4d564b2e584454)
		 * hypercall leaf: R11
		 * arguments: R12, R13, R14, R15.
		 */
		nr = tdvmcall_leaf(vcpu);
		a0 = kvm_r12_read(vcpu);
		a1 = kvm_r13_read(vcpu);
		a2 = kvm_r14_read(vcpu);
		a3 = kvm_r15_read(vcpu);
	} else {
		/*
		 * ABI for KVM tdvmcall argument:
		 * In Guest-Hypervisor Communication Interface(GHCI)
		 * specification, Non-zero leaf number (R10 != 0) is defined to
		 * indicate vendor-specific.  KVM uses this for KVM hypercall.
		 * NOTE: KVM hypercall number starts from one.  Zero isn't used
		 * for KVM hypercall number.
		 *
		 * R10: KVM h ypercall number
		 * arguments: R11, R12, R13, R14.
		 */
		a0 = kvm_r11_read(vcpu);
		a1 = kvm_r12_read(vcpu);
		a2 = kvm_r13_read(vcpu);
		a3 = kvm_r14_read(vcpu);
	}

	ret = __kvm_emulate_hypercall(vcpu, nr, a0, a1, a2, a3, true);

	tdvmcall_set_return_code(vcpu, ret);

	return 1;
}

static int tdx_emulate_cpuid(struct kvm_vcpu *vcpu)
{
	u32 eax, ebx, ecx, edx;

	/* EAX and ECX for cpuid is stored in R12 and R13. */
	eax = tdvmcall_a0_read(vcpu);
	ecx = tdvmcall_a1_read(vcpu);

	kvm_cpuid(vcpu, &eax, &ebx, &ecx, &edx, false);

	tdvmcall_a0_write(vcpu, eax);
	tdvmcall_a1_write(vcpu, ebx);
	tdvmcall_a2_write(vcpu, ecx);
	tdvmcall_a3_write(vcpu, edx);

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);

	return 1;
}

static int tdx_emulate_hlt(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	/* See tdx_protected_apic_has_interrupt() to avoid heavy seamcall */
	tdx->interrupt_disabled_hlt = tdvmcall_a0_read(vcpu);;

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
	return kvm_emulate_halt_noskip(vcpu);
}

static int tdx_complete_pio_in(struct kvm_vcpu *vcpu)
{
	struct x86_emulate_ctxt *ctxt = vcpu->arch.emulate_ctxt;
	unsigned long val = 0;
	int ret;

	WARN_ON(vcpu->arch.pio.count != 1);

	ret = ctxt->ops->pio_in_emulated(ctxt, vcpu->arch.pio.size,
					 vcpu->arch.pio.port, &val, 1);
	WARN_ON(!ret);

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
	tdvmcall_set_return_val(vcpu, val);

	return 1;
}

static int tdx_emulate_io(struct kvm_vcpu *vcpu)
{
	struct x86_emulate_ctxt *ctxt = vcpu->arch.emulate_ctxt;
	unsigned long val = 0;
	unsigned int port;
	int size, ret;
	bool write;

	++vcpu->stat.io_exits;

	size = tdvmcall_a0_read(vcpu);
	write = tdvmcall_a1_read(vcpu);
	port = tdvmcall_a2_read(vcpu);

	if (size != 1 && size != 2 && size != 4) {
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}

	if (write) {
		val = tdvmcall_a3_read(vcpu);
		ret = ctxt->ops->pio_out_emulated(ctxt, size, port, &val, 1);

		/* No need for a complete_userspace_io callback. */
		vcpu->arch.pio.count = 0;
	} else {
		ret = ctxt->ops->pio_in_emulated(ctxt, size, port, &val, 1);
		if (!ret)
			vcpu->arch.complete_userspace_io = tdx_complete_pio_in;
		else
			tdvmcall_set_return_val(vcpu, val);
	}
	if (ret)
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
	return ret;
}

static int tdx_complete_mmio(struct kvm_vcpu *vcpu)
{
	unsigned long val = 0;
	gpa_t gpa;
	int size;

	WARN_ON(vcpu->mmio_needed != 1);
	vcpu->mmio_needed = 0;

	if (!vcpu->mmio_is_write) {
		gpa = vcpu->mmio_fragments[0].gpa;
		size = vcpu->mmio_fragments[0].len;

		memcpy(&val, vcpu->run->mmio.data, size);
		tdvmcall_set_return_val(vcpu, val);
		trace_kvm_mmio(KVM_TRACE_MMIO_READ, size, gpa, &val);
	}
	return 1;
}

static inline int tdx_mmio_write(struct kvm_vcpu *vcpu, gpa_t gpa, int size,
				 unsigned long val)
{
	if (kvm_iodevice_write(vcpu, &vcpu->arch.apic->dev, gpa, size, &val) &&
	    kvm_io_bus_write(vcpu, KVM_MMIO_BUS, gpa, size, &val))
		return -EOPNOTSUPP;

	trace_kvm_mmio(KVM_TRACE_MMIO_WRITE, size, gpa, &val);
	return 0;
}

static inline int tdx_mmio_read(struct kvm_vcpu *vcpu, gpa_t gpa, int size)
{
	unsigned long val;

	if (kvm_iodevice_read(vcpu, &vcpu->arch.apic->dev, gpa, size, &val) &&
	    kvm_io_bus_read(vcpu, KVM_MMIO_BUS, gpa, size, &val))
		return -EOPNOTSUPP;

	tdvmcall_set_return_val(vcpu, val);
	trace_kvm_mmio(KVM_TRACE_MMIO_READ, size, gpa, &val);
	return 0;
}

static int tdx_emulate_mmio(struct kvm_vcpu *vcpu)
{
	struct kvm_memory_slot *slot;
	int size, write, r;
	unsigned long val;
	gpa_t gpa;

	WARN_ON(vcpu->mmio_needed);

	size = tdvmcall_a0_read(vcpu);
	write = tdvmcall_a1_read(vcpu);
	gpa = tdvmcall_a2_read(vcpu);
	val = write ? tdvmcall_a3_read(vcpu) : 0;

	if (size != 1 && size != 2 && size != 4 && size != 8)
		goto error;
	if (write != 0 && write != 1)
		goto error;

	/* Strip the shared bit, allow MMIO with and without it set. */
	gpa = gpa & ~gfn_to_gpa(kvm_gfn_shared_mask(vcpu->kvm));

	if (size > 8u || ((gpa + size - 1) ^ gpa) & PAGE_MASK)
		goto error;

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gpa_to_gfn(gpa));
	if (slot && !(slot->flags & KVM_MEMSLOT_INVALID))
		goto error;

	if (!kvm_io_bus_write(vcpu, KVM_FAST_MMIO_BUS, gpa, 0, NULL)) {
		trace_kvm_fast_mmio(gpa);
		return 1;
	}

	if (write)
		r = tdx_mmio_write(vcpu, gpa, size, val);
	else
		r = tdx_mmio_read(vcpu, gpa, size);
	if (!r) {
		/* Kernel completed device emulation. */
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
		return 1;
	}

	/* Request the device emulation to userspace device model. */
	vcpu->mmio_needed = 1;
	vcpu->mmio_is_write = write;
	vcpu->arch.complete_userspace_io = tdx_complete_mmio;

	vcpu->run->mmio.phys_addr = gpa;
	vcpu->run->mmio.len = size;
	vcpu->run->mmio.is_write = write;
	vcpu->run->exit_reason = KVM_EXIT_MMIO;

	if (write) {
		memcpy(vcpu->run->mmio.data, &val, size);
	} else {
		vcpu->mmio_fragments[0].gpa = gpa;
		vcpu->mmio_fragments[0].len = size;
		trace_kvm_mmio(KVM_TRACE_MMIO_READ_UNSATISFIED, size, gpa, NULL);
	}
	return 0;

error:
	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
	return 1;
}

static int tdx_emulate_rdmsr(struct kvm_vcpu *vcpu)
{
	u32 index = tdvmcall_a0_read(vcpu);
	u64 data;

	if (!kvm_msr_allowed(vcpu, index, KVM_MSR_FILTER_READ) ||
	    kvm_get_msr(vcpu, index, &data)) {
		trace_kvm_msr_read_ex(index);
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}
	trace_kvm_msr_read(index, data);

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
	tdvmcall_set_return_val(vcpu, data);
	return 1;
}

static int tdx_emulate_wrmsr(struct kvm_vcpu *vcpu)
{
	u32 index = tdvmcall_a0_read(vcpu);
	u64 data = tdvmcall_a1_read(vcpu);

	if (!kvm_msr_allowed(vcpu, index, KVM_MSR_FILTER_READ) ||
	    kvm_set_msr(vcpu, index, data)) {
		trace_kvm_msr_write_ex(index, data);
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}

	trace_kvm_msr_write(index, data);
	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
	return 1;
}

static int tdx_get_td_vm_call_info(struct kvm_vcpu *vcpu)
{
	if (tdvmcall_a0_read(vcpu))
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
	else {
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
		kvm_r11_write(vcpu, 0);
		tdvmcall_a0_write(vcpu, 0);
		tdvmcall_a1_write(vcpu, 0);
		tdvmcall_a2_write(vcpu, 0);
	}
	return 1;
}

static int tdx_report_fatal_error(struct kvm_vcpu *vcpu)
{
	/*
	 * Exit to userspace device model for teardown.
	 * Because guest TD is already panicing, returning an error to guerst TD
	 * doesn't make sense.  No argument check is done.
	 */

	vcpu->run->exit_reason = KVM_EXIT_SYSTEM_EVENT;
	vcpu->run->system_event.type = KVM_SYSTEM_EVENT_TDX;
	vcpu->run->system_event.ndata = 3;
	vcpu->run->system_event.data[0] = TDG_VP_VMCALL_REPORT_FATAL_ERROR;
	vcpu->run->system_event.data[1] = tdvmcall_a0_read(vcpu);
	vcpu->run->system_event.data[2] = tdvmcall_a1_read(vcpu);

	return 0;
}

static int tdx_complete_vp_vmcall(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx_vmcall *tdx_vmcall = &vcpu->run->tdx.u.vmcall;
	__u64 reg_mask;

	tdvmcall_set_return_code(vcpu, tdx_vmcall->status_code);
	tdvmcall_set_return_val(vcpu, tdx_vmcall->out_r11);

	reg_mask = kvm_rcx_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_R12)
		kvm_r12_write(vcpu, tdx_vmcall->out_r12);
	if (reg_mask & TDX_VMCALL_REG_MASK_R13)
		kvm_r13_write(vcpu, tdx_vmcall->out_r13);
	if (reg_mask & TDX_VMCALL_REG_MASK_R14)
		kvm_r14_write(vcpu, tdx_vmcall->out_r14);
	if (reg_mask & TDX_VMCALL_REG_MASK_R15)
		kvm_r15_write(vcpu, tdx_vmcall->out_r15);
	if (reg_mask & TDX_VMCALL_REG_MASK_RBX)
		kvm_rbx_write(vcpu, tdx_vmcall->out_rbx);
	if (reg_mask & TDX_VMCALL_REG_MASK_RDI)
		kvm_rdi_write(vcpu, tdx_vmcall->out_rdi);
	if (reg_mask & TDX_VMCALL_REG_MASK_RSI)
		kvm_rsi_write(vcpu, tdx_vmcall->out_rsi);
	if (reg_mask & TDX_VMCALL_REG_MASK_R8)
		kvm_r8_write(vcpu, tdx_vmcall->out_r8);
	if (reg_mask & TDX_VMCALL_REG_MASK_R9)
		kvm_r9_write(vcpu, tdx_vmcall->out_r9);
	if (reg_mask & TDX_VMCALL_REG_MASK_RDX)
		kvm_rdx_write(vcpu, tdx_vmcall->out_rdx);

	return 1;
}

static int tdx_vp_vmcall_to_user(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx_vmcall *tdx_vmcall = &vcpu->run->tdx.u.vmcall;
	__u64 reg_mask;

	vcpu->arch.complete_userspace_io = tdx_complete_vp_vmcall;
	memset(tdx_vmcall, 0, sizeof(*tdx_vmcall));

	vcpu->run->exit_reason = KVM_EXIT_TDX;
	vcpu->run->tdx.type = KVM_EXIT_TDX_VMCALL;
	tdx_vmcall->type = tdvmcall_exit_type(vcpu);
	tdx_vmcall->subfunction = tdvmcall_leaf(vcpu);

	reg_mask = kvm_rcx_read(vcpu);
	tdx_vmcall->reg_mask = reg_mask;
	if (reg_mask & TDX_VMCALL_REG_MASK_R12)
		tdx_vmcall->in_r12 = kvm_r12_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_R13)
		tdx_vmcall->in_r13 = kvm_r13_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_R14)
		tdx_vmcall->in_r14 = kvm_r14_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_R15)
		tdx_vmcall->in_r15 = kvm_r15_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_RBX)
		tdx_vmcall->in_rbx = kvm_rbx_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_RDI)
		tdx_vmcall->in_rdi = kvm_rdi_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_RSI)
		tdx_vmcall->in_rsi = kvm_rsi_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_R8)
		tdx_vmcall->in_r8 = kvm_r8_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_R9)
		tdx_vmcall->in_r9 = kvm_r9_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_RDX)
		tdx_vmcall->in_rdx = kvm_rdx_read(vcpu);

	/* notify userspace to handle the request */
	return 0;
}

static int tdx_get_quote(struct kvm_vcpu *vcpu)
{
	gpa_t gpa = tdvmcall_a0_read(vcpu);
	gpa_t size = tdvmcall_a1_read(vcpu);

	if (!IS_ALIGNED(gpa, PAGE_SIZE) || !IS_ALIGNED(size, PAGE_SIZE) ||
	    gpa + size < gpa || kvm_is_private_gpa(vcpu->kvm, gpa)) {
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}

	return tdx_vp_vmcall_to_user(vcpu);
}

static int tdx_setup_event_notify_interrupt(struct kvm_vcpu *vcpu)
{
	u64 vector = tdvmcall_a0_read(vcpu);

	if (!(vector >= 32 && vector <= 255)) {
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}

	return tdx_vp_vmcall_to_user(vcpu);
}

static void tdx_trace_tdvmcall_done(struct kvm_vcpu *vcpu)
{
	trace_kvm_tdx_hypercall_done(
		kvm_r11_read(vcpu), kvm_r10_read(vcpu),
		kvm_r12_read(vcpu), kvm_r13_read(vcpu), kvm_r14_read(vcpu),
		kvm_rbx_read(vcpu), kvm_rdi_read(vcpu), kvm_rsi_read(vcpu),
		kvm_r8_read(vcpu), kvm_r9_read(vcpu), kvm_rdx_read(vcpu));
}

static int tdx_map_gpa(struct kvm_vcpu *vcpu)
{
	struct kvm_memory_slot *slot;
	struct kvm *kvm = vcpu->kvm;
	gpa_t gpa = tdvmcall_a0_read(vcpu);
	gpa_t size = tdvmcall_a1_read(vcpu);
	gpa_t end = gpa + size;
	int ret;

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
	if (!IS_ALIGNED(gpa, 4096) || !IS_ALIGNED(size, 4096) ||
		end < gpa ||
		end > kvm_gfn_shared_mask(kvm) << (PAGE_SHIFT + 1) ||
		kvm_is_private_gpa(kvm, gpa) != kvm_is_private_gpa(kvm, end))
		return 1;

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);

	/*
	 * TODO: Add memfile notifier on changing private/shared.  Wire the
	 *       callback to kvm_mmu_map_gpa().
	 */
	ret = kvm_mmu_map_gpa(vcpu, gpa, end);
	if (ret) {
		tdvmcall_set_return_code(vcpu,
					 TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}

	gpa = gpa & ~gfn_to_gpa(kvm_gfn_shared_mask(vcpu->kvm));
	slot = kvm_vcpu_gfn_to_memslot(vcpu, gpa_to_gfn(gpa));
	if (slot && kvm_slot_is_private(slot))
		return tdx_vp_vmcall_to_user(vcpu);

	return 1;
}

static enum tdvmcall_service_id tdvmcall_get_service_id(guid_t guid)
{
	guid_t temp;

	temp = GUID_INIT(0xfb6fc5e1, 0x3378, 0x4acb, 0x89, 0x64,
			 0xfa, 0x5e, 0xe4, 0x3b, 0x9c, 0x8a);
	if (guid_equal(&guid, &temp))
		return TDVMCALL_SERVICE_ID_QUERY;

	temp = GUID_INIT(0xe60e6330, 0x1e09, 0x4387, 0xa4, 0x44,
			 0x8f, 0x32, 0xb8, 0xd6, 0x11, 0xe5);
	if (guid_equal(&guid, &temp))
		return TDVMCALL_SERVICE_ID_MIGTD;

	return TDVMCALL_SERVICE_ID_UNKNOWN;
}

static void tdx_handle_service_query(struct tdvmcall_service *cmd_hdr,
				     struct tdvmcall_service *status_hdr)
{
	struct tdvmcall_service_query *cmd_query =
			(struct tdvmcall_service_query *)cmd_hdr->data;
	struct tdvmcall_service_query *status_query =
			(struct tdvmcall_service_query *)status_hdr->data;
	enum tdvmcall_service_id service_id;

	status_query->version = TDVMCALL_SERVICE_QUERY_VERSION;
	if (cmd_query->version != status_query->version ||
	    cmd_query->cmd != TDVMCALL_SERVICE_CMD_QUERY) {
		printk("%s: not supported \n", __func__);
		status_hdr->status = TDVMCALL_SERVICE_S_UNSUPP;
	}

	service_id = tdvmcall_get_service_id(cmd_query->guid);
	if (service_id == TDVMCALL_SERVICE_ID_UNKNOWN)
		status_query->status = TDVMCALL_SERVICE_QUERY_S_UNSUPPORTED;
	else
		status_query->status = TDVMCALL_SERVICE_QUERY_S_SUPPORTED;

	status_query->cmd = cmd_query->cmd;
	import_guid(&status_query->guid, cmd_query->guid.b);

	status_hdr->length += sizeof(struct tdvmcall_service_query);
}

static int migtd_basic_info_setup(struct migtd_basic_info *basic,
				  struct tdx_binding_slot *slot,
				  uint64_t req_id)
{
	struct hob_guid_type_hdr *hdr = &basic->hob_hdr;

	hdr->generic_hdr.type = HOB_TYPE_GUID_EXTENSION;
	hdr->generic_hdr.length = sizeof(struct migtd_basic_info);
	hdr->guid = GUID_INIT(0x42b5e398, 0xa199, 0x4d30, 0xbe, 0xfc, 0xc7,
			      0x5a, 0xc3, 0xda, 0x5d, 0x7c);
	basic->req_id = req_id;
	basic->src = slot->is_src;
	basic->binding_handle = slot->handle;
	basic->policy_id = 0; // unused by MigTD currently
	basic->comm_id = 0;
	basic->cpu_version = cpuid_eax(0x1);
	memcpy(basic->usertd_uuid, (uint8_t *)slot->uuid, 32);

	return hdr->generic_hdr.length;
}

static int migtd_socket_info_setup(struct migtd_socket_info *socket,
				   struct tdx_binding_slot *slot)
{
	struct hob_guid_type_hdr *hdr = &socket->hob_hdr;

	hdr->generic_hdr.type = HOB_TYPE_GUID_EXTENSION;
	hdr->generic_hdr.length = sizeof(struct migtd_socket_info);
	hdr->guid = GUID_INIT(0x7a103b9d, 0x552b, 0x485f, 0xbb, 0x4c, 0x2f,
			      0x3d, 0x2e, 0x8b, 0x1e, 0xe);
	socket->comm_id = 0;
	socket->quote_service_port = 0; // unused by MigTD currently
	socket->migtd_cid = 2; // i.e. VMADDR_CID_HOST
	socket->channel_port = slot->vsock_port;

	return hdr->generic_hdr.length;
}

static int migtd_policy_info_setup(struct migtd_policy_info *policy,
				   struct tdx_binding_slot *slot)
{
	struct hob_guid_type_hdr *hdr = &policy->hob_hdr;

	hdr->generic_hdr.type = HOB_TYPE_GUID_EXTENSION;
	hdr->generic_hdr.length = sizeof(struct migtd_policy_info);
	hdr->guid = GUID_INIT(0xd64f771a, 0xf0c9, 0x4d33, 0x99, 0x8b, 0xe,
			      0x3d, 0x8b, 0x94, 0xa, 0x61);
	policy->policy_id = slot->vsock_port; // unused, testing purpose
	policy->policy_size = 0;

	return hdr->generic_hdr.length;
}

static int migtd_start_migration(struct tdvmcall_service_migtd *status_migtd,
				 struct tdx_binding_slot *slot,
				 uint64_t req_id)
{
	struct migtd_all_info *info =
		(struct migtd_all_info *)status_migtd->data;
	int len = 0;

	/* No one requested to start migration */
	if (req_id == SERVTD_SLOTS_MAX) {
		status_migtd->operation = TDVMCALL_SERVICE_MIGTD_OP_NOOP;
		return len;
	}

	/* Ask MigTD to start migration setup */
	len += migtd_basic_info_setup(&info->basic, slot, req_id);
	len += migtd_socket_info_setup(&info->socket, slot);
	len += migtd_policy_info_setup(&info->policy, slot);

	status_migtd->operation = TDVMCALL_SERVICE_MIGTD_OP_START_MIG;

	return len;
}

static bool tdx_binding_slot_premig_wait(struct tdx_binding_slot *slot)
{
	enum tdx_binding_slot_status old_status;

	old_status = atomic_cmpxchg(&slot->status,
				    TDX_BINDING_SLOT_STATUS_PREMIG_WAIT,
				    TDX_BINDING_SLOT_STATUS_PREMIG_PROGRESS);

	return old_status == TDX_BINDING_SLOT_STATUS_PREMIG_WAIT;
}

static int migtd_wait_for_request(struct kvm_tdx *tdx,
				  struct tdvmcall_service_migtd *status_migtd)
{
	struct tdx_binding_slot *slot;
	int i, len = sizeof(struct tdvmcall_service_migtd);

	for (i = 0; i < SERVTD_SLOTS_MAX; i++) {
		slot = tdx->usertd_binding_slots[i];
		if (slot && tdx_binding_slot_premig_wait(slot))
			break;
	}

	len += migtd_start_migration(status_migtd, slot, i);

	return len;
}

/*
 * Return length of filled bytes. 0 bytes means that the operation isn't
 * supported.
 */
static int migtd_report_status(struct kvm_tdx *tdx,
			       struct tdvmcall_service_migtd *cmd_migtd,
			       struct tdvmcall_service_migtd *status_migtd)
{
	uint64_t req_id = *(uint64_t *)cmd_migtd->data;
	struct tdx_binding_slot *slot = tdx->usertd_binding_slots[req_id];
	int len = sizeof(struct tdvmcall_service_migtd);
	enum tdx_binding_slot_status status;

	switch (cmd_migtd->operation) {
	case TDVMCALL_SERVICE_MIGTD_OP_NOOP: {
		break;
	}
	case TDVMCALL_SERVICE_MIGTD_OP_START_MIG: {
		status = tdx_binding_slot_get_status(slot);
		/* Sanity check if the status is unexpected */
		if (status != TDX_BINDING_SLOT_STATUS_PREMIG_PROGRESS)
			return 0;

		if (cmd_migtd->status != TDVMCALL_SERVICE_MIGTD_STATUS_SUCC) {
			pr_err("%s: pre-migration failed, status=%x\n",
				__func__, cmd_migtd->status);
			status = TDX_BINDING_SLOT_STATUS_BOUND;
		} else {
			status = TDX_BINDING_SLOT_STATUS_PREMIG_DONE;
		}

		tdx_binding_slot_set_status(slot, status);
		printk("%s: binding slot status=%d\n",
			__func__, tdx_binding_slot_get_status(slot));
		break;
	}
	default:
		len = 0;
		printk("%s: operation not supported \n", __func__);
	}

	return len;
}

/* Return true if the response isn't ready and need to block the vcpu */
static bool tdx_handle_service_migtd(struct kvm_tdx *tdx,
				     struct tdvmcall_service *cmd_hdr,
				     struct tdvmcall_service *status_hdr)
{
	struct tdvmcall_service_migtd *cmd_migtd =
		(struct tdvmcall_service_migtd *)cmd_hdr->data;
	struct tdvmcall_service_migtd *status_migtd =
		(struct tdvmcall_service_migtd *)status_hdr->data;
	uint32_t status, len = 0;

	status_migtd->cmd = cmd_migtd->cmd;

	spin_lock(&tdx->binding_slot_lock);
	switch (cmd_migtd->cmd) {
		case TDVMCALL_SERVICE_MIGTD_CMD_SHUTDOWN:
			/*TODO: end the migtd */
			printk("%s: end the migtd \n", __func__);
			status = TDVMCALL_SERVICE_S_UNSUPP;
			break;
		case TDVMCALL_SERVICE_MIGTD_CMD_WAIT:
			status_migtd->version =
				TDVMCALL_SERVICE_MIGTD_WAIT_VERSION;
			if (cmd_migtd->version != status_migtd->version) {
				printk("%s: version err\n", __func__);
				status = TDVMCALL_SERVICE_S_UNSUPP;
				break;
			}
			len = migtd_wait_for_request(tdx, status_migtd);
			status = TDVMCALL_SERVICE_S_RETURNED;
			break;
		case TDVMCALL_SERVICE_MIGTD_CMD_REPORT:
			status_migtd->version =
				TDVMCALL_SERVICE_MIGTD_REPORT_VERSION;
			if (cmd_migtd->version != status_migtd->version) {
				printk("%s: version err\n", __func__);
				status = TDVMCALL_SERVICE_S_UNSUPP;
				break;
			}
			len = migtd_report_status(tdx,
						  cmd_migtd,
						  status_migtd);
			if (len)
				status = TDVMCALL_SERVICE_S_RETURNED;
			else
				status = TDVMCALL_SERVICE_S_UNSUPP;
			break;
		default:
			printk("%s: cmd %d not supported \n",
				__func__, cmd_migtd->cmd);
			status = TDVMCALL_SERVICE_S_UNSUPP;
	}
	spin_unlock(&tdx->binding_slot_lock);

	status_hdr->length += len;
	status_hdr->status = status;

	if (status_migtd->operation == TDVMCALL_SERVICE_MIGTD_OP_NOOP)
		return true;

	return false;
}

static struct tdvmcall_service *tdvmcall_servbuf_alloc(struct kvm_vcpu *vcpu,
						       gpa_t gpa)
{
	uint32_t length;
	gfn_t gfn = gpa_to_gfn(gpa);
	struct tdvmcall_service __user *g_buf, *h_buf;

	if (!PAGE_ALIGNED(gpa)) {
		pr_err("%s: gpa=%llx not page aligned\n", __func__, gpa);
		return NULL;
	}

	g_buf = (struct tdvmcall_service *)kvm_vcpu_gfn_to_hva(vcpu, gfn);
	if (g_buf && get_user(length, &g_buf->length)) {
		pr_err("%s: failed to get length\n", __func__);
		return NULL;
	}

	if (!length) {
		pr_err("%s: length being 0 isn't valid\n", __func__);
		return NULL;
	}

	/* The status field by default is TDX_VMCALL_SERVICE_S_RETURNED */
	h_buf = kzalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
	if (!h_buf) {
		pr_err("%s: failed to alloc buf\n", __func__);
		return NULL;
	}

	if (copy_from_user(h_buf, g_buf, length)) {
		pr_err("%s: failed tp copy\n", __func__);
		kfree(h_buf);
		return NULL;
	}

	return h_buf;
}

static void tdvmcall_status_copy_and_free(struct tdvmcall_service *h_buf,
					  struct kvm_vcpu *vcpu, gpa_t gpa)
{
	gfn_t gfn;
	struct tdvmcall_service __user *g_buf;

	gfn = gpa_to_gfn(gpa);
	g_buf = (struct tdvmcall_service *)kvm_vcpu_gfn_to_hva(vcpu, gfn);
	if (copy_to_user(g_buf, h_buf, h_buf->length)) {
		/* Guest sees TDVMCALL_SERVICE_S_RSVD in status */
		pr_err("%s: failed to update the guest buffer\n",
			__func__);
	}
	kfree(h_buf);
}

static int tdx_handle_service(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_tdx *tdx = to_kvm_tdx(kvm);
	gpa_t cmd_gpa = tdvmcall_a0_read(vcpu) &
			~gfn_to_gpa(kvm_gfn_shared_mask(kvm));
	gpa_t status_gpa = tdvmcall_a1_read(vcpu) &
			~gfn_to_gpa(kvm_gfn_shared_mask(kvm));
	uint64_t nvector = tdvmcall_a2_read(vcpu);
	struct tdvmcall_service *cmd_buf, *status_buf;
	enum tdvmcall_service_id service_id;
	bool need_block = false;

	if (nvector) {
		pr_warn("%s: interrupt not supported, nvector %lld\n",
			__func__, nvector);
		goto err_cmd;
	}

	/* Sanity check if gpa is private */
	if (kvm_unaliased_gpa_is_private(kvm, cmd_gpa) ||
	    kvm_unaliased_gpa_is_private(kvm, status_gpa)) {
		pr_err("%s: cmd_gpa=%llx or status_gpa=%llx is private\n",
			__func__, cmd_gpa, status_gpa);
		goto err_cmd;
	}

	cmd_buf = tdvmcall_servbuf_alloc(vcpu, cmd_gpa);
	if (!cmd_buf)
		goto err_cmd;
	status_buf = tdvmcall_servbuf_alloc(vcpu, status_gpa);
	if (!status_buf)
		goto err_status;
	status_buf->length = sizeof(struct tdvmcall_service);

	service_id = tdvmcall_get_service_id(cmd_buf->guid);
	switch (service_id) {
		case TDVMCALL_SERVICE_ID_QUERY:
			tdx_handle_service_query(cmd_buf, status_buf);
			break;
		case TDVMCALL_SERVICE_ID_MIGTD:
			need_block = tdx_handle_service_migtd(tdx,
							cmd_buf, status_buf);
			break;
		default:
			status_buf->status = TDVMCALL_SERVICE_S_UNSUPP;
			printk("%s: unsupported service type \n", __func__);
	}

	/* Update the guest status buf and free the host buf */
	tdvmcall_status_copy_and_free(status_buf, vcpu, status_gpa);
err_status:
	kfree(cmd_buf);
err_cmd:
	if (need_block && !nvector)
		return kvm_emulate_halt_noskip(vcpu);

	return 1;
}

static int handle_tdvmcall(struct kvm_vcpu *vcpu)
{
	int r;

	if (tdvmcall_exit_type(vcpu))
		return tdx_emulate_vmcall(vcpu);

	trace_kvm_tdx_hypercall(
		tdvmcall_leaf(vcpu), kvm_rcx_read(vcpu),
		kvm_r12_read(vcpu), kvm_r13_read(vcpu), kvm_r14_read(vcpu),
		kvm_rbx_read(vcpu), kvm_rdi_read(vcpu), kvm_rsi_read(vcpu),
		kvm_r8_read(vcpu), kvm_r9_read(vcpu), kvm_rdx_read(vcpu));

	switch (tdvmcall_leaf(vcpu)) {
	case EXIT_REASON_CPUID:
		r = tdx_emulate_cpuid(vcpu);
		break;
	case EXIT_REASON_HLT:
		r = tdx_emulate_hlt(vcpu);
		break;
	case EXIT_REASON_IO_INSTRUCTION:
		r = tdx_emulate_io(vcpu);
		break;
	case EXIT_REASON_EPT_VIOLATION:
		r = tdx_emulate_mmio(vcpu);
		break;
	case EXIT_REASON_MSR_READ:
		r = tdx_emulate_rdmsr(vcpu);
		break;
	case EXIT_REASON_MSR_WRITE:
		r = tdx_emulate_wrmsr(vcpu);
		break;
	case TDG_VP_VMCALL_GET_TD_VM_CALL_INFO:
		r = tdx_get_td_vm_call_info(vcpu);
		break;
	case TDG_VP_VMCALL_REPORT_FATAL_ERROR:
		r = tdx_report_fatal_error(vcpu);
		break;
	case TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT:
		r = tdx_setup_event_notify_interrupt(vcpu);
		break;
	case TDG_VP_VMCALL_GET_QUOTE:
		r = tdx_get_quote(vcpu);
		break;
	case TDG_VP_VMCALL_MAP_GPA:
		r = tdx_map_gpa(vcpu);
		break;
	case TDG_VP_VMCALL_SERVICE:
		r = tdx_handle_service(vcpu);
		break;
	default:
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		r = 1;
		break;
	}

	tdx_trace_tdvmcall_done(vcpu);
	return r;
}

void tdx_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa, int pgd_level)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);

	if (!kvm_tdx->initialized) {
		vcpu->load_mmu_pgd_pending = true;
		return;
	}

	vcpu->load_mmu_pgd_pending = false;
	td_vmcs_write64(to_tdx(vcpu), SHARED_EPT_POINTER, root_hpa & PAGE_MASK);
}

static void tdx_measure_page(struct kvm_tdx *kvm_tdx, hpa_t gpa, int size)
{
	struct tdx_module_output out;
	u64 err;
	int i;

	WARN_ON_ONCE(size % TDX_EXTENDMR_CHUNKSIZE);

	for (i = 0; i < size; i += TDX_EXTENDMR_CHUNKSIZE) {
		err = tdh_mr_extend(kvm_tdx->tdr.pa, gpa + i, &out);
		if (KVM_BUG_ON(err, &kvm_tdx->kvm)) {
			pr_tdx_error(TDH_MR_EXTEND, err, &out);
			break;
		}
	}
}

static void tdx_unpin(struct kvm *kvm, gfn_t gfn, kvm_pfn_t pfn,
		      enum pg_level level)
{
	struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);
	int i;

	for (i = 0; i < KVM_PAGES_PER_HPAGE(level); i++) {
		struct page *page = pfn_to_page(pfn + i);

		put_page(page);
		WARN_ON(!page_count(page) && to_kvm_tdx(kvm)->hkid > 0);
	}
	if (kvm_slot_is_private(slot)) {
		/* Private slot case */
		return;
	}
}

static void __tdx_sept_set_private_spte(struct kvm *kvm, gfn_t gfn,
					enum pg_level level, kvm_pfn_t pfn)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	hpa_t hpa = pfn_to_hpa(pfn);
	gpa_t gpa = gfn_to_gpa(gfn);
	struct tdx_module_output out;
	hpa_t source_pa;
	u64 err;
	int i;

	if (WARN_ON_ONCE(is_error_noslot_pfn(pfn) || kvm_is_reserved_pfn(pfn)))
		return;

	/* Only support 4KB and 2MB pages */
	if (KVM_BUG_ON(level > PG_LEVEL_2M, kvm))
		return;

	/* To prevent page migration, do nothing on mmu notifier. */
	for (i = 0; i < KVM_PAGES_PER_HPAGE(level); i++)
		get_page(pfn_to_page(pfn + i));

	/* Build-time faults are induced and handled via TDH_MEM_PAGE_ADD. */
	if (likely(is_td_finalized(kvm_tdx))) {
		/*
		 * For now only 4K and 2M pages are tested by KVM MMU.
		 * TODO: support/test 1G large page.
		 */
		if (KVM_BUG_ON(level > PG_LEVEL_2M, kvm))
			return;

		err = tdh_mem_page_aug(kvm_tdx->tdr.pa, gpa, tdx_level, hpa, &out);
		if (KVM_BUG_ON(err, kvm)) {
			pr_tdx_error(TDH_MEM_PAGE_AUG, err, &out);
			tdx_unpin(kvm, gfn, pfn, level);
		}
		return;
	}

	/* KVM_INIT_MEM_REGION, tdx_init_mem_region(), supports only 4K page. */
	if (KVM_BUG_ON(level != PG_LEVEL_4K, kvm))
		return;

	/*
	 * In case of TDP MMU, fault handler can run concurrently.  Note
	 * 'source_pa' is a TD scope variable, meaning if there are multiple
	 * threads reaching here with all needing to access 'source_pa', it
	 * will break.  However fortunately this won't happen, because below
	 * TDH_MEM_PAGE_ADD code path is only used when VM is being created
	 * before it is running, using KVM_TDX_INIT_MEM_REGION ioctl (which
	 * always uses vcpu 0's page table and protected by vcpu->mutex).
	 */
	if (KVM_BUG_ON(kvm_tdx->source_pa == INVALID_PAGE, kvm)) {
		tdx_unpin(kvm, gfn, pfn, level);
		return;
	}

	source_pa = kvm_tdx->source_pa & ~KVM_TDX_MEASURE_MEMORY_REGION;

	err = tdh_mem_page_add(kvm_tdx->tdr.pa, gpa, tdx_level, hpa, source_pa, &out);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_PAGE_ADD, err, &out);
		tdx_unpin(kvm, gfn, pfn, level);
	} else if ((kvm_tdx->source_pa & KVM_TDX_MEASURE_MEMORY_REGION))
		tdx_measure_page(kvm_tdx, gpa, KVM_HPAGE_SIZE(level));

	kvm_tdx->source_pa = INVALID_PAGE;
}

static void tdx_sept_set_private_spte(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level, kvm_pfn_t pfn)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

	if (!kvm_tdx->initialized)
		return;

	spin_lock(&kvm_tdx->seamcall_lock);
	__tdx_sept_set_private_spte(kvm, gfn, level, pfn);
	spin_unlock(&kvm_tdx->seamcall_lock);
}

static void tdx_sept_drop_private_spte(
	struct kvm *kvm, gfn_t gfn, enum pg_level level, kvm_pfn_t pfn)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn);
	hpa_t hpa = pfn_to_hpa(pfn);
	hpa_t hpa_with_hkid;
	struct tdx_module_output out;
	u64 err = 0;
	int i;

	/*
	 * Allow TD tearing down (hkid has been freed in kvm_flush_shadow_all)
	 * due to migration cancel to reclaim pages that have been imported.
	 */
	if (!kvm_tdx->initialized && is_hkid_assigned(kvm_tdx))
		return;

	/* Only support 4KB and 2MB pages */
	if (KVM_BUG_ON(level > PG_LEVEL_2M, kvm))
		return;

	if (is_hkid_assigned(kvm_tdx)) {
		spin_lock(&kvm_tdx->seamcall_lock);
		err = tdh_mem_page_remove(kvm_tdx->tdr.pa, gpa, tdx_level, &out);
		spin_unlock(&kvm_tdx->seamcall_lock);
		if (KVM_BUG_ON(err, kvm)) {
			pr_tdx_error(TDH_MEM_PAGE_REMOVE, err, &out);
			return;
		}

		for (i = 0; i < KVM_PAGES_PER_HPAGE(level); i++) {
			hpa_with_hkid = set_hkid_to_hpa(hpa, (u16)kvm_tdx->hkid);
			spin_lock(&kvm_tdx->seamcall_lock);
			err = tdh_phymem_page_wbinvd(hpa_with_hkid);
			spin_unlock(&kvm_tdx->seamcall_lock);
			if (WARN_ON_ONCE(err))
				pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
			else
				tdx_unpin(kvm, gfn + i, pfn + i, PG_LEVEL_4K);
			hpa += PAGE_SIZE;
		}
	} else {
		/*
		 * The HKID assigned to this TD was already freed and cache
		 * was already flushed. We don't have to flush again.
		 */
		spin_lock(&kvm_tdx->seamcall_lock);
		err = tdx_reclaim_page((unsigned long)__va(hpa), hpa, level,
				       false, 0);
		spin_unlock(&kvm_tdx->seamcall_lock);
		if (!err)
			tdx_unpin(kvm, gfn, pfn, level);
/*
		else
			pr_err("%s:%d:%s gfn 0x%llx level 0x%x pfn 0x%llx\n",
			       __FILE__, __LINE__, __func__, gfn, level, pfn);
*/
	}
}

static int tdx_sept_link_private_sp(struct kvm *kvm, gfn_t gfn,
				    enum pg_level level, void *sept_page)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn);
	hpa_t hpa = __pa(sept_page);
	struct tdx_module_output out;
	u64 err;

	spin_lock(&kvm_tdx->seamcall_lock);
	err = tdh_mem_sept_add(kvm_tdx->tdr.pa, gpa, tdx_level, hpa, &out);
	spin_unlock(&kvm_tdx->seamcall_lock);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_SEPT_ADD, err, &out);
		return -EIO;
	}

	return 0;
}

static int tdx_sept_split_private_spte(struct kvm *kvm, gfn_t gfn,
				       enum pg_level level, void *sept_page)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn << PAGE_SHIFT;
	hpa_t hpa = __pa(sept_page);
	struct tdx_module_output out;
	u64 err;

	/* See comment in tdx_sept_set_private_spte() */
	spin_lock(&kvm_tdx->seamcall_lock);
	err = tdh_mem_page_demote(kvm_tdx->tdr.pa, gpa, tdx_level, hpa, &out);
	spin_unlock(&kvm_tdx->seamcall_lock);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_PAGE_DEMOTE, err, &out);
		return -EIO;
	}

	return 0;
}

static void tdx_sept_zap_private_spte(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn);
	struct tdx_module_output out;
	u64 err;

	if (!kvm_tdx->initialized || !is_hkid_assigned(kvm_tdx))
		return;

	spin_lock(&kvm_tdx->seamcall_lock);
	err = tdh_mem_range_block(kvm_tdx->tdr.pa, gpa, tdx_level, &out);
	spin_unlock(&kvm_tdx->seamcall_lock);
	if (KVM_BUG_ON(err, kvm))
		pr_tdx_error(TDH_MEM_RANGE_BLOCK, err, &out);

	WRITE_ONCE(kvm_tdx->has_range_blocked, true);
}

/*
 * TLB shoot down procedure:
 * There is a global epoch counter and each vcpu has local epoch counter.
 * - TDH.MEM.RANGE.BLOCK(TDR. level, range) on one vcpu
 *   This blocks the subsequenct creation of TLB translation on that range.
 *   This corresponds to clear the present bit(all RXW) in EPT entry
 * - TDH.MEM.TRACK(TDR): advances the epoch counter which is global.
 * - IPI to remote vcpus
 * - TDExit and re-entry with TDH.VP.ENTER on remote vcpus
 * - On re-entry, TDX module compares the local epoch counter with the global
 *   epoch counter.  If the local epoch counter is older than the global epoch
 *   counter, update the local epoch counter and flushes TLB.
 */
void tdx_track(struct kvm_tdx *kvm_tdx)
{
	u64 err;

	WARN_ON(!is_hkid_assigned(kvm_tdx));
	/* If TD isn't finalized, it's before any vcpu running. */
	if (unlikely(!is_td_finalized(kvm_tdx)))
		return;

	/*
	 * tdx_flush_tlb() waits for this function to issue TDH.MEM.TRACK() by
	 * the counter.  The counter is used instead of bool because multiple
	 * TDH_MEM_TRACK() can be issued concurrently by multiple vcpus.
	 */
	atomic_inc(&kvm_tdx->tdh_mem_track);
	/*
	 * KVM_REQ_TLB_FLUSH waits for the empty IPI handler, ack_flush(), with
	 * KVM_REQUEST_WAIT.
	 */
	kvm_make_all_cpus_request(&kvm_tdx->kvm, KVM_REQ_TLB_FLUSH);

	spin_lock(&kvm_tdx->seamcall_lock);
	err = tdh_mem_track(kvm_tdx->tdr.pa);
	spin_unlock(&kvm_tdx->seamcall_lock);

	/* Release remote vcpu waiting for TDH.MEM.TRACK in tdx_flush_tlb(). */
	atomic_dec(&kvm_tdx->tdh_mem_track);

	if (KVM_BUG_ON(err, &kvm_tdx->kvm))
		pr_tdx_error(TDH_MEM_TRACK, err, NULL);

}

static void tdx_sept_unzap_private_spte(struct kvm *kvm, gfn_t gfn,
					enum pg_level level)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn);
	struct tdx_module_output out;
	u64 err;

	tdx_track(kvm_tdx);

	spin_lock(&kvm_tdx->seamcall_lock);
	err = tdh_mem_range_unblock(kvm_tdx->tdr.pa, gpa, tdx_level, &out);
	spin_unlock(&kvm_tdx->seamcall_lock);
	if (KVM_BUG_ON(err, kvm))
		pr_tdx_error(TDH_MEM_RANGE_UNBLOCK, err, &out);
}

static int tdx_sept_free_private_sp(struct kvm *kvm, gfn_t gfn, enum pg_level level,
				    void *sept_page)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	int ret;

	/*
	 * free_private_sp() is (obviously) called when a shadow page is being
	 * zapped.  KVM doesn't (yet) zap private SPs while the TD is active.
	 * Note: This function is for private shadow page.  Not for private
	 * guest page.   private guest page can be zapped during TD is active.
	 * shared <-> private conversion and slot move/deletion.
	 *
	 * TODO: large page support.  If large page is supported, S-EPT page
	 * can be freed when promoting 4K page to 2M/1G page during TD running.
	 * In such case, flush cache and TDH.PAGE.RECLAIM.
	 */

	if (is_hkid_assigned(kvm_tdx)) {
		/*
		 * Inefficient. But this is only called for deleting memslot
		 * which isn't performance critical path.
		 *
		 * +1: remove this SEPT page from the parent's entry.
		 */
		gpa_t parent_gpa = gfn_to_gpa(gfn) & KVM_HPAGE_MASK(level + 1);
		int parent_tdx_level = pg_level_to_tdx_sept_level(level + 1);
		struct tdx_module_output out;
		u64 err;

		err = tdh_mem_range_block(kvm_tdx->tdr.pa, parent_gpa,
					parent_tdx_level, &out);
		if (KVM_BUG_ON(err, kvm)) {
			pr_tdx_error(TDH_MEM_RANGE_BLOCK, err, &out);
			return -EIO;
		}

		tdx_track(kvm_tdx);

		err = tdh_mem_sept_remove(kvm_tdx->tdr.pa, parent_gpa,
					parent_tdx_level, &out);
		if (KVM_BUG_ON(err, kvm)) {
			pr_tdx_error(TDH_MEM_PAGE_REMOVE, err, &out);
			return -EIO;
		}

		err = tdh_phymem_page_wbinvd(
			set_hkid_to_hpa(__pa(sept_page), kvm_tdx->hkid));
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
			return -EIO;
		}
		return 0;
	}

	/*
	 * The HKID assigned to this TD was already freed and cache was
	 * already flushed. We don't have to flush again.
	 */
	spin_lock(&kvm_tdx->seamcall_lock);
	ret = tdx_reclaim_page((unsigned long)sept_page, __pa(sept_page),
			       PG_LEVEL_4K, false, 0);
	spin_unlock(&kvm_tdx->seamcall_lock);

	return ret;
}

static int tdx_sept_tlb_remote_flush_with_range(struct kvm *kvm,
						struct kvm_tlb_range *range)
{
	struct kvm_tdx *kvm_tdx;

	if (!is_td(kvm))
		return -EOPNOTSUPP;

	kvm_tdx = to_kvm_tdx(kvm);
	if (is_hkid_assigned(kvm_tdx))
		tdx_track(kvm_tdx);

	return 0;
}

static int tdx_sept_tlb_remote_flush(struct kvm *kvm)
{
	struct kvm_tlb_range range = {
		.start_gfn = 0,
		.pages = -1ULL,
	};

	return tdx_sept_tlb_remote_flush_with_range(kvm, &range);
}

static void tdx_handle_private_zapped_spte(
	struct kvm *kvm, const struct kvm_spte_change *change)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

	WARN_ON(!is_td(kvm));
	WARN_ON(change->old.is_present);
	WARN_ON(!change->old.is_private_zapped);
	WARN_ON(change->new.is_private_zapped);

	/*
	 * Handle special case of old_spte being temporarily blocked private
	 * SPTE.  There are two cases: 1) Need to restore the original mapping
	 * (unblock) when guest accesses the private page; 2) Need to truly
	 * zap the SPTE because of zapping aliasing in fault handler, or when
	 * VM is being destroyed.
	 *
	 * Do this before handling "!was_present && !is_present" case below,
	 * because blocked private SPTE is also non-present.
	 */
	if (change->new.is_present) {
		/* map_gpa holds write lock. */
		lockdep_assert_held(&kvm->mmu_lock);

		if (change->old.pfn == change->new.pfn) {
			tdx_sept_unzap_private_spte(kvm, change->gfn, change->level);
		} else if (change->level > PG_LEVEL_4K &&
			   change->old.is_last && !change->new.is_last) {
			int i;

			/* This large SPTE is blocked already. */
			tdx_sept_split_private_spte(kvm, change->gfn, change->level, change->sept_page);
			/* Block on newly splited SPTEs as parent SPTE as blocked. */
			for (i = 0; i < PT64_ENT_PER_PAGE; i++)
				tdx_sept_zap_private_spte(kvm, change->gfn + i, change->level - 1);
			tdx_sept_tlb_remote_flush(kvm);
		} else {
			/*
			 * Because page is pined (refer to
			 * kvm_faultin_pfn_private()), page migration shouldn't
			 * be triggered for private page.  kvm private memory
			 * slot case should also prevent page migration.
			 */
			pr_err("gfn 0x%llx level %d "
			       "old_pfn 0x%llx was_present %d was_last %d was_priavte_zapped %d "
			       "new_pfn 0x%llx is_present %d is_last %d is_priavte_zapped %d\n",
			       change->gfn, change->level,
			       change->old.pfn, change->old.is_present,
			       change->old.is_last, change->old.is_private_zapped,
			       change->new.pfn, change->new.is_present,
			       change->new.is_last, change->new.is_private_zapped);
			WARN_ON(1);
		}
	} else {
		lockdep_assert_held_write(&kvm->mmu_lock);
		if (is_hkid_assigned(kvm_tdx))
			tdx_track(kvm_tdx);
		tdx_sept_drop_private_spte(kvm, change->gfn, change->level,
					change->old.pfn);
	}
}

static void tdx_handle_changed_private_spte(
	struct kvm *kvm, const struct kvm_spte_change *change)
{
	bool was_leaf = change->old.is_present && change->old.is_last;
	bool is_leaf = change->new.is_present && change->new.is_last;
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	const gfn_t gfn = change->gfn;
	const enum pg_level level = change->level;

	WARN_ON(!is_td(kvm));
	lockdep_assert_held(&kvm->mmu_lock);

	if (change->new.is_present) {
		/* Only flags changed */
		if (change->old.is_present) {
			/* Write disable. TODO: do batching at the caller */
			if (change->old.is_writable &&
			    !change->new.is_writable) {
				tdx_sept_write_disable_spte(kvm, (gfn_t *)&gfn,
							    1, level);
				return;
			}

			/* Write enable */
			if (!change->old.is_writable &&
			    change->new.is_writable) {
				tdx_sept_write_enable_spte(kvm, gfn, level);
				return;
			}
		}

		if (level > PG_LEVEL_4K && was_leaf && !is_leaf) {
			tdx_sept_zap_private_spte(kvm, gfn, level);
			tdx_sept_tlb_remote_flush(kvm);
			tdx_sept_split_private_spte(kvm, gfn, level, change->sept_page);
		} else if (is_leaf)
			tdx_sept_set_private_spte(
				kvm, gfn, level, change->new.pfn);
		else {
			WARN_ON(!change->sept_page);
			if (tdx_sept_link_private_sp(
				    kvm, gfn, level, change->sept_page))
				/* failed to update Secure-EPT.  */
				WARN_ON(1);
		}
	} else if (was_leaf) {
		/* non-present -> non-present doesn't make sense. */
		WARN_ON(!change->old.is_present);

		/*
		 * Zap private leaf SPTE.  Zapping private table is done
		 * below in handle_removed_tdp_mmu_page().
		 */
		tdx_sept_zap_private_spte(kvm, gfn, level);

		if (change->new.is_private_zapped) {
			lockdep_assert_held_write(&kvm->mmu_lock);
			WARN_ON(change->new.pfn != change->old.pfn);
		} else {
			lockdep_assert_held_write(&kvm->mmu_lock);
			WARN_ON(change->new.pfn);

			/*
			 * TDX requires TLB tracking before dropping private
			 * page.
			 */
			if (is_hkid_assigned(kvm_tdx))
				tdx_track(kvm_tdx);

			tdx_sept_drop_private_spte(kvm, gfn, level, change->old.pfn);
		}
	}
}

void tdx_deliver_interrupt(struct kvm_lapic *apic, int delivery_mode,
			   int trig_mode, int vector)
{
	struct kvm_vcpu *vcpu = apic->vcpu;
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	/* See comment in tdx_protected_apic_has_interrupt(). */
	tdx->buggy_hlt_workaround = 1;
	/* TDX supports only posted interrupt.  No lapic emulation. */
	__vmx_deliver_posted_interrupt(vcpu, &tdx->pi_desc, vector);
}

static int tdx_handle_ept_violation(struct kvm_vcpu *vcpu)
{
	union tdx_ext_exit_qualification ext_exit_qual;
	unsigned long exit_qual;
	int err_page_level = 0;

	ext_exit_qual.full = tdexit_ext_exit_qual(vcpu);

	if (ext_exit_qual.type >= NUM_EXT_EXIT_QUAL) {
		pr_err("EPT violation at gpa 0x%lx, with invalid ext exit qualification type 0x%x\n",
			tdexit_gpa(vcpu), ext_exit_qual.type);
		kvm_vm_bugged(vcpu->kvm);
		return 0;
	} else if (ext_exit_qual.type == EXT_EXIT_QUAL_ACCEPT) {
		err_page_level = ext_exit_qual.req_sept_level + 1;
	}

	if (kvm_is_private_gpa(vcpu->kvm, tdexit_gpa(vcpu))) {
		/*
		 * Always treat SEPT violations as write faults.  Ignore the
		 * EXIT_QUALIFICATION reported by TDX-SEAM for SEPT violations.
		 * TD private pages are always RWX in the SEPT tables,
		 * i.e. they're always mapped writable.  Just as importantly,
		 * treating SEPT violations as write faults is necessary to
		 * avoid COW allocations, which will cause TDAUGPAGE failures
		 * due to aliasing a single HPA to multiple GPAs.
		 */
#define TDX_SEPT_VIOLATION_EXIT_QUAL	EPT_VIOLATION_ACC_WRITE
		exit_qual = TDX_SEPT_VIOLATION_EXIT_QUAL;
	} else {
		exit_qual = tdexit_exit_qual(vcpu);
		if (exit_qual & EPT_VIOLATION_ACC_INSTR) {
			pr_warn("kvm: TDX instr fetch to shared GPA = 0x%lx @ RIP = 0x%lx\n",
				tdexit_gpa(vcpu), kvm_rip_read(vcpu));
			vcpu->run->exit_reason = KVM_EXIT_EXCEPTION;
			vcpu->run->ex.exception = PF_VECTOR;
			vcpu->run->ex.error_code = exit_qual;
			return 0;
		}
	}

	trace_kvm_page_fault(tdexit_gpa(vcpu), exit_qual);
	return __vmx_handle_ept_violation(vcpu, tdexit_gpa(vcpu), exit_qual, err_page_level);
}

static int tdx_handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	WARN_ON(1);

	vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_MISCONFIG;

	return 0;
}

static int tdx_handle_bus_lock_vmexit(struct kvm_vcpu *vcpu)
{
	/*
	 * When EXIT_REASON_BUS_LOCK, bus_lock_detected bit is not necessarily
	 * set.  Enforce the bit set so that tdx_handle_exit() will handle it
	 * uniformly.
	 */
	to_tdx(vcpu)->exit_reason.bus_lock_detected = true;
	return 1;
}

static int tdx_handle_dr_exit(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qual;
	int dr, dr7, reg;

	exit_qual = tdexit_exit_qual(vcpu);
	dr = exit_qual & DEBUG_REG_ACCESS_NUM;
	if (!kvm_require_dr(vcpu, dr)) {
		pr_err_skip_ud("accessing to DR4/5");
		return kvm_complete_insn_gp(vcpu, 0);
	}

	if (tdx_get_cpl(vcpu) > 0) {
		pr_err_skip_ud("DR accessing with CPL > 0");
		return kvm_complete_insn_gp(vcpu, 0);
	}

	dr7 = td_vmcs_read64(to_tdx(vcpu), GUEST_DR7);
	if (dr7 & DR7_GD) {
		/*
		 * DR VMEXIT takes precedence over the debug trap,see 25.1.3 in
		 * SDM Vol3. We need emulate it for host or guest debugging itself.
		 */
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP) {
			vcpu->run->debug.arch.dr6 = DR6_BD | DR6_ACTIVE_LOW;
			vcpu->run->debug.arch.dr7 = dr7;
			vcpu->run->debug.arch.pc = kvm_get_linear_rip(vcpu);
			vcpu->run->debug.arch.exception = DB_VECTOR;
			vcpu->run->exit_reason = KVM_EXIT_DEBUG;
			return 0;
		}

		kvm_queue_exception_p(vcpu, DB_VECTOR, DR6_BD);
		return 1;
	}

	/*
	 * Why do emulation when DR is only using by guest debug feature:
	 *
	 * Unlike VMX, we don't always intercept #DB for TDX guest, because
	 * #DB injection is not supported in TDX 1.0. We don't have correct
	 * DR6 value in hand when #DB is not intercepted, guest will get
	 * incorrect value if we still try to emulate the DR accessing in
	 * this scenario, for example:
	 *
	 *   Only KVM_GUESTDBG_USE_SW_BP is set AND guest is using DR
	 *
	 * We don't intercept #DB in this case, because we can't inject #DB
	 * back to guest and we need keep DR working in guest side, so we
	 * need rely on KVM_DEBUGREG_WONT_EXIT to sync (but ignore
	 * DR6) and retrieve DR6 (includes DR6) but not emulation.
	 */
	if (tdx_kvm_use_dr(vcpu)) {
		int err;
		unsigned long val;

		reg = DEBUG_REG_ACCESS_REG(exit_qual);
		if (exit_qual & TYPE_MOV_FROM_DR) {
			err = 0;
			kvm_get_dr(vcpu, dr, &val);
			kvm_register_write(vcpu, reg, val);
		} else {
			err = kvm_set_dr(vcpu, dr, kvm_register_read(vcpu, reg));
		}

		if (err) {
			pr_err_skip_ud("setting DR violation");
			err = 0;
		}

		return kvm_complete_insn_gp(vcpu, err);
	}

	td_vmcs_clearbit32(to_tdx(vcpu),
			   CPU_BASED_VM_EXEC_CONTROL,
			   CPU_BASED_MOV_DR_EXITING);
	/*
	 * force a reload of the debug registers
	 * and reenter on this instruction.  The next vmexit will
	 * retrieve the full state of the debug registers.
	 */
	vcpu->arch.switch_db_regs |= KVM_DEBUGREG_WONT_EXIT;
	return 1;
}

static int __tdx_handle_exit(struct kvm_vcpu *vcpu, fastpath_t fastpath)
{
	union tdx_exit_reason exit_reason = to_tdx(vcpu)->exit_reason;

	/* See the comment of tdh_sept_seamcall(). */
	if (unlikely(exit_reason.full == (TDX_OPERAND_BUSY | TDX_OPERAND_ID_SEPT)))
		return 1;

	if (unlikely(exit_reason.non_recoverable || exit_reason.error)) {
		if (exit_reason.basic == EXIT_REASON_TRIPLE_FAULT)
			return tdx_handle_triple_fault(vcpu);

		kvm_pr_unimpl("TD exit 0x%llx, %d hkid 0x%x hkid pa 0x%llx\n",
			      exit_reason.full, exit_reason.basic,
			      to_kvm_tdx(vcpu->kvm)->hkid,
			      set_hkid_to_hpa(0, to_kvm_tdx(vcpu->kvm)->hkid));

		/*
		 * tdx_handle_exit_irqoff() handled EXIT_REASON_OTHER_SMI.  It
		 * must be handled before enabling preemption because it's #MC.
		 */
		goto unhandled_exit;
	}

	WARN_ON_ONCE(fastpath != EXIT_FASTPATH_NONE);

	switch (exit_reason.basic) {
	case EXIT_REASON_EXCEPTION_NMI:
		return tdx_handle_exception(vcpu);
	case EXIT_REASON_EXTERNAL_INTERRUPT:
		return tdx_handle_external_interrupt(vcpu);
	case EXIT_REASON_TDCALL:
		return handle_tdvmcall(vcpu);
	case EXIT_REASON_EPT_VIOLATION:
		return tdx_handle_ept_violation(vcpu);
	case EXIT_REASON_EPT_MISCONFIG:
		return tdx_handle_ept_misconfig(vcpu);
	case EXIT_REASON_OTHER_SMI:
		/*
		 * Unlike VMX, all the SMI in SEAM non-root mode (i.e. when
		 * TD guest vcpu is running) will cause TD exit to TDX module,
		 * then SEAMRET to KVM. Once it exits to KVM, SMI is delivered
		 * and handled right away.
		 *
		 * - If it's an Machine Check System Management Interrupt
		 *   (MSMI), it's handled above due to non_recoverable bit set.
		 * - If it's not an MSMI, don't need to do anything here.
		 */
		return 1;
	case EXIT_REASON_BUS_LOCK:
		tdx_handle_bus_lock_vmexit(vcpu);
		return 1;
	case EXIT_REASON_DR_ACCESS:
		return tdx_handle_dr_exit(vcpu);
	default:
		break;
	}

unhandled_exit:
	vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu->run->hw.hardware_exit_reason = exit_reason.full;
	return 0;
}

int tdx_handle_exit(struct kvm_vcpu *vcpu, fastpath_t exit_fastpath)
{
	int ret = __tdx_handle_exit(vcpu, exit_fastpath);

	/* Exit to user space when bus-lock was detected in the guest TD. */
	if (to_tdx(vcpu)->exit_reason.bus_lock_detected) {
		if (ret > 0)
			vcpu->run->exit_reason = KVM_EXIT_X86_BUS_LOCK;

		vcpu->run->flags |= KVM_RUN_X86_BUS_LOCK;
		return 0;
	}
	return ret;
}

void tdx_get_exit_info(struct kvm_vcpu *vcpu, u32 *reason,
		u64 *info1, u64 *info2, u32 *intr_info, u32 *error_code)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	*reason = tdx->exit_reason.full;

	*info1 = tdexit_exit_qual(vcpu);
	*info2 = tdexit_ext_exit_qual(vcpu);

	*intr_info = tdexit_intr_info(vcpu);
	*error_code = 0;
}

bool tdx_is_emulated_msr(u32 index, bool write)
{
	switch (index) {
	case MSR_IA32_UCODE_REV:
	case MSR_IA32_ARCH_CAPABILITIES:
	case MSR_IA32_POWER_CTL:
	case MSR_MTRRcap:
	case 0x200 ... 0x26f:
		/* IA32_MTRR_PHYS{BASE, MASK}, IA32_MTRR_FIX*_* */
	case MSR_IA32_CR_PAT:
	case MSR_MTRRdefType:
	case MSR_IA32_TSC_DEADLINE:
	case MSR_IA32_MISC_ENABLE:
	case MSR_KVM_STEAL_TIME:
	case MSR_KVM_POLL_CONTROL:
	case MSR_PLATFORM_INFO:
	case MSR_MISC_FEATURES_ENABLES:
	case MSR_IA32_MCG_CAP:
	case MSR_IA32_MCG_STATUS:
	case MSR_IA32_MCG_CTL:
	case MSR_IA32_MCG_EXT_CTL:
	case MSR_IA32_MC0_CTL ... MSR_IA32_MCx_MISC(28) - 1:
		/* MSR_IA32_MCx_{CTL, STATUS, ADDR, MISC} */
		return true;
	case APIC_BASE_MSR ... APIC_BASE_MSR + 0xff:
		/*
		 * x2APIC registers that are virtualized by the CPU can't be
		 * emulated, KVM doesn't have access to the virtual APIC page.
		 */
		switch (index) {
		case X2APIC_MSR(APIC_TASKPRI):
		case X2APIC_MSR(APIC_PROCPRI):
		case X2APIC_MSR(APIC_EOI):
		case X2APIC_MSR(APIC_ISR) ... X2APIC_MSR(APIC_ISR + APIC_ISR_NR):
		case X2APIC_MSR(APIC_TMR) ... X2APIC_MSR(APIC_TMR + APIC_ISR_NR):
		case X2APIC_MSR(APIC_IRR) ... X2APIC_MSR(APIC_IRR + APIC_ISR_NR):
			return false;
		default:
			return true;
		}
	case MSR_IA32_APICBASE:
	case MSR_EFER:
		return !write;
	case MSR_IA32_MCx_CTL2(0) ... MSR_IA32_MCx_CTL2(31):
		/*
		 * 0x280 - 0x29f: The x86 common code doesn't emulate MCx_CTL2.
		 * Refer to kvm_{get,set}_msr_common(),
		 * kvm_mtrr_{get, set}_msr(), and msr_mtrr_valid().
		 */
	default:
		return false;
	}
}

int tdx_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	if (msr->host_initiated || tdx_is_emulated_msr(msr->index, false))
		return kvm_get_msr_common(vcpu, msr);
	return 1;
}

int tdx_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	if (msr->host_initiated || tdx_is_emulated_msr(msr->index, true))
		return kvm_set_msr_common(vcpu, msr);
	return 1;
}

int tdx_smi_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	/* SMI isn't supported for TDX. */
	WARN_ON_ONCE(1);
	return false;
}

int tdx_enter_smm(struct kvm_vcpu *vcpu, char *smstate)
{
	/* smi_allowed() is always false for TDX as above. */
	WARN_ON_ONCE(1);
	return 0;
}

int tdx_leave_smm(struct kvm_vcpu *vcpu, const char *smstate)
{
	WARN_ON_ONCE(1);
	return 0;
}

void tdx_enable_smi_window(struct kvm_vcpu *vcpu)
{
	/* SMI isn't supported for TDX.  Silently discard SMI request. */
	WARN_ON_ONCE(1);
	vcpu->arch.smi_pending = false;
}

void tdx_set_virtual_apic_mode(struct kvm_vcpu *vcpu)
{
	/* Only x2APIC mode is supported for TD. */
	WARN_ON_ONCE(kvm_get_apic_mode(vcpu) != LAPIC_MODE_X2APIC);
}

int tdx_get_cpl(struct kvm_vcpu *vcpu)
{
	if (!is_debug_td(vcpu))
		return 0;

	/*
	 * tdx_get_cpl() is called before TDX vCPU is ready,
	 * just return for this case to avoid SEAMCALL failure
	 */
	if (!to_tdx(vcpu)->initialized)
		return 0;

	return VMX_AR_DPL(td_vmcs_read32(to_tdx(vcpu), GUEST_SS_AR_BYTES));
}

void tdx_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	struct vcpu_tdx *vcpu_tdx;
	unsigned long guest_owned_bits;

	if (!is_td_vcpu(vcpu))
		return;

	if (!is_debug_td(vcpu)) {
		/* RIP can be read by tracepoints, stuff a bogus value and
		 * avoid a WARN/error.
		 */
		if (reg == VCPU_REGS_RIP) {
			kvm_register_mark_available(vcpu, reg);
			vcpu->arch.regs[reg] = 0xdeadul << 48;
		}
		return;
	}

	vcpu_tdx = to_tdx(vcpu);
	kvm_register_mark_available(vcpu, reg);

	switch (reg) {
	case VCPU_REGS_RSP:
		vcpu->arch.regs[reg] =
			td_vmcs_read64(vcpu_tdx, GUEST_RSP);
		break;
	case VCPU_REGS_RIP:
		vcpu->arch.regs[reg] =
			td_vmcs_read64(vcpu_tdx, GUEST_RIP);
		break;
	case VCPU_EXREG_PDPTR:
		WARN_ONCE(1, "PAE paging should not used by TDX guest\n");
		break;
	case VCPU_EXREG_CR0:
		guest_owned_bits = vcpu->arch.cr0_guest_owned_bits;
		vcpu->arch.cr0 &= ~guest_owned_bits;
		vcpu->arch.cr0 |= (td_vmcs_read64(vcpu_tdx, GUEST_CR0) &
				   guest_owned_bits);
		break;
	case VCPU_EXREG_CR3:
		vcpu->arch.cr3 = td_vmcs_read64(vcpu_tdx, GUEST_CR3);
		break;
	case VCPU_EXREG_CR4:
		guest_owned_bits = vcpu->arch.cr4_guest_owned_bits;
		vcpu->arch.cr4 &= guest_owned_bits;
		vcpu->arch.cr4 |= (td_vmcs_read64(vcpu_tdx, GUEST_CR4) &
				   guest_owned_bits);
		break;
	case VCPU_REGS_RAX:
	case VCPU_REGS_RCX:
	case VCPU_REGS_RDX:
	case VCPU_REGS_RBX:
	case VCPU_REGS_RBP:
	case VCPU_REGS_RSI:
	case VCPU_REGS_RDI:
#ifdef CONFIG_X86_64
	case VCPU_REGS_R8 ... VCPU_REGS_R15:
#endif
		vcpu->arch.regs[reg] = td_gpr_read64(vcpu_tdx, reg);
		break;
	default:
		KVM_BUG_ON(1, vcpu->kvm);
		break;
	}
}

unsigned long tdx_get_rflags(struct kvm_vcpu *vcpu)
{
	if (!is_debug_td(vcpu))
		return 0;

	return td_vmcs_read64(to_tdx(vcpu), GUEST_RFLAGS);
}

unsigned long tdx_get_cr2(struct kvm_vcpu *vcpu)
{
	if (!is_debug_td(vcpu))
		return 0;

	vcpu->arch.cr2 = td_state_read64(to_tdx(vcpu), TD_VCPU_CR2);
	return vcpu->arch.cr2;
}

unsigned long tdx_get_xcr(struct kvm_vcpu *vcpu, int index)
{
	if (!is_debug_td(vcpu))
		return 0;

	switch (index) {
	case XCR_XFEATURE_ENABLED_MASK:
		vcpu->arch.xcr0 = td_state_read64(to_tdx(vcpu), TD_VCPU_XCR0);
		return vcpu->arch.xcr0;
	default:
		return 0;
	}
}

bool tdx_get_if_flag(struct kvm_vcpu *vcpu)
{
	if (!is_debug_td(vcpu))
		return 0;

	return td_vmcs_read64(to_tdx(vcpu), GUEST_RFLAGS) & X86_EFLAGS_IF;
}

void tdx_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (!is_debug_td(vcpu))
		return;

	/*
	 * set_rflags happens before KVM_TDX_INIT_VCPU can
	 * do nothing because the guest has not been initialized.
	 * Just return for this case.
	 */
	if (!tdx->initialized)
		return;

	td_vmcs_write64(tdx, GUEST_RFLAGS, rflags);
}

u64 tdx_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	if (!is_debug_td(vcpu))
		return 0;

	return td_vmcs_read64(to_tdx(vcpu), kvm_vmx_segment_fields[seg].base);
}

void tdx_get_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	u32 ar;

	if (!is_debug_td(vcpu)) {
		memset(var, 0, sizeof(*var));
		return;
	}

	var->base = td_vmcs_read64(tdx, kvm_vmx_segment_fields[seg].base);
	var->limit = td_vmcs_read32(tdx, kvm_vmx_segment_fields[seg].limit);
	var->selector = td_vmcs_read16(tdx, kvm_vmx_segment_fields[seg].selector);
	ar = td_vmcs_read32(tdx, kvm_vmx_segment_fields[seg].ar_bytes);

	vmx_decode_ar_bytes(var, ar);
}


void tdx_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	u32 ar;

	if (KVM_BUG_ON(!is_debug_td(vcpu), vcpu->kvm))
		return;

	ar = td_vmcs_read32(to_tdx(vcpu),
			    kvm_vmx_segment_fields[VCPU_SREG_CS].ar_bytes);
	*db = (ar >> 14) & 1;
	*l = (ar >> 13) & 1;
}

void tdx_get_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	if (!is_debug_td(vcpu)) {
		memset(dt, 0, sizeof(*dt));
		return;
	}

	dt->size = td_vmcs_read32(to_tdx(vcpu), GUEST_IDTR_LIMIT);
	dt->address = td_vmcs_read64(to_tdx(vcpu), GUEST_IDTR_BASE);
}

void tdx_set_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	if (!is_debug_td(vcpu))
		return;

	td_vmcs_write32(to_tdx(vcpu), GUEST_IDTR_LIMIT,  dt->size);
	td_vmcs_write64(to_tdx(vcpu), GUEST_IDTR_BASE, dt->address);
}

void tdx_get_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	if (!is_debug_td(vcpu)) {
		memset(dt, 0, sizeof(*dt));
		return;
	}

	dt->size = td_vmcs_read32(to_tdx(vcpu), GUEST_GDTR_LIMIT);
	dt->address = td_vmcs_read64(to_tdx(vcpu), GUEST_GDTR_BASE);
}

void tdx_set_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	if (!is_debug_td(vcpu))
		return;

	td_vmcs_write32(to_tdx(vcpu), GUEST_GDTR_LIMIT, dt->size);
	td_vmcs_write64(to_tdx(vcpu), GUEST_GDTR_BASE, dt->address);
}
void tdx_queue_exception(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx;
	unsigned int nr;
	bool has_error_code;
	u32 error_code;
	u32 intr_info;

	if (KVM_BUG_ON(!is_debug_td(vcpu), vcpu->kvm))
		return;

	tdx = to_tdx(vcpu);
	nr = vcpu->arch.exception.nr;
	has_error_code = vcpu->arch.exception.has_error_code;
	error_code = vcpu->arch.exception.error_code;
	intr_info = nr | INTR_INFO_VALID_MASK;

	/*
	 * Emulate BP injection due to
	 * TDX doesn't support exception injection
	 */
	if (nr == BP_VECTOR)
		return tdx_emulate_inject_bp_begin(vcpu);

	kvm_deliver_exception_payload(vcpu);

	if (has_error_code) {
		td_vmcs_write32(tdx, VM_ENTRY_EXCEPTION_ERROR_CODE,
				error_code);
		intr_info |= INTR_INFO_DELIVER_CODE_MASK;
	}

	if (kvm_exception_is_soft(nr)) {
		td_vmcs_write32(tdx, VM_ENTRY_INSTRUCTION_LEN,
				vcpu->arch.event_exit_inst_len);
		intr_info |= INTR_TYPE_SOFT_EXCEPTION;
	} else {
		intr_info |= INTR_TYPE_HARD_EXCEPTION;
	}

	pr_warn_once("Exception injection is not supported by TDX.\n");
	/* td_vmcs_write32(tdx, VM_ENTRY_INTR_INFO_FIELD, intr_info);*/
}

void tdx_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	if (!is_debug_td(vcpu))
		return;

	vmx_set_interrupt_shadow(vcpu, mask);
}

int tdx_skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	unsigned long rip, orig_rip;

	if (!is_debug_td(vcpu))
		return 0;

	if (is_guest_mode(vcpu)) {
		/*
		 * Refer vmx_update_emulated_instruction(vcpu)
		 * for more information.
		 */
		kvm_pr_unimpl("No nested support to TDX guest\n");
		return 0;
	}

	/*
	 * Refer skip_emulated_instruction() in vmx.c for more information
	 * about this checking
	 */
	if (static_cpu_has(X86_FEATURE_HYPERVISOR) &&
	    to_tdx(vcpu)->exit_reason.basic == EXIT_REASON_EPT_MISCONFIG) {
		kvm_pr_unimpl("Failed to skip emulated instruction\n");
		return 0;
	}

	orig_rip = kvm_rip_read(vcpu);
	rip = orig_rip + td_vmcs_read32(to_tdx(vcpu), VM_EXIT_INSTRUCTION_LEN);
#ifdef CONFIG_X86_64
	rip = vmx_mask_out_guest_rip(vcpu, orig_rip, rip);
#endif
	kvm_rip_write(vcpu, rip);

	tdx_set_interrupt_shadow(vcpu, 0);

	return 1;
}

void tdx_load_guest_debug_regs(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx_vcpu = to_tdx(vcpu);

	if (!is_debug_td(vcpu))
		return;

	td_state_write64(tdx_vcpu, TD_VCPU_DR0, vcpu->arch.eff_db[0]);
	td_state_write64(tdx_vcpu, TD_VCPU_DR1, vcpu->arch.eff_db[1]);
	td_state_write64(tdx_vcpu, TD_VCPU_DR2, vcpu->arch.eff_db[2]);
	td_state_write64(tdx_vcpu, TD_VCPU_DR3, vcpu->arch.eff_db[3]);

	if (tdx_vcpu->dr6 != vcpu->arch.dr6) {
		td_state_write64(tdx_vcpu, TD_VCPU_DR6, vcpu->arch.dr6);
		tdx_vcpu->dr6 = vcpu->arch.dr6;
	}

	/*
	 * TDX module handle the DR context switch so we don't
	 * need to update DR every time.
	 */
	vcpu->arch.switch_db_regs &= ~KVM_DEBUGREG_BP_ENABLED;
}

void tdx_sync_dirty_debug_regs(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx_vcpu = to_tdx(vcpu);

	if (!is_debug_td(vcpu))
		return;

	vcpu->arch.db[0] = td_state_read64(tdx_vcpu, TD_VCPU_DR0);
	vcpu->arch.db[1] = td_state_read64(tdx_vcpu, TD_VCPU_DR1);
	vcpu->arch.db[2] = td_state_read64(tdx_vcpu, TD_VCPU_DR2);
	vcpu->arch.db[3] = td_state_read64(tdx_vcpu, TD_VCPU_DR3);

	vcpu->arch.dr6 = td_state_read64(tdx_vcpu, TD_VCPU_DR6);
	tdx_vcpu->dr6 = vcpu->arch.dr6;

	vcpu->arch.dr7 = td_vmcs_read64(to_tdx(vcpu), GUEST_DR7);

	vcpu->arch.switch_db_regs &= ~KVM_DEBUGREG_WONT_EXIT;
	td_vmcs_setbit32(tdx_vcpu,
			 CPU_BASED_VM_EXEC_CONTROL,
			 CPU_BASED_MOV_DR_EXITING);
}

void tdx_update_exception_bitmap(struct kvm_vcpu *vcpu)
{
	u32 eb;
	u32 new_eb;
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (!is_debug_td(vcpu) || !tdx->initialized)
		return;

	eb = td_vmcs_read32(tdx, EXCEPTION_BITMAP);
	new_eb = eb & ~((1u << DB_VECTOR) | (1u << BP_VECTOR));

	/*
	 * Why not always intercept #DB for TD guest:
	 * TDX module doesn't supprt #DB injection now so we
	 * only intercept #DB when KVM's guest debug feature
	 * is using DR register to avoid break DR feature
	 * inside guest.
	 */
	if (tdx_kvm_use_dr(vcpu) || tdx->emulate_inject_bp)
		new_eb |= (1u << DB_VECTOR);

	if (vcpu->guest_debug & KVM_GUESTDBG_USE_SW_BP)
		new_eb |= (1u << BP_VECTOR);

	/*
	 * Notice for nested support:
	 * No nested supporting due to TDX module doesn't
	 * support it so far, we should consult
	 * vmx_update_exception_bitmap() when nested support
	 * become ready in future.
	 */

	if (new_eb != eb)
		td_vmcs_write32(tdx, EXCEPTION_BITMAP, new_eb);
}

int tdx_dev_ioctl(void __user *argp)
{
	struct kvm_tdx_capabilities __user *user_caps;
	struct kvm_tdx_capabilities caps;
	struct kvm_tdx_cmd cmd;

	BUILD_BUG_ON(sizeof(struct kvm_tdx_cpuid_config) !=
		     sizeof(struct tdx_cpuid_config));

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;
	if (cmd.flags || cmd.error || cmd.unused)
		return -EINVAL;
	/*
	 * Currently only KVM_TDX_CAPABILITIES is defined for system-scoped
	 * mem_enc_ioctl().
	 */
	if (cmd.id != KVM_TDX_CAPABILITIES)
		return -EINVAL;

	user_caps = (void __user *)cmd.data;
	if (copy_from_user(&caps, user_caps, sizeof(caps)))
		return -EFAULT;

	if (caps.nr_cpuid_configs < tdx_caps.nr_cpuid_configs)
		return -E2BIG;

	caps = (struct kvm_tdx_capabilities) {
		.attrs_fixed0 = tdx_caps.attrs_fixed0,
		.attrs_fixed1 = tdx_caps.attrs_fixed1,
		.xfam_fixed0 = tdx_caps.xfam_fixed0,
		.xfam_fixed1 = tdx_caps.xfam_fixed1,
		.nr_cpuid_configs = tdx_caps.nr_cpuid_configs,
		.padding = 0,
	};

	if (copy_to_user(user_caps, &caps, sizeof(caps)))
		return -EFAULT;
	if (copy_to_user(user_caps->cpuid_configs, &tdx_caps.cpuid_configs,
			 tdx_caps.nr_cpuid_configs *
			 sizeof(struct tdx_cpuid_config)))
		return -EFAULT;

	return 0;
}

/*
 * cpuid entry lookup in TDX cpuid config way.
 * The difference is how to specify index(subleaves).
 * Specify index to TDX_CPUID_NO_SUBLEAF for CPUID leaf with no-subleaves.
 */
static const struct kvm_cpuid_entry2 *tdx_find_cpuid_entry(
	const struct kvm_cpuid2 *cpuid, u32 function, u32 index)
{
	int i;


	/* In TDX CPU CONFIG, TDX_CPUID_NO_SUBLEAF means index = 0. */
	if (index == TDX_CPUID_NO_SUBLEAF)
		index = 0;

	for (i = 0; i < cpuid->nent; i++) {
		const struct kvm_cpuid_entry2 *e = &cpuid->entries[i];

		if (e->function == function &&
		    (e->index == index ||
		     !(e->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX)))
			return e;
	}
	return NULL;
}

static int setup_tdparams(struct kvm *kvm, struct td_params *td_params,
			struct kvm_tdx_init_vm *init_vm)
{
	const struct kvm_cpuid2 *cpuid = &init_vm->cpuid;
	const struct kvm_cpuid_entry2 *entry;
	u64 guest_supported_xcr0;
	u64 guest_supported_xss;
	int max_pa;
	int i;

	td_params->max_vcpus = init_vm->max_vcpus;
	td_params->attributes = init_vm->attributes;

	for (i = 0; i < tdx_caps.nr_cpuid_configs; i++) {
		const struct tdx_cpuid_config *config = &tdx_caps.cpuid_configs[i];
		const struct kvm_cpuid_entry2 *entry =
			tdx_find_cpuid_entry(cpuid, config->leaf, config->sub_leaf);
		struct tdx_cpuid_value *value = &td_params->cpuid_values[i];

		if (!entry)
			continue;

		value->eax = entry->eax & config->eax;
		value->ebx = entry->ebx & config->ebx;
		value->ecx = entry->ecx & config->ecx;
		value->edx = entry->edx & config->edx;
	}

	max_pa = 36;
	entry = tdx_find_cpuid_entry(cpuid, 0x80000008, 0);
	if (entry)
		max_pa = entry->eax & 0xff;

	td_params->eptp_controls = VMX_EPTP_MT_WB;
	/*
	 * No CPU supports 4-level && max_pa > 48.
	 * "5-level paging and 5-level EPT" section 4.1 4-level EPT
	 * "4-level EPT is limited to translating 48-bit guest-physical
	 *  addresses."
	 * cpu_has_vmx_ept_5levels() check is just in case.
	 */
	if (cpu_has_vmx_ept_5levels() && max_pa > 48) {
		td_params->eptp_controls |= VMX_EPTP_PWL_5;
		td_params->exec_controls |= TDX_EXEC_CONTROL_MAX_GPAW;
	} else {
		td_params->eptp_controls |= VMX_EPTP_PWL_4;
	}

	/* Setup td_params.xfam */
	entry = tdx_find_cpuid_entry(cpuid, 0xd, 0);
	if (entry)
		guest_supported_xcr0 = (entry->eax | ((u64)entry->edx << 32));
	else
		guest_supported_xcr0 = 0;
	guest_supported_xcr0 &= kvm_caps.supported_xcr0;

	entry = tdx_find_cpuid_entry(cpuid, 0xd, 1);
	if (entry)
		guest_supported_xss = (entry->ecx | ((u64)entry->edx << 32));
	else
		guest_supported_xss = 0;

	/* PT can be exposed to TD guest regardless of KVM's XSS support */
	guest_supported_xss &=
		(kvm_caps.supported_xss | XFEATURE_MASK_PT | TDX_TD_XFAM_CET);

	td_params->xfam = guest_supported_xcr0 | guest_supported_xss;
	if (td_params->xfam & XFEATURE_MASK_LBR) {
		/*
		 * TODO: once KVM supports LBR(save/restore LBR related
		 * registers around TDENTER), remove this guard.
		 */
		pr_warn("TD doesn't support LBR yet. KVM needs to save/restore "
			"IA32_LBR_DEPTH properly.\n");
		return -EOPNOTSUPP;
	}

	td_params->tsc_frequency =
		TDX_TSC_KHZ_TO_25MHZ(kvm->arch.default_tsc_khz);

#define MEMCPY_SAME_SIZE(dst, src)				\
	do {							\
		BUILD_BUG_ON(sizeof(dst) != sizeof(src));	\
		memcpy((dst), (src), sizeof(dst));		\
	} while (0)

	MEMCPY_SAME_SIZE(td_params->mrconfigid, init_vm->mrconfigid);
	MEMCPY_SAME_SIZE(td_params->mrowner, init_vm->mrowner);
	MEMCPY_SAME_SIZE(td_params->mrownerconfig, init_vm->mrownerconfig);

	/* TD guest with migration support doesn't support large page yet */
	if (td_params->attributes & TDX_TD_ATTRIBUTE_MIG)
		kvm->arch.tdp_max_page_level = PG_LEVEL_4K;

	return 0;
}

int tdx_td_post_init(struct kvm_tdx *kvm_tdx)
{
	kvm_tdx->tsc_offset = td_tdcs_exec_read64(kvm_tdx, TD_TDCS_EXEC_TSC_OFFSET);
	kvm_tdx->initialized = true;

	return 0;
}

static int tdx_td_init(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_tdx_init_vm *init_vm = NULL;
	struct td_params *td_params = NULL;
	struct tdx_module_output out;
	int ret;
	u64 err;

	BUILD_BUG_ON(sizeof(*init_vm) != 16 * 1024);
	BUILD_BUG_ON((sizeof(*init_vm) - offsetof(typeof(*init_vm), entries)) /
		     sizeof(init_vm->entries[0]) < KVM_MAX_CPUID_ENTRIES);
	BUILD_BUG_ON(sizeof(struct td_params) != 1024);

	if (kvm_tdx->initialized)
		return -EINVAL;

	if (cmd->flags && cmd->flags != KVM_TDX_INIT_VM_F_POST_INIT)
		return -EINVAL;

	init_vm = kzalloc(sizeof(*init_vm), GFP_KERNEL);
	if (copy_from_user(init_vm, (void __user *)cmd->data, sizeof(*init_vm))) {
		ret = -EFAULT;
		goto out;
	}

	if (init_vm->max_vcpus > KVM_MAX_VCPUS) {
		ret = -EINVAL;
		goto out;
	}

	td_params = kzalloc(sizeof(struct td_params), GFP_KERNEL);
	if (!td_params) {
		ret = -ENOMEM;
		goto out;
	}

	ret = setup_tdparams(kvm, td_params, init_vm);
	if (ret)
		goto out;


	kvm_tdx->attributes = td_params->attributes;
	kvm_tdx->xfam = td_params->xfam;
	kvm_tdx->tsc_khz = TDX_TSC_25MHZ_TO_KHZ(td_params->tsc_frequency);
	kvm->max_vcpus = td_params->max_vcpus;

	if (td_params->exec_controls & TDX_EXEC_CONTROL_MAX_GPAW)
		kvm->arch.gfn_shared_mask = gpa_to_gfn(BIT_ULL(51));
	else
		kvm->arch.gfn_shared_mask = gpa_to_gfn(BIT_ULL(47));

	if (cmd->flags != KVM_TDX_INIT_VM_F_POST_INIT) {
		err = tdh_mng_init(kvm_tdx->tdr.pa, __pa(td_params), &out);
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_MNG_INIT, err, &out);
			ret = -EIO;
			goto out;
		}
		tdx_td_post_init(kvm_tdx);
	}
out:
	/* kfree() accepts NULL. */
	kfree(init_vm);
	kfree(td_params);
	return ret;
}

void tdx_flush_tlb(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct kvm_mmu *mmu = vcpu->arch.mmu;
	u64 root_hpa = mmu->root.hpa;

	/* Flush the shared EPTP, if it's valid. */
	if (VALID_PAGE(root_hpa))
		ept_sync_context(construct_eptp(vcpu, root_hpa,
						mmu->root_role.level));

	/*
	 * See tdx_track().  Wait for tlb shootdown initiater to finish
	 * TDH_MEM_TRACK() so that TLB is flushed on the next TDENTER.
	 */
	while (atomic_read(&kvm_tdx->tdh_mem_track))
		cpu_relax();
}

#define TDX_SEPT_PFERR	PFERR_WRITE_MASK

static int tdx_sept_prealloc(struct kvm *kvm,
			     uint64_t source_addr,
			     uint64_t gpa,
			     uint64_t nr_pages,
			     bool need_measure)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_vcpu *vcpu;
	struct page *page;
	kvm_pfn_t pfn;
	int idx, ret = 0;

	/* The BSP vCPU must be created before initializing memory regions. */
	if (!atomic_read(&kvm->online_vcpus))
		return -EINVAL;

	/* Sanity check */
	if (!IS_ALIGNED(source_addr, PAGE_SIZE) ||
	    !IS_ALIGNED(gpa, PAGE_SIZE) ||
	    !nr_pages ||
	    gpa + (nr_pages << PAGE_SHIFT) <= gpa ||
	    !kvm_is_private_gpa(kvm, gpa) ||
	    !kvm_is_private_gpa(kvm, gpa + (nr_pages << PAGE_SHIFT)))
		return -EINVAL;

	vcpu = kvm_get_vcpu(kvm, 0);
	if (mutex_lock_killable(&vcpu->mutex))
		return -EINTR;

	vcpu_load(vcpu);
	idx = srcu_read_lock(&kvm->srcu);

	kvm_mmu_reload(vcpu);

	while (nr_pages) {
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}

		if (need_resched())
			cond_resched();


		/* Pin the source page. */
		ret = get_user_pages_fast(source_addr, 1, 0, &page);
		if (ret < 0)
			break;
		if (ret != 1) {
			ret = -ENOMEM;
			break;
		}

		kvm_tdx->source_pa = pfn_to_hpa(page_to_pfn(page));
		if (need_measure)
			kvm_tdx->source_pa |= KVM_TDX_MEASURE_MEMORY_REGION;

		pfn = kvm_mmu_map_tdp_page(vcpu, gpa, TDX_SEPT_PFERR,
					   PG_LEVEL_4K);
		if (is_error_noslot_pfn(pfn) || kvm->vm_bugged)
			ret = -EFAULT;
		else
			ret = 0;

		put_page(page);
		if (ret)
			break;

		source_addr += PAGE_SIZE;
		gpa += PAGE_SIZE;
		nr_pages--;
	}

	srcu_read_unlock(&kvm->srcu, idx);
	vcpu_put(vcpu);

	mutex_unlock(&vcpu->mutex);

	return ret;
}

static int tdx_init_mem_region(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx_init_mem_region region;
	int ret = 0;

	if (cmd->flags & ~KVM_TDX_MEASURE_MEMORY_REGION)
		return -EINVAL;

	if (copy_from_user(&region, (void __user *)cmd->data, sizeof(region)))
		return -EFAULT;

	ret = tdx_sept_prealloc(kvm, region.source_addr,
				region.gpa, region.nr_pages,
				cmd->flags & KVM_TDX_MEASURE_MEMORY_REGION);

	if (copy_to_user((void __user *)cmd->data, &region, sizeof(region)))
		ret = -EFAULT;

	return ret;
}

int tdx_init_sept(struct kvm *kvm)
{
	struct kvm_memory_slot *memslot;
	struct kvm_memslots *slots = kvm_memslots(kvm);
	int bkt, ret = 0;

	kvm_for_each_memslot(memslot, bkt, slots) {
		ret = tdx_sept_prealloc(kvm, memslot->userspace_addr,
					gfn_to_gpa(memslot->base_gfn),
					memslot->npages, false);
		if (ret) {
			pr_err("%s: failed\n", __func__);
			return ret;
		}
	}

	return ret;
}

static int tdx_td_finalizemr(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	u64 err;

	if (!kvm_tdx->initialized || is_td_finalized(kvm_tdx))
		return -EINVAL;

	err = tdh_mr_finalize(kvm_tdx->tdr.pa);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MR_FINALIZE, err, NULL);
		return -EIO;
	}

	(void)tdh_mem_track(to_kvm_tdx(kvm)->tdr.pa);

	kvm_tdx->finalized = true;
	return 0;
}

static void tdx_binding_slot_bound_set_info(struct tdx_binding_slot *slot,
					    uint64_t handle,
					    uint64_t uuid0,
					    uint64_t uuid1,
					    uint64_t uuid2,
					    uint64_t uuid3)
{
	slot->handle = handle;
	memcpy(&slot->uuid[0], &uuid0, sizeof(uint64_t));
	memcpy(&slot->uuid[8], &uuid1, sizeof(uint64_t));
	memcpy(&slot->uuid[16], &uuid2, sizeof(uint64_t));
	memcpy(&slot->uuid[24], &uuid3, sizeof(uint64_t));
}

static int tdx_servtd_do_bind(struct kvm_tdx *usertd_tdx,
			      struct kvm_tdx *servtd_tdx,
			      struct kvm_tdx_servtd *servtd,
			      struct tdx_binding_slot *slot)
{
	struct tdx_module_output out;
	uint16_t slot_id = servtd->type;
	u64 err;

	/*TODO: check max binding_slots_id from rdall */
	err = tdh_servtd_bind(servtd_tdx->tdr.pa,
				usertd_tdx->tdr.pa,
				slot_id,
				servtd->attr,
				servtd->type,
				&out);
	if (KVM_BUG_ON(err, &usertd_tdx->kvm)) {
		pr_tdx_error(TDH_SERVTD_BIND, err, &out);
		return -EIO;
	}

	tdx_binding_slot_set_status(slot, TDX_BINDING_SLOT_STATUS_BOUND);
	tdx_binding_slot_bound_set_info(slot, out.rcx, out.r10,
					out.r11, out.r12, out.r13);

	return 0;
}

static int tdx_servtd_add_binding_slot(struct kvm_tdx *servtd_tdx,
				       struct tdx_binding_slot *slot)
{
	int i, ret = 0;

	spin_lock(&servtd_tdx->binding_slot_lock);
	for (i = 0; i < SERVTD_SLOTS_MAX; i++) {
		if (!servtd_tdx->usertd_binding_slots[i])
			break;
	}

	/*
	 * Unlikely. The arrary should be big enough to have an
	 * entry for each TD on the same host to add its binding
	 * slot.
	 */
	if (i == SERVTD_SLOTS_MAX) {
		ret = -EBUSY;
		goto out_unlock;
	}

	servtd_tdx->usertd_binding_slots[i] = slot;
	slot->servtd_tdx = servtd_tdx;
	slot->req_id = i;
out_unlock:
	spin_unlock(&servtd_tdx->binding_slot_lock);
	return ret;
}

static int tdx_servtd_prebind(struct kvm *usertd_kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *usertd_tdx = to_kvm_tdx(usertd_kvm);
	struct kvm_tdx_servtd servtd;
	struct tdx_binding_slot *slot;
	struct page *hash_page;
	uint16_t slot_id;
	uint64_t err;

	if (copy_from_user(&servtd, (void __user *)cmd->data,
			   sizeof(struct kvm_tdx_servtd)))
		return -EFAULT;

	if (cmd->flags ||
	    servtd.version != KVM_TDX_SERVTD_VERSION ||
	    servtd.type >= KVM_TDX_SERVTD_TYPE_MAX)
		return -EINVAL;

	slot_id = servtd.type;
	hash_page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!hash_page)
		return -ENOMEM;

	memcpy(page_to_virt(hash_page),
	       servtd.hash, KVM_TDX_SERVTD_HASH_SIZE);

	slot = &usertd_tdx->binding_slots[slot_id];
	tdx_binding_slot_set_status(slot, TDX_BINDING_SLOT_STATUS_INIT);

	err = tdh_servtd_prebind(usertd_tdx->tdr.pa,
				 page_to_phys(hash_page),
				 slot_id,
				 servtd.attr,
				 servtd.type);
	if (err) {
		pr_warn("failed to prebind servtd, err=%llx\n", err);
		return -EIO;
	}
	tdx_binding_slot_set_status(slot, TDX_BINDING_SLOT_STATUS_PREBOUND);

	__free_page(hash_page);
	if (copy_to_user((void __user *)cmd->data,
			 &servtd, sizeof(struct kvm_tdx_servtd)))
		return -EFAULT;

	return 0;
}

static int tdx_servtd_bind(struct kvm *usertd_kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm *servtd_kvm;
	struct kvm_tdx *servtd_tdx;
	struct kvm_tdx *usertd_tdx = to_kvm_tdx(usertd_kvm);
	struct kvm_tdx_servtd servtd;
	struct tdx_binding_slot *slot;
	uint16_t slot_id;
	int ret;

	if (copy_from_user(&servtd, (void __user *)cmd->data,
			   sizeof(struct kvm_tdx_servtd)))
		return -EFAULT;

	if (cmd->flags ||
	    servtd.version != KVM_TDX_SERVTD_VERSION ||
	    servtd.type >= KVM_TDX_SERVTD_TYPE_MAX) {
		return -EINVAL;
	}

	servtd_kvm = kvm_get_target_kvm(servtd.pid);
	if (!servtd_kvm) {
		pr_err("%s: servtd not found, pid=%d\n", __func__, servtd.pid);
		return -ENOENT;
	}
	servtd_tdx = to_kvm_tdx(servtd_kvm);

	slot_id = servtd.type;
	slot = &usertd_tdx->binding_slots[slot_id];

	ret = tdx_servtd_do_bind(usertd_tdx, servtd_tdx, &servtd, slot);
	if (ret)
		return ret;

	ret = tdx_servtd_add_binding_slot(servtd_tdx, slot);

	return ret;
}

static void tdx_notify_servtd(struct kvm_tdx *tdx)
{
	struct kvm *kvm;
	struct kvm_vcpu *vcpu;
	unsigned long i;

	kvm = &tdx->kvm;
	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (vcpu->arch.mp_state == KVM_MP_STATE_HALTED) {
			vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
			kvm_vcpu_kick(vcpu);
			printk("%s: wake up on vcpu\n", __func__);
		}
	}
}

static int tdx_migration_info_set(struct kvm_tdx_mig_info *info,
				  struct tdx_binding_slot *slot)
{
	struct kvm_tdx *servtd_tdx = slot->servtd_tdx;

	if (tdx_binding_slot_get_status(slot) !=
	    TDX_BINDING_SLOT_STATUS_BOUND) {
		pr_err("%s err: servtd not bound\n", __func__);
		return -EINVAL;
	}

	slot->vsock_port = info->vsock_port;
	slot->is_src = info->is_src;
	tdx_binding_slot_set_status(slot, TDX_BINDING_SLOT_STATUS_PREMIG_WAIT);
	tdx_notify_servtd(servtd_tdx);
	return 0;
}

static int tdx_migration_info(struct kvm *kvm,
			      struct kvm_tdx_cmd *cmd,
			      bool set)
{
	struct kvm_tdx *servtd_tdx;
	struct kvm_tdx *usertd_tdx = to_kvm_tdx(kvm);
	struct kvm_tdx_mig_info info;
	struct tdx_binding_slot *slot;


	if (copy_from_user(&info, (void __user *)cmd->data,
			   sizeof(struct kvm_tdx_mig_info)))
		return -EFAULT;

	if (cmd->flags ||
	    info.version != KVM_TDX_MIG_INFO_VERSION)
		return -EINVAL;

	slot = &usertd_tdx->binding_slots[KVM_TDX_SERVTD_TYPE_MIGTD];
	servtd_tdx = slot->servtd_tdx;
	if (!servtd_tdx)
		return -ENOENT;

	spin_lock(&servtd_tdx->binding_slot_lock);
	if (set && tdx_migration_info_set(&info, slot)) {
		spin_unlock(&servtd_tdx->binding_slot_lock);
		return -EINVAL;
	}

	/*
	 * For KVM_TDX_GET_MIGRATION_INFO, only status needs to be copied to
	 * userspace currently.
	 * For KVM_TDX_SET_MIGRATION_INFO, after setting the info from
	 * userspace, also updates to the userspace about the status.
	 */
	info.status = tdx_binding_slot_get_status(slot);
	spin_unlock(&servtd_tdx->binding_slot_lock);

	if (copy_to_user((void __user *)cmd->data, &info,
			 sizeof(struct kvm_tdx_mig_info)))
		return -EFAULT;

	return 0;
}

int tdx_vm_ioctl(struct kvm *kvm, void __user *argp)
{
	struct kvm_tdx_cmd tdx_cmd;
	int r;

	if (copy_from_user(&tdx_cmd, argp, sizeof(struct kvm_tdx_cmd)))
		return -EFAULT;
	if (tdx_cmd.error || tdx_cmd.unused)
		return -EINVAL;

	mutex_lock(&kvm->lock);

	switch (tdx_cmd.id) {
	case KVM_TDX_INIT_VM:
		r = tdx_td_init(kvm, &tdx_cmd);
		break;
	case KVM_TDX_INIT_MEM_REGION:
		r = tdx_init_mem_region(kvm, &tdx_cmd);
		break;
	case KVM_TDX_FINALIZE_VM:
		r = tdx_td_finalizemr(kvm);
		break;
	case KVM_TDX_SERVTD_PREBIND:
		r = tdx_servtd_prebind(kvm, &tdx_cmd);
		break;
	case KVM_TDX_SERVTD_BIND:
		r = tdx_servtd_bind(kvm, &tdx_cmd);
		break;
	case KVM_TDX_GET_MIGRATION_INFO:
		r = tdx_migration_info(kvm, &tdx_cmd, false);
		break;
	case KVM_TDX_SET_MIGRATION_INFO:
		r = tdx_migration_info(kvm, &tdx_cmd, true);
		break;
	default:
		r = -EINVAL;
		goto out;
	}

	if (copy_to_user(argp, &tdx_cmd, sizeof(struct kvm_tdx_cmd)))
		r = -EFAULT;

out:
	mutex_unlock(&kvm->lock);
	return r;
}

void tdx_vcpu_posted_intr_setup(struct vcpu_tdx *tdx)
{
	td_vmcs_write16(tdx, POSTED_INTR_NV, POSTED_INTR_VECTOR);
	td_vmcs_write64(tdx, POSTED_INTR_DESC_ADDR, __pa(&tdx->pi_desc));
	td_vmcs_setbit32(tdx, PIN_BASED_VM_EXEC_CONTROL, PIN_BASED_POSTED_INTR);
}

int tdx_vcpu_ioctl(struct kvm_vcpu *vcpu, void __user *argp)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct kvm_tdx_cmd cmd;
	u64 err;

	if (tdx->initialized)
		return -EINVAL;

	if (!kvm_tdx->initialized || is_td_finalized(kvm_tdx))
		return -EINVAL;

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;

	if (cmd.error || cmd.unused)
		return -EINVAL;
	if (cmd.flags || cmd.id != KVM_TDX_INIT_VCPU)
		return -EINVAL;

	err = tdh_vp_init(tdx->tdvpr.pa, cmd.data);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_VP_INIT, err, NULL);
		return -EIO;
	}

	tdx_vcpu_posted_intr_setup(tdx);

	/*
	 * Check if VM_{ENTRY, EXIT}_LOAD_IA32_PERF_GLOBAL_CTRL are set in case
	 * of a TDX module bug. It is required to monitor TD with PMU events.
	 * Note that these two bits are read-only even for debug TD.
	 */
	if ((td_profile_state == TD_PROFILE_NONE) &&
	    (kvm_tdx->attributes & TDX_TD_ATTRIBUTE_DEBUG) &&
	    !(kvm_tdx->attributes & TDX_TD_ATTRIBUTE_PERFMON))	{
		u32 exit, entry;

		exit = td_vmcs_read32(tdx, VM_EXIT_CONTROLS);
		entry = td_vmcs_read32(tdx, VM_ENTRY_CONTROLS);

		if ((exit & VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL) &&
		    (entry & VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL))
			td_profile_state = TD_PROFILE_ENABLE;
		else {
			pr_warn_once("Cannot monitor TD with PMU events\n");
			td_profile_state = TD_PROFILE_DISABLE;
		}
	}

	if (vcpu->kvm->arch.bus_lock_detection_enabled)
		td_vmcs_setbit32(tdx,
				 SECONDARY_VM_EXEC_CONTROL,
				 SECONDARY_EXEC_BUS_LOCK_DETECTION);

	if (is_debug_td(vcpu)) {
		td_vmcs_setbit32(tdx,
				 CPU_BASED_VM_EXEC_CONTROL,
				 CPU_BASED_MOV_DR_EXITING);
	}

	tdx->initialized = true;
	return 0;
}

static void tdx_guest_pmi_handler(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_tdx  *tdx;

	vcpu = kvm_get_running_vcpu();

	WARN_ON(!vcpu || !is_td_vcpu(vcpu));

	tdx = to_kvm_tdx(vcpu->kvm);
	WARN_ON(!(tdx->attributes & TDX_TD_ATTRIBUTE_PERFMON));

	kvm_make_request(KVM_REQ_PMI, vcpu);
}

bool is_sys_rd_supported(void)
{
	return !!tdx_caps.sys_rd;
}

int tdx_module_setup(void)
{
	const struct tdsysinfo_struct *tdsysinfo;
	struct tdx_module_output out;
	int ret = 0;
	u64 err;

	BUILD_BUG_ON(sizeof(*tdsysinfo) != 1024);
	BUILD_BUG_ON(TDX_MAX_NR_CPUID_CONFIGS != 37);

	ret = tdx_init();
	if (ret) {
		pr_info("Failed to initialize TDX module.\n");
		return ret;
	}

	tdx_global_keyid = tdx_get_global_keyid();

	tdsysinfo = tdx_get_sysinfo();
	if (tdsysinfo->num_cpuid_config > TDX_MAX_NR_CPUID_CONFIGS)
		return -EIO;

	tdx_caps = (struct tdx_capabilities) {
		.tdcs_nr_pages = tdsysinfo->tdcs_base_size / PAGE_SIZE,
		/*
		 * TDVPS = TDVPR(4K page) + TDVPX(multiple 4K pages).
		 * -1 for TDVPR.
		 */
		.tdvpx_nr_pages = tdsysinfo->tdvps_base_size / PAGE_SIZE - 1,
		.attrs_fixed0 = tdsysinfo->attributes_fixed0,
		.attrs_fixed1 = tdsysinfo->attributes_fixed1,
		.xfam_fixed0 =	tdsysinfo->xfam_fixed0,
		.xfam_fixed1 = tdsysinfo->xfam_fixed1,
		.nr_cpuid_configs = tdsysinfo->num_cpuid_config,
		.sys_rd = tdsysinfo->sys_rd,
	};

	err = tdh_sys_rd(TDX_MD_FID_SERVTD_MAX_SERVTDS, &out);
	/*
	 * If error happens, it isn't critical and no need to fail the entire
	 * tdx setup. Only servtd binding (which is optional) won't be allowed
	 * later, as we keep max_servtds be 0.
	 */
	if (err == TDX_SUCCESS) {
		tdx_caps.max_servtds = out.r8;
		if (KVM_TDX_SERVTD_TYPE_MAX > tdx_caps.max_servtds) {
			pr_warn("TDX support less servtds than KVM\n");
			return -EINVAL;
		}
		printk(KERN_EMERG"%s: max_servtds=%d\n",
		       __func__, tdx_caps.max_servtds);
	}

	if (!memcpy(tdx_caps.cpuid_configs, tdsysinfo->cpuid_configs,
			tdsysinfo->num_cpuid_config *
			sizeof(struct tdx_cpuid_config)))
		return -EIO;

	return 0;
}

bool tdx_is_vm_type_supported(unsigned long type)
{
	/* enable_tdx check is done by the caller. */
	return type == KVM_X86_TDX_VM;
}

struct tdx_guest_memory_operator {
	int (*prepare_access)(void __user *ubuf, void *kbuf, u32 size);

	int (*finish_access)(void __user *ubuf, void *kbuf, u32 size);

	/* shared page accessor */
	int (*s_accessor)(struct kvm_memory_slot *slot, gfn_t gfn,
			  void *data, int offset, unsigned long len);
	/* private page accessor */
	int (*p_accessor)(struct kvm *kvm, gpa_t addr, u32 request_len,
			  u32 *complete_len, void *buf);
};

static int tdx_access_guest_memory_prepare(void __user *ubuf,
					   void *kbuf, u32 size,
					   struct tdx_guest_memory_operator *op)
{
	if (op && op->prepare_access)
		return op->prepare_access(ubuf, kbuf, size);
	return 0;
}

static int tdx_access_guest_memory_finish(void __user *ubuf, void *kbuf, u32 size,
					  struct tdx_guest_memory_operator *op)
{
	if (op && op->finish_access)
		return op->finish_access(ubuf, kbuf, size);
	return 0;
}

static int tdx_access_guest_memory(struct kvm *kvm,
				   gpa_t gpa, void *buf, u32 access_len,
				   u32 *completed_len,
				   struct tdx_guest_memory_operator *operator)
{
	struct kvm_memory_slot *memslot;
	u32 offset = offset_in_page(gpa);
	u32 done_len;
	bool is_private;
	kvm_pfn_t pfn;
	int idx;
	int ret;

	if (!access_len ||
	    access_len > PAGE_SIZE ||
	    access_len + offset > PAGE_SIZE) {
		*completed_len = 0;
		return -EINVAL;
	}

	idx = srcu_read_lock(&kvm->srcu);
	memslot = gfn_to_memslot(kvm, gpa_to_gfn(gpa));
	if (!kvm_is_visible_memslot(memslot)) {
		done_len = 0;
		ret = -EINVAL;
		goto exit_unlock_srcu;
	}

	write_lock(&kvm->mmu_lock);
	ret = kvm_mmu_is_page_private(kvm, memslot, gpa_to_gfn(gpa),
				      &is_private, &pfn);
	if (ret) {
		is_private = false;
		done_len = 0;
		goto exit_unlock;
	}

	if (is_private) {
		u32 len = 0;

		ret = 0;
		for (done_len = 0; done_len < access_len && !ret;
		     done_len += len)
			ret = operator->p_accessor(kvm, gpa + done_len,
						   access_len - done_len,
						   &len, buf + done_len);
	} else {
		ret = operator->s_accessor(memslot,
					   gpa_to_gfn(gpa), buf,
					   offset, access_len);
		done_len = !ret ? access_len : 0;
	}

exit_unlock:
	write_unlock(&kvm->mmu_lock);
exit_unlock_srcu:
	srcu_read_unlock(&kvm->srcu, idx);

	if (completed_len)
		*completed_len = done_len;
	if (is_private && kvm_slot_is_private(memslot))
		kvm_private_mem_put_pfn(memslot, pfn);
	return ret;
}

static int tdx_read_write_memory(struct kvm *kvm, gpa_t gpa, u64 len,
				 u64 *complete_len, void __user *buf,
				 struct tdx_guest_memory_operator *operator)
{
	void *tmp_buf;
	u64 complete;
	gpa_t gpa_end;
	int ret = 0;

	if (!operator) {
		complete = 0;
		ret = -EFAULT;
		goto exit;
	}

	tmp_buf = (void *)__get_free_page(GFP_KERNEL);
	if (!tmp_buf) {
		if (complete_len)
			*complete_len = 0;
		return -ENOMEM;
	}

	complete = 0;
	gpa_end = gpa + len;
	while (gpa < gpa_end) {
		u32 done_len;
		u32 access_len = min(len - complete,
				 (u64)(PAGE_SIZE - offset_in_page(gpa)));

		cond_resched();
		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		ret = tdx_access_guest_memory_prepare(buf, tmp_buf, access_len,
						      operator);
		if (ret)
			break;

		ret = tdx_access_guest_memory(kvm, gpa,
					      tmp_buf, access_len,
					      &done_len, operator);
		if (ret)
			break;

		ret = tdx_access_guest_memory_finish(buf, tmp_buf, done_len,
						     operator);
		if (ret)
			break;

		buf += done_len;
		complete += done_len;
		gpa += done_len;
	}

	free_page((u64)tmp_buf);
 exit:
	if (complete_len)
		*complete_len = complete;
	return ret;
}

static int tdx_guest_memory_access_check(struct kvm *kvm, struct kvm_rw_memory *rw_memory)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

	if (!is_td(kvm))
		return -EINVAL;

	if (!(to_kvm_tdx(kvm)->attributes & TDX_TD_ATTRIBUTE_DEBUG))
		return -EINVAL;

	if (!kvm_tdx->initialized)
		return -EINVAL;

	if (rw_memory->len == 0 || !rw_memory->ubuf)
		return -EINVAL;

	if (rw_memory->addr + rw_memory->len < rw_memory->addr)
		return -EINVAL;

	return 0;
}

static __always_inline void tdx_get_memory_chunk_and_offset(gpa_t addr,
							    u64 *chunk,
							    u32 *offset)
{
	*chunk = addr & TDX_MEMORY_RW_CHUNK_MASK;
	*offset = addr & TDX_MEMORY_RW_CHUNK_OFFSET_MASK;
}

static int read_private_memory(struct kvm *kvm, gpa_t addr, u64 *val)
{
	u64 err;
	struct tdx_module_output tdx_ret;

	err = tdh_mem_rd(to_kvm_tdx(kvm)->tdr.pa, addr, &tdx_ret);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MEM_RD, err, NULL);
		return -EIO;
	}

	*val = tdx_ret.r8;
	return 0;
}

static int read_private_memory_unalign(struct kvm *kvm, gpa_t addr,
				       u32 request_len,
				       u32 *complete_len, void *out_buf)
{
	gpa_t chunk_addr;
	u32 in_chunk_offset;
	u32 len;
	int ret;
	union {
		u64 u64;
		u8 u8[TDX_MEMORY_RW_CHUNK];
	} l_buf;

	tdx_get_memory_chunk_and_offset(addr, &chunk_addr,
					&in_chunk_offset);
	len = min(request_len, TDX_MEMORY_RW_CHUNK - in_chunk_offset);
	if (len < TDX_MEMORY_RW_CHUNK) {
		/* unaligned GPA head/tail */
		ret = read_private_memory(kvm,
					  chunk_addr,
					  &l_buf.u64);
		if (!ret)
			memcpy(out_buf,
			       l_buf.u8 + in_chunk_offset,
			       len);
	} else {
		ret = read_private_memory(kvm,
					  chunk_addr,
					  out_buf);
	}

	if (complete_len && !ret)
		*complete_len = len;
	return ret;
}

static int finish_read_private_memory(void __user *ubuf, void *kbuf, u32 size)
{
	if (copy_to_user(ubuf, kbuf, size))
		return -EFAULT;
	return 0;
}

static struct tdx_guest_memory_operator tdx_memory_read_operator = {
	.s_accessor = kvm_read_guest_atomic,
	.p_accessor = read_private_memory_unalign,
	.finish_access = finish_read_private_memory,
};

static int tdx_read_guest_memory(struct kvm *kvm, struct kvm_rw_memory *rw_memory)
{
	int ret;
	u64 complete_len = 0;

	rw_memory->addr = rw_memory->addr & ~gfn_to_gpa(kvm_gfn_shared_mask(kvm));

	ret = tdx_guest_memory_access_check(kvm, rw_memory);
	if (!ret)
		ret = tdx_read_write_memory(kvm, rw_memory->addr,
					    rw_memory->len, &complete_len,
					    (void __user *)rw_memory->ubuf,
					    &tdx_memory_read_operator);
	rw_memory->len = complete_len;
	return ret;
}

static int write_private_memory(struct kvm *kvm, gpa_t addr, u64 *val)
{
	u64 err;
	struct tdx_module_output tdx_ret;

	err = tdh_mem_wr(to_kvm_tdx(kvm)->tdr.pa, addr, *val, &tdx_ret);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MEM_WR, err, NULL);
		return -EIO;
	}

	return 0;
}

static int write_private_memory_unalign(struct kvm *kvm, gpa_t addr,
					u32 request_len,
					u32 *complete_len, void *in_buf)
{
	gpa_t chunk_addr;
	u32 in_chunk_offset;
	u32 len;
	void *ptr;
	int ret;
	union {
		u64 u64;
		u8 u8[TDX_MEMORY_RW_CHUNK];
	} l_buf;

	tdx_get_memory_chunk_and_offset(addr, &chunk_addr, &in_chunk_offset);
	len = min(request_len, TDX_MEMORY_RW_CHUNK - in_chunk_offset);
	if (len < TDX_MEMORY_RW_CHUNK) {
		ret = read_private_memory(kvm,
					  chunk_addr,
					  &l_buf.u64);
		if (!ret)
			memcpy(l_buf.u8 + in_chunk_offset, in_buf, len);
		ptr = l_buf.u8;
	} else {
		ret = 0;
		ptr = in_buf;
	}

	if (!ret)
		ret = write_private_memory(kvm, chunk_addr, ptr);

	if (complete_len && !ret)
		*complete_len = len;

	return ret;
}

static int prepare_write_private_memory(void __user *ubuf, void *kbuf, u32 size)
{
	if (copy_from_user(kbuf, ubuf, size))
		return -EFAULT;
	return 0;
}

static struct tdx_guest_memory_operator tdx_memory_write_operator = {
	.s_accessor = kvm_write_guest_atomic,
	.p_accessor = write_private_memory_unalign,
	.prepare_access = prepare_write_private_memory,
};

static int tdx_write_guest_memory(struct kvm *kvm, struct kvm_rw_memory *rw_memory)
{
	int ret;
	u64 complete_len = 0;

	rw_memory->addr = rw_memory->addr & ~gfn_to_gpa(kvm_gfn_shared_mask(kvm));

	ret = tdx_guest_memory_access_check(kvm, rw_memory);
	if (!ret)
		ret = tdx_read_write_memory(kvm, rw_memory->addr,
					    rw_memory->len, &complete_len,
					    (void __user *)rw_memory->ubuf,
					    &tdx_memory_write_operator);

	rw_memory->len = complete_len;
	return ret;
}

static int __init tdx_module_update_init(void);
static void tdx_module_update_destroy(void);
int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	int max_pkgs;
	u32 max_pa;
	int i, ret;

	if (!enable_ept) {
		pr_warn("Cannot enable TDX with EPT disabled\n");
		return -EINVAL;
	}

	if (!platform_tdx_enabled()) {
		pr_warn("Cannot enable TDX on TDX disabled platform\n");
		return -ENODEV;
	}

	/* Safe guard check because TDX overrides tlb_remote_flush callback. */
	if (WARN_ON_ONCE(x86_ops->tlb_remote_flush))
		return -EIO;

	for (i = 0; i < ARRAY_SIZE(tdx_uret_msrs); i++) {
		/*
		 * Here it checks if MSRs (tdx_uret_msrs) can be saved/restored
		 * before returning to user space.
		 *
		 * this_cpu_ptr(user_return_msrs)->registerd isn't checked
		 * because the registration is done at vcpu runtime by
		 * kvm_set_user_return_msr().
		 * Here is setting up cpu feature before running vcpu,
		 * registered is alreays false.
		 */
		tdx_uret_msrs[i].slot = kvm_find_user_return_msr(tdx_uret_msrs[i].msr);
		if (tdx_uret_msrs[i].slot == -1) {
			/* If any MSR isn't supported, it is a KVM bug */
			pr_err("MSR %x isn't included by kvm_find_user_return_msr\n",
				tdx_uret_msrs[i].msr);
			return -EIO;
		}
	}

	/*
	 * TDX supports tdx_num_keyids keys total, the first private key is used
	 * as global encryption key to encrypt TDX module managed global scope.
	 * The left private keys is the available keys for launching guest TDs.
	 * The total number of available keys for TDs is (tdx_num_keyid - 1).
	 */
	if (misc_cg_set_capacity(MISC_CG_RES_TDX, tdx_get_num_keyid() - 1))
		return  -EINVAL;

	max_pkgs = topology_max_packages();
	tdx_mng_key_config_lock = kcalloc(max_pkgs, sizeof(*tdx_mng_key_config_lock),
				   GFP_KERNEL);
	if (!tdx_mng_key_config_lock)
		return -ENOMEM;
	for (i = 0; i < max_pkgs; i++)
		mutex_init(&tdx_mng_key_config_lock[i]);

	max_pa = cpuid_eax(0x80000008) & 0xff;
	hkid_start_pos = boot_cpu_data.x86_phys_bits;
	hkid_mask = GENMASK_ULL(max_pa - 1, hkid_start_pos);
	pr_info("kvm: TDX is supported. hkid start pos %d mask 0x%llx\n",
		hkid_start_pos, hkid_mask);

	x86_ops->tlb_remote_flush_with_range = tdx_sept_tlb_remote_flush_with_range;
	x86_ops->tlb_remote_flush = tdx_sept_tlb_remote_flush;
	x86_ops->free_private_sp = tdx_sept_free_private_sp;
	x86_ops->split_private_spte = tdx_sept_split_private_spte;
	x86_ops->handle_private_zapped_spte = tdx_handle_private_zapped_spte;
	x86_ops->handle_changed_private_spte = tdx_handle_changed_private_spte;
	x86_ops->set_private_spte = tdx_sept_set_private_spte;
	x86_ops->drop_private_spte = tdx_sept_drop_private_spte;
	x86_ops->zap_private_spte = tdx_sept_zap_private_spte;
	x86_ops->unzap_private_spte = tdx_sept_unzap_private_spte;
	x86_ops->link_private_sp = tdx_sept_link_private_sp;
	x86_ops->mem_enc_read_memory = tdx_read_guest_memory;
	x86_ops->mem_enc_write_memory = tdx_write_guest_memory;
	x86_ops->write_disable_spte = tdx_sept_write_disable_spte;
	x86_ops->write_enable_spte = tdx_sept_write_enable_spte;

	kvm_set_tdx_guest_pmi_handler(tdx_guest_pmi_handler);

	ret = kvm_tdx_mig_stream_ops_init();
	if (ret) {
		pr_err("%s: failed to init tdx mig, %d\n", __func__, ret);
		return ret;
	}

	return tdx_module_update_init();
}

void tdx_hardware_unsetup(void)
{
	kvm_tdx_mig_stream_ops_exit();
	/* kfree accepts NULL. */
	kfree(tdx_mng_key_config_lock);
	misc_cg_set_capacity(MISC_CG_RES_TDX, 0);
	kvm_set_tdx_guest_pmi_handler(NULL);
	tdx_module_update_destroy();
}

#ifdef CONFIG_INTEL_TDX_MODULE_UPDATE
static int kvm_tdx_module_update(const void *module, size_t module_size,
				 const void *sigstruct, size_t sigstruct_size)
{
	int ret;
	unsigned int num_tds;
	struct tmu_req req;

	num_tds = td_creation_block();

	/* tdx_module_update() expects VMXON executed on all CPUs */
	ret = kvm_hardware_enable_all();
	if (ret)
		goto unblock;

	req.preserving = !!num_tds;
	req.module = module;
	req.signature = sigstruct;
	req.module_size = module_size;
	req.signature_size = sigstruct_size;

	if (req.preserving) {
		/* Block TDX module APIs */
		percpu_down_write(&tdx_update_percpu_rwsem);
		/*
		 * tdx_module_update_prepare should be called
		 * after holding write lock of tdx_update_percpu_rwsem.
		 *
		 * Because tdx_module_update_prepare graps cpus_read_lock
		 * and in existing paths (e.g., tdx_vm_init()), the locking
		 * order is tdx_update_percpu_rwsem -> cpus_read_lock.
		 */
		ret = tdx_module_update_prepare(&req);
		if (ret) {
			percpu_up_write(&tdx_update_percpu_rwsem);
			goto hardware_disable;
		}

		/* Block mmu notifier invalidation */
		percpu_down_write(&tdx_update_percpu_rwsem_mn_invalidate);
		write_lock(&tdx_update_rwlock);

		ret = tdx_module_update();

		/* Unblock mmu notifier invalidation */
		write_unlock(&tdx_update_rwlock);
		percpu_up_write(&tdx_update_percpu_rwsem_mn_invalidate);

		tdx_module_update_end();
		/* Unblock TDX module APIs */
		percpu_up_write(&tdx_update_percpu_rwsem);
	} else {
		ret = tdx_module_update_prepare(&req);
		if (ret)
			goto hardware_disable;

		ret = tdx_module_update();
		tdx_module_update_end();
	}

	if (!ret) {
		ret = tdx_module_setup();
		enable_tdx = !ret;
	} else {
		enable_tdx = false;
	}

hardware_disable:
	kvm_hardware_disable_all();
unblock:
	td_creation_unblock();
	return ret;
}

static ssize_t reload_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf, size_t size)
{
	int ret;
	const struct firmware *module, *sigstruct;

	if (!sysfs_streq(buf, "update"))
		return -EINVAL;

	ret = request_firmware_direct(&module, "intel-seam/libtdx.bin",
				      &tdx_pdev->dev);
	if (ret)
		return ret;

	ret = request_firmware_direct(&sigstruct,
				      "intel-seam/libtdx.bin.sigstruct",
				      &tdx_pdev->dev);
	if (ret) {
		release_firmware(module);
		return ret;
	}

	ret = kvm_tdx_module_update(module->data, module->size,
				    sigstruct->data, sigstruct->size);
	if (!ret)
		ret = size;

	release_firmware(sigstruct);
	release_firmware(module);
	return ret;
}
static DEVICE_ATTR_WO(reload);

static struct attribute *cpu_root_tdx_attrs[] = {
	&dev_attr_reload.attr,
	NULL
};

static const struct attribute_group cpu_root_tdx_group = {
	.name  = "tdx",
	.attrs = cpu_root_tdx_attrs,
};

static int __init tdx_module_update_init(void)
{
	int ret;

	ret = sysfs_create_group(&cpu_subsys.dev_root->kobj, &cpu_root_tdx_group);
	if (ret) {
		pr_err("Fail to create tdx group\n");
		return ret;
	}

	tdx_pdev = platform_device_register_simple("tdx", -1, NULL, 0);
	if (IS_ERR(tdx_pdev)) {
		sysfs_remove_group(&cpu_subsys.dev_root->kobj, &cpu_root_tdx_group);
		return PTR_ERR(tdx_pdev);
	}

	return ret;
}

static void tdx_module_update_destroy(void)
{
	/*
	 * Invoked unconditionally on removal of kvm-intel.ko. if tdx_pdev
	 * isn't valid, initialization isn't done. Then, no need to do the
	 * cleanup.
	 */
	if (!tdx_pdev || IS_ERR(tdx_pdev))
		return;
	sysfs_remove_group(&cpu_subsys.dev_root->kobj, &cpu_root_tdx_group);
	platform_device_unregister(tdx_pdev);
}
#else /* !CONFIG_INTEL_TDX_MODULE_UPDATE */
static int __init tdx_module_update_init(void)
{
	return 0;
}

static void tdx_module_update_destroy(void)
{
}
#endif /* CONFIG_INTEL_TDX_MODULE_UPDATE */
