// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/iommu.h>
#include <linux/mmu_context.h>
#include <linux/misc_cgroup.h>

#include <asm/fpu/xcr.h>
#include <asm/virtext.h>
#include <asm/tdx.h>

#include "capabilities.h"
#include "x86_ops.h"
#include "common.h"
#include "tdx.h"
#include "vmx.h"
#include "x86.h"
#include "mmu.h"

#include <trace/events/kvm.h>
#include "trace.h"

/* Table 3-42, GHCI spec */
struct tdvmcall_service {
	guid_t   guid;
	/* Length of the hdr and payload */
	uint32_t length;
	uint32_t status;
	uint8_t  data[0];
};

enum tdvmcall_service_id {
	TDVMCALL_SERVICE_ID_QUERY = 0,
	TDVMCALL_SERVICE_ID_MIGTD = 1,
	TDVMCALL_SERVICE_ID_VTPM,
	TDVMCALL_SERVICE_ID_VTPMTD,
	TDVMCALL_SERVICE_ID_TDCM,
	TDVMCALL_SERVICE_ID_SPDM,
	TDVMCALL_SERVICE_ID_TPA,

	TDVMCALL_SERVICE_ID_MAX,
};

static guid_t tdvmcall_service_ids[TDVMCALL_SERVICE_ID_MAX] __read_mostly = {
	[TDVMCALL_SERVICE_ID_QUERY]	= GUID_INIT(0xfb6fc5e1, 0x3378, 0x4acb,
						    0x89, 0x64, 0xfa, 0x5e,
						    0xe4, 0x3b, 0x9c, 0x8a),
	[TDVMCALL_SERVICE_ID_MIGTD]	= GUID_INIT(0xe60e6330, 0x1e09, 0x4387,
						    0xa4, 0x44, 0x8f, 0x32,
						    0xb8, 0xd6, 0x11, 0xe5),
	[TDVMCALL_SERVICE_ID_VTPM]	= GUID_INIT(0x64590793, 0x7852, 0x4e52,
						    0xbe, 0x45, 0xcd, 0xbb,
						    0x11, 0x6f, 0x20, 0xf3),
	[TDVMCALL_SERVICE_ID_VTPMTD]	= GUID_INIT(0xc3c87a08, 0x3b4a, 0x41ad,
						    0xa5, 0x2d, 0x96, 0xf1,
						    0x3c, 0xf8, 0x9a, 0x66),
	[TDVMCALL_SERVICE_ID_TDCM]	= GUID_INIT(0x6270da51, 0x9a23, 0x4b6b,
						    0x81, 0xce, 0xdd, 0xd8,
						    0x69, 0x70, 0xf2, 0x96),
	[TDVMCALL_SERVICE_ID_SPDM]	= GUID_INIT(0xa148b5dd, 0x50c, 0x4be4,
						    0xa6, 0x30, 0xe5, 0xe5,
						    0x30, 0x1f, 0x2a, 0x9b),
	[TDVMCALL_SERVICE_ID_TPA]	= GUID_INIT(0x0320dae8, 0x75b6, 0x4ac8,
						    0xa9, 0xda, 0x2d, 0xe6,
						    0x9d, 0x18, 0x59, 0xda),
};

enum tdvmcall_service_status {
	TDVMCALL_SERVICE_S_RETURNED = 0x0,

	TDVMCALL_SERVICE_S_UNSUPP = 0xFFFFFFFE,
};

struct tdvmcall_service_query {
#define TDVMCALL_SERVICE_QUERY_VERSION	0
	uint8_t version;
#define TDVMCALL_SERVICE_CMD_QUERY	0
	uint8_t cmd;
#define TDVMCALL_SERVICE_QUERY_S_SUPPORTED	0
#define TDVMCALL_SERVICE_QUERY_S_UNSUPPORTED	1
	uint8_t status;
	uint8_t rsvd;
	guid_t  guid;
};

/* PI Spec: vol 3, 5.6 GUID extension HOB */
struct hob_generic_hdr {
#define HOB_TYPE_GUID_EXTENSION	0x0004
	uint16_t type;
	/* Length of the payload */
	uint16_t length;
	uint32_t rsvd;
};

struct hob_guid_type_hdr {
	struct hob_generic_hdr		generic_hdr;
	guid_t				guid;
	uint8_t				data[0];
};

struct migtd_basic_info {
	struct hob_guid_type_hdr	hob_hdr;
	uint64_t			req_id;
	bool				src;
	uint32_t			cpu_version;
	uint8_t				usertd_uuid[32];
	uint64_t			binding_handle;
	uint64_t			policy_id;
	uint64_t			comm_id;
};

struct migtd_socket_info {
	struct hob_guid_type_hdr	hob_hdr;
	uint64_t			comm_id;
	uint64_t			migtd_cid;
	uint32_t			channel_port;
	uint32_t			quote_service_port;
};

struct migtd_policy_info {
	struct hob_guid_type_hdr	hob_hdr;
	uint64_t			policy_id;
	uint32_t			policy_size;
	uint8_t				pad[4];
	uint8_t				policy_data[0];
};

struct migtd_all_info {
	struct migtd_basic_info		basic;
	struct migtd_socket_info	socket;
	struct migtd_policy_info	policy;
};

struct tdvmcall_service_migtd {
#define TDVMCALL_SERVICE_MIGTD_WAIT_VERSION	0
#define TDVMCALL_SERVICE_MIGTD_REPORT_VERSION	0
	uint8_t version;
#define TDVMCALL_SERVICE_MIGTD_CMD_SHUTDOWN	0
#define TDVMCALL_SERVICE_MIGTD_CMD_WAIT		1
#define TDVMCALL_SERVICE_MIGTD_CMD_REPORT	2
	uint8_t cmd;
#define TDVMCALL_SERVICE_MIGTD_OP_NOOP		0
#define TDVMCALL_SERVICE_MIGTD_OP_START_MIG	1
	uint8_t operation;
#define TDVMCALL_SERVICE_MIGTD_STATUS_SUCC	0
	uint8_t status;
	uint8_t data[0];
};

static struct kvm_firmware *tdx_module;

#include "tdx_mig.c"

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define pr_err_skip_ud(_x) \
	pr_err_once("Skip #UD injection for " _x " due to it's not supported in TDX 1.0\n")

#define TDX_MAX_NR_CPUID_CONFIGS					\
	((TDSYSINFO_STRUCT_SIZE -					\
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
static atomic_t nr_configured_hkid;

static int tdx_tdi_iq_inv_iotlb(struct kvm_tdx *kvm_tdx);
static int tdx_tdi_mmio_map(struct kvm_tdx *kvm_tdx, gfn_t gfn,
			    enum pg_level level, kvm_pfn_t pfn);

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

static inline void
tdx_binding_slot_set_state(struct tdx_binding_slot *slot,
			   enum tdx_binding_slot_state state)
{
	slot->state = state;
}

static inline enum tdx_binding_slot_state
tdx_binding_slot_get_state(struct tdx_binding_slot *slot)
{
	return slot->state;
}

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

static __always_inline unsigned long tdexit_exit_qual(struct kvm_vcpu *vcpu)
{
	return to_tdx(vcpu)->exit_qualification;
}

static __always_inline unsigned long tdexit_ext_exit_qual(struct kvm_vcpu *vcpu)
{
	return to_tdx(vcpu)->ext_exit_qualification;
}

static __always_inline unsigned long tdexit_gpa(struct kvm_vcpu *vcpu)
{
	return to_tdx(vcpu)->exit_gpa;
}

static __always_inline unsigned long tdexit_intr_info(struct kvm_vcpu *vcpu)
{
	return to_tdx(vcpu)->exit_intr_info;
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

static inline bool is_td_created(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->tdr_pa;
}

static inline void tdx_hkid_free(struct kvm_tdx *kvm_tdx)
{
	tdx_keyid_free(kvm_tdx->hkid);
	kvm_tdx->hkid = 0;
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
	if (to_tdx(vcpu)->vcpu_initialized) {
		/*
		 * No need to retry.  TDX Resources needed for TDH.VP.FLUSH are,
		 * TDVPR as exclusive, TDR as shared, and TDCS as shared.  This
		 * vp flush function is called when destructing vcpu/TD or vcpu
		 * migration.  No other thread uses TDVPR in those cases.
		 */
		err = tdh_vp_flush(to_tdx(vcpu)->tdvpr_pa);
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
	int cpu = vcpu->cpu;

	if (unlikely(cpu == -1))
		return;

	smp_call_function_single(cpu, tdx_flush_vp, &arg, 1);
	if (WARN_ON_ONCE(arg.err)) {
		pr_err("cpu: %d ", cpu);
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
	unsigned long j;
	u64 err;
	int ret;
	int i;

	if (!is_hkid_assigned(kvm_tdx))
		return;

	if (!is_td_created(kvm_tdx))
		goto free_hkid;

	kvm_for_each_vcpu(j, vcpu, kvm)
		tdx_flush_vp_on_cpu(vcpu);

	mutex_lock(&tdx_lock);
	err = tdh_mng_vpflushdone(kvm_tdx->tdr_pa);
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
	err = tdh_mng_key_freeid(kvm_tdx->tdr_pa);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_FREEID, err, NULL);
		pr_err("tdh_mng_key_freeid failed. HKID %d is leaked.\n",
			kvm_tdx->hkid);
		return;
	} else
		atomic_dec(&nr_configured_hkid);

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
		 * Only need to NULL the servtd_tdx field. Other fileds are
		 * still valid for later migration process to reference, e.g.
		 * migtd_data.is_src to indicate if this is a source TD. This
		 * allows the user TD to be migrated to the destination after
		 * the MigTD is destroyed.
		 *
		 * The live migration could be initiated much later after
		 * pre-migration is done, there is no need to keep MigTD
		 * running. The slot's state will be reset to INIT when a new
		 * MigTD is bound, e.g. in order to change the migration
		 * destination.
		 */
		slot->servtd_tdx = NULL;
	}
	spin_unlock(&kvm_tdx->binding_slot_lock);
}

static void tdx_vm_free_tdcs(struct kvm_tdx *kvm_tdx)
{
	int i;

	if (!kvm_tdx->tdcs_pa)
		return;

	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++)
		tdx_reclaim_td_page(kvm_tdx->tdcs_pa[i]);

	kfree(kvm_tdx->tdcs_pa);
	kvm_tdx->tdcs_pa = NULL;
}

static void tdx_vm_free_tdr(struct kvm_tdx *kvm_tdx)
{
	if (!kvm_tdx->tdr_pa)
		return;

	/*
	 * TDX module maps TDR with TDX global HKID.  TDX module may access TDR
	 * while operating on TD (Especially reclaiming TDCS).  Cache flush with
	 * TDX global HKID is needed.
	 */
	if (tdx_reclaim_page(kvm_tdx->tdr_pa, PG_LEVEL_4K, true, tdx_global_keyid))
		return;

	free_page((unsigned long)__va(kvm_tdx->tdr_pa));
	kvm_tdx->tdr_pa = 0;
}

void tdx_vm_free(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

	/* Can't reclaim or free TD pages if teardown failed. */
	if (is_hkid_assigned(kvm_tdx))
		return;

	tdx_binding_slots_cleanup(kvm_tdx);
	tdx_mig_state_destroy(kvm_tdx);

	tdx_vm_free_tdcs(kvm_tdx);
	tdx_vm_free_tdr(kvm_tdx);
	kvm_tdx->td_initialized = false;
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

int tdx_vm_init(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

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
	kvm_mmu_set_mmio_spte_value(kvm, 0);

	/* TDH.MEM.PAGE.AUG supports up to 2MB page. */
	kvm->arch.tdp_max_page_level = PG_LEVEL_2M;

	kvm_tdx->has_range_blocked = false;
	spin_lock_init(&kvm_tdx->binding_slot_lock);

	mutex_init(&kvm_tdx->ttdi_mutex);
	INIT_LIST_HEAD_RCU(&kvm_tdx->ktiommu_list);
	INIT_LIST_HEAD_RCU(&kvm_tdx->ttdi_list);

	/*
	 * This function initializes only KVM software construct.  It doesn't
	 * initialize TDX stuff, e.g. TDCS, TDR, TDCX, HKID etc.
	 * It is handled by KVM_TDX_INIT_VM, __tdx_td_init().
	 */

	return 0;
}

u8 tdx_get_mt_mask(struct kvm_vcpu *vcpu, gfn_t gfn, bool is_mmio)
{
	/* Private MMIO is UC for TDXIO. Shared MMIO is also UC of course */
	if (is_mmio)
		return MTRR_TYPE_UNCACHABLE << VMX_EPT_MT_EPTE_SHIFT;

	/* TDX private GPA is always WB. */
	if (!(gfn & kvm_gfn_shared_mask(vcpu->kvm)))
		return  MTRR_TYPE_WRBACK << VMX_EPT_MT_EPTE_SHIFT;

	/*
	 * Device assignemnt without VT-d snooping capability with shared-GPA
	 * is dubious.
	 */
	WARN_ON_ONCE(kvm_arch_has_noncoherent_dma(vcpu->kvm));
	return (MTRR_TYPE_WRBACK << VMX_EPT_MT_EPTE_SHIFT) | VMX_EPT_IPAT_BIT;
}

int tdx_vcpu_create(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct kvm_cpuid_entry2 *e;

	/*
	 * On cpu creation, cpuid entry is blank.  Forcibly enable
	 * X2APIC feature to allow X2APIC.
	 * Because vcpu_reset() can't return error, allocation is done here.
	 */
	WARN_ON_ONCE(vcpu->arch.cpuid_entries);
	WARN_ON_ONCE(vcpu->arch.cpuid_nent);
	e = kvmalloc_array(1, sizeof(*e), GFP_KERNEL_ACCOUNT);
	if (!e)
		return -ENOMEM;
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

	/* TDX only supports x2APIC, which requires an in-kernel local APIC. */
	if (!vcpu->arch.apic)
		return -EINVAL;

	fpstate_set_confidential(&vcpu->arch.guest_fpu);
	vcpu->arch.apic->guest_apic_protected = true;
	INIT_LIST_HEAD(&tdx->pi_wakeup_list);

	vcpu->arch.efer = EFER_SCE | EFER_LME | EFER_LMA | EFER_NX;

	vcpu->arch.switch_db_regs = KVM_DEBUGREG_AUTO_SWITCH;
	/*
	 * kvm_arch_vcpu_reset(init_event=false) reads cr0 to reset MMU.
	 * Prevent to read CR0 via SEAMCALL.
	 */
	vcpu->arch.cr0_guest_owned_bits = 0ul;
	vcpu->arch.cr4_guest_owned_bits = -1ul;
	vcpu->arch.root_mmu.no_prefetch = true;

	vcpu->arch.guest_state_protected =
		!(to_kvm_tdx(vcpu->kvm)->attributes & TDX_TD_ATTRIBUTE_DEBUG);

	if ((kvm_tdx->xfam & XFEATURE_MASK_XTILE) == XFEATURE_MASK_XTILE)
		vcpu->arch.xfd_no_write_intercept = true;

	tdx->pi_desc.nv = POSTED_INTR_VECTOR;
	tdx->pi_desc.sn = 1;

	tdx->host_state_need_save = true;
	tdx->host_state_need_restore = false;

	tdx->tdvmcall.regs_mask = 0xffffffff;

	return 0;
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
	details.full = td_state_non_arch_read64(tdx, TD_VCPU_STATE_DETAILS_NON_ARCH);
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

static void tdx_vcpu_free_tdvpx(struct vcpu_tdx *tdx)
{
	unsigned long td_page_pa;
	int i;

	if (!tdx->tdvpx_pa)
		return;

	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++) {
		td_page_pa = tdx->tdvpx_pa[i];
		if (tdx->vcpu_initialized)
			tdx_reclaim_td_page(td_page_pa);
		else
			free_page((unsigned long)__va(td_page_pa));
	}

	kfree(tdx->tdvpx_pa);
	tdx->tdvpx_pa = NULL;
}

static void tdx_vcpu_free_tdvpr(struct vcpu_tdx *tdx)
{
	if (!tdx->tdvpr_pa)
		return;

	if (tdx->vcpu_initialized)
		tdx_reclaim_td_page(tdx->tdvpr_pa);
	else
		free_page((unsigned long)__va(tdx->tdvpr_pa));

	tdx->tdvpr_pa = 0;
}

void tdx_vcpu_free(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	/* Can't reclaim or free pages if teardown failed. */
	if (is_hkid_assigned(to_kvm_tdx(vcpu->kvm)))
		return;

	tdx_vcpu_free_tdvpx(tdx);
	tdx_vcpu_free_tdvpr(tdx);
	tdx->vcpu_initialized = false;

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
	WARN_ON_ONCE(vcpu->cpu != -1);
}

void tdx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct msr_data apic_base_msr;

	/* TDX doesn't support INIT event. */
	if (WARN_ON_ONCE(init_event))
		goto td_bugged;
	if (WARN_ON_ONCE(tdx->vcpu_initialized))
		goto td_bugged;

	/* TDX rquires X2APIC. */
	apic_base_msr.data = APIC_DEFAULT_PHYS_BASE | LAPIC_MODE_X2APIC;
	if (kvm_vcpu_is_reset_bsp(vcpu))
		apic_base_msr.data |= MSR_IA32_APICBASE_BSP;
	apic_base_msr.host_initiated = true;
	if (WARN_ON_ONCE(kvm_set_apic_base(vcpu, &apic_base_msr)))
		goto td_bugged;
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

	/*
	 * Don't update mp_state to runnable because more initialization
	 * is needed by TDX_VCPU_INIT.
	 */
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
	{.msr = MSR_SYSCALL_MASK, .defval = 0x20200},
	{.msr = MSR_STAR,},
	{.msr = MSR_LSTAR,},
	{.msr = MSR_TSC_AUX,},
};
static unsigned int tdx_uret_tsx_ctrl_slot;

static void tdx_user_return_update_cache(struct kvm_vcpu *vcpu)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tdx_uret_msrs); i++)
		kvm_user_return_update_cache(tdx_uret_msrs[i].slot,
					     tdx_uret_msrs[i].defval);
	/*
	 * TSX_CTRL is reset to 0 if guest TSX is supported. Otherwise
	 * preserved.
	 */
	if (to_kvm_tdx(vcpu->kvm)->tsx_supported && tdx_uret_tsx_ctrl_slot != -1)
		kvm_user_return_update_cache(tdx_uret_tsx_ctrl_slot, 0);
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
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct perf_guest_switch_msr *msrs;
	int i, nr_msrs;

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
		tdx->exit_reason.full = __tdx_vcpu_run(tdx->tdvpr_pa,
						     vcpu->arch.regs,
					    tdx->tdvmcall.regs_mask);

		if (tdx->exit_reason.full == TDX_INCONSISTENT_MSR_TSX) {
			pr_err_once("TDX module is outdated. Use v1.0.3 or newer.\n");
			break;
		}

		err = tdx->exit_reason.full & TDX_SEAMCALL_STATUS_MASK;

		if (retries++ > TDX_SEAMCALL_RETRY_MAX * 10) {
			pr_err("%s: called, retries=%llx\n", __func__, retries);
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

	tdx_vcpu_enter_exit(vcpu, tdx);

	tdx_user_return_update_cache(vcpu);

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

	tdx->exit_qualification = kvm_rcx_read(vcpu);
	tdx->ext_exit_qualification = kvm_rdx_read(vcpu);
	tdx->exit_gpa = kvm_r8_read(vcpu);
	tdx->exit_intr_info = kvm_r9_read(vcpu);
	if (tdx->exit_reason.basic == EXIT_REASON_TDCALL)
		tdx->tdvmcall.rcx = kvm_rcx_read(vcpu);
	else
		tdx->tdvmcall.rcx = 0;

	trace_kvm_exit(vcpu, KVM_ISA_VMX);

	tdx_complete_interrupts(vcpu);

	if (is_debug_td(vcpu))
		tdx_reset_regs_cache(vcpu);
	else
		vcpu->arch.regs_avail &= ~VMX_REGS_LAZY_LOAD_SET;

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
		 * #MSMI(Machine Check System Management Interrupt) with
		 * exit_qualification bit 0 set in TD guest.
		 * The #MSMI is delivered right after SEAMCALL returns,
		 * and an #MC is delivered to host kernel after SMI handler
		 * returns.
		 *
		 * The #MC right after SEAMCALL is fixed up and skipped in #MC
		 * handler because it's an #MC happens in TD guest we cannot
		 * handle it with host's context.
		 *
		 * Call KVM's machine check handler explicitly here.
		 */
		if (tdx->exit_reason.basic == EXIT_REASON_OTHER_SMI) {
			#define TD_EXIT_OTHER_SMI_IS_MSMI 0x1
			unsigned long exit_qual;

			exit_qual = tdexit_exit_qual(vcpu);
			if (exit_qual & TD_EXIT_OTHER_SMI_IS_MSMI)
				kvm_machine_check();
		}
	}
}

static bool tdx_kvm_use_dr(struct kvm_vcpu *vcpu)
{
	return !!(vcpu->guest_debug &
		  (KVM_GUESTDBG_USE_HW_BP | KVM_GUESTDBG_SINGLESTEP));
}

static int tdx_handle_exception(struct kvm_vcpu *vcpu)
{
	u32 intr_info = tdexit_intr_info(vcpu);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	u32 ex_no;

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
				KVM_BUG_ON(!tdx_skip_emulated_instruction(vcpu), vcpu->kvm);

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

	if (!is_debug_td(vcpu) || !tdx->vcpu_initialized)
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
	unsigned long guest_debug_old;
	unsigned long rflags;

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

static int tdx_complete_vp_vmcall(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx_vmcall *tdx_vmcall = &vcpu->run->tdx.u.vmcall;
	__u64 reg_mask;
	int r;

	if (unlikely(vcpu->arch.complete_tdx_vp_vmcall)) {
		int (*ctvv)(struct kvm_vcpu *) = vcpu->arch.complete_tdx_vp_vmcall;

		vcpu->arch.complete_tdx_vp_vmcall = NULL;
		r = ctvv(vcpu);
		if (r <= 0)
			return r;
	}

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
	tdx_vmcall->status_code = TDG_VP_VMCALL_INVALID_OPERAND;

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
	tdx->interrupt_disabled_hlt = tdvmcall_a0_read(vcpu);

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
	return kvm_emulate_halt_noskip(vcpu);
}

static int tdx_complete_pio_in(struct kvm_vcpu *vcpu)
{
	struct x86_emulate_ctxt *ctxt = vcpu->arch.emulate_ctxt;
	unsigned long val = 0;
	int ret;

	WARN_ON_ONCE(vcpu->arch.pio.count != 1);

	ret = ctxt->ops->pio_in_emulated(ctxt, vcpu->arch.pio.size,
					 vcpu->arch.pio.port, &val, 1);
	WARN_ON_ONCE(!ret);

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

	KVM_BUG_ON(vcpu->mmio_needed != 1, vcpu->kvm);
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

	KVM_BUG_ON(vcpu->mmio_needed, vcpu->kvm);

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

	if (!kvm_msr_allowed(vcpu, index, KVM_MSR_FILTER_WRITE) ||
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

/* used for both shared EPT and security EPT */
#define TDX_EPT_PFERR (PFERR_WRITE_MASK | PFERR_USER_MASK)

static int tdx_complete_map_gpa(struct kvm_vcpu *vcpu)
{
	gpa_t gpa = tdvmcall_a0_read(vcpu);
	gpa_t size = tdvmcall_a1_read(vcpu);
	bool prefault = tdx_io_enabled();

	WARN_ON(!prefault);

	while (size) {
		kvm_pfn_t pfn;

		pfn = kvm_mmu_map_tdp_page(vcpu, gpa, TDX_EPT_PFERR,
					   PG_LEVEL_4K, false);

		if (is_error_noslot_pfn(pfn) || vcpu->kvm->vm_bugged) {
			pr_err("failed to pin shared pages %llx\n", gpa);
		}

		size -= PAGE_SIZE;
		gpa += PAGE_SIZE;
	}

	return 1;
}

static int tdx_map_gpa(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	gpa_t gpa = tdvmcall_a0_read(vcpu);
	gpa_t size = tdvmcall_a1_read(vcpu);
	bool prefault = tdx_io_enabled();
	gpa_t end = gpa + size;
	gfn_t s = gpa_to_gfn(gpa) & ~kvm_gfn_shared_mask(kvm);
	gfn_t e = gpa_to_gfn(end) & ~kvm_gfn_shared_mask(kvm);
	bool map_private = kvm_is_private_gpa(kvm, gpa);
	bool range_in_slot = false;
	int ret;
	int i;

	if (!IS_ALIGNED(gpa, 4096) || !IS_ALIGNED(size, 4096) ||
	    end < gpa ||
	    end > kvm_gfn_shared_mask(kvm) << (PAGE_SHIFT + 1) ||
	    kvm_is_private_gpa(kvm, gpa) != kvm_is_private_gpa(kvm, end)) {
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}

	/*
	 * Check how the requested region overlaps with the KVM memory slots.
	 * For simplicity, require that it must be contained within a memslot or
	 * it must not overlap with any memslots (MMIO).
	 */
	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
		struct kvm_memslots *slots = __kvm_memslots(kvm, i);
		struct kvm_memslot_iter iter;

		kvm_for_each_memslot_in_gfn_range(&iter, slots, s, e) {
			struct kvm_memory_slot *slot = iter.slot;
			gfn_t slot_s = slot->base_gfn;
			gfn_t slot_e = slot->base_gfn + slot->npages;

			/* no overlap */
			if (e < slot_s || s >= slot_e)
				continue;

			/* contained in slot */
			if (slot_s <= s && e <= slot_e) {
				range_in_slot = true;
				if (kvm_slot_can_be_private(slot)) {
					if (prefault)
						vcpu->arch.complete_tdx_vp_vmcall = tdx_complete_map_gpa;
					return tdx_vp_vmcall_to_user(vcpu);
				}
				continue;
			}

			break;
		}
	}

	ret = kvm_mmu_map_private(vcpu, &s, e, map_private);
	if (ret == -EAGAIN) {
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_RETRY);
		tdvmcall_set_return_val(vcpu, gfn_to_gpa(s));
	} else if (ret) {
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
	} else {
		if (prefault && range_in_slot)
			tdx_complete_map_gpa(vcpu);
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
	}
	return 1;
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
	trace_kvm_tdx_hypercall_done(kvm_r11_read(vcpu), kvm_r10_read(vcpu),
				     kvm_r12_read(vcpu), kvm_r13_read(vcpu), kvm_r14_read(vcpu),
				     kvm_rbx_read(vcpu), kvm_rdi_read(vcpu), kvm_rsi_read(vcpu),
				     kvm_r8_read(vcpu), kvm_r9_read(vcpu), kvm_rdx_read(vcpu));
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
	h_buf = kzalloc(max_t(size_t, length, PAGE_SIZE), GFP_KERNEL_ACCOUNT);
	if (!h_buf)
		return NULL;

	if (copy_from_user(h_buf, g_buf, length)) {
		pr_err("%s: failed to copy\n", __func__);
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
		pr_err("%s: failed to update the guest buffer\n", __func__);
	}
	kfree(h_buf);
}

static enum tdvmcall_service_id tdvmcall_get_service_id(guid_t guid)
{
	enum tdvmcall_service_id id;

	for (id = 0; id < TDVMCALL_SERVICE_ID_MAX; id++) {
		if (guid_equal(&guid, &tdvmcall_service_ids[id]))
			break;
	}

	return id;
}

static void tdx_handle_service_query(struct tdvmcall_service *cmd_hdr,
				     struct tdvmcall_service *resp_hdr)
{
	struct tdvmcall_service_query *cmd_query =
			(struct tdvmcall_service_query *)cmd_hdr->data;
	struct tdvmcall_service_query *resp_query =
			(struct tdvmcall_service_query *)resp_hdr->data;
	enum tdvmcall_service_id service_id;

	resp_query->version = TDVMCALL_SERVICE_QUERY_VERSION;
	if (cmd_query->version != resp_query->version ||
	    cmd_query->cmd != TDVMCALL_SERVICE_CMD_QUERY) {
		pr_warn("%s: queried cmd not supported\n", __func__);
		resp_hdr->status = TDVMCALL_SERVICE_S_UNSUPP;
	}

	service_id = tdvmcall_get_service_id(cmd_query->guid);
	if (service_id == TDVMCALL_SERVICE_ID_MAX)
		resp_query->status = TDVMCALL_SERVICE_QUERY_S_UNSUPPORTED;
	else
		resp_query->status = TDVMCALL_SERVICE_QUERY_S_SUPPORTED;

	resp_query->cmd = cmd_query->cmd;
	import_guid(&resp_query->guid, cmd_query->guid.b);

	resp_hdr->length += sizeof(struct tdvmcall_service_query);
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
	basic->src = slot->migtd_data.is_src;
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
	socket->channel_port = slot->migtd_data.vsock_port;

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
	policy->policy_id = slot->migtd_data.vsock_port; // unused, testing purpose
	policy->policy_size = 0;

	return hdr->generic_hdr.length;
}

static int migtd_start_migration(struct tdvmcall_service_migtd *resp_migtd,
				 struct tdx_binding_slot *slot,
				 uint64_t req_id)
{
	struct migtd_all_info *info =
		(struct migtd_all_info *)resp_migtd->data;
	int len = 0;

	/* No one requested to start migration */
	if (req_id == SERVTD_SLOTS_MAX) {
		resp_migtd->operation = TDVMCALL_SERVICE_MIGTD_OP_NOOP;
		return len;
	}

	/* Ask MigTD to start migration setup */
	len += migtd_basic_info_setup(&info->basic, slot, req_id);
	len += migtd_socket_info_setup(&info->socket, slot);
	len += migtd_policy_info_setup(&info->policy, slot);

	resp_migtd->operation = TDVMCALL_SERVICE_MIGTD_OP_START_MIG;

	return len;
}

static bool tdx_binding_slot_premig_wait(struct tdx_binding_slot *slot)
{
	bool slot_is_waiting = false;

	if (slot->state == TDX_BINDING_SLOT_STATE_PREMIG_WAIT) {
		slot->state = TDX_BINDING_SLOT_STATE_PREMIG_PROGRESS;
		slot_is_waiting = true;
	}

	return slot_is_waiting;
}

static int migtd_wait_for_request(struct kvm_tdx *tdx,
				  struct tdvmcall_service_migtd *resp_migtd)
{
	struct tdx_binding_slot *slot;
	int i, len = sizeof(struct tdvmcall_service_migtd);

	for (i = 0; i < SERVTD_SLOTS_MAX; i++) {
		slot = tdx->usertd_binding_slots[i];
		if (slot && tdx_binding_slot_premig_wait(slot))
			break;
	}

	len += migtd_start_migration(resp_migtd, slot, i);

	return len;
}

/*
 * Return length of filled bytes. 0 bytes means that the operation isn't
 * supported.
 */
static int migtd_report_status(struct kvm_tdx *tdx,
			       struct tdvmcall_service_migtd *cmd_migtd,
			       struct tdvmcall_service_migtd *resp_migtd)
{
	uint64_t req_id = *(uint64_t *)cmd_migtd->data;
	struct tdx_binding_slot *slot = tdx->usertd_binding_slots[req_id];
	int len = sizeof(struct tdvmcall_service_migtd);
	enum tdx_binding_slot_state state;

	/* Not bounded any more, e.g. the user TD is destroyed */
	if (!slot)
		return 0;

	switch (cmd_migtd->operation) {
	case TDVMCALL_SERVICE_MIGTD_OP_NOOP:
		break;
	case TDVMCALL_SERVICE_MIGTD_OP_START_MIG:
		state = tdx_binding_slot_get_state(slot);
		/* Sanity check if the state is unexpected */
		if (state != TDX_BINDING_SLOT_STATE_PREMIG_PROGRESS)
			return 0;

		if (cmd_migtd->status != TDVMCALL_SERVICE_MIGTD_STATUS_SUCC) {
			pr_err("%s: pre-migration failed, state=%x\n",
				__func__, cmd_migtd->status);
			state = TDX_BINDING_SLOT_STATE_BOUND;
		} else {
			state = TDX_BINDING_SLOT_STATE_PREMIG_DONE;
			pr_info("Pre-migration is done, userspace pid=%d\n",
				tdx->kvm.userspace_pid);
		}

		tdx_binding_slot_set_state(slot, state);
		break;
	default:
		len = 0;
		pr_err("%s: operation not supported\n", __func__);
	}

	return len;
}

/* Return true if the response isn't ready and need to block the vcpu */
static bool tdx_handle_service_migtd(struct kvm_tdx *tdx,
				     struct tdvmcall_service *cmd_hdr,
				     struct tdvmcall_service *resp_hdr)
{
	struct tdvmcall_service_migtd *cmd_migtd =
		(struct tdvmcall_service_migtd *)cmd_hdr->data;
	struct tdvmcall_service_migtd *resp_migtd =
		(struct tdvmcall_service_migtd *)resp_hdr->data;
	uint32_t status, len = 0;

	resp_migtd->cmd = cmd_migtd->cmd;

	spin_lock(&tdx->binding_slot_lock);
	switch (cmd_migtd->cmd) {
	case TDVMCALL_SERVICE_MIGTD_CMD_SHUTDOWN:
		/*TODO: end migtd */
		pr_err("%s: end migtd, not supported\n", __func__);
		status = TDVMCALL_SERVICE_S_UNSUPP;
		break;
	case TDVMCALL_SERVICE_MIGTD_CMD_WAIT:
		resp_migtd->version = TDVMCALL_SERVICE_MIGTD_WAIT_VERSION;
		if (cmd_migtd->version != resp_migtd->version) {
			pr_warn("%s: version err\n", __func__);
			status = TDVMCALL_SERVICE_S_UNSUPP;
			break;
		}
		len = migtd_wait_for_request(tdx, resp_migtd);
		status = TDVMCALL_SERVICE_S_RETURNED;
		break;
	case TDVMCALL_SERVICE_MIGTD_CMD_REPORT:
		resp_migtd->version = TDVMCALL_SERVICE_MIGTD_REPORT_VERSION;
		if (cmd_migtd->version != resp_migtd->version) {
			pr_warn("%s: version err\n", __func__);
			status = TDVMCALL_SERVICE_S_UNSUPP;
			break;
		}
		len = migtd_report_status(tdx, cmd_migtd, resp_migtd);
		if (len)
			status = TDVMCALL_SERVICE_S_RETURNED;
		else
			status = TDVMCALL_SERVICE_S_UNSUPP;
		break;
	default:
		pr_warn("%s: cmd %d not supported\n",
			 __func__, cmd_migtd->cmd);
		status = TDVMCALL_SERVICE_S_UNSUPP;
	}
	spin_unlock(&tdx->binding_slot_lock);

	resp_hdr->length += len;
	resp_hdr->status = status;

	if (resp_migtd->operation == TDVMCALL_SERVICE_MIGTD_OP_NOOP)
		return true;

	return false;
}

static void tdx_inject_notification(struct kvm_vcpu *vcpu, uint8_t vector)
{
	struct kvm_kernel_irq_routing_entry route;
	struct kvm *kvm = vcpu->kvm;
	struct msi_msg x86_msi = {
		.arch_addr_lo  = {
			.reserved_0 = 0,
			.dest_mode_logical = 0,
			.redirect_hint = 0,
			.reserved_1 = 0,
			.virt_destid_8_14 = 0,
			.destid_0_7 = kvm_xapic_id(vcpu->arch.apic) & 0xff,
		},
		.arch_addr_hi = {
			.reserved = 0,
			.destid_8_31 = 0,
		},
		.arch_data = {
			.vector = vector,
			.delivery_mode = 0,
			.dest_mode_logical = 0,
			.reserved = 0,
			.active_low = 0,
			.is_level = 0,
		},
	};

	route.msi.address_lo = x86_msi.address_lo;
	route.msi.address_hi = x86_msi.address_hi;
	route.msi.data = x86_msi.data;
	route.msi.flags = 0;
	route.msi.devid = 0;

	kvm_set_msi(&route, kvm, KVM_USERSPACE_IRQ_SOURCE_ID, 1, false);
}

static int tdx_handle_service(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_tdx *tdx = to_kvm_tdx(kvm);
	gpa_t cmd_gpa = tdvmcall_a0_read(vcpu) &
			~gfn_to_gpa(kvm_gfn_shared_mask(kvm));
	gpa_t resp_gpa = tdvmcall_a1_read(vcpu) &
			~gfn_to_gpa(kvm_gfn_shared_mask(kvm));
	uint64_t nvector = tdvmcall_a2_read(vcpu);
	struct tdvmcall_service *cmd_buf, *resp_buf;
	enum tdvmcall_service_id service_id;
	bool need_block = false;
	int ret = 1;
	unsigned long tdvmcall_ret = TDG_VP_VMCALL_INVALID_OPERAND;

	if ((nvector > 0 && nvector < 32) || nvector > 255)  {
		pr_warn("%s: interrupt not supported, nvector %lld\n",
			__func__, nvector);
		nvector = 0;
		goto err_cmd;
	}

	cmd_buf = tdvmcall_servbuf_alloc(vcpu, cmd_gpa);
	if (!cmd_buf)
		goto err_cmd;
	resp_buf = tdvmcall_servbuf_alloc(vcpu, resp_gpa);
	if (!resp_buf)
		goto err_status;
	resp_buf->length = sizeof(struct tdvmcall_service);

	service_id = tdvmcall_get_service_id(cmd_buf->guid);
	switch (service_id) {
	case TDVMCALL_SERVICE_ID_QUERY:
		tdx_handle_service_query(cmd_buf, resp_buf);
		break;
	case TDVMCALL_SERVICE_ID_MIGTD:
		if (nvector) {
			pr_warn("%s: interrupt not supported, nvector %lld\n",
				__func__, nvector);
			nvector = 0;
			break;
		}
		need_block = tdx_handle_service_migtd(tdx, cmd_buf, resp_buf);
		break;
	case TDVMCALL_SERVICE_ID_VTPM:
	case TDVMCALL_SERVICE_ID_VTPMTD:
	case TDVMCALL_SERVICE_ID_TDCM:
	case TDVMCALL_SERVICE_ID_TPA:
	case TDVMCALL_SERVICE_ID_SPDM:
		ret = 0;
		break;
	default:
		resp_buf->status = TDVMCALL_SERVICE_S_UNSUPP;
		pr_warn("%s: unsupported service type\n", __func__);
	}

	if (ret == 0) {
		/* user handles the service and update the guest status buf */
		ret = tdx_vp_vmcall_to_user(vcpu);
		kfree(resp_buf);
	} else {
		/* Update the guest status buf and free the host buf */
		tdvmcall_status_copy_and_free(resp_buf, vcpu, resp_gpa);
		tdvmcall_ret = TDG_VP_VMCALL_SUCCESS;
	}

err_status:
	kfree(cmd_buf);
	if (need_block && !nvector)
		return kvm_emulate_halt_noskip(vcpu);
err_cmd:
	if (ret) {
		tdvmcall_set_return_code(vcpu, tdvmcall_ret);

		if (nvector)
			tdx_inject_notification(vcpu, nvector);
	}

	return ret;
}

static int handle_tdvmcall(struct kvm_vcpu *vcpu)
{
	int r;

	if (tdvmcall_exit_type(vcpu))
		return tdx_emulate_vmcall(vcpu);

	trace_kvm_tdx_hypercall(tdvmcall_leaf(vcpu), kvm_rcx_read(vcpu),
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
		/*
		 * Exit to userspace device model for tear down.
		 * Because guest TD is already panicking, returning an error to
		 * guest TD doesn't make sense.  No argument check is done.
		 */
		r = tdx_vp_vmcall_to_user(vcpu);
		break;
	case TDG_VP_VMCALL_MAP_GPA:
		r = tdx_map_gpa(vcpu);
		break;
	case TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT:
		r = tdx_setup_event_notify_interrupt(vcpu);
		break;
	case TDG_VP_VMCALL_GET_QUOTE:
		r = tdx_get_quote(vcpu);
		break;
	case TDG_VP_VMCALL_SERVICE:
		r = tdx_handle_service(vcpu);
		break;
	default:
		/*
		 * Unknown VMCALL.  Toss the request to the user space as it may
		 * know how to handle.
		 */
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		r = tdx_vp_vmcall_to_user(vcpu);
		break;
	}

	tdx_trace_tdvmcall_done(vcpu);
	return r;
}

void tdx_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa, int pgd_level)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);

	if (!kvm_tdx->td_initialized) {
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
		err = tdh_mr_extend(kvm_tdx->tdr_pa, gpa + i, &out);
		if (KVM_BUG_ON(err, &kvm_tdx->kvm)) {
			pr_tdx_error(TDH_MR_EXTEND, err, &out);
			break;
		}
	}
}

static void tdx_unpin(struct kvm *kvm, gfn_t gfn, kvm_pfn_t pfn,
		      enum pg_level level)
{
	int i;

	for (i = 0; i < KVM_PAGES_PER_HPAGE(level); i++)
		put_page(pfn_to_page(pfn + i));
}

static int tdx_sept_set_private_spte(struct kvm *kvm, gfn_t gfn,
				     enum pg_level level, kvm_pfn_t pfn)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	hpa_t hpa = pfn_to_hpa(pfn);
	gpa_t gpa = gfn_to_gpa(gfn);
	struct tdx_module_output out;
	hpa_t source_pa;
	bool measure;
	u64 err;
	int i;

	if (WARN_ON_ONCE(is_error_noslot_pfn(pfn)) || !kvm_tdx->td_initialized)
		return -EINVAL;

	if (kvm_is_mmio_pfn(pfn)) {
		tdx_tdi_mmio_map(kvm_tdx, gfn, level, pfn);
		return 0;
	}

	if (!kvm_pfn_to_refcounted_page(pfn))
		return -EINVAL;

	/*
	 * Because restricted mem doesn't support page migration with
	 * a_ops->migrate_page (yet), no callback isn't triggered for KVM on
	 * page migration.  Until restricted mem supports page migration,
	 * prevent page migration.
	 * TODO: Once restricted mem introduces callback on page migration,
	 * implement it and remove get_page/put_page().
	 */
	for (i = 0; i < KVM_PAGES_PER_HPAGE(level); i++)
		get_page(pfn_to_page(pfn + i));

	/* Build-time faults are induced and handled via TDH_MEM_PAGE_ADD. */
	if (likely(is_td_finalized(kvm_tdx))) {
		err = tdh_mem_page_aug(kvm_tdx->tdr_pa, gpa, tdx_level, hpa, &out);
		if (KVM_BUG_ON(err, kvm)) {
			pr_tdx_error(TDH_MEM_PAGE_AUG, err, &out);
			tdx_unpin(kvm, gfn, pfn, level);
			return -EIO;
		}
		return 0;
	}

	/*
	 * KVM_INIT_MEM_REGION, tdx_init_mem_region(), supports only 4K page
	 * because tdh_mem_page_add() supports only 4K page.
	 */
	if (KVM_BUG_ON(level != PG_LEVEL_4K, kvm))
		return -EINVAL;

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
		return -EINVAL;
	}

	source_pa = kvm_tdx->source_pa & ~KVM_TDX_MEASURE_MEMORY_REGION;
	measure = kvm_tdx->source_pa & KVM_TDX_MEASURE_MEMORY_REGION;
	kvm_tdx->source_pa = INVALID_PAGE;

	err = tdh_mem_page_add(kvm_tdx->tdr_pa, gpa, tdx_level, hpa,
			       source_pa, &out);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_PAGE_ADD, err, &out);
		tdx_unpin(kvm, gfn, pfn, level);
		return -EIO;
	} else if (measure)
		tdx_measure_page(kvm_tdx, gpa, KVM_HPAGE_SIZE(level));

	return 0;
}

static int tdx_sept_drop_private_spte(struct kvm *kvm, gfn_t gfn,
				       enum pg_level level, kvm_pfn_t pfn)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_module_output out;
	gpa_t gpa = gfn_to_gpa(gfn);
	hpa_t hpa = pfn_to_hpa(pfn);
	hpa_t hpa_with_hkid;
	int r = 0;
	u64 err;
	int i;

	/*
	 * we couldn't block and unmap private mmio here, cause devif should
	 * be unlocked first
	 */
	if (kvm_is_mmio_pfn(pfn))
		return 0;

	if (!is_hkid_assigned(kvm_tdx)) {
		/*
		 * The HKID assigned to this TD was already freed and cache
		 * was already flushed. We don't have to flush again.
		 */
		err = tdx_reclaim_page(hpa, level, false, 0);
		if (!err)
			tdx_unpin(kvm, gfn, pfn, level);
		return 0;
	}

	if (!kvm_tdx->td_initialized)
		return 0;

	/*
	 * When zapping private page, write lock is held. So no race
	 * condition with other vcpu sept operation.  Race only with
	 * TDH.VP.ENTER.
	 */
	err = tdh_mem_page_remove(kvm_tdx->tdr_pa, gpa, tdx_level, &out);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_PAGE_REMOVE, err, &out);
		return -EIO;
	}

	for (i = 0; i < KVM_PAGES_PER_HPAGE(level); i++) {
		hpa_with_hkid = set_hkid_to_hpa(hpa, (u16)kvm_tdx->hkid);
		do {
			/*
			 * TDX_OPERAND_BUSY can happen on locking PAMT entry.
			 * Because this page was removed above, other thread
			 * shouldn't be repeatedly operating on this page.
			 * Simple retry should work.
			 */
			err = tdh_phymem_page_wbinvd(hpa_with_hkid);
		} while (err == (TDX_OPERAND_BUSY | TDX_OPERAND_ID_RCX));
		if (KVM_BUG_ON(err, kvm)) {
			pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
			r = -EIO;
		} else {
			tdx_set_page_present(hpa);
			tdx_clear_page(hpa, PAGE_SIZE);
			tdx_unpin(kvm, gfn + i, pfn + i, PG_LEVEL_4K);
		}
		hpa += PAGE_SIZE;
	}
	return r;
}

static int tdx_sept_link_private_spt(struct kvm *kvm, gfn_t gfn,
				     enum pg_level level, void *private_spt)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn);
	hpa_t hpa = __pa(private_spt);
	struct tdx_module_output out;
	u64 err;

	err = tdh_mem_sept_add(kvm_tdx->tdr_pa, gpa, tdx_level, hpa, &out);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_SEPT_ADD, err, &out);
		return -EIO;
	}

	return 0;
}

static int tdx_sept_split_private_spt(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level, void *private_spt)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn);
	hpa_t hpa = __pa(private_spt);
	struct tdx_module_output out;
	u64 err;

	/* See comment in tdx_sept_set_private_spte() */
	err = tdh_mem_page_demote(kvm_tdx->tdr_pa, gpa, tdx_level, hpa, &out);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_PAGE_DEMOTE, err, &out);
		return -EIO;
	}

	return 0;
}

static int tdx_sept_merge_private_spt(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level, void *private_spt)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_module_output out;
	gpa_t gpa = gfn_to_gpa(gfn);
	u64 err;

	/* See comment in tdx_sept_set_private_spte() */
	err = tdh_mem_page_promote(kvm_tdx->tdr_pa, gpa, tdx_level, &out);
	if (seamcall_masked_status(err) == TDX_EPT_INVALID_PROMOTE_CONDITIONS)
		/*
		 * Some pages are accepted, some pending.  Need to wait for TD
		 * to accept all pages.  Tell it the caller.
		 */
		return -EAGAIN;
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_PAGE_PROMOTE, err, &out);
		return -EIO;
	}
	WARN_ON_ONCE(out.rcx != __pa(private_spt));

	/*
	 * TDH.MEM.PAGE.PROMOTE frees the Secure-EPT page for the lower level.
	 * Flush cache for reuse.
	 */
	do {
		err = tdh_phymem_page_wbinvd(set_hkid_to_hpa(__pa(private_spt),
							     to_kvm_tdx(kvm)->hkid));
	} while (err == (TDX_OPERAND_BUSY | TDX_OPERAND_ID_RCX));
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
		return -EIO;
	}

	tdx_set_page_present(__pa(private_spt));
	tdx_clear_page(__pa(private_spt), PAGE_SIZE);
	return 0;
}

static int tdx_sept_zap_private_spte(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn);
	struct tdx_module_output out;
	u64 err;

	if (!is_hkid_assigned(kvm_tdx) || !kvm_tdx->td_initialized)
		return 0;

	err = tdh_mem_range_block(kvm_tdx->tdr_pa, gpa, tdx_level, &out);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_RANGE_BLOCK, err, &out);
		return -EIO;
	}
	WRITE_ONCE(kvm_tdx->has_range_blocked, true);

	return 0;
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

	KVM_BUG_ON(!is_hkid_assigned(kvm_tdx), &kvm_tdx->kvm);
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

	do {
		/*
		 * kvm_flush_remote_tlbs() doesn't allow to return error and
		 * retry.
		 */
		err = tdh_mem_track(kvm_tdx->tdr_pa);
	} while ((err & TDX_SEAMCALL_STATUS_MASK) == TDX_OPERAND_BUSY);

	/* Release remote vcpu waiting for TDH.MEM.TRACK in tdx_flush_tlb(). */
	atomic_dec(&kvm_tdx->tdh_mem_track);

	if (KVM_BUG_ON(err, &kvm_tdx->kvm))
		pr_tdx_error(TDH_MEM_TRACK, err, NULL);
	else
		tdx_tdi_iq_inv_iotlb(kvm_tdx);
}

static int tdx_sept_unzap_private_spte(struct kvm *kvm, gfn_t gfn,
				       enum pg_level level)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn);
	struct tdx_module_output out;
	u64 err;

	do {
		err = tdh_mem_range_unblock(kvm_tdx->tdr_pa, gpa, tdx_level, &out);

		/*
		 * tdh_mem_range_block() is accompanied with tdx_track() via kvm
		 * remote tlb flush.  Wait for the caller of
		 * tdh_mem_range_block() to complete TDX track.
		 */
	} while (err == (TDX_TLB_TRACKING_NOT_DONE | TDX_OPERAND_ID_SEPT));
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_RANGE_UNBLOCK, err, &out);
		return -EIO;
	}
	return 0;
}

static int tdx_sept_free_private_spt(struct kvm *kvm, gfn_t gfn,
				     enum pg_level level, void *private_spt)
{
	/* +1 to remove this SEPT page from the parent's entry. */
	gpa_t parent_gpa = gfn_to_gpa(gfn) & KVM_HPAGE_MASK(level + 1);
	int parent_tdx_level = pg_level_to_tdx_sept_level(level + 1);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_module_output out;
	u64 err;

	/*
	 * The HKID assigned to this TD was already freed and cache was
	 * already flushed. We don't have to flush again.
	 */
	if (!is_hkid_assigned(kvm_tdx))
		return tdx_reclaim_page(__pa(private_spt), PG_LEVEL_4K, false, 0);

	/*
	 * Inefficient. But this is only called for deleting memslot
	 * which isn't performance critical path.
	 *
	 * free_private_spt() is (obviously) called when a shadow page is being
	 * zapped.  KVM doesn't (yet) zap private SPs while the TD is active.
	 * Note: This function is for private shadow page.  Not for private
	 * guest page.   private guest page can be zapped during TD is active.
	 * shared <-> private conversion and slot move/deletion.
	 */
	if (kvm_tdx->td_initialized) {
		err = tdh_mem_range_block(kvm_tdx->tdr_pa, parent_gpa,
					  parent_tdx_level, &out);
		if (KVM_BUG_ON(err, kvm)) {
			pr_tdx_error(TDH_MEM_RANGE_BLOCK, err, &out);
			return -EIO;
		}
	}

	tdx_track(kvm_tdx);

	err = tdh_mem_sept_remove(kvm_tdx->tdr_pa, parent_gpa,
				  parent_tdx_level, &out);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_SEPT_REMOVE, err, &out);
		return -EIO;
	}

	err = tdh_phymem_page_wbinvd(set_hkid_to_hpa(__pa(private_spt),
						     kvm_tdx->hkid));
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
		return -EIO;
	}

	tdx_set_page_present(__pa(private_spt));
	tdx_clear_page(__pa(private_spt), PAGE_SIZE);
	return 0;
}

int tdx_sept_tlb_remote_flush_with_range(struct kvm *kvm,
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

int tdx_sept_tlb_remote_flush(struct kvm *kvm)
{
	struct kvm_tlb_range range = {
		.start_gfn = 0,
		.pages = -1ULL,
	};

	return tdx_sept_tlb_remote_flush_with_range(kvm, &range);
}

static int tdx_sept_remove_private_spte(struct kvm *kvm, gfn_t gfn,
					 enum pg_level level, kvm_pfn_t pfn)
{
	/*
	 * TDX requires TLB tracking before dropping private page.  Do
	 * it here, although it is also done later.
	 * If hkid isn't assigned, the guest is destroying and no vcpu
	 * runs further.  TLB shootdown isn't needed.
	 *
	 * TODO: implement with_range version for optimization.
	 * kvm_flush_remote_tlbs_with_address(kvm, gfn, 1);
	 *   => tdx_sept_tlb_remote_flush_with_range(kvm, gfn,
	 *                                 KVM_PAGES_PER_HPAGE(level));
	 */
	if (is_hkid_assigned(to_kvm_tdx(kvm)))
		kvm_flush_remote_tlbs(kvm);

	return tdx_sept_drop_private_spte(kvm, gfn, level, pfn);
}

static void tdx_link_shared_spte(struct kvm *kvm, gfn_t gfn, int level,
				 u64 spte)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_module_output out;
	gpa_t gpa = gfn_to_gpa(gfn);
	u64 gpa_info;
	u64 err;

	if (!is_td(kvm) || !tdx_io_support())
		return;

	gpa_info = (u64)gpa | (level - 1);

	err = tdh_mem_shared_sept_wr(gpa_info, kvm_tdx->tdr_pa, spte, &out);
	pr_info("%s gpa_info=0x%llx, spte=0x%llx, err=0x%llx, out_rcx=0x%llx, out_rdx=0x%llx\n",
		__func__, gpa_info, spte, err, out.rcx, out.rdx);
	if (WARN_ON_ONCE(err))
		pr_tdx_error(TDH_MEM_SHARED_SEPT_WR, err, &out);
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
		 * For the RWX bits, always treat them as write faults. This
		 * avoids COW allocations, which will cause TDAUGPAGE failures
		 * due to aliasing a single HPA to multiple GPAs.
		 *
		 * For other bits, keep them the same as that reported from the
		 * TDX module. For example, the fault may be triggered via
		 * write-blocking the private page, and this is detected from
		 * the exit_qualification bits returned from the TDX module.
		 */
		exit_qual = tdexit_exit_qual(vcpu) & (~VMX_EPT_RWX_MASK);
		exit_qual |= EPT_VIOLATION_ACC_WRITE;
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

	trace_kvm_page_fault(vcpu, tdexit_gpa(vcpu), exit_qual);
	return __vmx_handle_ept_violation(vcpu, tdexit_gpa(vcpu), exit_qual, err_page_level);
}

static int tdx_handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	WARN_ON_ONCE(1);

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
	else if (unlikely(exit_reason.full == TDX_SEAMCALL_UD)) {
		kvm_spurious_fault();
		return 1;
	}

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

	/*
	 * When TDX module saw VMEXIT_REASON_FAILED_VMENTER_MC etc, TDH.VP.ENTER
	 * returns with TDX_SUCCESS | exit_reason with failed_vmentry = 1.
	 * Because TDX module maintains TD VMCS correctness, usually vmentry
	 * failure shouldn't happen.  In some corner cases it can happen.  For
	 * example
	 * - machine check during entry: EXIT_REASON_MCE_DURING_VMENTRY
	 * - TDH.VP.WR with debug TD.  VMM can corrupt TD VMCS
	 *   - EXIT_REASON_INVALID_STATE
	 *   - EXIT_REASON_MSR_LOAD_FAIL
	 */
	if (unlikely(exit_reason.failed_vmentry)) {
		pr_err("TDExit: exit_reason 0x%016llx qualification=%016lx ext_qualification=%016lx\n",
		       exit_reason.full, tdexit_exit_qual(vcpu), tdexit_ext_exit_qual(vcpu));
		vcpu->run->exit_reason = KVM_EXIT_FAIL_ENTRY;
		vcpu->run->fail_entry.hardware_entry_failure_reason
			= exit_reason.full;
		vcpu->run->fail_entry.cpu = vcpu->arch.last_vmentry_cpu;

		return 0;
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
	vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
	vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON;
	vcpu->run->internal.ndata = 2;
	vcpu->run->internal.data[0] = exit_reason.full;
	vcpu->run->internal.data[1] = vcpu->arch.last_vmentry_cpu;
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

static bool tdx_is_emulated_kvm_msr(u32 index, bool write)
{
	switch (index) {
	case MSR_KVM_POLL_CONTROL:
		return true;
	default:
		return false;
	}
}

bool tdx_has_emulated_msr(u32 index, bool write)
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
	case MSR_PLATFORM_INFO:
	case MSR_MISC_FEATURES_ENABLES:
	case MSR_IA32_MCG_CAP:
	case MSR_IA32_MCG_STATUS:
	case MSR_IA32_MCG_CTL:
	case MSR_IA32_MCG_EXT_CTL:
	case MSR_IA32_MC0_CTL ... MSR_IA32_MCx_CTL(KVM_MAX_MCE_BANKS) - 1:
	case MSR_IA32_MC0_CTL2 ... MSR_IA32_MCx_CTL2(KVM_MAX_MCE_BANKS) - 1:
		/* MSR_IA32_MCx_{CTL, STATUS, ADDR, MISC, CTL2} */
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
	case 0x4b564d00 ... 0x4b564dff:
		/* KVM custom MSRs */
		return tdx_is_emulated_kvm_msr(index, write);
	default:
		return false;
	}
}

int tdx_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	if (msr->host_initiated || tdx_has_emulated_msr(msr->index, false))
		return kvm_get_msr_common(vcpu, msr);
	return 1;
}

int tdx_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	if (msr->host_initiated || tdx_has_emulated_msr(msr->index, true))
		return kvm_set_msr_common(vcpu, msr);
	return 1;
}

#ifdef CONFIG_KVM_SMM
int tdx_smi_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	/* SMI isn't supported for TDX. */
	WARN_ON_ONCE(1);
	return false;
}

int tdx_enter_smm(struct kvm_vcpu *vcpu, union kvm_smram *smram)
{
	/* smi_allowed() is always false for TDX as above. */
	WARN_ON_ONCE(1);
	return 0;
}

int tdx_leave_smm(struct kvm_vcpu *vcpu, const union kvm_smram *smram)
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
#endif

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
	if (!to_tdx(vcpu)->vcpu_initialized)
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
	if (!tdx->vcpu_initialized)
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
void tdx_inject_exception(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx;
	unsigned int vector;
	bool has_error_code;
	u32 error_code;
	u32 intr_info;

	if (KVM_BUG_ON(!is_debug_td(vcpu), vcpu->kvm))
		return;

	tdx = to_tdx(vcpu);
	vector = vcpu->arch.exception.vector;
	has_error_code = vcpu->arch.exception.has_error_code;
	error_code = vcpu->arch.exception.error_code;
	intr_info = vector | INTR_INFO_VALID_MASK;

	/*
	 * Emulate BP injection due to
	 * TDX doesn't support exception injection
	 */
	if (vector == BP_VECTOR)
		return tdx_emulate_inject_bp_begin(vcpu);

	kvm_deliver_exception_payload(vcpu, &vcpu->arch.exception);

	if (has_error_code) {
		td_vmcs_write32(tdx, VM_ENTRY_EXCEPTION_ERROR_CODE,
				error_code);
		intr_info |= INTR_INFO_DELIVER_CODE_MASK;
	}

	if (kvm_exception_is_soft(vector)) {
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

	if (!is_debug_td(vcpu) || !tdx->vcpu_initialized)
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
static const struct kvm_cpuid_entry2 *tdx_find_cpuid_entry(const struct kvm_cpuid2 *cpuid,
							   u32 function, u32 index)
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

	if (kvm->created_vcpus)
		return -EBUSY;
	td_params->max_vcpus = kvm->max_vcpus;
	td_params->attributes = init_vm->attributes;

	entry = tdx_find_cpuid_entry(cpuid, 0x7, 0);
	if (entry) {
		u64 mask = __feature_bit(X86_FEATURE_HLE) |
			   __feature_bit(X86_FEATURE_RTM);

		if ((entry->ebx & mask) &&
		    (entry->ebx & mask) != mask) {
			pr_info_ratelimited("{HLE,RTM} must be set same!\n");
				return -EINVAL;
		} else {
			to_kvm_tdx(kvm)->tsx_supported = !!(entry->ebx & mask);
		}
	}

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

		if (config->leaf == 0x1 &&
		    (value->ecx & __feature_bit(X86_FEATURE_MWAIT)) &&
		    !kvm_mwait_in_guest(kvm)) {
			pr_info_ratelimited("Invalid mwait configuration!\n");
			return -EINVAL;
		}
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

	if ((td_params->attributes & TDX_TD_ATTRIBUTE_MIG) &&
	    tdx_mig_state_create(to_kvm_tdx(kvm))) {
		pr_warn("Failed to create mig state\n");
		return -ENOMEM;
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

	return 0;
}

static int __tdx_td_init(struct kvm *kvm, struct td_params *td_params)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	cpumask_var_t packages;
	unsigned long *tdcs_pa = NULL;
	unsigned long tdr_pa = 0;
	unsigned long va;
	int ret, i;
	u64 err;

	ret = tdx_keyid_alloc();
	if (ret < 0)
		return ret;
	kvm_tdx->hkid = ret;
	kvm_tdx->misc_cg = get_current_misc_cg();
	ret = misc_cg_try_charge(MISC_CG_RES_TDX, kvm_tdx->misc_cg, 1);
	if (ret)
		goto free_hkid;

	va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!va)
		goto free_hkid;
	tdr_pa = __pa(va);

	tdcs_pa = kcalloc(tdx_caps.tdcs_nr_pages, sizeof(*kvm_tdx->tdcs_pa),
			  GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!tdcs_pa)
		goto free_tdr;
	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++) {
		va = __get_free_page(GFP_KERNEL_ACCOUNT);
		if (!va)
			goto free_tdcs;
		tdcs_pa[i] = __pa(va);
	}

	if (!zalloc_cpumask_var(&packages, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto free_tdcs;
	}
	cpus_read_lock();
	/*
	 * Need at least one CPU of the package to be online in order to
	 * program all packages for host key id.  Check it.
	 */
	for_each_present_cpu(i)
		cpumask_set_cpu(topology_physical_package_id(i), packages);
	for_each_online_cpu(i)
		cpumask_clear_cpu(topology_physical_package_id(i), packages);
	if (!cpumask_empty(packages)) {
		ret = -EIO;
		/*
		 * Because it's hard for human operator to figure out the
		 * reason, warn it.
		 */
		pr_warn("All packages need to have online CPU to create TD. Online CPU and retry.\n");
		goto free_packages;
	}

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
	err = tdh_mng_create(tdr_pa, kvm_tdx->hkid);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_CREATE, err, NULL);
		ret = -EIO;
		goto free_packages;
	}
	kvm_tdx->tdr_pa = tdr_pa;

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
				      &kvm_tdx->tdr_pa, true);
		mutex_unlock(&tdx_mng_key_config_lock[pkg]);
		if (ret)
			break;
	}
	if (!ret)
		atomic_inc(&nr_configured_hkid);
	cpus_read_unlock();
	free_cpumask_var(packages);
	if (ret)
		goto teardown;

	kvm_tdx->tdcs_pa = tdcs_pa;
	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++) {
		err = tdh_mng_addcx(kvm_tdx->tdr_pa, tdcs_pa[i]);
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_MNG_ADDCX, err, NULL);
			for (i++; i < tdx_caps.tdcs_nr_pages; i++) {
				free_page((unsigned long)__va(tdcs_pa[i]));
				tdcs_pa[i] = 0;
			}
			ret = -EIO;
			goto teardown;
		}
	}

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

free_packages:
	cpus_read_unlock();
	free_cpumask_var(packages);
free_tdcs:
	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++) {
		if (tdcs_pa[i])
			free_page((unsigned long)__va(tdcs_pa[i]));
	}
	kfree(tdcs_pa);
	kvm_tdx->tdcs_pa = NULL;

free_tdr:
	if (tdr_pa)
		free_page((unsigned long)__va(tdr_pa));
	kvm_tdx->tdr_pa = 0;
free_hkid:
	if (is_hkid_assigned(kvm_tdx))
		tdx_hkid_free(kvm_tdx);
	return ret;
}

int tdx_td_post_init(struct kvm_tdx *kvm_tdx)
{
	kvm_tdx->tsc_offset = td_tdcs_exec_read64(kvm_tdx, TD_TDCS_EXEC_TSC_OFFSET);
	kvm_tdx->mmio_offset = td_tdr_tdxio_read64(kvm_tdx, TD_TDR_TDXIO_RND_HPA_OFFSET);
	kvm_tdx->td_initialized = true;

	return 0;
}

static int tdx_td_init(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_tdx_init_vm *init_vm = NULL;
	struct td_params *td_params = NULL;
	struct tdx_module_output out;
	u64 err;
	void *entries_end;
	int ret;

	BUILD_BUG_ON(sizeof(*init_vm) != 16 * 1024);
	BUILD_BUG_ON((sizeof(*init_vm) - offsetof(typeof(*init_vm), entries)) /
		     sizeof(init_vm->entries[0]) < KVM_MAX_CPUID_ENTRIES);
	BUILD_BUG_ON(sizeof(struct td_params) != 1024);

	if (is_hkid_assigned(kvm_tdx))
		return -EINVAL;

	if (cmd->flags && cmd->flags != KVM_TDX_INIT_VM_F_POST_INIT)
		return -EINVAL;

	init_vm = kzalloc(sizeof(*init_vm), GFP_KERNEL);
	if (!init_vm)
		return -ENOMEM;
	if (copy_from_user(init_vm, (void __user *)cmd->data, sizeof(*init_vm))) {
		ret = -EFAULT;
		goto out;
	}

	ret = -EINVAL;
	if (init_vm->cpuid.padding)
		goto out;
	/* init_vm->entries shouldn't overrun. */
	entries_end = init_vm->entries + init_vm->cpuid.nent;
	if (entries_end > (void *)(init_vm + 1))
		goto out;
	/* Unused part must be zero. */
	if (memchr_inv(entries_end, 0, (void *)(init_vm + 1) - entries_end))
		goto out;

	td_params = kzalloc(sizeof(struct td_params), GFP_KERNEL);
	if (!td_params) {
		ret = -ENOMEM;
		goto out;
	}

	ret = setup_tdparams(kvm, td_params, init_vm);
	if (ret)
		goto out;

	ret = __tdx_td_init(kvm, td_params);
	if (ret)
		goto out;

	kvm_tdx->attributes = td_params->attributes;
	kvm_tdx->xfam = td_params->xfam;
	kvm_tdx->eptp_controls = td_params->eptp_controls;

	if (td_params->exec_controls & TDX_EXEC_CONTROL_MAX_GPAW)
		kvm->arch.gfn_shared_mask = gpa_to_gfn(BIT_ULL(51));
	else
		kvm->arch.gfn_shared_mask = gpa_to_gfn(BIT_ULL(47));

	if (cmd->flags != KVM_TDX_INIT_VM_F_POST_INIT) {
		err = tdh_mng_init(kvm_tdx->tdr_pa, __pa(td_params), &out);
		if ((err & TDX_SEAMCALL_STATUS_MASK) == TDX_OPERAND_INVALID) {
			/* Because a user gives operands, don't warn. */
			ret = -EINVAL;
			goto out;
		} else if (WARN_ON_ONCE(err)) {
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

static int tdx_init_mem_region(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_tdx_init_mem_region region;
	struct kvm_vcpu *vcpu;
	struct page *page;
	u64 error_code;
	kvm_pfn_t pfn;
	int idx, ret = 0;

	/* The BSP vCPU must be created before initializing memory regions. */
	if (!atomic_read(&kvm->online_vcpus))
		return -EINVAL;

	if (cmd->flags & ~KVM_TDX_MEASURE_MEMORY_REGION)
		return -EINVAL;

	if (copy_from_user(&region, (void __user *)cmd->data, sizeof(region)))
		return -EFAULT;

	/* Sanity check */
	if (!IS_ALIGNED(region.source_addr, PAGE_SIZE) ||
	    !IS_ALIGNED(region.gpa, PAGE_SIZE) ||
	    !region.nr_pages ||
	    region.gpa + (region.nr_pages << PAGE_SHIFT) <= region.gpa ||
	    !kvm_is_private_gpa(kvm, region.gpa) ||
	    !kvm_is_private_gpa(kvm, region.gpa + (region.nr_pages << PAGE_SHIFT)))
		return -EINVAL;

	vcpu = kvm_get_vcpu(kvm, 0);
	if (mutex_lock_killable(&vcpu->mutex))
		return -EINTR;

	vcpu_load(vcpu);
	idx = srcu_read_lock(&kvm->srcu);

	kvm_mmu_reload(vcpu);

	while (region.nr_pages) {
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}

		if (need_resched())
			cond_resched();

		/* Pin the source page. */
		ret = get_user_pages_fast(region.source_addr, 1, 0, &page);
		if (ret < 0)
			break;
		if (ret != 1) {
			ret = -ENOMEM;
			break;
		}

		kvm_tdx->source_pa = pfn_to_hpa(page_to_pfn(page)) |
				     (cmd->flags & KVM_TDX_MEASURE_MEMORY_REGION);

		/* TODO: large page support. */
		error_code = TDX_SEPT_PFERR;
		error_code |= (PG_LEVEL_4K << PFERR_LEVEL_START_BIT) &
			PFERR_LEVEL_MASK;
		pfn = kvm_mmu_map_tdp_page(vcpu, region.gpa, error_code,
					   PG_LEVEL_4K, false);
		if (is_error_noslot_pfn(pfn) || kvm->vm_bugged)
			ret = -EFAULT;
		else
			ret = 0;

		put_page(page);
		if (ret)
			break;

		region.source_addr += PAGE_SIZE;
		region.gpa += PAGE_SIZE;
		region.nr_pages--;
	}

	srcu_read_unlock(&kvm->srcu, idx);
	vcpu_put(vcpu);

	mutex_unlock(&vcpu->mutex);

	if (copy_to_user((void __user *)cmd->data, &region, sizeof(region)))
		ret = -EFAULT;

	return ret;
}

static int tdx_td_finalizemr(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	u64 err;

	if (!is_hkid_assigned(kvm_tdx) || is_td_finalized(kvm_tdx))
		return -EINVAL;

	err = tdh_mr_finalize(kvm_tdx->tdr_pa);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MR_FINALIZE, err, NULL);
		return -EIO;
	}

	/*
	 * Blindly do TDH_MEM_TRACK after finalizing the measurement to handle
	 * the case where SEPT entries were zapped/blocked, e.g. from failed
	 * NUMA balancing, after they were added to the TD via
	 * tdx_init_mem_region().  TDX module doesn't allow TDH_MEM_TRACK prior
	 * to TDH.MR.FINALIZE, and conversely requires TDH.MEM.TRACK for entries
	 * that were TDH.MEM.RANGE.BLOCK'd prior to TDH.MR.FINALIZE.
	 */
	(void)tdh_mem_track(to_kvm_tdx(kvm)->tdr_pa);
	tdx_tdi_iq_inv_iotlb(kvm_tdx);

	kvm_tdx->finalized = true;
	return 0;
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
	if (tdx_binding_slot_get_state(slot) != TDX_BINDING_SLOT_STATE_INIT)
		return -EPERM;

	err = tdh_servtd_prebind(usertd_tdx->tdr_pa,
				 page_to_phys(hash_page),
				 slot_id,
				 servtd.attr,
				 servtd.type);
	__free_page(hash_page);
	if (err) {
		pr_warn("failed to prebind servtd, err=%llx\n", err);
		return -EIO;
	}

	tdx_binding_slot_set_state(slot, TDX_BINDING_SLOT_STATE_PREBOUND);
	if (copy_to_user((void __user *)cmd->data,
			 &servtd, sizeof(struct kvm_tdx_servtd)))
		return -EFAULT;

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
	err = tdh_servtd_bind(servtd_tdx->tdr_pa,
			      usertd_tdx->tdr_pa,
			      slot_id,
			      servtd->attr,
			      servtd->type,
			      &out);
	if (KVM_BUG_ON(err, &usertd_tdx->kvm)) {
		pr_tdx_error(TDH_SERVTD_BIND, err, &out);
		return -EIO;
	}

	tdx_binding_slot_bound_set_info(slot, out.rcx, out.r10,
					out.r11, out.r12, out.r13);
	tdx_binding_slot_set_state(slot, TDX_BINDING_SLOT_STATE_BOUND);

	return 0;
}

static int tdx_servtd_add_binding_slot(struct kvm_tdx *servtd_tdx,
				       struct tdx_binding_slot *slot)
{
	int i, ret = 0;

	spin_lock(&servtd_tdx->binding_slot_lock);
	for (i = 0; i < SERVTD_SLOTS_MAX; i++) {
		if (slot == servtd_tdx->usertd_binding_slots[i])
			goto out_unlock;

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
	if (!servtd_kvm || !is_td(servtd_kvm)) {
		pr_err("%s: servtd not found, pid=%d\n", __func__, servtd.pid);
		return -ENOENT;
	}
	servtd_tdx = to_kvm_tdx(servtd_kvm);

	/* Each type of servtd has one slot, so reuse the type number as id */
	slot_id = servtd.type;
	slot = &usertd_tdx->binding_slots[slot_id];

	ret = tdx_servtd_do_bind(usertd_tdx, servtd_tdx, &servtd, slot);
	if (ret)
		return ret;

	return tdx_servtd_add_binding_slot(servtd_tdx, slot);

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
		}
	}
}

static int tdx_set_migration_info(struct kvm *kvm,
				  struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *servtd_tdx;
	struct kvm_tdx *usertd_tdx = to_kvm_tdx(kvm);
	struct kvm_tdx_set_migration_info info;
	struct tdx_binding_slot *slot;
	struct tdx_binding_slot_migtd *migtd_data;

	if (copy_from_user(&info, (void __user *)cmd->data,
			   sizeof(struct kvm_tdx_set_migration_info)))
		return -EFAULT;

	if (cmd->flags ||
	    info.version != KVM_TDX_SET_MIGRATION_INFO_VERSION)
		return -EINVAL;

	slot = &usertd_tdx->binding_slots[KVM_TDX_SERVTD_TYPE_MIGTD];
	servtd_tdx = slot->servtd_tdx;
	if (!servtd_tdx)
		return -ENOENT;

	migtd_data = &slot->migtd_data;
	spin_lock(&servtd_tdx->binding_slot_lock);

	migtd_data->vsock_port = info.vsock_port;
	migtd_data->is_src = info.is_src;
	tdx_binding_slot_set_state(slot, TDX_BINDING_SLOT_STATE_PREMIG_WAIT);

	spin_unlock(&servtd_tdx->binding_slot_lock);

	tdx_notify_servtd(servtd_tdx);
	return 0;
}

static int tdx_get_migration_info(struct kvm *kvm,
				  struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *usertd_tdx = to_kvm_tdx(kvm);
	struct kvm_tdx_get_migration_info info;
	struct tdx_binding_slot *slot;

	if (copy_from_user(&info, (void __user *)cmd->data,
			   sizeof(struct kvm_tdx_get_migration_info)))
		return -EFAULT;

	if (cmd->flags ||
	    info.version != KVM_TDX_GET_MIGRATION_INFO_VERSION)
		return -EINVAL;

	slot = &usertd_tdx->binding_slots[KVM_TDX_SERVTD_TYPE_MIGTD];
	if (tdx_binding_slot_get_state(slot) ==
			TDX_BINDING_SLOT_STATE_PREMIG_DONE)
		info.premig_done = 1;
	else
		info.premig_done = 0;

	if (copy_to_user((void __user *)cmd->data, &info,
			 sizeof(struct kvm_tdx_get_migration_info)))
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
	case KVM_TDX_SET_MIGRATION_INFO:
		r = tdx_set_migration_info(kvm, &tdx_cmd);
		break;
	case KVM_TDX_GET_MIGRATION_INFO:
		r = tdx_get_migration_info(kvm, &tdx_cmd);
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

int tdx_td_vcpu_setup(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	unsigned long *tdvpx_pa = tdx->tdvpx_pa;
	int i;
	u64 err;

	err = tdh_vp_create(kvm_tdx->tdr_pa, tdx->tdvpr_pa);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_VP_CREATE, err, NULL);
		return -EIO;
	}

	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++) {
		err = tdh_vp_addcx(tdx->tdvpr_pa, tdvpx_pa[i]);
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_VP_ADDCX, err, NULL);
			for (; i < tdx_caps.tdvpx_nr_pages; i++) {
				free_page((unsigned long)__va(tdvpx_pa[i]));
				tdvpx_pa[i] = 0;
			}
			return -EIO;
		}
	}

	return 0;
}

void tdx_td_vcpu_post_init(struct vcpu_tdx *tdx)
{
	struct kvm_vcpu *vcpu = &tdx->vcpu;
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);

	if (!kvm_tdx->td_initialized)
		return;

	td_vmcs_write16(tdx, POSTED_INTR_NV, POSTED_INTR_VECTOR);
	td_vmcs_write64(tdx, POSTED_INTR_DESC_ADDR, __pa(&tdx->pi_desc));
	td_vmcs_setbit32(tdx, PIN_BASED_VM_EXEC_CONTROL, PIN_BASED_POSTED_INTR);

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

	vcpu->arch.tsc_offset = to_kvm_tdx(vcpu->kvm)->tsc_offset;
	vcpu->arch.l1_tsc_offset = vcpu->arch.tsc_offset;
	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	tdx->vcpu_initialized = true;
}

static int tdx_td_vcpu_init(struct kvm_vcpu *vcpu, u64 vcpu_rcx)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	unsigned long *tdvpx_pa = NULL;
	unsigned long tdvpr_pa;
	unsigned long va;
	int ret, i;
	u64 err;

	if (tdx->tdvpr_pa)
		return -EINVAL;

	va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!va)
		return -ENOMEM;
	tdvpr_pa = __pa(va);
	tdx->tdvpr_pa = tdvpr_pa;

	tdvpx_pa = kcalloc(tdx_caps.tdvpx_nr_pages, sizeof(*tdx->tdvpx_pa),
			   GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!tdvpx_pa) {
		ret = -ENOMEM;
		goto free_tdvpr;
	}
	tdx->tdvpx_pa = tdvpx_pa;

	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++) {
		va = __get_free_page(GFP_KERNEL_ACCOUNT);
		if (!va)
			goto free_tdvpx;
		tdvpx_pa[i] = __pa(va);
	}

	/*
	 * Keep the tdvpr and tdvpx pages allocated above, but adding them to
	 * the TDX module and the TDH_VP_CREATE seamcall require TD to be
	 * initialized.
	 */
	if (!kvm_tdx->td_initialized)
		return 0;

	ret = tdx_td_vcpu_setup(vcpu);
	if (ret)
		goto td_bugged_free_tdvpx;

	err = tdh_vp_init(tdx->tdvpr_pa, vcpu_rcx);
	if (WARN_ON_ONCE(err)) {
		ret = -EIO;
		pr_tdx_error(TDH_VP_INIT, err, NULL);
		goto td_bugged;
	}

	return 0;

td_bugged_free_tdvpx:
	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++) {
		free_page((unsigned long)__va(tdvpx_pa[i]));
		tdvpx_pa[i] = 0;
	}
	kfree(tdvpx_pa);
td_bugged:
	vcpu->kvm->vm_bugged = true;
	return ret;

free_tdvpx:
	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++)
		if (tdvpx_pa[i])
			free_page((unsigned long)__va(tdvpx_pa[i]));
	kfree(tdvpx_pa);
	tdx->tdvpx_pa = NULL;
free_tdvpr:
	if (tdvpr_pa)
		free_page((unsigned long)__va(tdvpr_pa));
	tdx->tdvpr_pa = 0;

	return ret;
}

int tdx_vcpu_ioctl(struct kvm_vcpu *vcpu, void __user *argp)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct kvm_tdx_cmd cmd;
	int ret;

	if (tdx->vcpu_initialized)
		return -EINVAL;

	if (!is_hkid_assigned(kvm_tdx) || is_td_finalized(kvm_tdx))
		return -EINVAL;

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;

	if (cmd.error || cmd.unused)
		return -EINVAL;

	/* Currently only KVM_TDX_INTI_VCPU is defined for vcpu operation. */
	if (cmd.flags || cmd.id != KVM_TDX_INIT_VCPU)
		return -EINVAL;

	ret = tdx_td_vcpu_init(vcpu, (u64)cmd.data);
	if (ret)
		return ret;

	tdx_td_vcpu_post_init(tdx);

	return 0;
}

static void tdx_guest_pmi_handler(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_tdx  *tdx;

	vcpu = kvm_get_running_vcpu();

	WARN_ON_ONCE(!vcpu || !is_td_vcpu(vcpu));

	tdx = to_kvm_tdx(vcpu->kvm);
	WARN_ON_ONCE(!(tdx->attributes & TDX_TD_ATTRIBUTE_PERFMON));

	kvm_make_request(KVM_REQ_PMI, vcpu);
}

/* Clear poisoned bit to avoid further #MC */
static int tdx_mce_notifier(struct notifier_block *nb, unsigned long val,
			    void *data)
{
	const void *zero_page = (const void *) __va(page_to_phys(ZERO_PAGE(0)));
	struct mce *m = (struct mce *)data;
	unsigned long kaddr;
	unsigned long addr;
	struct page *page;
	u16 hkid;

	/* Direct write is needed to clear poison bit. */
	if (!boot_cpu_has(X86_FEATURE_MOVDIR64B))
		return NOTIFY_DONE;

	/* Handle memory failure only. */
	if (!m)
		return NOTIFY_DONE;
	if (!mce_is_memory_error(m))
		return NOTIFY_DONE;

	addr = m->addr & ((1ULL << boot_cpu_data.x86_phys_bits) - 1);
	hkid = m->addr >> boot_cpu_data.x86_phys_bits;

	/* Is hkid used for TDX? */
	if (hkid < tdx_global_keyid)
		return NOTIFY_DONE;

	/*
	 * MCE handler may make the page non-present in direct map. Map the page
	 * to access.  Use VM_FLUSH_RESET_PERMS flag to tlb flush at vunmap()
	 * and reset direct mapping region.
	 */
	page = pfn_to_page(addr >> PAGE_SHIFT);
	kaddr = (unsigned long)vmap(&page, 1, VM_FLUSH_RESET_PERMS, PAGE_KERNEL);
	if (!kaddr)
		return NOTIFY_DONE;

	/* Adjust page offset. */
	kaddr |= addr & ~PAGE_MASK;
	/* Align to cache line. */
	kaddr = ALIGN_DOWN(kaddr, 64);
	/* Direct write to clear poison bit. */
	movdir64b((void *)kaddr, zero_page);
	__mb();

	vunmap((void *)(kaddr & PAGE_MASK));

	pr_err("cleared poisoned cache hkid 0x%x pa 0x%lx\n", hkid, addr);
	return NOTIFY_DONE;
}

static struct notifier_block tdx_mce_nb = {
	.notifier_call = tdx_mce_notifier,
	.priority = MCE_PRIO_CEC,
};

bool is_sys_rd_supported(void)
{
	return !!tdx_caps.sys_rd;
}

static int tdx_module_setup(void)
{
	const struct tdsysinfo_struct *tdsysinfo;
	struct tdx_module_output out;
	int ret = 0;
	u64 err;

	BUILD_BUG_ON(sizeof(*tdsysinfo) > TDSYSINFO_STRUCT_SIZE);
	BUILD_BUG_ON(TDX_MAX_NR_CPUID_CONFIGS != 37);

	ret = tdx_enable();
	if (ret) {
		pr_info("Failed to initialize TDX module.\n");
		return ret;
	}

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
	 * later, as we keep max_servtds being 0.
	 */
	if (err == TDX_SUCCESS)
		tdx_caps.max_servtds = out.r8;
	pr_info("tdx: max servtds supported per user TD is %d\n",
		tdx_caps.max_servtds);

	ret = tdx_mig_capabilities_setup();
	if (ret)
		pr_info("tdx: live migration not supported\n");
	else
		pr_info("tdx: live migration supported\n");

	if (!memcpy(tdx_caps.cpuid_configs, tdsysinfo->cpuid_configs,
			tdsysinfo->num_cpuid_config *
			sizeof(struct tdx_cpuid_config)))
		return -EIO;

	pr_info("TDX is supported.\n");
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
				      &is_private);
	if (ret) {
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
	if (!is_td(kvm))
		return -EINVAL;

	if (!(to_kvm_tdx(kvm)->attributes & TDX_TD_ATTRIBUTE_DEBUG))
		return -EINVAL;

	if (!is_hkid_assigned(to_kvm_tdx(kvm)))
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

	err = tdh_mem_rd(to_kvm_tdx(kvm)->tdr_pa, addr, &tdx_ret);
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

	err = tdh_mem_wr(to_kvm_tdx(kvm)->tdr_pa, addr, *val, &tdx_ret);
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

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	int max_pkgs;
	int i;
	int r;

	if (!enable_ept) {
		pr_warn("Cannot enable TDX with EPT disabled\n");
		return -EINVAL;
	}

	tdx_module = kvm_register_fw(KVM_FIRMWARE_TDX_MODULE);
	if (IS_ERR(tdx_module))
		return PTR_ERR(tdx_module);

	for (i = 0; i < ARRAY_SIZE(tdx_uret_msrs); i++) {
		/*
		 * Here it checks if MSRs (tdx_uret_msrs) can be saved/restored
		 * before returning to user space.
		 *
		 * this_cpu_ptr(user_return_msrs)->registered isn't checked
		 * because the registration is done at vcpu runtime by
		 * kvm_set_user_return_msr().
		 * Here is setting up cpu feature before running vcpu,
		 * registered is already false.
		 */
		tdx_uret_msrs[i].slot = kvm_find_user_return_msr(tdx_uret_msrs[i].msr);
		if (tdx_uret_msrs[i].slot == -1) {
			/* If any MSR isn't supported, it is a KVM bug */
			pr_err("MSR %x isn't included by kvm_find_user_return_msr\n",
				tdx_uret_msrs[i].msr);
			return -EIO;
		}
	}
	tdx_uret_tsx_ctrl_slot = kvm_find_user_return_msr(MSR_IA32_TSX_CTRL);
	if (unlikely(tdx_uret_tsx_ctrl_slot == -1 &&
		     boot_cpu_has(X86_FEATURE_MSR_TSX_CTRL))) {
		pr_err("MSR_IA32_TSX_CTRL isn't included by kvm_find_user_return_msr\n");
		return -EIO;
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

	/* TDX requires VMX. */
	r = vmxon_all();
	if (!r) {
		tdx_update_fw(false);
		r = tdx_module_setup();
	}
	vmxoff_all();
	if (r)
		return r;

	x86_ops->link_private_spt = tdx_sept_link_private_spt;
	x86_ops->free_private_spt = tdx_sept_free_private_spt;
	x86_ops->split_private_spt = tdx_sept_split_private_spt;
	x86_ops->merge_private_spt = tdx_sept_merge_private_spt;
	x86_ops->set_private_spte = tdx_sept_set_private_spte;
	x86_ops->remove_private_spte = tdx_sept_remove_private_spte;
	x86_ops->zap_private_spte = tdx_sept_zap_private_spte;
	x86_ops->unzap_private_spte = tdx_sept_unzap_private_spte;
	x86_ops->drop_private_spte = tdx_sept_drop_private_spte;
	x86_ops->mem_enc_read_memory = tdx_read_guest_memory;
	x86_ops->mem_enc_write_memory = tdx_write_guest_memory;
	x86_ops->write_block_private_pages = tdx_write_block_private_pages;
	x86_ops->write_unblock_private_page = tdx_write_unblock_private_page;
	x86_ops->restore_private_page = tdx_restore_private_page;
	x86_ops->import_private_pages = tdx_mig_stream_import_private_pages;
	x86_ops->link_shared_spte = tdx_link_shared_spte;
	kvm_set_tdx_guest_pmi_handler(tdx_guest_pmi_handler);
	mce_register_decode_chain(&tdx_mce_nb);

	r = kvm_tdx_mig_stream_ops_init();
	if (r) {
		pr_err("%s: failed to init tdx mig, %d\n", __func__, r);
		return r;
	}

	return tdx_module_update_init();
}

void tdx_hardware_unsetup(void)
{
	if (!enable_ept || !enable_tdx)
		return;

	kvm_tdx_mig_stream_ops_exit();
	mce_unregister_decode_chain(&tdx_mce_nb);
	/* kfree accepts NULL. */
	kfree(tdx_mng_key_config_lock);
	misc_cg_set_capacity(MISC_CG_RES_TDX, 0);
	kvm_set_tdx_guest_pmi_handler(NULL);
	tdx_module_update_destroy();
	kvm_unregister_fw(tdx_module);
}

int tdx_offline_cpu(void)
{
	int curr_cpu = smp_processor_id();
	cpumask_var_t packages;
	int ret = 0;
	int i;

	if (!atomic_read(&nr_configured_hkid))
		return 0;

	/*
	 * To reclaim hkid, need to call TDH.PHYMEM.PAGE.WBINVD on all packages.
	 * If this is the last online cpu on the package, refuse offline.
	 */
	if (!zalloc_cpumask_var(&packages, GFP_KERNEL))
		return -ENOMEM;

	for_each_online_cpu(i) {
		if (i != curr_cpu)
			cpumask_set_cpu(topology_physical_package_id(i), packages);
	}
	if (!cpumask_test_cpu(topology_physical_package_id(curr_cpu), packages))
		ret = -EBUSY;
	free_cpumask_var(packages);
	if (ret)
		/*
		 * Because it's hard for human operator to understand the
		 * reason, warn it.
		 */
		pr_warn("TDX requires all packages to have an online CPU.  "
			"Delete all TDs in order to offline all CPUs of a package.\n");
	return ret;
}

int __init tdx_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		INIT_LIST_HEAD(&per_cpu(associated_tdvcpus, cpu));
	return 0;
}

#ifdef CONFIG_INTEL_TDX_MODULE_UPDATE
int tdx_update_fw(bool live_update)
{
	int ret;
	bool recoverable = false;

	ret = tdx_module_update(live_update, &recoverable);
	if (!ret) {
		ret = tdx_module_setup();
		enable_tdx = !ret;
	} else if (!recoverable) {
		enable_tdx = false;
	}

	return ret;
}

static ssize_t reload_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf, size_t size)
{
	if (!sysfs_streq(buf, "update"))
		return -EINVAL;

	return kvm_update_fw(tdx_module) ? : size;
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

int __init tdx_module_update_init(void)
{
	int ret;

	ret = sysfs_create_group(&cpu_subsys.dev_root->kobj, &cpu_root_tdx_group);
	if (ret)
		pr_err("Fail to create tdx group\n");

	return ret;
}

void tdx_module_update_destroy(void)
{
	sysfs_remove_group(&cpu_subsys.dev_root->kobj, &cpu_root_tdx_group);

}
#endif

static inline struct device *tdx_tdi_to_dev(struct tdx_tdi *ttdi)
{
	return &ttdi->tdi->pdev->dev;
}

static void tdx_tdi_devif_remove(struct tdx_tdi *ttdi)
{
	struct device *dev = tdx_tdi_to_dev(ttdi);
	struct tdx_module_output out = { 0 };
	u64 retval;

	dev_info(dev, "%s: remove tdisp devif\n", __func__);

	retval = tdh_devif_remove(ttdi->id.func_id, &out);

	dev_info(dev, "%s ret %llx func_id %x td_buf %llx vmm_buf %llx\n",
		 __func__, retval, ttdi->id.func_id, out.rcx, out.rdx);

	if (retval)
		dev_err(dev, "failed to remove DEVIF %llx\n", retval);
	if ((u64)ttdi->td_buff_pa != out.rcx)
		dev_err(dev, "td buffer address doesn't match\n");
	if ((u64)ttdi->vmm_buff_pa != out.rdx)
		dev_err(dev, "vmm buffer address doesn't match\n");

	free_page((unsigned long)__va(ttdi->vmm_buff_pa));
	free_page((unsigned long)__va(ttdi->td_buff_pa));
	free_page((unsigned long)__va(ttdi->devifcs_pa));
}

static int tdx_tdi_devif_create(struct tdx_tdi *ttdi)
{
	struct device *dev = tdx_tdi_to_dev(ttdi);
	struct kvm_tdx *kvm_tdx = ttdi->kvm_tdx;
	struct pci_tdi *tdi = ttdi->tdi;
	struct iommu_device_info_vtd info;
	unsigned long va;
	u64 retval;
	int ret;

	dev_info(dev, "%s: create tdisp devif\n", __func__);

	/* Per-condition, IOMMU for target device must support TDX-IO */
	ret = iommu_get_hw_info(dev, IOMMU_DEVICE_DATA_INTEL_VTD,
				(void *)&info, sizeof(struct iommu_device_info_vtd));
	if (ret) {
		dev_err(dev, "%s: Failed to get IOMMU ID\n", __func__);
		return ret;
	}

	/*
	 * PT_DEVIFCS_R(devifcs)/NR(td_buff/vm_buff) doesn't need
	 * tdh_phymem_page_reclaim()
	 */
	va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!va)
		return -ENOMEM;
	ttdi->devifcs_pa = __pa(va);

	va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!va) {
		ret = -ENOMEM;
		goto free_devifcs;
	}
	ttdi->td_buff_pa = __pa(va);

	va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!va) {
		ret = -ENOMEM;
		goto free_td_buff;
	}
	ttdi->vmm_buff_pa = __pa(va);

	ttdi->id.func_id = tdi->intf_id.func_id;
	ttdi->id.stream_id = tdi->stream_id;
	ttdi->id.iommu_id = (u16)info.id;
	ttdi->id.type = TDX_DEVIF_TYPE_PFVF;

	retval = tdh_devif_create(ttdi->id.raw, kvm_tdx->tdr_pa,
				  ttdi->devifcs_pa, ttdi->td_buff_pa,
				  ttdi->vmm_buff_pa);

	dev_info(dev, "%s ret %llx id %llx func_id %x tdr %lx devifcs %lx td buf %lx vmm buf %lx\n",
		 __func__, retval, ttdi->id.raw, ttdi->id.func_id,
		 kvm_tdx->tdr_pa, ttdi->devifcs_pa, ttdi->td_buff_pa,
		 ttdi->vmm_buff_pa);

	if (retval) {
		ret = -EFAULT;
		goto free_vmm_buff;
	}

	return 0;

free_vmm_buff:
	free_page((unsigned long)__va(ttdi->vmm_buff_pa));
free_td_buff:
	free_page((unsigned long)__va(ttdi->td_buff_pa));
free_devifcs:
	free_page((unsigned long)__va(ttdi->devifcs_pa));
	return ret;
}

union mt_node_key {
	struct {
		u64 base_id:60;
		u64 level:4;
	};
	u64 key;
};

struct mt_node {
	struct hlist_node hnode;
	union mt_node_key key;
	unsigned long va;
	u64 pa;
	atomic64_t cnt;
};

#define MT_HTABLE_ORDER	8
struct mt_table {
	DECLARE_HASHTABLE(table, MT_HTABLE_ORDER);
	unsigned int nr_levels;
	u8 *level_shift;
	int (*add_node)(struct mt_node *node);
	void (*remove_node)(struct mt_node *node);
	int (*set_entry)(struct mt_node *node, u64 entry_id, void *data, bool set);
};

static struct mt_node *mt_node_find(struct mt_table *mt_tbl, u64 key)
{
	struct mt_node *n;

	hash_for_each_possible(mt_tbl->table, n, hnode, key) {
		if (n->key.key == key)
			return n;
	}

	return NULL;
}

static int mt_entry_populate(struct mt_table *mt_tbl,
			     u64 entry_id, unsigned int entry_lvl, void *data)
{
	union mt_node_key key;
	struct mt_node *node;
	unsigned int plvl;
	int ret;

	if (entry_lvl >= mt_tbl->nr_levels) {
		pr_err("%s invalid level %d, table levels %d\n",
		       __func__, entry_lvl, mt_tbl->nr_levels);
		return -EINVAL;
	}

	for (plvl = mt_tbl->nr_levels; plvl > entry_lvl; plvl--) {
		key.level = plvl - 1;
		key.base_id = entry_id & ~((1ULL << mt_tbl->level_shift[key.level]) - 1);

		node = mt_node_find(mt_tbl, key.key);
		if (node) {
			atomic64_inc(&node->cnt);
			continue;
		}

		node = kzalloc(sizeof(*node), GFP_ATOMIC);
		if (WARN(!node, "%s: key 0x%llx\n", __func__, key.key))
			return -ENOMEM;

		node->va = __get_free_page(GFP_KERNEL_ACCOUNT);
		if (!node->va) {
			kfree(node);
			return -ENOMEM;
		}
		node->pa = __pa(node->va);
		node->key.key = key.key;
		atomic64_set(&node->cnt, 1);

		ret = mt_tbl->add_node(node);
		if (ret) {
			free_page(node->va);
			kfree(node);
			return ret;
		}

		hash_add(mt_tbl->table, &node->hnode, node->key.key);
	}

	if (mt_tbl->set_entry)
		mt_tbl->set_entry(node, entry_id, data, true);

	return 0;
}

static void mt_entry_depopulate(struct mt_table *mt_tbl,
				u64 entry_id, unsigned int entry_lvl)
{
	union mt_node_key key;
	struct mt_node *node;
	unsigned int lvl;

	pr_debug("%s: entry_id=%llx, entry_lvl=%d\n", __func__, entry_id, entry_lvl);

	for (lvl = entry_lvl; lvl < mt_tbl->nr_levels; lvl++) {
		key.level = lvl;
		key.base_id = entry_id & ~((1ULL << mt_tbl->level_shift[key.level]) - 1);

		node = mt_node_find(mt_tbl, key.key);
		if (!node) {
			pr_err("mmiomt remove non-existent entry key %llx\n", key.key);
			return;
		}

		if (mt_tbl->set_entry && lvl == entry_lvl)
			mt_tbl->set_entry(node, entry_id, NULL, false);

		if (!atomic64_dec_return(&node->cnt)) {
			mt_tbl->remove_node(node);
			hash_del(&node->hnode);
			free_page(node->va);
			kfree(node);
		}
	}
}

union devifmt_idx {
	struct {
		u64 level:3;
		u64 rsvd:29;
		u64 func_id:32;
	};
	u64 raw;
};

union devifmt_entry {
	struct {
		u64 p:1;
		u64 lock:1;
		u64 rsvd1:10;
		u64 pfn:40;
		u64 rsvd2:12;
	};
	u64 raw;
};

static int tdx_devifmt_read(u64 func_id, int entry_level, union devifmt_entry *entry)
{
	union devifmt_idx devifmt_idx = { 0 };
	struct tdx_module_output out;
	u64 ret;

	devifmt_idx.func_id = func_id;
	devifmt_idx.level = entry_level;

	ret = tdh_devifmt_read(devifmt_idx.raw, &out);
	if (ret) {
		pr_err("%s: ret %llx devifmt_idx %llx", __func__, ret, devifmt_idx.raw);
		return -EFAULT;
	}

	entry->raw = out.rcx;

	pr_debug("%s func_id=0x%llx, entry_level=%d, entry 0x%llx\n",
		 __func__, func_id, entry_level, entry->raw);

	return 0;
}

static int devif_mt_add_node(struct mt_node *node)
{
	int parent_entry_level = node->key.level + 1;
	u64 base_func_id = node->key.base_id;
	union devifmt_idx devifmt_idx = { 0 };
	union devifmt_entry entry;
	u64 ret;

	tdx_devifmt_read(base_func_id, parent_entry_level, &entry);
	if (entry.p) {
		pr_err("%s parent entry is linked, but not by OS\n", __func__);
		return -EFAULT;
	}

	devifmt_idx.func_id = base_func_id;
	devifmt_idx.level = parent_entry_level;

	ret = tdh_devifmt_add(devifmt_idx.raw, node->pa);
	if (ret) {
		pr_err("%s: ret %llx devifmt_idx %llx base_func_id %llx parent_entry_level %x devifmt_pa %llx\n",
		       __func__, ret, devifmt_idx.raw, base_func_id, parent_entry_level,
		       node->pa);
		return -EFAULT;
	}

	tdx_devifmt_read(base_func_id, parent_entry_level, &entry);

	return 0;
}

static void devif_mt_remove_node(struct mt_node *node)
{
	union devifmt_idx devifmt_idx = { 0 };
	int parent_entry_level = node->key.level + 1;
	u64 base_func_id = node->key.base_id;
	u64 ret;

	devifmt_idx.func_id = base_func_id;
	devifmt_idx.level = parent_entry_level;

	ret = tdh_devifmt_remove(devifmt_idx.raw);
	if (ret)
		pr_err("%s: devifmt_idx =%llx, ret=%llx\n", __func__, devifmt_idx.raw, ret);
}

static u8 devif_mt_level_shift[] = { 9, 18, 27, 32 };

static struct mt_table devif_mt_table = {
	.table = { [0 ... ((1 << (MT_HTABLE_ORDER)) - 1)] = HLIST_HEAD_INIT },
	.nr_levels = ARRAY_SIZE(devif_mt_level_shift),
	.level_shift = devif_mt_level_shift,
	.add_node = devif_mt_add_node,
	.remove_node = devif_mt_remove_node,
};

static void tdx_tdi_devifmt_uinit(struct tdx_tdi *ttdi)
{
	mt_entry_depopulate(&devif_mt_table, ttdi->tdi->intf_id.func_id, 0);
}

static int tdx_tdi_devifmt_init(struct tdx_tdi *ttdi)
{
	return mt_entry_populate(&devif_mt_table, ttdi->tdi->intf_id.func_id, 0, NULL);
}

union mmiomt_idx {
	struct {
		u64 level:3;
		u64 reserved_0:9;
		u64 pfn:40;
		u64 reserved_1:12;
	};
	u64 raw;
};

union mmiomt_info {
	struct {
		u64 type:2;
		u64 reserved_0:10;
		u64 func_id:32;
		u64 reserved_1:20;
	};
	u64 raw;
};

union mmiomt_entry {
	struct {
		u64 xlock:1;
		u64 type:2;
	};
	struct qnode {
		struct qnode_pa {
			u64 rsvd1:11;
			u64 p:1;
			u64 pfn:40;
			u64 rsvd2:12;
		} pa[4];
	} qnode;
	u64 value[4];
};

static u8 mmio_mt_level_shift[] = { 19, 28, 37, 46, 52 };
#define MMIOMT_LEVEL_SHIFT(x) (mmio_mt_level_shift[(x)])
#define MMIOMT_PA_TO_IDX(_pa, _l) (((_pa) >> MMIOMT_LEVEL_SHIFT(_l)) & 0x3)

#define MMIOMT_TYPE_QNODE	0
#define MMIOMT_TYPE_DATA	1

static int tdx_mmiomt_read(u64 mmio_pa, int entry_level, union mmiomt_entry *entry)
{
	union mmiomt_idx mmiomt_idx = { 0 };
	struct tdx_module_output out;
	u64 ret;

	mmiomt_idx.pfn = mmio_pa >> PAGE_SHIFT;
	mmiomt_idx.level = entry_level;

	ret = tdh_mmiomt_read(mmiomt_idx.raw, &out);
	if (ret) {
		pr_err("%s: ret %llx mmiomt_idx %llx", __func__, ret, mmiomt_idx.raw);
		return -EFAULT;
	}

	entry->value[0] = out.rcx;
	entry->value[1] = out.rdx;
	entry->value[2] = out.r8;
	entry->value[3] = out.r9;

	pr_debug("%s mmio_pa=0x%llx, entry_level=%d, entry 0x%llx 0x%llx 0x%llx 0x%llx\n",
		 __func__, mmio_pa, entry_level, entry->value[0],
		 entry->value[1], entry->value[2], entry->value[3]);

	return 0;
}

static int mmio_mt_add_node(struct mt_node *node)
{
	int parent_entry_level = node->key.level + 1;
	u64 base_mmio_pa = node->key.base_id;
	union mmiomt_idx mmiomt_idx = { 0 };
	union mmiomt_entry entry;
	u8 pa_idx = MMIOMT_PA_TO_IDX(base_mmio_pa, node->key.level);
	u64 ret;

	tdx_mmiomt_read(base_mmio_pa, parent_entry_level, &entry);
	if (entry.type != MMIOMT_TYPE_QNODE) {
		pr_err("%s parent entry is not qnode\n", __func__);
		return -EFAULT;
	}

	if (entry.qnode.pa[pa_idx].p) {
		pr_err("%s parent entry is linked, but not by OS\n", __func__);
		return -EFAULT;
	}

	mmiomt_idx.pfn = base_mmio_pa >> PAGE_SHIFT;
	mmiomt_idx.level = parent_entry_level;

	ret = tdh_mmiomt_add(mmiomt_idx.raw, node->pa);
	if (ret) {
		pr_err("%s: ret %llx mmiomt_idx %llx base_mmio_pa %llx parent_entry_level %x mmiomt_pa %llx\n",
		       __func__, ret, mmiomt_idx.raw, base_mmio_pa, parent_entry_level,
		       node->pa);
		return -EFAULT;
	}

	tdx_mmiomt_read(base_mmio_pa, parent_entry_level, &entry);

	return 0;
}

static void mmio_mt_remove_node(struct mt_node *node)
{
	union mmiomt_idx mmiomt_idx = { 0 };
	int parent_entry_level = node->key.level + 1;
	u64 base_mmio_pa = node->key.base_id;
	u64 ret;

	mmiomt_idx.pfn = base_mmio_pa >> PAGE_SHIFT;
	mmiomt_idx.level = parent_entry_level;
	ret = tdh_mmiomt_remove(mmiomt_idx.raw);
	if (ret)
		pr_err("%s: mmiomt_idx =%llx, ret=%llx\n", __func__, mmiomt_idx.raw, ret);
}

static int mmio_mt_set_entry(struct mt_node *node, u64 entry_id, void *data, bool set)
{
	union mmiomt_info mmiomt_info = { 0 };
	union mmiomt_idx mmiomt_idx = { 0 };
	int entry_level = node->key.level;
	u64 mmio_pa = entry_id;
	u64 ret;

	mmiomt_idx.pfn = mmio_pa >> PAGE_SHIFT;
	mmiomt_idx.level = entry_level;

	if (set) {
		u32 func_id = *(u32 *)data;

		mmiomt_info.func_id = func_id; //set : func_id; unset: 0
		mmiomt_info.type = 1; // set: data; unset: qnode
	}

	ret = tdh_mmiomt_set(mmiomt_idx.raw, mmiomt_info.raw);
	if (ret) {
		pr_err("%s: ret %llx mmio_idx %llx, mmiomt_info %llx\n",
		       __func__, ret, mmiomt_idx.raw, mmiomt_info.raw);
		return -EFAULT;
	}

	return 0;
}

static struct mt_table mmio_mt_table = {
	.table = { [0 ... ((1 << (MT_HTABLE_ORDER)) - 1)] = HLIST_HEAD_INIT },
	.nr_levels = ARRAY_SIZE(mmio_mt_level_shift),
	.level_shift = mmio_mt_level_shift,
	.add_node = mmio_mt_add_node,
	.remove_node = mmio_mt_remove_node,
	.set_entry = mmio_mt_set_entry,
};

static void tdx_tdi_mmiomt_remove(struct tdx_tdi *ttdi, u64 mmio_pa, int level)
{
	pr_debug("%s: mmio_pa=%llx, level=%d\n", __func__, mmio_pa, level);

	mt_entry_depopulate(&mmio_mt_table, mmio_pa, level);
}

struct devif_mmiomt {
	hpa_t mmio_hpa;
	int level;
	unsigned long devifcs_pa;
	struct list_head list;
};

static int tdx_tdi_mmiomt_add(struct tdx_tdi *ttdi, u64 mmio_pa, int level)
{
	struct devif_mmiomt *devmmio;

	devmmio = kzalloc(sizeof(*devmmio), GFP_ATOMIC);
	if (!devmmio)
		return -ENOMEM;

	devmmio->mmio_hpa = mmio_pa;
	devmmio->level = level;
	devmmio->devifcs_pa = ttdi->devifcs_pa;
	list_add(&devmmio->list, &ttdi->mmiomt);

	pr_debug("%s, mmio_pa=%llx, level=%d\n", __func__, mmio_pa, level);

	return mt_entry_populate(&mmio_mt_table, mmio_pa, level, &ttdi->tdi->intf_id.func_id);
}

static void tdx_tdi_mmiomt_uinit(struct tdx_tdi *ttdi)
{
	struct list_head *mmiomt_list = &ttdi->mmiomt;
	struct pci_dev *pdev = ttdi->tdi->pdev;
	struct devif_mmiomt *mmiomt, *tmp;

	dev_info(&pdev->dev, "%s: mmiomt uinit\n", __func__);

	list_for_each_entry_safe(mmiomt, tmp, mmiomt_list, list) {
		if (mmiomt->devifcs_pa != ttdi->devifcs_pa)
			continue;

		tdx_tdi_mmiomt_remove(ttdi, mmiomt->mmio_hpa, mmiomt->level);
		list_del(&mmiomt->list);
		kfree(mmiomt);
	}
}

static int tdx_tdi_mmiomt_init(struct tdx_tdi *ttdi)
{
	struct pci_dev *pdev = ttdi->tdi->pdev;
	struct resource *res;
	int i;

	dev_info(&pdev->dev, "%s: mmiomt init\n", __func__);

	for (i = 0; i < PCI_STD_NUM_BARS; i++) {
		int bar = i + PCI_STD_RESOURCES;
		unsigned long mmio_len, offset;

		res = &pdev->resource[bar];
		mmio_len = resource_size(res);

		/*
		 * mmio for tdxio device must be 64k aligned in DIMP spec.
		 * keep it to 4K for now
		 */
		if ((res->start & ~PAGE_MASK) || !mmio_len || !(res->flags & IORESOURCE_MEM))
			continue;

		/* level 0 means page of size 4K */
		for (offset = 0; offset < mmio_len; offset += PAGE_SIZE)
			tdx_tdi_mmiomt_add(ttdi, res->start + offset, 0);
	}

	return 0;
}

/* level 0 corresponds to PG_LEVEL_4K */
#define to_gpa_info_level(x)   ((x) - 1)

union mmio_map_page_info {
	struct {
		u64 level:3;		/* Level */
		u64 reserved_0:9;	/* Must be 0 */
		u64 gpa:40;		/* GPA of the page */
		u64 reserved_1:12;	/* Must be 0 */
	};
	u64 raw;
};

static u64 tdx_mmio_map(hpa_t tdr, gpa_t gpa, hpa_t mmio_pa, int level)
{
	union mmio_map_page_info gpa_page_info = { 0 };
	u64 ret;

	if (level < PG_LEVEL_4K) {
		pr_err("%s wrong level %d\n", __func__, level);
		return -EINVAL;
	}

	gpa_page_info.level = to_gpa_info_level(level);
	gpa_page_info.gpa = (gpa & GENMASK(51, 12)) >> 12;

	ret = tdh_mmio_map(gpa_page_info.raw, tdr, mmio_pa);
	pr_debug("%s: ret=%llx tdr %llx mmio_pa %llx gpa info %llx\n",
		 __func__, ret, tdr, mmio_pa, gpa);

	return ret;
}

static void tdx_mmio_block(hpa_t tdr, gpa_t gpa, int level)
{
	union mmio_map_page_info gpa_page_info = { 0 };
	u64 ret;

	gpa_page_info.level = to_gpa_info_level(level);
	gpa_page_info.gpa = (gpa & GENMASK(51, 12)) >> 12;

	ret = tdh_mmio_block(gpa_page_info.raw, tdr);
	pr_debug("%s: ret=%llx tdr %llx gpa info=%llx\n", __func__,
		 ret, tdr, gpa_page_info.raw);
}

static void tdx_mmio_unmap(hpa_t tdr, gpa_t gpa, int level)
{
	union mmio_map_page_info gpa_page_info = { 0 };
	u64 ret;

	gpa_page_info.level = to_gpa_info_level(level);
	gpa_page_info.gpa = (gpa & GENMASK(51, 12)) >> 12;

	ret = tdh_mmio_unmap(gpa_page_info.raw, tdr);
	pr_debug("%s: ret=%llx tdr %llx gpa info=%llx\n",
		 __func__, ret, tdr, gpa_page_info.raw);
}

static struct tdx_tdi *tdx_mmio_pfn_to_tdi(struct kvm_tdx *kvm_tdx,
					   enum pg_level level, kvm_pfn_t pfn);

struct devif_mmio {
	gfn_t mmio_gfn;
	int level;
	struct list_head list;
};

static int tdx_tdi_mmio_map(struct kvm_tdx *kvm_tdx, gfn_t gfn,
			    enum pg_level level, kvm_pfn_t pfn)
{
	struct devif_mmio *mmio;
	struct tdx_tdi *ttdi;
	u64 ret;

	ttdi = tdx_mmio_pfn_to_tdi(kvm_tdx, level, pfn);
	if (!ttdi)
		return -ENODEV;

	ret = tdx_mmio_map(kvm_tdx->tdr_pa, gfn << PAGE_SHIFT, pfn << PAGE_SHIFT, level);
	if (ret)
		return -EFAULT;

	mmio = kzalloc(sizeof(*mmio), GFP_ATOMIC);
	if (!mmio)
		return -ENOMEM;

	mmio->mmio_gfn = gfn;
	mmio->level = level;
	list_add(&mmio->list, &ttdi->mmio);

	return 0;
}

static void tdx_tdi_mmio_unmap_all(struct tdx_tdi *ttdi)
{
	struct kvm_tdx *kvm_tdx = ttdi->kvm_tdx;
	struct list_head *mmio_list = &ttdi->mmio;
	struct pci_dev *pdev = ttdi->tdi->pdev;
	struct devif_mmio *mmio, *tmp;

	dev_info(&pdev->dev, "%s: mmio unmap\n", __func__);

	list_for_each_entry_safe(mmio, tmp, mmio_list, list) {
		/* TODO: handle large pages. */
		if (KVM_BUG_ON(mmio->level != PG_LEVEL_4K, &kvm_tdx->kvm))
			continue;

		tdx_mmio_block(kvm_tdx->tdr_pa, mmio->mmio_gfn << PAGE_SHIFT, mmio->level);
		tdx_sept_tlb_remote_flush(&kvm_tdx->kvm);
		tdx_mmio_unmap(kvm_tdx->tdr_pa, mmio->mmio_gfn << PAGE_SHIFT, mmio->level);

		list_del(&mmio->list);
		kfree(mmio);
	}
}

enum tdxio_inv_type {
	INVAL_IOTLB,
	INVAL_RTE,
	INVAL_CTE,
	INVAL_PDE,
	INVAL_PTE,
};

union tdxio_inv_target {
	struct {
		u64 rid	: 16; /* set to 0 for INVAL_IOTLB */
		u64 reserved1 : 16; /* must be 0 */
		u64 pasid : 20; /* set to 0 for INVAL_RTE & INVAL_CTE */
		u64 reserved2 : 12; /* must be 0 */
	};
	u64 tdr_pa;
	u64 raw;
};

static int tdx_iq_inv(struct tdx_iommu *tiommu, enum tdxio_inv_type inv_type,
		      u64 inv_target_raw)
{
	u64 iommu_id = tiommu->iommu_id;
	unsigned long flags;
	u64 wait_desc[2];
	u64 *status_addr;
	u64 tdx_ret = 0;

	raw_spin_lock_irqsave(&tiommu->invq_lock, flags);

	wait_desc[0] = (((u64)2) << 32) | (((u64)1) << 6 | (((u64)1) << 5) | 0x5);
	wait_desc[1] = tiommu->wait_desc_pa;

	status_addr = (u64 *)(__va(tiommu->wait_desc_pa));
	*status_addr = 1;

	tdx_ret = tdh_iqinv_req(iommu_id, inv_type, inv_target_raw, wait_desc[0], wait_desc[1]);
	if (tdx_ret) {
		pr_err("%s inv req ret=%llx, iommu_id=%llx, inv_type=%x, inv_target=%llx, wait_desc= %llx %llx\n",
		       __func__, tdx_ret, iommu_id, inv_type, inv_target_raw,
		       wait_desc[0], wait_desc[1]);
		goto out;
	} else if (inv_type != INVAL_IOTLB) {
		pr_debug("%s inv req ret=%llx, iommu_id=%llx, inv_type=%x, inv_target=%llx, wait_desc= %llx %llx\n",
		       __func__, tdx_ret, iommu_id, inv_type, inv_target_raw,
		       wait_desc[0], wait_desc[1]);
	}

	do {
		tdx_ret = tdh_iqinv_process(iommu_id);
		cpu_relax();
	} while ((tdx_ret == TDX_INTERRUPTED_RESUMABLE) ||
		 (!tdx_ret && *status_addr != 2));

	if (tdx_ret) {
		pr_err("%s inv process ret=%llx, inv_type=%d iommu_id=%llx, descriptor status=%lld\n",
		       __func__, tdx_ret, inv_type, iommu_id, *status_addr);
	} else if (inv_type != INVAL_IOTLB) {
		pr_debug("%s inv process ret=%llx, inv_type=%d iommu_id=%llx, descriptor status=%lld\n",
		       __func__, tdx_ret, inv_type, iommu_id, *status_addr);
	}

out:
	raw_spin_unlock_irqrestore(&tiommu->invq_lock, flags);

	if (tdx_ret)
		return -EFAULT;

	return 0;
}

static int tdx_tdi_iq_inv_rte(struct tdx_tdi *ttdi)
{
	union tdxio_inv_target inv_target = { 0 };

	inv_target.rid = ttdi->rid;

	return tdx_iq_inv(ttdi->tiommu, INVAL_RTE, inv_target.raw);
}

static int tdx_tdi_iq_inv_cte(struct tdx_tdi *ttdi)
{
	union tdxio_inv_target inv_target = { 0 };

	inv_target.rid = ttdi->rid;

	return tdx_iq_inv(ttdi->tiommu, INVAL_CTE, inv_target.raw);
}

static int tdx_tdi_iq_inv_pde(struct tdx_tdi *ttdi)
{
	union tdxio_inv_target inv_target = { 0 };

	inv_target.rid = ttdi->rid;
	inv_target.pasid = 0;//TODO:  CONFIRM the value

	return tdx_iq_inv(ttdi->tiommu, INVAL_PDE, inv_target.raw);
}

static int tdx_tdi_iq_inv_pte(struct tdx_tdi *ttdi)
{
	union tdxio_inv_target inv_target = { 0 };

	inv_target.rid = ttdi->rid;
	inv_target.pasid = 0;//TODO:  CONFIRM the value

	return tdx_iq_inv(ttdi->tiommu, INVAL_PTE, inv_target.raw);
}

static int tdx_tdi_iq_inv_iotlb(struct kvm_tdx *kvm_tdx)
{
	union tdxio_inv_target inv_target = { 0 };
	struct kvm_tdx_iommu *ktiommu;

	inv_target.tdr_pa = kvm_tdx->tdr_pa;

	rcu_read_lock();
	list_for_each_entry_rcu(ktiommu, &kvm_tdx->ktiommu_list, node)
		tdx_iq_inv(ktiommu->tiommu, INVAL_IOTLB, inv_target.raw);

	rcu_read_unlock();

	return 0;
}

#define TD_DMAR_LEVEL_PASID_TBL		0x0
#define TD_DMAR_LEVEL_PASID_DIR		0x1
#define TD_DMAR_LEVEL_CTX_TBL		0x2
#define TD_DMAR_LEVEL_ROOT_TBL		0x3
#define TD_DMAR_LEVEL_INV		0x4

union dmar_index {
	struct {
		u64 level:3;
		u64 reserved:9;
		u64 pasid:20;
		u64 rid:16;
		u64 iommu_id:16;
	};
	u64 raw;
};

union dmar_param {
	struct {
		u64 present:1;
		u64 rsvd:11;
		u64 ctp:52;
	} rte;
	struct {
		u64 present:1; /* must be 1 */
		u64 fpd:1;
		u64 dte:1; /* must be 0 */
		u64 paside:1;
		u64 pre:1; /* must be 0 */
		u64 rsvd1:4;
		u64 pdts:3;
		u64 pasiddirptr:52;

		u64 rid_pasid:20;
		u64 rid_priv:1;
		u64 rsvd2:43;
		u64 rsvd3;
		u64 rsvd4;
	} cte;
	struct {
		u64 present:1; /* must be 1 */
		u64 fpd:1;
		u64 rsvd:10;
		u64 smptblptr:52;
	} pasidde;
	struct {
		u64 present:1;
		u64 fpd:1;
		u64 aw:3;
		u64 slee:1;
		u64 pgtt:3;
		u64 slade:1;
		u64 rsvd1:2;
		u64 slptptr:52;

		u64 did:16;
		u64 rsvd2:7;
		u64 pwsnp:1;
		u64 pgsnp:1;
		u64 cd:1;
		u64 emte:1;
		u64 emt:3;
		u64 pwt:1;
		u64 pcd:1;
		u64 pat:32;

		u64 sre:1;
		u64 ere:1;
		u64 flpm:2;
		u64 wpe:1;
		u64 nxe:1;
		u64 smep:1;
		u64 eafe:1;
		u64 rsvd3:4;
		u64 flptptr:52;

		u64 rsvd4;
		u64 rsvd5;
		u64 rsvd6;
		u64 rsvd7;
		u64 rsvd8;
	} pasidte;
	u64 raw[8];
};

static inline const char *dmaradd_level_to_string(u8 level)
{
	switch (level) {
	case TD_DMAR_LEVEL_ROOT_TBL:
		return "RTE";
	case TD_DMAR_LEVEL_PASID_DIR:
		return "PASIDDE";
	case TD_DMAR_LEVEL_CTX_TBL:
		return "CTE";
	case TD_DMAR_LEVEL_PASID_TBL:
		return "PASIDTE";
	}

	return "Unknown";
}

static inline void dmar_param_dump(u8 level, union dmar_param *p)
{
	switch (level) {
	case TD_DMAR_LEVEL_ROOT_TBL:
		pr_info("%s: %016llx", __func__, p->raw[0]);
		break;
	case TD_DMAR_LEVEL_PASID_DIR:
		pr_info("%s: %016llx", __func__, p->raw[0]);
		break;
	case TD_DMAR_LEVEL_CTX_TBL:
		pr_info("%s: %016llx %016llx %016llx %016llx\n",
			__func__, p->raw[0], p->raw[1], p->raw[2], p->raw[3]);
		break;
	case TD_DMAR_LEVEL_PASID_TBL:
		pr_info("%s: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
			__func__, p->raw[0], p->raw[1], p->raw[2], p->raw[3],
				  p->raw[4], p->raw[5], p->raw[6], p->raw[7]);
		break;
	}
}

static int tdx_iommu_dmar_add(union dmar_index index, hpa_t tdr,
			      union dmar_param *p)
{
	u64 ret;

	do {
		ret = tdh_dmar_add(index.raw, tdr, p->raw[0], p->raw[1], p->raw[2],
				   p->raw[3], p->raw[4], p->raw[5], p->raw[6],
				   p->raw[7]);
	} while (ret == TDX_INTERRUPTED_RESUMABLE);

	pr_info("%s: %s: ret %llx\n",
		__func__, dmaradd_level_to_string(index.level), ret);

	dmar_param_dump(index.level, p);

	if (ret)
		return -EFAULT;

	return 0;
}

static int tdx_iommu_dmar_read(union dmar_index index,
			       union dmar_param *p)
{
	struct tdx_module_output out;
	u64 ret;

	ret = tdh_dmar_read(index.raw, &out);

	pr_info("%s: %s: ret %llx, RDX %llx\n",
		__func__, dmaradd_level_to_string(index.level), ret, out.rdx);

	if (ret)
		return -EFAULT;

	switch (index.level) {
	case TD_DMAR_LEVEL_ROOT_TBL:
	case TD_DMAR_LEVEL_PASID_DIR:
		p->raw[0] = out.r8;
		break;
	case TD_DMAR_LEVEL_PASID_TBL:
		p->raw[4] = out.r12;
		p->raw[5] = out.r13;
		p->raw[6] = out.r14;
		p->raw[7] = out.r15;
		fallthrough;
	case TD_DMAR_LEVEL_CTX_TBL:
		p->raw[0] = out.r8;
		p->raw[1] = out.r9;
		p->raw[2] = out.r10;
		p->raw[3] = out.r11;
		break;
	default:
		break;
	}

	dmar_param_dump(index.level, p);

	return 0;
}

static void tdx_iommu_dmar_block(union dmar_index index)
{
	u64 ret = tdh_dmar_block(index.raw);

	pr_info("%s ret %llx index %llx\n", __func__, ret, index.raw);

	if (ret) {
		union dmar_param p = { 0 };

		tdx_iommu_dmar_read(index, &p);
	}
}

static void tdx_iommu_dmar_remove(union dmar_index index)
{
	u64 ret;

	do {
		ret = tdh_dmar_remove(index.raw);
	} while (ret == TDX_INTERRUPTED_RESUMABLE);

	pr_info("%s ret %llx index %llx\n", __func__, ret, index.raw);

	if (ret) {
		union dmar_param p = { 0 };

		tdx_iommu_dmar_read(index, &p);
	}
}

static DEFINE_MUTEX(global_tiommu_lock);
static LIST_HEAD(global_tiommu_list);

static struct tdx_iommu *tdx_iommu_get(u64 iommu_id)
{
	struct tdx_iommu *tiommu;
	unsigned long va;
	int ret;

	mutex_lock(&global_tiommu_lock);

	list_for_each_entry(tiommu, &global_tiommu_list, node) {
		if (tiommu->iommu_id == iommu_id) {
			kref_get(&tiommu->ref);
			mutex_unlock(&global_tiommu_lock);
			return tiommu;
		}
	}

	tiommu = kzalloc(sizeof(*tiommu), GFP_KERNEL);
	if (!tiommu) {
		ret = -ENOMEM;
		goto unlock;
	}

	tiommu->iommu_id = iommu_id;
	raw_spin_lock_init(&tiommu->invq_lock);
	va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!va) {
		ret = -ENOMEM;
		goto free_tiommu;
	}
	tiommu->wait_desc_pa = __pa(va);

	kref_init(&tiommu->ref);

	list_add(&tiommu->node, &global_tiommu_list);
	mutex_unlock(&global_tiommu_lock);

	return tiommu;

free_tiommu:
	kfree(tiommu);
unlock:
	mutex_unlock(&global_tiommu_lock);
	return ERR_PTR(ret);
}

static void tdx_iommu_release(struct kref *kref)
{
	struct tdx_iommu *tiommu = container_of(kref, struct tdx_iommu, ref);

	mutex_lock(&global_tiommu_lock);
	list_del(&tiommu->node);
	mutex_unlock(&global_tiommu_lock);

	free_page((unsigned long)__va(tiommu->wait_desc_pa));
	kfree(tiommu);
}

static void tdx_iommu_put(struct tdx_iommu *tiommu)
{
	kref_put(&tiommu->ref, tdx_iommu_release);
}

static int tdx_iommu_add(struct kvm_tdx *kvm_tdx, struct tdx_iommu *tiommu)
{
	struct kvm_tdx_iommu *ktiommu;

	list_for_each_entry(ktiommu, &kvm_tdx->ktiommu_list, node) {
		if (ktiommu->tiommu == tiommu) {
			kref_get(&ktiommu->ref);
			return 0;
		}
	}

	ktiommu = kzalloc(sizeof(*ktiommu), GFP_KERNEL);
	if (!ktiommu)
		return -ENOMEM;

	ktiommu->tiommu = tiommu;
	kref_init(&ktiommu->ref);
	list_add_rcu(&ktiommu->node, &kvm_tdx->ktiommu_list);

	return 0;
}

static void kvm_tdx_iommu_release(struct kref *kref)
{
	struct kvm_tdx_iommu *ktiommu = container_of(kref, struct kvm_tdx_iommu, ref);

	list_del_rcu(&ktiommu->node);
	synchronize_rcu();

	kfree(ktiommu);
}

static void tdx_iommu_del(struct kvm_tdx *kvm_tdx, struct tdx_iommu *tiommu)
{
	struct kvm_tdx_iommu *ktiommu;

	list_for_each_entry(ktiommu, &kvm_tdx->ktiommu_list, node) {
		if (ktiommu->tiommu == tiommu) {
			kref_put(&ktiommu->ref, kvm_tdx_iommu_release);
			return;
		}
	}
}

static void tdx_tdi_dmar_uinit(struct tdx_tdi *ttdi)
{
	struct pci_dev *pdev = ttdi->tdi->pdev;
	struct kvm_tdx *kvm_tdx = ttdi->kvm_tdx;
	union dmar_index index;

	dev_info(&pdev->dev, "%s: dmar uinit\n", __func__);

	tdx_iommu_del(kvm_tdx, ttdi->tiommu);

	index.raw = 0;
	index.rid = ttdi->rid;
	index.iommu_id = ttdi->id.iommu_id;
	index.pasid = 0;

	index.level = TD_DMAR_LEVEL_PASID_TBL;
	tdx_iommu_dmar_block(index);
	tdx_tdi_iq_inv_pte(ttdi);
	tdx_iommu_dmar_remove(index);

	index.level = TD_DMAR_LEVEL_PASID_DIR;
	tdx_iommu_dmar_block(index);
	tdx_tdi_iq_inv_pde(ttdi);
	tdx_iommu_dmar_remove(index);

	index.level = TD_DMAR_LEVEL_CTX_TBL;
	tdx_iommu_dmar_block(index);
	tdx_tdi_iq_inv_cte(ttdi);
	tdx_iommu_dmar_remove(index);

	index.level = TD_DMAR_LEVEL_ROOT_TBL;
	tdx_iommu_dmar_block(index);
	tdx_tdi_iq_inv_rte(ttdi);
	tdx_iommu_dmar_remove(index);

	free_pages(ttdi->dmar_pages_va, 5);

	tdx_iommu_put(ttdi->tiommu);
}

static int tdx_tdi_dmar_init(struct tdx_tdi *ttdi)
{
	struct pci_dev *pdev = ttdi->tdi->pdev;
	struct kvm_tdx *kvm_tdx = ttdi->kvm_tdx;
	union dmar_index index = { 0 };
	union dmar_param p = { 0 };

	unsigned long va, offset;
	hpa_t pa;

	dev_info(&pdev->dev, "%s: dmar init\n", __func__);

	ttdi->tiommu = tdx_iommu_get(ttdi->id.iommu_id);
	if (IS_ERR(ttdi->tiommu))
		return PTR_ERR(ttdi->tiommu);

	va = __get_free_pages(GFP_KERNEL_ACCOUNT, 5);
	pa = __pa(va);
	offset = 0;

	index.rid = ttdi->rid;
	index.iommu_id = ttdi->id.iommu_id;
	index.pasid = 0;

	/* Setup Root Table Entry 1 page */
	index.level = TD_DMAR_LEVEL_ROOT_TBL;
	tdx_iommu_dmar_read(index, &p);
	if (p.raw[0])
		dev_warn(&pdev->dev, "%s: rte exists!\n", __func__);
	memset(&p, 0, sizeof(p));
	p.raw[0] = pa + offset;
	/* Present must be 1 */
	p.rte.present = 1;
	tdx_iommu_dmar_add(index, 0, &p);
	tdx_iommu_dmar_read(index, &p);
	offset += PAGE_SIZE;

	/* Setup Context Table Entry 16 pages */
	index.level = TD_DMAR_LEVEL_CTX_TBL;
	memset(&p, 0, sizeof(p));
	tdx_iommu_dmar_read(index, &p);
	if (p.raw[0])
		dev_warn(&pdev->dev, "%s: cte exists!\n", __func__);
	memset(&p, 0, sizeof(p));
	/*
	 * only allow FPD DTE PASIDE PRE PDTS RID_PASID RID_PRIV
	 * PASIDPTR to be configured.
	 */
	p.raw[0] = pa + offset;
	/* 16 pages */
	p.cte.pdts = 0x6;
	/*
	 * Present must be 1.
	 * DTE must be 0.
	 * PRE must be 0.
	 */
	p.cte.present = 1;
	p.cte.dte = 0;
	p.cte.pre = 0;
	tdx_iommu_dmar_add(index, 0, &p);
	tdx_iommu_dmar_read(index, &p);
	offset += 16 * PAGE_SIZE;

	/* Setup PASID Directory Entry 1 page */
	index.level = TD_DMAR_LEVEL_PASID_DIR;
	memset(&p, 0, sizeof(p));
	tdx_iommu_dmar_read(index, &p);
	if (p.raw[0])
		dev_warn(&pdev->dev, "%s: pasidde exists!\n", __func__);
	memset(&p, 0, sizeof(p));
	/* only allow FPD SLPTPTR */
	p.raw[0] = pa + offset;
	/* Present must be 1. */
	p.pasidde.present = 1;
	tdx_iommu_dmar_add(index, 0, &p);
	tdx_iommu_dmar_read(index, &p);

	/* Setup PASID Table Entry */
	index.level = TD_DMAR_LEVEL_PASID_TBL;
	memset(&p, 0, sizeof(p));
	/* TODO, set it according to current page table level */
	p.pasidte.pgtt = 0x2;
	if ((kvm_tdx->eptp_controls & VMX_EPTP_PWL_MASK) == VMX_EPTP_PWL_5)
		p.pasidte.aw = 0x3;
	else
		p.pasidte.aw = 0x2;
	if ((kvm_tdx->eptp_controls & VMX_EPTP_AD_ENABLE_BIT))
		p.pasidte.slade = 0x1;
	else
		p.pasidte.slade = 0x0;
	/*
	 * Present must be 0.
	 * PWT PCD PAT CD must be 0.
	 * SLPTR must be 0.
	 * DID must be 0.
	 * EMT must be 6.
	 * EMT PGSNP PWSNP must be 1.
	 */
	p.pasidte.present = 0;
	p.pasidte.did = 0; /* will be ignored by seam module */
	p.pasidte.pwsnp = 1;
	p.pasidte.pgsnp = 1;
	p.pasidte.emte = 1;
	p.pasidte.slee = 1;
	p.pasidte.emt = 6;
	p.pasidte.cd = 0;
	p.pasidte.pwt = 0;
	p.pasidte.pcd = 0;
	p.pasidte.pat = 0;
	tdx_iommu_dmar_add(index, kvm_tdx->tdr_pa, &p);
	tdx_iommu_dmar_read(index, &p);

	ttdi->dmar_pages_va = va;

	tdx_iommu_add(kvm_tdx, ttdi->tiommu);

	return 0;
}

static struct tdx_tdi *tdx_tdi_find_by_func_id(struct kvm_tdx *kvm_tdx,
					       u32 func_id)
{
	struct tdx_tdi *ttdi;

	mutex_lock(&kvm_tdx->ttdi_mutex);
	list_for_each_entry(ttdi, &kvm_tdx->ttdi_list, node) {
		if (ttdi->tdi->intf_id.func_id == func_id) {
			mutex_unlock(&kvm_tdx->ttdi_mutex);
			return ttdi;
		}
	}
	mutex_unlock(&kvm_tdx->ttdi_mutex);

	return NULL;
}

static struct tdx_tdi *tdx_mmio_pfn_to_tdi(struct kvm_tdx *kvm_tdx,
					   enum pg_level level, kvm_pfn_t pfn)
{
	struct tdx_tdi *ttdi;
	struct pci_dev *pdev;
	u64 size = page_level_size(level);
	u64 start = pfn << PAGE_SHIFT;
	u64 end = start + size - 1;
	struct resource *res;
	int bar, i;

	rcu_read_lock();
	list_for_each_entry_rcu(ttdi, &kvm_tdx->ttdi_list, node) {
		pdev = ttdi->tdi->pdev;
		for (i = 0; i < PCI_STD_NUM_BARS; i++) {
			bar = i + PCI_STD_RESOURCES;
			res = &pdev->resource[bar];

			if (!(res->flags & IORESOURCE_MEM))
				continue;

			if (res->start <= start && res->end >= end) {
				rcu_read_unlock();
				return ttdi;
			}
		}
	}
	rcu_read_unlock();

	pr_err("%s fail! pfn 0x%llx, level %d\n", __func__, pfn, level);

	return NULL;
}

static void tdx_tdi_free(struct tdx_tdi *ttdi)
{
	kfree(ttdi);
}

static struct tdx_tdi *tdx_tdi_alloc(struct kvm_tdx *kvm_tdx,
				     struct pci_tdi *tdi)
{
	struct pci_dev *pdev = tdi->pdev;
	struct tdx_tdi *ttdi;

	ttdi = kzalloc(sizeof(*ttdi), GFP_KERNEL);
	if (!ttdi)
		return NULL;

	INIT_LIST_HEAD(&ttdi->mmiomt);
	INIT_LIST_HEAD(&ttdi->mmio);
	ttdi->tdi = tdi;
	ttdi->kvm_tdx = kvm_tdx;
	ttdi->rid = PCI_DEVID(pdev->bus->number, pdev->devfn);
	tdi->mmio_offset = kvm_tdx->mmio_offset;
	pr_info("%s: tdi mmio_offset = %llx\n", __func__, tdi->mmio_offset);
	return ttdi;
}

static bool __is_tdx_tdi_added(struct kvm_tdx *kvm_tdx, struct tdx_tdi *ttdi)
{
	struct tdx_tdi *tmp;

	list_for_each_entry(tmp, &kvm_tdx->ttdi_list, node) {
		if (tmp == ttdi)
			return true;
	}

	return false;
}

static void tdx_tdi_add(struct tdx_tdi *ttdi)
{
	struct kvm_tdx *kvm_tdx = ttdi->kvm_tdx;

	list_add_rcu(&ttdi->node, &kvm_tdx->ttdi_list);
}

static void tdx_tdi_del(struct tdx_tdi *ttdi)
{
	list_del_rcu(&ttdi->node);
	synchronize_rcu();
}

#define TDI_BUFF_SIZE		PAGE_SIZE
/*
 * TDI_BUFF_SIZE - 8 (DOE header) - 8 (SPDM Secured Msg.header) -
 * 11 (PCISIG vendor header) - 16 (SPDM Secured Msg.MAC) - 3 (max DW padding)
 * - 1 (application id byte)
 * = PAGE_SIZE - 47 = 4049
 */
#define TDI_MAX_PAYLOAD_SIZE	(TDI_BUFF_SIZE - 46)
#define TDI_MIN_PAYLOAD_SIZE	16

struct tdx_tdi_request {
	unsigned long flags;
#define TDI_REQUEST_FLAGS_TD	0x1

	unsigned long req_in_va;	/* TDISP request payload */
	unsigned long req_out_va;	/* Full encrypted request */
        unsigned long rsp_in_va;	/* Full encrypted response */
	unsigned long rsp_out_va;	/* TDISP response payload */
	size_t        req_in_sz;
	size_t        req_out_sz;
	size_t        rsp_in_sz;
	size_t        rsp_out_sz;
};

void tdx_tdi_request_free(struct tdx_tdi_request *req)
{
	free_pages(req->req_in_va,  get_order(req->req_in_sz));
	free_pages(req->req_out_va, get_order(req->req_out_sz));
	free_pages(req->rsp_in_va,  get_order(req->rsp_in_sz));
	free_pages(req->rsp_out_va, get_order(req->rsp_out_sz));
	kfree(req);
}

struct tdx_tdi_request *tdx_tdi_request_alloc(unsigned long flags)
{
	unsigned int order = get_order(TDI_BUFF_SIZE);
	struct tdx_tdi_request *req;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return NULL;

	/*
	 * TDX module only supports MAX message size to 4K including
	 * DOE and SPDM header, per current version of TDX module it
	 * only supports SPDM 1.2 and DOE 1.0. The headers are 46
	 * byte, so MAX_TDX_SPDM_PAYLOAD_SIZE is PAGE_SIZE - 46, same
	 * for TDISP requests and response, PAGE_SIZE buffer is enough
	 */
	if (!(flags & TDI_REQUEST_FLAGS_TD)) {
		req->req_in_sz  = TDI_BUFF_SIZE;
		req->rsp_out_sz = TDI_BUFF_SIZE;
		req->req_in_va  = __get_free_pages(GFP_KERNEL, order);
		req->rsp_out_va = __get_free_pages(GFP_KERNEL, order);
	}

	req->req_out_sz = TDI_BUFF_SIZE;
	req->rsp_in_sz  = TDI_BUFF_SIZE;
	req->req_out_va = __get_free_pages(GFP_KERNEL, order);
	req->rsp_in_va  = __get_free_pages(GFP_KERNEL, order);

	if (!req->rsp_in_va || !req->req_out_va) {
		tdx_tdi_request_free(req);
		return NULL;
	}

	if (!(flags & TDI_REQUEST_FLAGS_TD) &&
	    (!req->rsp_out_va || !req->req_in_va)) {
		tdx_tdi_request_free(req);
		return NULL;
	}

	req->flags = flags;
	return req;
}

static inline u8 req_to_rsp_message(u8 message)
{
	return message & 0x7f;
}

static int tdx_tdi_req(struct tdx_tdi *ttdi, unsigned long flags,
		       struct tdisp_request_parm *parm)
{
	struct device *dev = &ttdi->tdi->pdev->dev;
	struct tdisp_response_parm rsp_parm;
	u64 retval, req_out_pa, rsp_out_pa;
	struct tdx_payload_parm payload;
	struct tdx_tdi_request *request;
	struct spdm_message msg = { 0 };
	struct tdx_module_output out;
	unsigned int actual_sz;
	int ret;

	request = tdx_tdi_request_alloc(flags);
	if (!request) {
		dev_err(dev, "fail to alloc tdi request\n");
		return -ENOMEM;
	}

	ret = pci_tdi_msg_exchange_prepare(ttdi->tdi);
	if (ret) {
		dev_err(dev, "fail to prepare tdi msg exchange %d\n", ret);
		goto exit_req_free;
	}

	/*
	 * TDH.DEVIF.REQUEST
	 *
	 * td_flag = 1
	 *    no need to generate request payload (payload.req_in_pa == NULL)
	 * td_flag = 0
	 *    generated request payload (valid payload.req_in_pa)
	 *
	 * need encrypted request message from TDX module (req_out_pa)
	 */
	if (request->flags & TDI_REQUEST_FLAGS_TD) {
		payload.raw = 0;
		payload.req.td_flag = 1;
	} else {
		ret = pci_tdi_gen_req(ttdi->tdi, request->req_in_va,
				      request->req_in_sz, parm, &actual_sz);
		if (ret) {
			dev_err(dev, "fail to gen req %d\n", ret);
			goto exit_msg_complete;
		}

		payload.raw = __pa(request->req_in_va);
		payload.req.td_flag = 0;
		payload.req.size = actual_sz;
	}
	req_out_pa = __pa(request->req_out_va);

	retval = tdh_devif_request(ttdi->id.func_id, payload.raw,
				   req_out_pa, &out);
	if (retval) {
		dev_err(dev, "fail to devif request\n");
		ret = -EFAULT;
		goto exit_msg_complete;
	}

	/*
	 * Message exchange
	 *
	 * req_size could be larger than actual message length.
	 * resp_size is provided as max response buffer.
	 */
	msg.flags = SPDM_MSG_FLAGS_DOE | SPDM_MSG_FLAGS_SECURE;
	msg.req_addr = request->req_out_va;
	msg.req_size = request->req_out_sz;
	msg.resp_addr = request->rsp_in_va;
	msg.resp_size = request->rsp_in_sz;

	ret = pci_tdi_msg_exchange(ttdi->tdi, &msg);
	if (ret) {
		dev_err(dev, "fail to exchange tdi msg %d\n", ret);
		goto exit_msg_complete;
	}

	/*
	 * TDH.DEVIF.RESPONSE
	 *
	 * provide encrypted response message to TDX module (payload.rsp_in_pa)
	 *
	 * td_flag = 1
	 *   no need to process response payload (rsp_out_pa == NULL)
	 * td_flag = 0
	 *   process response payload (valid rsp_out_pa)
	 *
	 */
	payload.raw = __pa(request->rsp_in_va);

	if (request->flags & TDI_REQUEST_FLAGS_TD) {
		payload.rsp.td_flag = 1;
		rsp_out_pa = 0;
	} else {
		payload.rsp.td_flag = 0;
		rsp_out_pa = __pa(request->rsp_out_va);
	}

	retval = tdh_devif_response(ttdi->id.func_id, payload.raw,
				    rsp_out_pa, &out);
	if (retval) {
		ret = -EFAULT;
		goto exit_msg_complete;
	}

	if (!(request->flags & TDI_REQUEST_FLAGS_TD)) {
		rsp_parm.message = tdisp_req_to_rsp_message(parm->message);

		ret = pci_tdi_process_rsp(ttdi->tdi, request->rsp_out_va,
					  out.rdx, &rsp_parm);
		if (ret)
			dev_err(dev, "fail to process tdi rsp %d\n", ret);
	}

exit_msg_complete:
	pci_tdi_msg_exchange_complete(ttdi->tdi);
exit_req_free:
	tdx_tdi_request_free(request);
	return ret;
}

int tdx_bind_tdi(struct kvm *kvm, struct pci_tdi *tdi)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdisp_request_parm parm = { 0 };
	struct device *dev = &tdi->pdev->dev;
	struct tdx_tdi *ttdi;
	int ret;

	mutex_lock(&kvm_tdx->ttdi_mutex);

	ttdi = tdx_tdi_alloc(kvm_tdx, tdi);
	if (!ttdi) {
		ret = -ENOMEM;
		goto unlock;
	}
	tdi->priv = ttdi;

	/*
	 * Steps to bind the TDISP device
	 *
	 * 1. Create DEVIF
	 * 2. Create MMIOMT
	 * 3. Create DMAR tables
	 */

	ret = tdx_tdi_devifmt_init(ttdi);
	if (ret)
		goto devif_free;

	ret = tdx_tdi_devif_create(ttdi);
	if (ret)
		goto devifmt_uinit;

	ret = tdx_tdi_mmiomt_init(ttdi);
	if (ret)
		goto devif_remove;

	ret = tdx_tdi_dmar_init(ttdi);
	if (ret)
		goto mmiomt_uinit;

	/* Move TDISP Device Interface state from UNLOCKED to LOCKED */
	parm.message = TDISP_LOCK_INTF_REQ;
	parm.lock_intf.lock_flags = TDI_LOCK_FLAGS_NO_FW_UPDATE;
	ret = tdx_tdi_req(ttdi, 0, &parm);
	if (ret)
		goto dmar_uinit;

	parm.message = TDISP_GET_DEVIF_STATE;
	ret = tdx_tdi_req(ttdi, 0, &parm);
	if (ret)
		goto dmar_uinit;

	dev_dbg(dev, "%s: current TDI state is %u\n", __func__, tdi->state);

	tdx_tdi_add(ttdi);
	mutex_unlock(&kvm_tdx->ttdi_mutex);
	return 0;

dmar_uinit:
	tdx_tdi_dmar_uinit(ttdi);
mmiomt_uinit:
	tdx_tdi_mmiomt_uinit(ttdi);
devif_remove:
	tdx_tdi_devif_remove(ttdi);
devifmt_uinit:
	tdx_tdi_devifmt_uinit(ttdi);
devif_free:
	tdi->priv = NULL;
	tdx_tdi_free(ttdi);
unlock:
	mutex_unlock(&kvm_tdx->ttdi_mutex);
	return ret;
}

int __tdx_unbind_tdi(struct kvm_tdx *kvm_tdx, struct tdx_tdi *ttdi)
{
	struct tdisp_request_parm parm = { 0 };
	struct pci_tdi *tdi = ttdi->tdi;
	struct device *dev = &tdi->pdev->dev;

	if (!ttdi || !__is_tdx_tdi_added(kvm_tdx, ttdi)) {
		dev_err(dev, "%s: target device is not bound\n", __func__);
		return -ENODEV;
	}

	tdx_tdi_del(ttdi);

	/* Move TDISP Device Interface state from LOCKED to UNLOCKED */
	parm.message = TDISP_STOP_INTF_REQ;
	tdx_tdi_req(ttdi, 0, &parm);

	parm.message = TDISP_GET_DEVIF_STATE;
	tdx_tdi_req(ttdi, 0, &parm);

	dev_dbg(dev, "%s: current TDI state is %u\n", __func__, tdi->state);

	/*
	 * Steps to unbind the TDISP device
	 *
	 * 1. Unmap MMIO
	 * 2. Remove DMAR tables
	 * 3. Remove DEVIF
	 * 4. Remove MMIOMT
	 */

	tdx_tdi_mmio_unmap_all(ttdi);
	tdx_tdi_dmar_uinit(ttdi);
	tdx_tdi_devif_remove(ttdi);
	tdx_tdi_devifmt_uinit(ttdi);
	tdx_tdi_mmiomt_uinit(ttdi);
	tdi->priv = NULL;
	tdx_tdi_free(ttdi);

	return 0;
}

int tdx_unbind_tdi(struct kvm *kvm, struct pci_tdi *tdi)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_tdi *ttdi = tdi->priv;

	mutex_lock(&kvm_tdx->ttdi_mutex);
	__tdx_unbind_tdi(kvm_tdx, ttdi);
	mutex_unlock(&kvm_tdx->ttdi_mutex);
	return 0;
}

void tdx_unbind_tdi_all(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_tdi *ttdi;

	mutex_lock(&kvm_tdx->ttdi_mutex);
	list_for_each_entry(ttdi, &kvm_tdx->ttdi_list, node)
		__tdx_unbind_tdi(kvm_tdx, ttdi);
	mutex_unlock(&kvm_tdx->ttdi_mutex);
}

int tdx_tdi_get_info(struct kvm *kvm, struct kvm_tdi_info *info)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_tdi *ttdi;

	ttdi = tdx_tdi_find_by_func_id(kvm_tdx, info->func_id);
	if (!ttdi)
		return -EINVAL;

	info->nonce0 = ttdi->tdi->nonce[0];
	info->nonce1 = ttdi->tdi->nonce[1];
	info->nonce2 = ttdi->tdi->nonce[2];
	info->nonce3 = ttdi->tdi->nonce[3];
	return 0;
}

int tdx_tdi_user_request(struct kvm *kvm, struct kvm_tdi_user_request *req)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_tdi *ttdi;

	ttdi = tdx_tdi_find_by_func_id(kvm_tdx, req->func_id);
	if (!ttdi)
		return -EINVAL;

	return tdx_tdi_req(ttdi, TDI_REQUEST_FLAGS_TD, 0);
}

