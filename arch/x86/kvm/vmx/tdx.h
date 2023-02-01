/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_TDX_H
#define __KVM_X86_TDX_H

#ifdef CONFIG_INTEL_TDX_HOST

#include "posted_intr.h"
#include "pmu_intel.h"
#include "tdx_ops.h"

extern bool enable_tdx;

struct tdx_binding_slot_migtd {
	/* Is migration source VM */
	uint8_t	 is_src;
	/* vsock port for MigTD to connect to host */
	uint32_t vsock_port;
};

enum tdx_binding_slot_state {
	/* Slot is available for a new user */
	TDX_BINDING_SLOT_STATE_INIT = 0,
	/* Slot is used, and servtd is pre-bound */
	TDX_BINDING_SLOT_STATE_PREBOUND = 1,
	/* Slot is used, and a servtd instance is bound */
	TDX_BINDING_SLOT_STATE_BOUND = 2,
	/* Slot is used, and holds all the info. Ready for pre-migration */
	TDX_BINDING_SLOT_STATE_PREMIG_WAIT = 3,
	/* Slot is used, and the pre-migration setup is in progress */
	TDX_BINDING_SLOT_STATE_PREMIG_PROGRESS = 4,
	/* Slot is used, and the pre-migration setup is done */
	TDX_BINDING_SLOT_STATE_PREMIG_DONE = 5,

	TDX_BINDING_SLOT_STATE_UNKNOWN
};

struct tdx_binding_slot {
	enum tdx_binding_slot_state state;
	/* Identify the user TD and the binding slot */
	uint64_t handle;
	/* UUID of the user TD */
	uint8_t  uuid[32];
	/* Idx to servtd's usertd_binding_slots array */
	uint16_t req_id;
	/* The servtd that the slot is bound to */
	struct kvm_tdx *servtd_tdx;
	/*
	 * Data specific to MigTD.
	 * Futher type specific data can be added with union.
	 */
	struct tdx_binding_slot_migtd migtd_data;
};

#define SERVTD_SLOTS_MAX 32
struct kvm_tdx {
	struct kvm kvm;

	unsigned long tdr_pa;
	unsigned long *tdcs_pa;

	u64 attributes;
	u64 xfam;
	int hkid;
	struct misc_cg *misc_cg;

	hpa_t source_pa;

	bool td_initialized;
	bool finalized;
	atomic_t tdh_mem_track;

	u64 tsc_offset;

	/* TDP MMU */
	bool has_range_blocked;

	/*
	 * Pointer to an array of tdx binding slots. Each servtd type has one
	 * binding slot in the array, and the slot is indexed using the servtd
	 * type. Each binding slot corresponds to an entry in the binding table
	 * held by TDCS (see TDX module v1.5 Base Architecture Spec, 13.2.1).
	 */
	struct tdx_binding_slot binding_slots[KVM_TDX_SERVTD_TYPE_MAX];

	/*
	 * Used when being a servtd. A servtd can be bound to multiple user
	 * TDs. Each entry in the array is a pointer to the user TD's binding
	 * slot.
	 */
	struct tdx_binding_slot *usertd_binding_slots[SERVTD_SLOTS_MAX];

	/*
	 * The lock is on the servtd side, so when a user TD needs to lock,
	 * it should lock the one from the service TD that it has bound to,
	 * e.g. tdx_binding_slot->servtd_tdx->binding_slot_lock.
	 *
	 * The lock is used for two synchronization puporses:
	 * #1 insertion and removal of a binding slot to the
	 *    usertd_binding_slots array by different user TDs;
	 * #2 read and write to the fields of a binding slot.
	 *
	 * In theory, #1 and #2 are two independent synchronization usages
	 * and can use two separate locks. But those operations are neither
	 * frequent nor in performance critical path, so simply use one lock
	 * for the two purposes.
	 */
	spinlock_t binding_slot_lock;

	void *mig_state;
};

union tdx_exit_reason {
	struct {
		/* 31:0 mirror the VMX Exit Reason format */
		u64 basic		: 16;
		u64 reserved16		: 1;
		u64 reserved17		: 1;
		u64 reserved18		: 1;
		u64 reserved19		: 1;
		u64 reserved20		: 1;
		u64 reserved21		: 1;
		u64 reserved22		: 1;
		u64 reserved23		: 1;
		u64 reserved24		: 1;
		u64 reserved25		: 1;
		u64 bus_lock_detected	: 1;
		u64 enclave_mode	: 1;
		u64 smi_pending_mtf	: 1;
		u64 smi_from_vmx_root	: 1;
		u64 reserved30		: 1;
		u64 failed_vmentry	: 1;

		/* 63:32 are TDX specific */
		u64 details_l1		: 8;
		u64 class		: 8;
		u64 reserved61_48	: 14;
		u64 non_recoverable	: 1;
		u64 error		: 1;
	};
	u64 full;
};

struct vcpu_tdx {
	struct kvm_vcpu	vcpu;

	/* Posted interrupt descriptor */
	struct pi_desc pi_desc;

	/* Used if this vCPU is waiting for PI notification wakeup. */
	struct list_head pi_wakeup_list;
	/* Until here same layout to struct vcpu_pi. */

	unsigned long tdvpr_pa;
	unsigned long *tdvpx_pa;

	struct list_head cpu_list;

	union {
		struct {
			union {
				struct {
					u16 gpr_mask;
					u16 xmm_mask;
				};
				u32 regs_mask;
			};
			u32 reserved;
		};
		u64 rcx;
	} tdvmcall;
	union tdx_exit_reason exit_reason;
	u64 exit_qualification;
	u64 ext_exit_qualification;
	u64 exit_gpa;
	u32 exit_intr_info;

	bool vcpu_initialized;

	bool host_state_need_save;
	bool host_state_need_restore;
	bool emulate_inject_bp;

	u64 msr_host_kernel_gs_base;
	u64 guest_perf_global_ctrl;

	bool interrupt_disabled_hlt;
	unsigned int buggy_hlt_workaround;

	/*
	 * Dummy to make pmu_intel not corrupt memory.
	 * TODO: Support PMU for TDX.  Future work.
	 */
	struct lbr_desc lbr_desc;

	unsigned long dr6;
};

/* Table 3-42, GHCI spec */
struct tdvmcall_service {
	guid_t   guid;
	/* Length of the hdr and payload */
	uint32_t length;
	uint32_t status;
	uint8_t  data[0];
};

enum tdvmcall_service_id {
	TDVMCALL_SERVICE_ID_QUERY,
	TDVMCALL_SERVICE_ID_MIGTD,

	TDVMCALL_SERVICE_ID_UNKNOWN,
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

static inline bool is_td(struct kvm *kvm)
{
	return kvm->arch.vm_type == KVM_X86_TDX_VM;
}

static inline bool is_td_vcpu(struct kvm_vcpu *vcpu)
{
	return is_td(vcpu->kvm);
}

static inline bool is_debug_td(struct kvm_vcpu *vcpu)
{
	return !vcpu->arch.guest_state_protected;
}

static inline struct kvm_tdx *to_kvm_tdx(struct kvm *kvm)
{
	KVM_BUG_ON(!is_td(kvm), kvm);
	return container_of(kvm, struct kvm_tdx, kvm);
}

static inline struct vcpu_tdx *to_tdx(struct kvm_vcpu *vcpu)
{
	KVM_BUG_ON(!is_td_vcpu(vcpu), vcpu->kvm);
	return container_of(vcpu, struct vcpu_tdx, vcpu);
}

static __always_inline void tdvps_vmcs_check(u32 field, u8 bits)
{
#define VMCS_ENC_ACCESS_TYPE_MASK	0x1UL
#define VMCS_ENC_ACCESS_TYPE_FULL	0x0UL
#define VMCS_ENC_ACCESS_TYPE_HIGH	0x1UL
#define VMCS_ENC_ACCESS_TYPE(field)	((field) & VMCS_ENC_ACCESS_TYPE_MASK)

	/* TDX is 64bit only.  HIGH field isn't supported. */
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) &&
			 VMCS_ENC_ACCESS_TYPE(field) == VMCS_ENC_ACCESS_TYPE_HIGH,
			 "Read/Write to TD VMCS *_HIGH fields not supported");

	BUILD_BUG_ON(bits != 16 && bits != 32 && bits != 64);

#define VMCS_ENC_WIDTH_MASK	GENMASK(14, 13)
#define VMCS_ENC_WIDTH_16BIT	(0UL << 13)
#define VMCS_ENC_WIDTH_64BIT	(1UL << 13)
#define VMCS_ENC_WIDTH_32BIT	(2UL << 13)
#define VMCS_ENC_WIDTH_NATURAL	(3UL << 13)
#define VMCS_ENC_WIDTH(field)	((field) & VMCS_ENC_WIDTH_MASK)

	/* TDX is 64bit only.  i.e. natural width = 64bit. */
	BUILD_BUG_ON_MSG(bits != 64 && __builtin_constant_p(field) &&
			 (VMCS_ENC_WIDTH(field) == VMCS_ENC_WIDTH_64BIT ||
			  VMCS_ENC_WIDTH(field) == VMCS_ENC_WIDTH_NATURAL),
			 "Invalid TD VMCS access for 64-bit field");
	BUILD_BUG_ON_MSG(bits != 32 && __builtin_constant_p(field) &&
			 VMCS_ENC_WIDTH(field) == VMCS_ENC_WIDTH_32BIT,
			 "Invalid TD VMCS access for 32-bit field");
	BUILD_BUG_ON_MSG(bits != 16 && __builtin_constant_p(field) &&
			 VMCS_ENC_WIDTH(field) == VMCS_ENC_WIDTH_16BIT,
			 "Invalid TD VMCS access for 16-bit field");
}

static __always_inline void tdvps_gpr_check(u64 field, u8 bits)
{
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) && (field) >= NR_VCPU_REGS,
			 "Invalid TDX Guest GPR index");
}

static __always_inline void tdvps_state_non_arch_check(u64 field, u8 bits) {}
static __always_inline void tdvps_management_check(u64 field, u8 bits) {}
static __always_inline void tdvps_state_check(u64 field, u8 bits) {}

#define TDX_BUILD_TDVPS_ACCESSORS(bits, uclass, lclass)				\
static __always_inline u##bits td_##lclass##_read##bits(struct vcpu_tdx *tdx,	\
							u32 field)		\
{										\
	struct tdx_module_output out;						\
	u64 err;								\
										\
	tdvps_##lclass##_check(field, bits);					\
	err = tdh_vp_rd(tdx->tdvpr_pa, TDVPS_##uclass(field), &out);		\
	if (KVM_BUG_ON(err, tdx->vcpu.kvm)) {					\
		pr_err("TDH_VP_RD["#uclass".0x%x] failed: 0x%llx\n",		\
		       field, err);						\
		return 0;							\
	}									\
	return (u##bits)out.r8;							\
}										\
static __always_inline void td_##lclass##_write##bits(struct vcpu_tdx *tdx,	\
						      u32 field, u##bits val)	\
{										\
	struct tdx_module_output out;						\
	u64 err;								\
										\
	tdvps_##lclass##_check(field, bits);					\
	err = tdh_vp_wr(tdx->tdvpr_pa, TDVPS_##uclass(field), val,		\
		      GENMASK_ULL(bits - 1, 0), &out);				\
	if (KVM_BUG_ON(err, tdx->vcpu.kvm))					\
		pr_err("TDH_VP_WR["#uclass".0x%x] = 0x%llx failed: 0x%llx\n",	\
		       field, (u64)val, err);					\
}										\
static __always_inline void td_##lclass##_setbit##bits(struct vcpu_tdx *tdx,	\
						       u32 field, u64 bit)	\
{										\
	struct tdx_module_output out;						\
	u64 err;								\
										\
	tdvps_##lclass##_check(field, bits);					\
	err = tdh_vp_wr(tdx->tdvpr_pa, TDVPS_##uclass(field), bit, bit, &out);	\
	if (KVM_BUG_ON(err, tdx->vcpu.kvm))					\
		pr_err("TDH_VP_WR["#uclass".0x%x] |= 0x%llx failed: 0x%llx\n",	\
		       field, bit, err);					\
}										\
static __always_inline void td_##lclass##_clearbit##bits(struct vcpu_tdx *tdx,	\
							 u32 field, u64 bit)	\
{										\
	struct tdx_module_output out;						\
	u64 err;								\
										\
	tdvps_##lclass##_check(field, bits);					\
	err = tdh_vp_wr(tdx->tdvpr_pa, TDVPS_##uclass(field), 0, bit, &out);	\
	if (KVM_BUG_ON(err, tdx->vcpu.kvm))					\
		pr_err("TDH_VP_WR["#uclass".0x%x] &= ~0x%llx failed: 0x%llx\n",	\
		       field, bit,  err);					\
}

TDX_BUILD_TDVPS_ACCESSORS(16, VMCS, vmcs);
TDX_BUILD_TDVPS_ACCESSORS(32, VMCS, vmcs);
TDX_BUILD_TDVPS_ACCESSORS(64, VMCS, vmcs);

TDX_BUILD_TDVPS_ACCESSORS(8, MANAGEMENT, management);
TDX_BUILD_TDVPS_ACCESSORS(64, STATE_NON_ARCH, state_non_arch);
TDX_BUILD_TDVPS_ACCESSORS(64, GPR, gpr);
TDX_BUILD_TDVPS_ACCESSORS(64, STATE, state);

static __always_inline u64 td_tdcs_exec_read64(struct kvm_tdx *kvm_tdx, u32 field)
{
	struct tdx_module_output out;
	u64 err;

	err = tdh_mng_rd(kvm_tdx->tdr_pa, TDCS_EXEC(field), &out);
	if (unlikely(err)) {
		pr_err("TDH_MNG_RD[EXEC.0x%x] failed: 0x%llx\n", field, err);
		return 0;
	}
	return out.r8;
}

static __always_inline int pg_level_to_tdx_sept_level(enum pg_level level)
{
	WARN_ON_ONCE(level == PG_LEVEL_NONE);
	return level - 1;
}

void tdx_reclaim_td_page(unsigned long td_page_pa);

void tdx_track(struct kvm_tdx *kvm_tdx);

int tdx_td_post_init(struct kvm_tdx *kvm_tdx);

void tdx_add_vcpu_association(struct vcpu_tdx *tdx, int cpu);

void tdx_flush_vp_on_cpu(struct kvm_vcpu *vcpu);

int tdx_td_vcpu_setup(struct kvm_vcpu *vcpu);

#else
struct kvm_tdx {
	struct kvm kvm;
};

struct vcpu_tdx {
	struct kvm_vcpu	vcpu;
};

static inline bool is_td(struct kvm *kvm) { return false; }
static inline bool is_td_vcpu(struct kvm_vcpu *vcpu) { return false; }
static inline bool is_debug_td(struct kvm_vcpu *vcpu) { return false; }
static inline struct kvm_tdx *to_kvm_tdx(struct kvm *kvm) { return NULL; }
static inline struct vcpu_tdx *to_tdx(struct kvm_vcpu *vcpu) { return NULL; }
#endif /* CONFIG_INTEL_TDX_HOST */

#endif /* __KVM_X86_TDX_H */
