/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2022 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#include <linux/init.h>
#include <linux/bits.h>
#include <asm/ptrace.h>
#include <asm/shared/tdx.h>

#ifdef CONFIG_INTEL_TDX_HOST

#include <asm/trapnr.h>

/*
 * SW-defined error codes.
 *
 * Bits 47:40 == 0xFF indicate Reserved status code class that never used by
 * TDX module.
 */
#define TDX_ERROR_BIT			63
#define TDX_ERROR			_BITUL(TDX_ERROR_BIT)
#define TDX_SW_ERROR			(TDX_ERROR | GENMASK_ULL(47, 40))
#define TDX_SEAMCALL_VMFAILINVALID	(TDX_SW_ERROR | _UL(0xFFFF0000))
#define TDX_SEAMCALL_VMFAILVALID	(TDX_SW_ERROR | _UL(0xFFFE0000))

#define TDX_SEAMCALL_GP			(TDX_SW_ERROR | X86_TRAP_GP)
#define TDX_SEAMCALL_UD			(TDX_SW_ERROR | X86_TRAP_UD)

#endif

#define TDX_NON_RECOVERABLE_BIT		62
/*
 * Error with the non-recoverable bit cleared indicates that the error is
 * likely recoverable (e.g. due to lock busy in TDX module), and the seamcall
 * can be retried.
 */
#define TDX_SEAMCALL_ERR_RECOVERABLE(err) \
	(err >> TDX_NON_RECOVERABLE_BIT == 0x2)

/* The max number of seamcall retries */
#define TDX_SEAMCALL_RETRY_MAX	10000

#ifndef __ASSEMBLY__

/* TDX supported page sizes from the TDX module ABI. */
#define TDX_PS_4K	0
#define TDX_PS_2M	1
#define TDX_PS_1G	2

/*
 * Used by the #VE exception handler to gather the #VE exception
 * info from the TDX module. This is a software only structure
 * and not part of the TDX module/VMM ABI.
 */
struct ve_info {
	u64 exit_reason;
	u64 exit_qual;
	/* Guest Linear (virtual) Address */
	u64 gla;
	/* Guest Physical Address */
	u64 gpa;
	u32 instr_len;
	u32 instr_info;
};

#ifdef CONFIG_INTEL_TDX_GUEST

extern int tdx_notify_irq;

void __init tdx_early_init(void);

bool tdx_debug_enabled(void);

void __init tdx_early_init(void);

void tdx_get_ve_info(struct ve_info *ve);

void __init tdx_filter_init(void);

bool tdx_handle_virt_exception(struct pt_regs *regs, struct ve_info *ve);

void tdx_safe_halt(void);

bool tdx_early_handle_ve(struct pt_regs *regs);

int tdx_mcall_get_report0(u8 *reportdata, u8 *tdreport);

bool tdx_enc_status_changed_phys(phys_addr_t start, phys_addr_t end, bool enc);

u64 tdx_mcall_verify_report(u8 *reportmac);

int tdx_mcall_extend_rtmr(u8 *data, u8 index);

int tdx_hcall_get_quote(void *tdquote, int size);

bool tdx_allowed_port(short int port);

#else

static inline void tdx_early_init(void) { };
static inline void tdx_safe_halt(void) { };
static inline void tdx_filter_init(void) { };

static inline bool tdx_early_handle_ve(struct pt_regs *regs) { return false; }

#endif /* CONFIG_INTEL_TDX_GUEST */

#if defined(CONFIG_KVM_GUEST) && defined(CONFIG_INTEL_TDX_GUEST)
long tdx_kvm_hypercall(unsigned int nr, unsigned long p1, unsigned long p2,
		       unsigned long p3, unsigned long p4);
#else
static inline long tdx_kvm_hypercall(unsigned int nr, unsigned long p1,
				     unsigned long p2, unsigned long p3,
				     unsigned long p4)
{
	return -ENODEV;
}
#endif /* CONFIG_INTEL_TDX_GUEST && CONFIG_KVM_GUEST */

#ifdef CONFIG_INTEL_TDX_HOST

/* -1 indicates CPUID leaf with no sub-leaves. */
#define TDX_CPUID_NO_SUBLEAF	((u32)-1)
struct tdx_cpuid_config {
	u32	leaf;
	u32	sub_leaf;
	u32	eax;
	u32	ebx;
	u32	ecx;
	u32	edx;
} __packed;

#define TDSYSINFO_STRUCT_SIZE		1024
#define TDSYSINFO_STRUCT_ALIGNMENT	1024

/*
 * The size of this structure itself is flexible.  The actual structure
 * passed to TDH.SYS.INFO must be padded to TDSYSINFO_STRUCT_SIZE and be
 * aligned to TDSYSINFO_STRUCT_ALIGNMENT using DECLARE_PADDED_STRUCT().
 */
struct tdsysinfo_struct {
	/* TDX-SEAM Module Info */
	u32	attributes;
	u32	vendor_id;
	u32	build_date;
	u16	build_num;
	u16	minor_version;
	u16	major_version;
	u8	sys_rd;
	u8	reserved0[13];
	/* Memory Info */
	u16	max_tdmrs;
	u16	max_reserved_per_tdmr;
	u16	pamt_entry_size;
	u8	reserved1[10];
	/* Control Struct Info */
	u16	tdcs_base_size;
	u8	reserved2[2];
	u16	tdvps_base_size;
	u8	tdvps_xfam_dependent_size;
	u8	reserved3[9];
	/* TD Capabilities */
	u64	attributes_fixed0;
	u64	attributes_fixed1;
	u64	xfam_fixed0;
	u64	xfam_fixed1;
	u8	reserved4[32];
	u32	num_cpuid_config;
	/*
	 * The actual number of CPUID_CONFIG depends on above
	 * 'num_cpuid_config'.
	 */
	DECLARE_FLEX_ARRAY(struct tdx_cpuid_config, cpuid_configs);
} __packed;

const struct tdsysinfo_struct *tdx_get_sysinfo(void);
bool platform_tdx_enabled(void);
int tdx_enable(void);
/*
 * Key id globally used by TDX module: TDX module maps TDR with this TDX global
 * key id.  TDR includes key id assigned to the TD.  Then TDX module maps other
 * TD-related pages with the assigned key id.  TDR requires this TDX global key
 * id for cache flush unlike other TD-related pages.
 */
extern u32 tdx_global_keyid __read_mostly;
u32 tdx_get_num_keyid(void);
int tdx_keyid_alloc(void);
void tdx_keyid_free(int keyid);
bool tdx_io_support(void);
bool tdx_io_enabled(void);

u64 __seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10,
	       u64 r11, u64 r12, u64 r13, struct tdx_module_output *out);
u64 __seamcall_io(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10, u64 r11,
		  u64 r12, u64 r13, u64 r14, u64 r15,
		  struct tdx_module_output *out);

#define TDH_IOMMU_SETREG		128
#define TDH_IOMMU_GETREG		129
#define TDH_SPDM_CREATE			130
#define TDH_SPDM_DELETE			131
#define TDH_IDE_STREAM_CREATE		132
#define TDH_IDE_STREAM_BLOCK		133
#define TDH_IDE_STREAM_DELETE		134
#define TDH_IDE_STREAM_IDEKMREQ		135
#define TDH_IDE_STREAM_IDEKMRSP		136
#define TDH_MMIO_MAP			158
#define TDH_MMIO_BLOCK			159
#define TDH_MMIO_UNMAP			160

static inline u64 tdh_iommu_setreg(u64 iommu_id, u64 reg, u64 val)
{
	u64 ret;

        /*
         * Input: RCX: iommu id
         * Input: RDX: register id
         * Input: R8:  register value
         */
	ret = __seamcall_io(TDH_IOMMU_SETREG, iommu_id, reg, val,
			    0, 0, 0, 0, 0, 0, 0, NULL);

	pr_info("%s: iommu_id 0x%llx reg 0x%llx val 0x%llx ret 0x%llx\n",
		__func__, iommu_id, reg, val, ret);

	return ret;
}

static inline u64 tdh_iommu_getreg(u64 iommu_id, u64 reg, u64 *val)
{
        struct tdx_module_output out;
        u64 ret;

	/*
         * Input: RCX: iommu id
         * Input: RDX: register id
         * Output: R8: register value
	 */
	ret = __seamcall_io(TDH_IOMMU_GETREG, iommu_id, reg,
			    0, 0, 0, 0, 0, 0, 0, 0, &out);

	pr_info("%s: iommu_id 0x%llx reg 0x%llx val 0x%llx ret 0x%llx\n",
		__func__, iommu_id, reg, out.r8, ret);

	if (!ret)
		*val = out.r8;

        return ret;
}

static inline u64 tdh_spdm_create(u64 iommu_id, u64 spdm_session_idx, u64 spdm_info_pa)
{
	u64 ret;

	/*
	 * TDH.SPDM.CREATE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - IOMMU hosting the stream
	 * Input: RDX - SPDM session index of device connected to stream
	 * Input: R8  - Physical address of page a free page in PAMT to
	 * hold SPDM session information
	 *
	 * Output: RAX - SEAMCALL instruction return code
	 */

	ret = __seamcall_io(TDH_SPDM_CREATE, iommu_id, spdm_session_idx,
			    spdm_info_pa, 0, 0, 0, 0, 0, 0, 0, NULL);
	pr_info("%s: iommu_id 0x%llx spdm_session_idx 0x%llx spdm_info_pa 0x%llx ret 0x%llx\n",
		__func__, iommu_id, spdm_session_idx, spdm_info_pa, ret);

	return ret;
}

static inline u64 tdh_spdm_delete(u64 iommu_id, u64 spdm_session_idx, u64 *spdm_info_pa)
{
	struct tdx_module_output out;
	u64 ret;

	/*
	 * TDH.SPDM.DELETE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - IOMMU hosting the stream
	 * Input: RDX - SPDM session index of device connected to stream
	 *
	 * Output: RAX - SEAMCALL instruction return code
	 * Output: RCX - Physical address of the freed SPDM session information page
	 */

	ret = __seamcall_io(TDH_SPDM_DELETE, iommu_id, spdm_session_idx,
			    0, 0, 0, 0, 0, 0, 0, 0, &out);
	pr_info("%s: iommu_id 0x%llx spdm_session_idx 0x%llx ret 0x%llx\n",
		__func__, iommu_id, spdm_session_idx, ret);

	if (!ret && spdm_info_pa)
		*spdm_info_pa = out.rcx;

	return ret;
}

static inline u64 tdh_ide_stream_create(u64 iommu_id,
					u64 spdm_session_idx,
					u64 stream_cfg_reg,
					u64 stream_ctrl_reg,
					u64 rid_assoc1_reg,
					u64 rid_assoc2_reg,
					u64 addr_assoc1_reg,
					u64 addr_assoc2_reg,
					u64 addr_assoc3_reg,
					u64 stream_exinfo_pa)
{
	u64 ret;

	/*
	 * TDH.IDE.STREAM.CREATE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - IOMMU hosting the stream
	 * Input: RDX - SPDM session index of device connected to stream
	 * Input: R8  - Stream configuration information   Type: IDE_STREAM_CONFIG_T
	 * Input: R9  - Stream Control register configurations   Type: IDE_STREAM_CONTROL_T
	 * Input: R10 - RID association register 1   Type: IDE_RID_ASSOC_REG_1_T
	 * Input: R11 - RID association register 2   Type: IDE_RID_ASSOC_REG_2_T
	 * Input: R12 - Address association register 1   Type: IDE_ADDR_ASSOC_REG_1_T
	 * Input: R13 - Address association register 2   Type: IDE_ADDR_ASSOC_REG_2_T
	 * Input: R14 - Address association register 3   Type: IDE_ADDR_ASSOC_REG_3_T
	 * Input: R15 - Physical address of a free page in PAMT to
	 * hold stream extended information
	 *
	 * Output: RAX - SEAMCALL instruction return code
	 */

	ret = __seamcall_io(TDH_IDE_STREAM_CREATE, iommu_id, spdm_session_idx,
			    stream_cfg_reg, stream_ctrl_reg, rid_assoc1_reg,
			    rid_assoc2_reg, addr_assoc1_reg, addr_assoc2_reg,
			    addr_assoc3_reg, stream_exinfo_pa, NULL);
	pr_info("%s: iommu_id 0x%llx spdm_session_idx 0x%llx stream_cfg 0x%llx stream_ctrl_reg 0x%llx rid_assoc1_reg 0x%llx rid_assoc2_reg 0x%llx addr_assoc1_reg 0x%llx addr_assoc2_reg 0x%llx addr_assoc3_reg 0x%llx stream_exinfo_pa 0x%llx ret 0x%llx\n",
		__func__, iommu_id, spdm_session_idx, stream_cfg_reg, stream_ctrl_reg,
		rid_assoc1_reg, rid_assoc2_reg, addr_assoc1_reg, addr_assoc2_reg,
		addr_assoc3_reg, stream_exinfo_pa, ret);

	return ret;
}

static inline u64 tdh_ide_stream_block(u64 iommu_id, u64 stream_id)
{
	u64 ret;

	/*
	 * TDH.IDE.STREAM.BLOCK
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - IOMMU hosting the stream
	 * Input: RDX - Stream ID of stream to delete
	 *
	 * Output: RAX - SEAMCALL instruction return code
	 */

	ret = __seamcall_io(TDH_IDE_STREAM_BLOCK, iommu_id, stream_id,
			    0, 0, 0, 0, 0, 0, 0, 0, NULL);
	pr_info("%s: iommu_id 0x%llx stream_id 0x%llx ret 0x%llx\n",
		__func__, iommu_id, stream_id, ret);

	return ret;
}

static inline u64 tdh_ide_stream_delete(u64 iommu_id, u64 stream_id)
{
	u64 ret;

	/*
	 * TDH.IDE.STREAM.DELETE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - IOMMU hosting the stream
	 * Input: RDX - Stream ID of stream to delete
	 *
	 * Output: RAX - SEAMCALL instruction return code
	 */

	ret = __seamcall_io(TDH_IDE_STREAM_DELETE, iommu_id, stream_id,
			    0, 0, 0, 0, 0, 0, 0, 0, NULL);

	pr_info("%s: iommu_id 0x%llx stream_id 0x%llx ret 0x%llx\n",
		__func__, iommu_id, stream_id, ret);

	return ret;
}

static inline u64 tdh_ide_stream_idekmreq(u64 iommu_id,
					  u64 stream_id,
					  u64 object_id,
					  u64 ide_km_param,
					  u64 slot_id,
					  u64 message_pa)
{
	u64 ret;

	/*
	 * TDH.IDE.STREAM.IDEKMREQ
	 *
	 * Input: RAX - SEAMCALL ins]truction leaf number
	 * Input: RCX - IOMMU hosting the stream
	 * Input: RDX - Stream ID of stream to generate key management request message for
	 * Input: R8  - Object ID of message to generate
	 * Input: R9  - IDE Key Management message parameters - Type: IDE_KM_PARAM_T
	 * Input: R10 - Key Slot ID to configure if needed in the root port
	 * Input: R11 - Physical address of a shared memory buffer in which to
	 * emit the key management protocol message
	 *
	 * Output: RAX - SEAMCALL instruction return code
	 */

	ret = __seamcall_io(TDH_IDE_STREAM_IDEKMREQ, iommu_id, stream_id,
			    object_id, ide_km_param, slot_id, message_pa,
			    0, 0, 0, 0, NULL);

	pr_info("%s: iommu_id 0x%llx stream_id 0x%llx object_id 0x%llx ide_km_param 0x%llx slot_id 0x%llx message_pa 0x%llx ret 0x%llx\n",
		__func__, iommu_id, stream_id, object_id,
		ide_km_param, slot_id, message_pa, ret);

	return ret;
}

static inline u64 tdh_ide_stream_idekmrsp(u64 iommu_id,
					  u64 stream_id,
					  u64 message_pa,
					  u64 *resp_data)
{
	struct tdx_module_output out;
	u64 ret;

	/*
	 * TDH.IDE.STREAM.IDEKMRSP
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - IOMMU hosting the stream
	 * Input: RDX - Stream ID of stream to generate key management request message for
	 * Input: R8  - Physical address of a shared memory buffer holding the response message
	 *
	 * Output: RAX - SEAMCALL instruction return code
	 * Output: RCX - Returns 8 bytes of the IDE Key management response
	 * if authentication successful
	 */

	ret = __seamcall_io(TDH_IDE_STREAM_IDEKMRSP, iommu_id, stream_id,
			    message_pa, 0, 0, 0, 0, 0, 0, 0, &out);
	pr_info("%s: iommu_id 0x%llx stream_id 0x%llx message_pa 0x%llx ret 0x%llx\n",
		__func__, iommu_id, stream_id, message_pa, ret);

	if (!ret && resp_data)
		*resp_data = out.rcx;

	return ret;
}

static inline u64 tdh_mmio_map(u64 gpa_page_info, u64 tdr_pa, u64 mmio_pa)
{
	/*
	 * TDH.MMIO.MAP
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX -  GPA PAGE INFO
	 * Input: RDX - TDR PA
	 * Input: R8 - MMIO PA
	 */
	return __seamcall_io(TDH_MMIO_MAP, gpa_page_info, tdr_pa, mmio_pa,
			     0, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mmio_block(u64 gpa_page_info, u64 tdr_pa)
{
	/*
	 * TDH.MMIO.BLOCK
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX -  GPA PAGE INFO
	 * Input: RDX - TDR PA
	 */
	return __seamcall_io(TDH_MMIO_BLOCK, gpa_page_info, tdr_pa,
			     0, 0, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mmio_unmap(u64 gpa_page_info, u64 tdr_pa)
{
	/*
	 * TDH.MMIO.UNMAP
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX -  GPA PAGE INFO
	 * Input: RDX - TDR PA
	 */
	return __seamcall_io(TDH_MMIO_UNMAP, gpa_page_info, tdr_pa,
			     0, 0, 0, 0, 0, 0, 0, 0, NULL);
}

#else	/* !CONFIG_INTEL_TDX_HOST */
struct tdsysinfo_struct;
static inline const struct tdsysinfo_struct *tdx_get_sysinfo(void) { return NULL; }
static inline bool platform_tdx_enabled(void) { return false; }
static inline int tdx_enable(void)  { return -EINVAL; }
static inline u32 tdx_get_num_keyid(void) { return 0; }
static inline int tdx_keyid_alloc(void) { return -EOPNOTSUPP; }
static inline void tdx_keyid_free(int keyid) { }
static inline bool tdx_io_support(void) { return false; }
static inline bool tdx_io_enabled(void) { return false; }
static inline u64 tdh_iommu_setreg(u64 iommu_id, u64 reg, u64 val) { return 0; }
static inline u64 tdh_iommu_getreg(u64 iommu_id, u64 reg, u64 *val) { return 0; }
static inline u64 tdh_mmio_map(u64 gpa_page_info, u64 tdr_pa,
			       u64 mmio_pa) { return -EOPNOTSUPP; }
static inline u64 tdh_mmio_block(u64 gpa_page_info,
				 u64 tdr_pa) { return -EOPNOTSUPP; }
static inline u64 tdh_mmio_unmap(u64 gpa_page_info,
				 u64 tdr_pa) { return -EOPNOTSUPP; }
static inline u64 tdh_ide_stream_create(u64 iommu_id,
					u64 spdm_session_idx,
					u64 stream_cfg_reg,
					u64 stream_ctrl_reg,
					u64 rid_assoc1_reg,
					u64 rid_assoc2_reg,
					u64 addr_assoc1_reg,
					u64 addr_assoc2_reg,
					u64 addr_assoc3_reg,
					u64 stream_exinfo_pa) { return -EOPNOTSUPP; }
static inline u64 tdh_ide_stream_block(u64 iommu_id, u64 stream_id) { return -EOPNOTSUPP; }
static inline u64 tdh_ide_stream_delete(u64 iommu_id, u64 stream_id) { return -EOPNOTSUPP; }
static inline u64 tdh_ide_stream_idekmreq(u64 iommu_id,
					  u64 stream_id,
					  u64 object_id,
					  u64 ide_km_param,
					  u64 slot_id,
					  u64 message_pa) { return -EOPNOTSUPP; }
static inline u64 tdh_ide_stream_idekmrsp(u64 iommu_id,
					  u64 stream_id,
					  u64 message_pa,
					  u64 *resp_data) { return -EOPNOTSUPP; }
#endif	/* CONFIG_INTEL_TDX_HOST */

#ifdef CONFIG_INTEL_TDX_MODULE_UPDATE
int tdx_module_update(bool live_update, bool *recoverable);
#else /* !CONFIG_INTEL_TDX_MODULE_UPDATE */
static inline int tdx_module_update(bool live_update, bool *recoverable)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_INTEL_TDX_MODULE_UPDATE */

#endif /* !__ASSEMBLY__ */
#endif /* _ASM_X86_TDX_H */
