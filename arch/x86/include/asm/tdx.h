/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2022 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#include <linux/init.h>
#include <linux/bits.h>
#include <asm/ptrace.h>
#include <asm/shared/tdx.h>

/*
 * SW-defined error codes.
 *
 * Bits 47:40 == 0xFF indicate Reserved status code class that never used by
 * TDX module.
 */
#define TDX_ERROR			_BITUL(63)
#define TDX_SW_ERROR			(TDX_ERROR | GENMASK_ULL(47, 40))
#define TDX_SEAMCALL_VMFAILINVALID	(TDX_SW_ERROR | _UL(0xFFFF0000))

#ifndef __ASSEMBLY__

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

void __init tdx_early_init(void);
bool tdx_debug_enabled(void);

void tdx_get_ve_info(struct ve_info *ve);

void __init tdx_filter_init(void);

bool tdx_handle_virt_exception(struct pt_regs *regs, struct ve_info *ve);

void tdx_safe_halt(void);

bool tdx_early_handle_ve(struct pt_regs *regs);

extern int tdx_notify_irq;

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

struct tdsysinfo_struct {
	/* TDX-SEAM Module Info */
	u32	attributes;
	u32	vendor_id;
	u32	build_date;
	u16	build_num;
	u16	minor_version;
	u16	major_version;
	u8	reserved0[14];
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
	 * 'num_cpuid_config'.  The size of 'struct tdsysinfo_struct'
	 * is 1024B defined by TDX architecture.  Use a union with
	 * specific padding to make 'sizeof(struct tdsysinfo_struct)'
	 * equal to 1024.
	 */
	union {
		struct tdx_cpuid_config	cpuid_configs[0];
		u8			reserved5[892];
	};
} __packed __aligned(TDSYSINFO_STRUCT_ALIGNMENT);

struct tdx_td_page {
	unsigned long va;
	u64 pa;
	bool added;
};

static __always_inline int pg_level_to_tdx_sept_level(enum pg_level level)
{
	WARN_ON(level == PG_LEVEL_NONE);
	return level - 1;
}

extern u64 hkid_mask __ro_after_init;
extern u8 hkid_start_pos __ro_after_init;

static __always_inline u64 set_hkid_to_hpa(u64 pa, u16 hkid)
{
	pa &= ~hkid_mask;
	pa |= (u64)hkid << hkid_start_pos;

	return pa;
}

bool platform_tdx_enabled(void);
int tdx_init(void);
const struct tdsysinfo_struct *tdx_get_sysinfo(void);
u32 tdx_get_global_keyid(void);
u32 tdx_get_num_keyid(void);
int tdx_keyid_alloc(void);
void tdx_keyid_free(int keyid);
void tdx_hw_enable(void *junk);
void tdx_hw_disable(void *junk);
bool tdx_io_support(void);
int tdx_reclaim_page(unsigned long va, u64 pa, enum pg_level level,
		     bool do_wb, u16 hkid);
int tdx_alloc_td_page(struct tdx_td_page *page);
void tdx_mark_td_page_added(struct tdx_td_page *page);
void tdx_reclaim_td_page(struct tdx_td_page *page);

u64 __seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
	       struct tdx_module_output *out);
u64 __seamcall_io(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10, u64 r11,
		  u64 r12, u64 r13, u64 r14, u64 r15,
		  struct tdx_module_output *out);

/* Export Intel-IOMMU registers for other components */
#define DMAR_CONFIG_RP_REG	0x8000000B
#define DMAR_CLEAR_RP_REG	0x8000000C

#define TDH_PHYMEM_PAGE_RECLAIM		28
#define TDH_PHYMEM_PAGE_WBINVD		41
#define TDH_IOMMU_SETREG		128
#define TDH_IOMMU_GETREG		129
#define TDH_SPDM_CREATE			130
#define TDH_SPDM_DELETE			131
#define TDH_IDE_STREAM_CREATE		132
#define TDH_IDE_STREAM_BLOCK		133
#define TDH_IDE_STREAM_DELETE		134
#define TDH_IDE_STREAM_IDEKMREQ		135
#define TDH_IDE_STREAM_IDEKMRSP		136
#define TDH_DEVIF_CREATE		137
#define TDH_DEVIF_REMOVE		138
#define TDH_DEVIF_REQUEST		139
#define TDH_DEVIF_RESPONSE		140
#define TDH_DMAR_ADD			150
#define TDH_DMAR_BLOCK			151
#define TDH_DMAR_READ			152
#define TDH_DMAR_REMOVE			153
#define TDH_MMIOMT_ADD			154
#define TDH_MMIOMT_SET			155
#define TDH_MMIOMT_RD			156
#define TDH_MMIOMT_REMOVE		157
#define TDH_MMIO_MAP			158
#define TDH_MMIO_BLOCK			159
#define TDH_MMIO_UNMAP			160
#define TDH_IQINV_REQ			161
#define TDH_IQINV_PROC			162

static inline u64 tdh_phymem_page_reclaim(u64 page,
					  struct tdx_module_output *out)
{
	return __seamcall(TDH_PHYMEM_PAGE_RECLAIM, page, 0, 0, 0, out);
}

static inline u64 tdh_phymem_page_wbinvd(u64 page)
{
	return __seamcall(TDH_PHYMEM_PAGE_WBINVD, page, 0, 0, 0, NULL);
}

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

static inline u64 tdh_mmiomt_add(u64 mmiomt_idx, u64 mmiomt_pa)
{
	u64 ret;
	/*
	 * TDH.MMIOMT.ADD
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - MMIOMT index (level + PA)
	 * Input: RDX - MMIOMT PA of new page
	 *
	 */
	ret =  __seamcall_io(TDH_MMIOMT_ADD, mmiomt_idx, mmiomt_pa,
			     0, 0, 0, 0, 0, 0, 0, 0, NULL);
	pr_debug("%s: ret %llx, mmiomt_idx %llx, mmiomt_pa %llx\n",
		 __func__, ret, mmiomt_idx, mmiomt_pa);

	return ret;
}

static inline u64 tdh_mmiomt_set(u64 mmiomt_idx, u64 mmiomt_info)
{
	u64 ret;
	/*
	 * TDH.MMIOMT.SET
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - MMIOMT index (level + PA)
	 * Input: RDX - MMIOMT INFO: devifcs PA and DATA type
	 *
	 */
	ret = __seamcall_io(TDH_MMIOMT_SET, mmiomt_idx, mmiomt_info,
			    0, 0, 0, 0, 0, 0, 0, 0, NULL);

	pr_debug("%s: ret %llx, mmiomt_idx %llx, mmiomt_info %llx\n",
		 __func__, ret, mmiomt_idx, mmiomt_info);

	return ret;
}

static inline u64 tdh_mmiomt_read(u64 mmiomt_idx, struct tdx_module_output *out)
{
	/*
	 * TDH.MMIOMT.READ
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - MMIOMT index (level + PA)
	 *
	 * Output: Entry Value - RCX, RDX, R8, R9
	 */
	return __seamcall_io(TDH_MMIOMT_RD, mmiomt_idx,
			     0, 0, 0, 0, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_mmiomt_remove(u64 mmiomt_idx)
{
	u64 ret;
	/*
	 * TDH.MMIOMT.REMOVE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX -  MMIOMT index
	 *
	 */
	ret = __seamcall_io(TDH_MMIOMT_REMOVE, mmiomt_idx,
			    0, 0, 0, 0, 0, 0, 0, 0, 0, NULL);

	pr_debug("%s: ret %llx, mmiomt_idx %llx\n",
		 __func__, ret, mmiomt_idx);

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

static inline u64 tdh_dmar_add(u64 index, u64 tdr_pa, u64 entry0, u64 entry1,
			       u64 entry2, u64 entry3, u64 entry4, u64 entry5,
			       u64 entry6, u64 entry7)
{
	/*
	 * TDH.DMAR.ADD
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - Index to locate the DMAR entry
	 * Input: RDX - TDR, valid for PASIDTE only
	 * Input: R8-R15 - parameters
	 *   RTE: R8 R9
	 *   CTE: R8 R9 R10 R11
	 *   PASIDDE: R8
	 *   PASIDTE: R8 R9 R10 R11 R12 R13 R14 R15
	 *
	 * Output: RAX - SEAMCALL return code
	 */
	return __seamcall_io(TDH_DMAR_ADD, index, tdr_pa,
			     entry0, entry1, entry2, entry3,
			     entry4, entry5, entry6, entry7, NULL);
}

static inline u64 tdh_dmar_block(u64 index)
{
	/*
	 * TDH.DMAR.BLOCK
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - Index to locate the DMAR entry
	 *
	 * Output: RAX - SEAMCALL return code
	 */
	return __seamcall_io(TDH_DMAR_BLOCK, index,
			     0, 0, 0, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_dmar_read(u64 index, struct tdx_module_output *out)
{
	/*
	 * TDH.DMAR.READ
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - Index to locate the DMAR entry
	 *
	 * Output: RAX - SEAMCALL return code
	 * Output: R8-R15
	 */
	return __seamcall_io(TDH_DMAR_READ, index,
			     0, 0, 0, 0, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_dmar_remove(u64 index)
{
	/*
	 * TDH.DMAR.REMOVE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - Index to locate the DMAR entry
	 *
	 * Output: RAX - SEAMCALL return code
	 */
	return __seamcall_io(TDH_DMAR_REMOVE, index,
			     0, 0, 0, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_iqinv_req(u64 iommu_id, u64 inv_type, u64 inv_target,
				u64 wait_desc_1, u64 wait_desc_2)
{
	/*
	 * TDH.IQ.INV.REQUEST
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - IOMMU ID
	 * Input: RDX - INVALIDATION TYPE
	 * Input: R8  - RID, PASID and TDR PA
	 * Input: R9 - Invalidation Wait Descriptor bits 63:0
	 * Input: R10 - Invalidation Wait Descriptor bits 127:64
	 */
	return __seamcall_io(TDH_IQINV_REQ, iommu_id, inv_type, inv_target,
			     wait_desc_1, wait_desc_2, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_iqinv_process(u64 iommu_id)
{
	/*
	 * TDH.IQ.INV.PROCESS
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - IOMMU ID
	 */
	return __seamcall_io(TDH_IQINV_PROC, iommu_id,
			     0, 0, 0, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64
tdh_devif_create(u64 devifcs_pa, u64 tdr_pa, u64 tdisp_msg_pa, u64 devif_info,
		 u64 devif_id, struct tdx_module_output *out)
{
	/*
	 * TDH.DEVIF.CREATE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX  devifcs_pa
	 * Input: RDX - TDR PA
	 * Input: R8 - devif_tdisp_msg_pa
	 * Input: R9 - devif_info
	 * Input: R10 - devif_id
	 *
	 * Output: RAX - SEAMCALL return code
	 * Output: RCX - devif handle
	 */
	return __seamcall_io(TDH_DEVIF_CREATE, devifcs_pa, tdr_pa,
			     tdisp_msg_pa, devif_info, devif_id,
			     0, 0, 0, 0, 0, out);
}

static inline u64
tdh_devif_remove(u64 devifcs_pa, struct tdx_module_output *out)
{
	/*
	 * TDH.DEVIF.REMOVE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX  devifcs_pa
	 *
	 * Output: RAX - SEAMCALL return code
	 * Output: RCX - tdisp msg pa
	 */
	return __seamcall_io(TDH_DEVIF_REMOVE, devifcs_pa,
			     0, 0, 0, 0, 0, 0, 0, 0, 0, out);
}

static inline u64
tdh_devif_request(u64 devifcs_pa, u64 req_parm, u64 req_info, u64 req_pa)
{
	/*
	 * TDH.DEVIF.REQUEST
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - devifcs_pa
	 * Input: RDX - TDISP request parameter
	 * Input: R8 - TDISP request info
	 * Input: R9 - pa target of TDISP request message output
	 *
	 * Output: RAX - SEAMCALL return code
	 */
	return __seamcall_io(TDH_DEVIF_REQUEST, devifcs_pa, req_parm, req_info,
			     req_pa, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64
tdh_devif_response(u64 devifcs_pa, u64 tdisp_input_pa,
		   struct tdx_module_output *out)
{
	/*
	 * TDH.DEVIF.RESPONSE
	 *
	 * Input: RAX - SEAMCALL instruction leaf number
	 * Input: RCX - devifcs_pa
	 * Input: RDX - TDISP msg input
	 *
	 * Output: RAX - SEAMCALL return code
	 * Output: RCX - TDISP msg type
	 */
	return __seamcall_io(TDH_DEVIF_RESPONSE, devifcs_pa, tdisp_input_pa,
			     0, 0, 0, 0, 0, 0, 0, 0, out);
}

#else	/* !CONFIG_INTEL_TDX_HOST */
static inline bool platform_tdx_enabled(void) { return false; }
static inline int tdx_init(void)  { return -ENODEV; }
struct tdsysinfo_struct;
static inline const struct tdsysinfo_struct *tdx_get_sysinfo(void) { return NULL; }
static inline u32 tdx_get_global_keyid(void) { return 0; }
static inline u32 tdx_get_num_keyid(void) { return 0; }
static inline int tdx_keyid_alloc(void) { return -EOPNOTSUPP; }
static inline void tdx_keyid_free(int keyid) { }
static inline void tdx_hw_enable(void *junk) { }
static inline void tdx_hw_disable(void *junk) { }
static inline bool tdx_io_support(void) { return false; }
static inline int tdx_reclaim_page(unsigned long va, u64 pa,
				   enum pg_level level, bool do_wb,
				   u16 hkid) { return -EOPNOTSUPP; }
struct tdx_td_page;
static inline int tdx_alloc_td_page(struct tdx_td_page *page) { return -ENOMEM; }
static inline void tdx_mark_td_page_added(struct tdx_td_page *page) { }
static inline void tdx_reclaim_td_page(struct tdx_td_page *page) { }
static inline u64 tdh_phymem_page_reclaim(u64 page,
					  struct tdx_module_output *out) { return -EOPNOTSUPP; }
static inline u64 tdh_phymem_page_wbinvd(u64 page) { return -EOPNOTSUPP; }
static inline u64 tdh_iommu_setreg(u64 iommu_id, u64 reg, u64 val) { return 0; }
static inline u64 tdh_iommu_getreg(u64 iommu_id, u64 reg, u64 *val) { return 0; }
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
static inline u64 tdh_mmiomt_add(u64 mmiomt_idx,
				 u64 mmiomt_pa) { return -EOPNOTSUPP; }
static inline u64 tdh_mmiomt_set(u64 mmiomt_idx,
				 u64 mmiomt_info) { return -EOPNOTSUPP; }
static inline u64
tdh_mmiomt_read(u64 mmiomt_idx,
		struct tdx_module_output *out) { return -EOPNOTSUPP; }
static inline u64 tdh_mmiomt_remove(u64 mmiomt_idx) { return -EOPNOTSUPP; }
static inline u64 tdh_mmio_map(u64 gpa_page_info, u64 tdr_pa,
			       u64 mmio_pa) { return -EOPNOTSUPP; }
static inline u64 tdh_mmio_block(u64 gpa_page_info,
				 u64 tdr_pa) { return -EOPNOTSUPP; }
static inline u64 tdh_mmio_unmap(u64 gpa_page_info,
				 u64 tdr_pa) { return -EOPNOTSUPP; }
static inline u64 tdh_dmar_add(u64 index, u64 tdr_pa, u64 entry0, u64 entry1,
			       u64 entry2, u64 entry3, u64 entry4, u64 entry5,
			       u64 entry6, u64 entry7) { return -EOPNOTSUPP; }
static inline u64 tdh_dmar_block(u64 index) { return -EOPNOTSUPP; }
static inline u64
tdh_dmar_read(u64 index, struct tdx_module_output *out) { return -EOPNOTSUPP; }
static inline u64 tdh_dmar_remove(u64 index) { return -EOPNOTSUPP; }
static inline u64 tdh_iqinv_req(u64 iommu_id, u64 inv_type, u64 inv_target,
				u64 wait_desc_1,
				u64 wait_desc_2) { return -EOPNOTSUPP; }
static inline u64 tdh_iqinv_process(u64 iommu_id) { return -EOPNOTSUPP; }
static inline u64
tdh_devif_create(u64 devifcs_pa, u64 tdr_pa, u64 tdisp_msg_pa, u64 devif_info,
		 u64 devif_id,
		 struct tdx_module_output *out) { return -EOPNOTSUPP; }
static inline u64
tdh_devif_remove(u64 devifcs_pa,
		 struct tdx_module_output *out) { return -EOPNOTSUPP; }
static inline u64
tdh_devif_request(u64 devifcs_pa, u64 req_parm, u64 req_info,
		  u64 req_pa) { return -EOPNOTSUPP; }
static inline u64
tdh_devif_response(u64 devifcs_pa, u64 tdisp_input_pa,
		   struct tdx_module_output *out) { return -EOPNOTSUPP; }
#endif	/* CONFIG_INTEL_TDX_HOST */

#endif /* !__ASSEMBLY__ */
#endif /* _ASM_X86_TDX_H */
