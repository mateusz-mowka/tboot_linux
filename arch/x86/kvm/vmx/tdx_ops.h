/* SPDX-License-Identifier: GPL-2.0 */
/* constants/data definitions for TDX SEAMCALLs */

#ifndef __KVM_X86_TDX_OPS_H
#define __KVM_X86_TDX_OPS_H

#include <linux/compiler.h>

#include <asm/pgtable_types.h>
#include <asm/cacheflush.h>
#include <asm/asm.h>
#include <asm/kvm_host.h>
#include <asm/tdx.h>

#include "tdx_errno.h"
#include "tdx_arch.h"

#ifdef CONFIG_INTEL_TDX_HOST

void pr_tdx_error(u64 op, u64 error_code, const struct tdx_module_output *out);

static inline enum pg_level tdx_sept_level_to_pg_level(int tdx_level)
{
       return tdx_level + 1;
}

static inline void tdx_clflush_page(hpa_t addr, enum pg_level level)
{
	clflush_cache_range(__va(addr), KVM_HPAGE_SIZE(level));
}

static inline uint64_t kvm_seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
				    struct tdx_module_output *out)
{
	u64 err, retries = 0;

	do {
		err = __seamcall(op, rcx, rdx, r8, r9, out);

		/*
		 * On success, non-recoverable errors, or recoverable errors
		 * that don't expect retries, hand it over to the caller.
		 */
		if (!err ||
		    err == TDX_VCPU_ASSOCIATED ||
		    err == TDX_VCPU_NOT_ASSOCIATED ||
		    err == TDX_INTERRUPTED_RESUMABLE)
			return err;

		if (retries++ > TDX_SEAMCALL_RETRY_MAX)
			break;
	} while (TDX_SEAMCALL_ERR_RECOVERABLE(err));

	return err;
}

static inline u64 tdh_mng_addcx(hpa_t tdr, hpa_t addr)
{
	tdx_clflush_page(addr, PG_LEVEL_4K);
	return kvm_seamcall(TDH_MNG_ADDCX, addr, tdr, 0, 0, NULL);
}

static inline u64 tdh_mem_page_add(hpa_t tdr, gpa_t gpa, int level, hpa_t hpa,
				   hpa_t source, struct tdx_module_output *out)
{
	tdx_clflush_page(hpa, tdx_sept_level_to_pg_level(level));
	return kvm_seamcall(TDH_MEM_PAGE_ADD, gpa | level, tdr, hpa,
				   source, out);
}

static inline u64 tdh_mem_sept_add(hpa_t tdr, gpa_t gpa, int level, hpa_t page,
				   struct tdx_module_output *out)
{
	tdx_clflush_page(page, PG_LEVEL_4K);
	return kvm_seamcall(TDH_MEM_SEPT_ADD, gpa | level, tdr, page, 0,
				   out);
}

static inline u64 tdh_mem_sept_remove(hpa_t tdr, gpa_t gpa, int level,
				      struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MEM_SEPT_REMOVE, gpa | level, tdr, 0, 0, out);
}

static inline u64 tdh_vp_addcx(hpa_t tdvpr, hpa_t addr)
{
	tdx_clflush_page(addr, PG_LEVEL_4K);
	return kvm_seamcall(TDH_VP_ADDCX, addr, tdvpr, 0, 0, NULL);
}

static inline u64 tdh_mem_page_relocate(hpa_t tdr, gpa_t gpa, hpa_t hpa,
					struct tdx_module_output *out)
{
	tdx_clflush_page(hpa, PG_LEVEL_4K);
	return kvm_seamcall(TDH_MEM_PAGE_RELOCATE, gpa, tdr, hpa, 0, out);
}

static inline u64 tdh_mem_page_aug(hpa_t tdr, gpa_t gpa, int level, hpa_t hpa,
				   struct tdx_module_output *out)
{
	tdx_clflush_page(hpa, tdx_sept_level_to_pg_level(level));
	return kvm_seamcall(TDH_MEM_PAGE_AUG, gpa | level, tdr, hpa, 0,
				   out);
}

static inline u64 tdh_mem_range_block(hpa_t tdr, gpa_t gpa, int level,
				      struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MEM_RANGE_BLOCK, gpa | level, tdr, 0, 0,
				   out);
}

static inline u64 tdh_mng_key_config(hpa_t tdr)
{
	return kvm_seamcall(TDH_MNG_KEY_CONFIG, tdr, 0, 0, 0, NULL);
}

static inline u64 tdh_mng_create(hpa_t tdr, int hkid)
{
	tdx_clflush_page(tdr, PG_LEVEL_4K);
	return kvm_seamcall(TDH_MNG_CREATE, tdr, hkid, 0, 0, NULL);
}

static inline u64 tdh_vp_create(hpa_t tdr, hpa_t tdvpr)
{
	tdx_clflush_page(tdvpr, PG_LEVEL_4K);
	return kvm_seamcall(TDH_VP_CREATE, tdvpr, tdr, 0, 0, NULL);
}

static inline u64 tdh_mem_rd(hpa_t tdr, gpa_t addr, struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MEM_RD, addr, tdr, 0, 0, out);
}

static inline u64 tdh_mem_wr(hpa_t tdr, hpa_t addr, u64 val, struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MEM_WR, addr, tdr, val, 0, out);
}

static inline u64 tdh_mng_rd(hpa_t tdr, u64 field, struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MNG_RD, tdr, field, 0, 0, out);
}

static inline u64 tdh_mem_page_demote(hpa_t tdr, gpa_t gpa, int level, hpa_t page,
				      struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MEM_PAGE_DEMOTE, gpa | level, tdr, page,
				   0, out);
}

static inline u64 tdh_mr_extend(hpa_t tdr, gpa_t gpa,
				struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MR_EXTEND, gpa, tdr, 0, 0, out);
}

static inline u64 tdh_mr_finalize(hpa_t tdr)
{
	return kvm_seamcall(TDH_MR_FINALIZE, tdr, 0, 0, 0, NULL);
}

static inline u64 tdh_vp_flush(hpa_t tdvpr)
{
	return kvm_seamcall(TDH_VP_FLUSH, tdvpr, 0, 0, 0, NULL);
}

static inline u64 tdh_mng_vpflushdone(hpa_t tdr)
{
	return kvm_seamcall(TDH_MNG_VPFLUSHDONE, tdr, 0, 0, 0, NULL);
}

static inline u64 tdh_mng_key_freeid(hpa_t tdr)
{
	return kvm_seamcall(TDH_MNG_KEY_FREEID, tdr, 0, 0, 0, NULL);
}

static inline u64 tdh_mng_init(hpa_t tdr, hpa_t td_params,
			       struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MNG_INIT, tdr, td_params, 0, 0, out);
}

static inline u64 tdh_vp_init(hpa_t tdvpr, u64 rcx)
{
	return kvm_seamcall(TDH_VP_INIT, tdvpr, rcx, 0, 0, NULL);
}

static inline u64 tdh_vp_rd(hpa_t tdvpr, u64 field,
			    struct tdx_module_output *out)
{
	u64 actual_field = field;

	/*
	 * The non-architectural fields have different field ids in different
	 * TDX module versions. Callers use the field id based on the first
	 * version of TDX module. Do a switch of the field id based on the TDX
	 * module version here.
	 */
	if (field & TDX_NON_ARCH)
		actual_field = tdx_non_arch_field_switch(field);

	return kvm_seamcall(TDH_VP_RD, tdvpr, actual_field, 0, 0, out);
}

static inline u64 tdh_mng_key_reclaimid(hpa_t tdr)
{
	return kvm_seamcall(TDH_MNG_KEY_RECLAIMID, tdr, 0, 0, 0, NULL);
}

#if 0
static inline u64 tdh_phymem_page_reclaim(hpa_t page,
					  struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_PHYMEM_PAGE_RECLAIM, page, 0, 0, 0, out);
}
#endif

static inline u64 tdh_mem_page_remove(hpa_t tdr, gpa_t gpa, int level,
				      struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MEM_PAGE_REMOVE, gpa | level, tdr, 0, 0,
				   out);
}

static inline u64 tdh_sys_lp_shutdown(void)
{
	return kvm_seamcall(TDH_SYS_LP_SHUTDOWN, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mem_track(hpa_t tdr)
{
	return kvm_seamcall(TDH_MEM_TRACK, tdr, 0, 0, 0, NULL);
}

static inline u64 tdh_mem_range_unblock(hpa_t tdr, gpa_t gpa, int level,
					struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MEM_RANGE_UNBLOCK, gpa | level, tdr, 0, 0,
				   out);
}

static inline u64 tdh_phymem_cache_wb(bool resume)
{
	return kvm_seamcall(TDH_PHYMEM_CACHE_WB, resume ? 1 : 0, 0, 0, 0, NULL);
}

#if 0
static inline u64 tdh_phymem_page_wbinvd(hpa_t page)
{
	return kvm_seamcall(TDH_PHYMEM_PAGE_WBINVD, page, 0, 0, 0, NULL);
}
#endif

static inline u64 tdh_vp_wr(hpa_t tdvpr, u64 field, u64 val, u64 mask,
			    struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_VP_WR, tdvpr, field, val, mask, out);
}
#endif /* CONFIG_INTEL_TDX_HOST */

#endif /* __KVM_X86_TDX_OPS_H */
