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
#include "x86.h"

#ifdef CONFIG_INTEL_TDX_HOST

bool is_sys_rd_supported(void);

void pr_tdx_error(u64 op, u64 error_code, const struct tdx_module_output *out);

static inline enum pg_level tdx_sept_level_to_pg_level(int tdx_level)
{
       return tdx_level + 1;
}

static inline void tdx_clflush_page(hpa_t addr, enum pg_level level)
{
	clflush_cache_range(__va(addr), KVM_HPAGE_SIZE(level));
}

static inline uint64_t kvm_seamcall(u64 op, u64 rcx, u64 rdx, u64 r8,
				    u64 r9, u64 r10, u64 r11, u64 r12,
				    u64 r13, struct tdx_module_output *out)
{
	u64 err, retries = 0;

	do {
		err = __seamcall(op, rcx, rdx, r8, r9,
				   r10, r11, r12, r13, out);

		/*
		 * On success, non-recoverable errors, or recoverable errors
		 * that don't expect retries, hand it over to the caller.
		 */
		if (!err ||
		    err == TDX_VCPU_ASSOCIATED ||
		    err == TDX_VCPU_NOT_ASSOCIATED ||
		    err == TDX_INTERRUPTED_RESUMABLE)
			return err;
		else if (unlikely(err == TDX_SEAMCALL_UD)) {
			kvm_spurious_fault();
			return 0;
		}

		if (retries++ > TDX_SEAMCALL_RETRY_MAX)
			break;
	} while (TDX_SEAMCALL_ERR_RECOVERABLE(err));

	return err;
}

static inline u64 tdh_mng_addcx(hpa_t tdr, hpa_t addr)
{
	tdx_clflush_page(addr, PG_LEVEL_4K);
	return kvm_seamcall(TDH_MNG_ADDCX, addr,
			    tdr, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mem_page_add(hpa_t tdr, gpa_t gpa, int level, hpa_t hpa,
				   hpa_t source, struct tdx_module_output *out)
{
	tdx_clflush_page(hpa, tdx_sept_level_to_pg_level(level));
	return kvm_seamcall(TDH_MEM_PAGE_ADD, gpa | level, tdr,
			    hpa, source, 0, 0, 0, 0, out);
}

static inline u64 tdh_mem_sept_add(hpa_t tdr, gpa_t gpa, int level, hpa_t page,
				   struct tdx_module_output *out)
{
	tdx_clflush_page(page, PG_LEVEL_4K);
	return kvm_seamcall(TDH_MEM_SEPT_ADD, gpa | level,
			    tdr, page, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_mem_sept_remove(hpa_t tdr, gpa_t gpa, int level,
				      struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MEM_SEPT_REMOVE,
			    gpa | level, tdr, 0, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_vp_addcx(hpa_t tdvpr, hpa_t addr)
{
	tdx_clflush_page(addr, PG_LEVEL_4K);
	return kvm_seamcall(TDH_VP_ADDCX, addr,
			    tdvpr, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mem_page_relocate(hpa_t tdr, gpa_t gpa, hpa_t hpa,
					struct tdx_module_output *out)
{
	tdx_clflush_page(hpa, PG_LEVEL_4K);
	return kvm_seamcall(TDH_MEM_PAGE_RELOCATE, gpa,
			    tdr, hpa, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_mem_page_aug(hpa_t tdr, gpa_t gpa, int level, hpa_t hpa,
				   struct tdx_module_output *out)
{
	tdx_clflush_page(hpa, tdx_sept_level_to_pg_level(level));
	return kvm_seamcall(TDH_MEM_PAGE_AUG, gpa | level,
			    tdr, hpa, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_mem_range_block(hpa_t tdr, gpa_t gpa, int level,
				      struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MEM_RANGE_BLOCK,
			    gpa | level, tdr, 0, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_mng_key_config(hpa_t tdr)
{
	return kvm_seamcall(TDH_MNG_KEY_CONFIG, tdr,
			    0, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mng_create(hpa_t tdr, int hkid)
{
	tdx_clflush_page(tdr, PG_LEVEL_4K);
	return kvm_seamcall(TDH_MNG_CREATE, tdr,
			    hkid, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_vp_create(hpa_t tdr, hpa_t tdvpr)
{
	tdx_clflush_page(tdvpr, PG_LEVEL_4K);
	return kvm_seamcall(TDH_VP_CREATE, tdvpr,
			    tdr, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mem_rd(hpa_t tdr, gpa_t addr,
			     struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MEM_RD, addr,
			    tdr, 0, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_mem_wr(hpa_t tdr, hpa_t addr, u64 val,
			     struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MEM_WR, addr, tdr,
			    val, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_mng_rd(hpa_t tdr, u64 field,
			     struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MNG_RD, tdr,
			    field, 0, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_mem_page_demote(hpa_t tdr, gpa_t gpa,
				      int level, hpa_t page,
				      struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MEM_PAGE_DEMOTE,
			    gpa | level, tdr, page, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_mr_extend(hpa_t tdr, gpa_t gpa,
				struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MR_EXTEND, gpa,
			    tdr, 0, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_mr_finalize(hpa_t tdr)
{
	return kvm_seamcall(TDH_MR_FINALIZE, tdr,
			    0, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_vp_flush(hpa_t tdvpr)
{
	return kvm_seamcall(TDH_VP_FLUSH, tdvpr,
			    0, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mng_vpflushdone(hpa_t tdr)
{
	return kvm_seamcall(TDH_MNG_VPFLUSHDONE, tdr,
			    0, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mng_key_freeid(hpa_t tdr)
{
	return kvm_seamcall(TDH_MNG_KEY_FREEID, tdr,
			    0, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mng_init(hpa_t tdr, hpa_t td_params,
			       struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MNG_INIT, tdr,
			    td_params, 0, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_vp_init(hpa_t tdvpr, u64 rcx)
{
	return kvm_seamcall(TDH_VP_INIT, tdvpr, rcx, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_vp_rd(hpa_t tdvpr, u64 field,
			    struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_VP_RD, tdvpr, field,
			    0, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_mng_key_reclaimid(hpa_t tdr)
{
	return kvm_seamcall(TDH_MNG_KEY_RECLAIMID,
			    tdr, 0, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_phymem_page_reclaim(hpa_t page,
					  struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_PHYMEM_PAGE_RECLAIM,
			    page, 0, 0, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_mem_page_remove(hpa_t tdr, gpa_t gpa, int level,
				      struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MEM_PAGE_REMOVE,
			    gpa | level, tdr, 0, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_sys_rd(u64 fid, struct tdx_module_output *out)
{
	if (!is_sys_rd_supported())
		return TDX_SYS_NOT_READY;

	return kvm_seamcall(TDH_SYS_RD, 0, fid, 0, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_sys_lp_shutdown(void)
{
	return kvm_seamcall(TDH_SYS_LP_SHUTDOWN, 0, 0, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mem_track(hpa_t tdr)
{
	return kvm_seamcall(TDH_MEM_TRACK, tdr, 0, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mem_range_unblock(hpa_t tdr, gpa_t gpa, int level,
					struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_MEM_RANGE_UNBLOCK,
			    gpa | level, tdr, 0, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_phymem_cache_wb(bool resume)
{
	return kvm_seamcall(TDH_PHYMEM_CACHE_WB,
			    resume ? 1 : 0, 0, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_phymem_page_wbinvd(hpa_t page)
{
	return kvm_seamcall(TDH_PHYMEM_PAGE_WBINVD,
			    page, 0, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_vp_wr(hpa_t tdvpr, u64 field, u64 val, u64 mask,
			    struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_VP_WR, tdvpr, field,
			    val, mask, 0, 0, 0, 0, out);
}

static inline u64 tdh_servtd_prebind(hpa_t target_tdr,
				     hpa_t hash_addr,
				     u64 slot_idx,
				     u64 attr,
				     enum kvm_tdx_servtd_type type)
{
	return kvm_seamcall(TDH_SERVTD_PREBIND, target_tdr,
			    hash_addr, slot_idx, type, attr, 0, 0, 0, NULL);
}

static inline u64 tdh_servtd_bind(hpa_t servtd_tdr,
				  hpa_t target_tdr,
				  u64 slot_idx,
				  u64 attr,
				  enum kvm_tdx_servtd_type type,
				  struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_SERVTD_BIND, target_tdr,
			    servtd_tdr, slot_idx, type, attr, 0, 0, 0, out);
}

static inline u64 tdh_stream_create(hpa_t tdr, hpa_t migsc)
{
	return kvm_seamcall(TDH_STREAM_CREATE, migsc, tdr,
			    0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_export_state_immutable(hpa_t tdr,
					     u64 mbmd_config,
					     u64 buf_list_config,
					     u64 mig_stream_config,
					     struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_EXPORT_STATE_IMMUTABLE, tdr, 0, mbmd_config,
			    buf_list_config, mig_stream_config, 0, 0, 0,out);
}

static inline u64 tdh_import_state_immutable(hpa_t tdr,
					     u64 mbmd_config,
					     u64 buf_list_config,
					     u64 mig_stream_config,
					     struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_IMPORT_STATE_IMMUTABLE, tdr, 0, mbmd_config,
			    buf_list_config, mig_stream_config, 0, 0, 0, out);
}

static inline u64 tdh_export_blockw(hpa_t tdr,
				    u64 gpa_list_config,
				    struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_EXPORT_BLOCKW, gpa_list_config, tdr,
			    0, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_export_unblockw(hpa_t tdr,
				      hpa_t ept_config,
				      struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_EXPORT_UNBLOCKW, ept_config, tdr,
			    0, 0, 0, 0, 0, 0, out);
}

static inline u64 tdh_export_track(hpa_t tdr,
				   u64 mbmd_config,
				   u64 mig_stream_config)
{
	return kvm_seamcall(TDH_EXPORT_TRACK, tdr, 0, mbmd_config, 0,
			    mig_stream_config, 0, 0, 0, NULL);
}

static inline u64 tdh_import_track(hpa_t tdr,
				    u64 mbmd_config,
				    u64 mig_stream_config)
{
	return kvm_seamcall(TDH_IMPORT_TRACK, tdr, 0, mbmd_config, 0,
			    mig_stream_config, 0, 0, 0, NULL);
}

static inline u64 tdh_export_mem(hpa_t tdr,
				 u64 mbmd_config,
				 u64 gpa_list_config,
				 u64 buf_list_config,
				 u64 mac_list_config_0,
				 u64 mac_list_config_1,
				 u64 mig_stream_config,
				 struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_EXPORT_MEM,
			    gpa_list_config,
			    tdr,
			    mbmd_config,
			    buf_list_config,
			    mig_stream_config,
			    mac_list_config_0,
			    mac_list_config_1,
			    0,
			    out);
}

static inline u64 tdh_import_mem(hpa_t tdr,
				 u64 mbmd_config,
				 u64 gpa_list_config,
				 u64 buf_list_config,
				 u64 mac_list_config_0,
				 u64 mac_list_config_1,
				 u64 private_page_list,
				 u64 mig_stream_config,
				 struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_IMPORT_MEM,
			    gpa_list_config,
			    tdr,
			    mbmd_config,
			    buf_list_config,
			    mig_stream_config,
			    mac_list_config_0,
			    mac_list_config_1,
			    private_page_list,
			    out);
}

static inline u64 tdh_export_pasue(hpa_t tdr)
{
	return kvm_seamcall(TDH_EXPORT_PAUSE, tdr, 0, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_export_state_vp(hpa_t tdvpr,
				      u64 mbmd_config,
				      u64 buf_list_config,
				      u64 mig_stream_config,
				      struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_EXPORT_STATE_VP, tdvpr, 0, mbmd_config,
			    buf_list_config, mig_stream_config, 0, 0, 0, out);
}

static inline u64 tdh_import_state_vp(hpa_t tdvpr,
				      u64 mbmd_config,
				      u64 buf_list_config,
				      u64 mig_stream_config,
				      struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_IMPORT_STATE_VP, tdvpr, 0, mbmd_config,
			    buf_list_config, mig_stream_config, 0, 0, 0, out);
}

static inline u64 tdh_export_state_td(hpa_t tdr,
				      u64 mbmd_config,
				      u64 buf_list_config,
				      u64 mig_stream_config,
				      struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_EXPORT_STATE_TD, tdr, 0, mbmd_config,
			    buf_list_config, mig_stream_config, 0, 0, 0, out);
}

static inline u64 tdh_import_state_td(hpa_t tdr,
				      u64 mbmd_config,
				      u64 buf_list_config,
				      u64 mig_stream_config,
				      struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_IMPORT_STATE_TD, tdr, 0, mbmd_config,
			    buf_list_config, mig_stream_config, 0, 0, 0, out);
}

static inline u64 tdh_import_end(hpa_t tdr)
{
	return kvm_seamcall(TDH_IMPORT_END, tdr, 0, 0, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_export_abort(hpa_t tdr,
				   u64 abort_token_config,
				   u64 mig_stream_config)
{
	return kvm_seamcall(TDH_EXPORT_ABORT, tdr, 0, abort_token_config,
			    0, mig_stream_config, 0, 0, 0, NULL);
}

static inline u64 tdh_export_restore(hpa_t tdr,
				     u64 gpa_list_config,
				     struct tdx_module_output *out)
{
	return kvm_seamcall(TDH_EXPORT_RESTORE, gpa_list_config, tdr,
			    0, 0, 0, 0, 0, 0, out);
}

#endif /* CONFIG_INTEL_TDX_HOST */

#endif /* __KVM_X86_TDX_OPS_H */
