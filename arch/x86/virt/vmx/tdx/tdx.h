/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_VIRT_TDX_H
#define _X86_VIRT_TDX_H

#include <linux/types.h>
#include <linux/bits.h>

/*
 * This file contains both macros and data structures defined by the TDX
 * architecture and Linux defined software data structures and functions.
 * The two should not be mixed together for better readability.  The
 * architectural definitions come first.
 */

/*
 * Intel Trusted Domain CPU Architecture Extension spec:
 *
 * IA32_MTRRCAP:
 *   Bit 15:	The support of SEAMRR
 *
 * IA32_SEAMRR_PHYS_MASK (core-scope):
 *   Bit 10:	Lock bit
 *   Bit 11:	Enable bit
 */
#define MTRR_CAP_SEAMRR			BIT_ULL(15)

#define MSR_IA32_SEAMRR_PHYS_MASK	0x00001401

#define SEAMRR_PHYS_MASK_ENABLED	BIT_ULL(11)
#define SEAMRR_PHYS_MASK_LOCKED		BIT_ULL(10)
#define SEAMRR_ENABLED_BITS	\
	(SEAMRR_PHYS_MASK_ENABLED | SEAMRR_PHYS_MASK_LOCKED)

/*
 * IA32_MKTME_KEYID_PARTIONING:
 *   Bit [31:0]:	Number of MKTME KeyIDs.
 *   Bit [63:32]:	Number of TDX private KeyIDs.
 *
 * MKTME KeyIDs start from KeyID 1. TDX private KeyIDs start
 * after the last MKTME KeyID.
 */
#define MSR_IA32_MKTME_KEYID_PARTITIONING	0x00000087

#define TDX_KEYID_START(_keyid_part)	\
		((u32)(((_keyid_part) & 0xffffffffull) + 1))
#define TDX_KEYID_NUM(_keyid_part)	((u32)((_keyid_part) >> 32))


/*
 * TDX module SEAMCALL leaf functions
 */
#define TDH_SYS_KEY_CONFIG	31
#define TDH_SYS_INFO		32
#define TDH_SYS_INIT		33
#define TDH_SYS_LP_INIT		35
#define TDH_SYS_TDMR_INIT	36
#define TDH_SYS_LP_SHUTDOWN	44
#define TDH_SYS_CONFIG		45

struct cmr_info {
	u64	base;
	u64	size;
} __packed;

#define MAX_CMRS			32
#define CMR_INFO_ARRAY_ALIGNMENT	512

struct tdmr_reserved_area {
	u64 offset;
	u64 size;
} __packed;

#define TDMR_INFO_ALIGNMENT	512
#define TDMR_INFO_PA_ARRAY_ALIGNMENT	512

struct tdmr_info {
	u64 base;
	u64 size;
	u64 pamt_1g_base;
	u64 pamt_1g_size;
	u64 pamt_2m_base;
	u64 pamt_2m_size;
	u64 pamt_4k_base;
	u64 pamt_4k_size;
	/*
	 * Actual number of reserved areas depends on
	 * 'struct tdsysinfo_struct'::max_reserved_per_tdmr.
	 */
	struct tdmr_reserved_area reserved_areas[0];
} __packed __aligned(TDMR_INFO_ALIGNMENT);

#define SEAMLDR_MAX_NR_MODULE_PAGES	496

#define SEAMLDR_PARAMS_ALIGNMENT	4096
#define SEAMLDR_SIGSTRUCT_SIZE		2048

#define SEAMLDR_SCENARIO_LOAD		0
#define SEAMLDR_SCENARIO_UPDATE		1

/* Passed to P-SEAMLDR to describe information about the TDX module to load */
struct seamldr_params {
	u32	version;
	u32	scenario; /* SEAMLDR_SCENARIO_LOAD/UPDATE */
	u64	sigstruct_pa;
	u8	reserved[104];
	u64	num_module_pages;
	u64	mod_pages_pa_list[SEAMLDR_MAX_NR_MODULE_PAGES];
} __packed __aligned(SEAMLDR_PARAMS_ALIGNMENT);

/*
 * Do not put any hardware-defined TDX structure representations below this
 * comment!
 */

struct tdx_module_output;
u64 __seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10, u64 r11,
	       u64 r12, u64 r13, struct tdx_module_output *out);

#endif
