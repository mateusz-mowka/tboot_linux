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

/* TDX module update request */
struct tmu_req {
	const void *module;	/* Pointer to TDX module binary */
	const void *signature;	/* Pointer to TDX module signature struct */
	int module_size;
	int signature_size;
};

#ifdef CONFIG_INTEL_TDX_MODULE_UPDATE
int tdx_module_update(const struct tmu_req *req);
#else /* !CONFIG_INTEL_TDX_MODULE_UPDATE */
static inline int tdx_module_update(const struct tmu_req *req)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_INTEL_TDX_MODULE_UPDATE */

bool platform_tdx_enabled(void);
int tdx_init(void);
const struct tdsysinfo_struct *tdx_get_sysinfo(void);
u32 tdx_get_global_keyid(void);
u32 tdx_get_num_keyid(void);
int tdx_keyid_alloc(void);
void tdx_keyid_free(int keyid);

u64 __seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10,
	       u64 r11, u64 r12, u64 r13, struct tdx_module_output *out);
#else	/* !CONFIG_INTEL_TDX_HOST */
static inline bool platform_tdx_enabled(void) { return false; }
static inline int tdx_init(void)  { return -ENODEV; }
struct tdsysinfo_struct;
static inline const struct tdsysinfo_struct *tdx_get_sysinfo(void) { return NULL; }
static inline u32 tdx_get_global_keyid(void) { return 0; }
static inline u32 tdx_get_num_keyid(void) { return 0; }
static inline int tdx_keyid_alloc(void) { return -EOPNOTSUPP; }
static inline void tdx_keyid_free(int keyid) { }
#endif	/* CONFIG_INTEL_TDX_HOST */

#endif /* !__ASSEMBLY__ */
#endif /* _ASM_X86_TDX_H */
