
/***************************************************************************/
/**                   I N T E L  C O N F I D E N T I A L                  **/
/***************************************************************************/
/**                                                                       **/
/**  Copyright (c) 2020 Intel Corporation                                 **/
/**                                                                       **/
/**  This program contains proprietary and confidential information.      **/
/**  All rights reserved.                                                 **/
/**                                                                       **/
/***************************************************************************/
/**                   I N T E L  C O N F I D E N T I A L                  **/
/***************************************************************************/

// Provides definitions of kernel interfaces exported specifically for SVFS use.

#ifndef _LINUX_SVOS_SVFS_EXPORTS_H
#define _LINUX_SVOS_SVFS_EXPORTS_H
#ifdef __KERNEL__

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/crash_dump.h>
#include <linux/export.h>
#include <linux/mmzone.h>
#include <linux/pfn.h>
#include <linux/suspend.h>
#include <linux/acpi.h>
#include <linux/firmware-map.h>
#include <linux/irqdomain.h>
#include <linux/memblock.h>
#include <linux/mm_types.h>
#include <linux/sort.h>
#include <linux/cpumask.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/kdb.h>
#include <linux/svos.h>

// svos_svfs_exports requires headers from arch/x86 that are only available in
// x86 builds.
#ifdef CONFIG_X86
#include <asm/e820/types.h>
#include <asm/mtrr.h>
#include <asm/special_insns.h>
#include <asm/proto.h>
#include <asm/setup.h>
#include <asm/tlbflush.h>
#include <asm/memtype.h>
#include <asm/hw_irq.h>
#include <asm/io_apic.h>

// Including this table in the CONFIG_X86 guard. It's referenced
// in arch/x86/kernel/svos.c so should only show up in x86 builds
// anyways.
extern struct e820_table e820_svos;
#endif

extern struct svos_node_memory svos_node_memory[MAX_NUMNODES];
extern nodemask_t svos_nodes_parsed;

//
// Trap hook called from do_trap_no_signal on traps
//   the handler return code tells trap code whether to
//   continue the normal processing or return.
//
extern int (*svTrapHandlerKernelP)(int index, struct pt_regs *regs);

extern struct mm_struct *svoskern_init_mm;
extern struct task_struct *svoskern_find_task_by_pid_ns(pid_t nr, struct pid_namespace *ns);

extern struct list_head *svoskern_pci_mmcfg_list;

extern unsigned long
svoskern_ksys_mmap_pgoff(unsigned long addr, unsigned long len,
			      unsigned long prot, unsigned long flags,
			      unsigned long fd, unsigned long pgoff);

extern int (*svoskern_svfs_callback_trap_handler)(int index, struct pt_regs *regs);

//
// Hooks for syncing vtd state between the kernel's DMAR driver and the
// SVFS vt-d driver.
//
#ifdef CONFIG_DMAR_TABLE
extern int (*svoskern_svfs_callback_vtd_submit_sync)(u64, void *);
extern int (*svoskern_svfs_callback_vtd_fault_handler)(u64, void *);
extern void svoskern_svfs_callback_reset_vtd_inval_que(u64 reg_phys_address);
#endif

extern void svoskern_lock_pci(void);
extern void svoskern_unlock_pci(void);
extern void svoskern_lock_pci_irqsave(unsigned long *flags);
extern void svoskern_unlock_pci_irqrestore(unsigned long *flags);
extern int svoskern_pci_setup_device(struct pci_dev *dev);
extern void svoskern_pci_device_add(struct pci_dev *dev, struct pci_bus *bus);

extern unsigned long svoskern_get_cr4_features(void);
extern void svoskern_clear_in_cr4(unsigned long mask);
extern void svoskern_set_in_cr4(unsigned long mask);
extern unsigned long svoskern_native_read_cr0(void);
extern unsigned long svoskern_native_read_cr2(void);
extern unsigned long svoskern_native_read_cr3(void);
extern unsigned long svoskern_native_read_cr4(void);
extern void svoskern_native_write_cr0(unsigned long val);
extern void svoskern_native_write_cr2(unsigned long val);
extern void svoskern_native_write_cr3(unsigned long val);
extern void svoskern_native_write_cr4(unsigned long val);

extern bool svoskern_pat_enabled(void);
extern u8 svoskern_mtrr_type_lookup(u64 start, u64 end, u8 *uniform);

extern int svoskern__irq_domain_alloc_irqs(struct irq_domain *domain, int irq_base,
				     unsigned int nr_irqs, int node, void *arg,
				     bool realloc);

extern void svoskern_flush_tlb_page(struct vm_area_struct *vma, unsigned long page_addr);
extern void svoskern_flush_tlb_local(void);
extern void svoskern_flush_tlb_all(void);

extern void svoskern_set_cpu_online(unsigned int cpu, bool online);

#ifdef CONFIG_KALLSYMS
extern unsigned long svoskern_kallsyms_lookup_name(const char *name);
#endif

#ifdef CONFIG_KGDB_KDB
extern int svoskern_kdb_register(kdbtab_t *cmd);
extern void svoskern_kdb_unregister(kdbtab_t *cmd);
extern int svoskern_kdb_printf(const char *fmt, ...);
extern void svoskern_kgdb_breakpoint(void);
extern int svoskern_kdbgetularg(const char *arg, unsigned long *value);
extern int svoskern_kdbgetaddrarg(int argc, const char **argv, int *nextarg, unsigned long *value,
					long *offset, char **name);
extern void svoskern_kdb_symbol_print(unsigned long addr,  unsigned int punc);
#endif

#endif // __KERNEL__
#endif // _LINUX_SVOS_SVFS_EXPORTS_H
