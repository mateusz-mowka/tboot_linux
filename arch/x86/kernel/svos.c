/***************************************************************************/
/**                   I N T E L  C O N F I D E N T I A L                  **/
/***************************************************************************/
/**                                                                       **/
/**  Copyright (c) 2016 Intel Corporation                                 **/
/**                                                                       **/
/**  This program contains proprietary and confidential information.      **/
/**  All rights reserved.                                                 **/
/**                                                                       **/
/***************************************************************************/
/**                   I N T E L  C O N F I D E N T I A L                  **/
/***************************************************************************/

#include <linux/svos.h>
#include <linux/svos_svfs_exports.h>
#include <asm/e820/api.h>

/* Avoid using small segments */
#define SVOS_MIN_TARGET_E820_SIZE	(20 * 1024 * 1024)
/* Give the kernel some low space */
#define SVOS_KERNEL_LOW_SPACE		(20 * 1024 * 1024)

/*
 * Starting point for svos hooks in the arch tree.
 * The strategy is to minimize code placement in base kernel
 * files to just hook calls or minor changes.
 */

int svos_enable_ras_errorcorrect = 0;
EXPORT_SYMBOL(svos_enable_ras_errorcorrect);

/* Standard OS Memory (SOM) is memory given to the kernel for all normal
   kernel uses: drivers, stacks, heaps, processes, pagetables, etc. This
   is differentiated from SVOS target memory, which is dedicated for validation
   tests and is not reported to the kernel. */
static unsigned long long som_goal_bytes;

struct e820_table e820_svos;
EXPORT_SYMBOL(e820_svos);

struct	svos_node_memory svos_node_memory[MAX_NUMNODES];
EXPORT_SYMBOL(svos_node_memory);

nodemask_t svos_nodes_parsed;
EXPORT_SYMBOL(svos_nodes_parsed);

/*
 * Enable error correction if indicated on kernel command line.
 */
static int __init svos_enable_ras(char *str)
{
	svos_enable_ras_errorcorrect = 1;
	printk_once(KERN_INFO
		    "NOTE: Error correction is enabled via svos_enable_ras - "
		    "ONLY to be used for RAS testing!!!\n");
	return 0;
}
early_param("svos_enable_ras", svos_enable_ras);

__init unsigned long
svos_adjgap(unsigned long gapsize)
{
	unsigned long round;
	unsigned long start;

	round = 0x100000;
	while ((gapsize >> 4) > round)
		round += round;

	start = (gapsize + round) & -round;
	return start;
}

void __init svos_mem_init(void)
{
	int i;
	u64 accum;
	u64 goal;
	u64 addr, size;
	u64 kernel_start = __pa_symbol(_text);
	/* Add a buffer of low space for kernel internal use */
	u64 kernel_end = __pa_symbol(_end) + SVOS_KERNEL_LOW_SPACE;

	pr_info("kernel_start (text) at 0x%llx\n", kernel_start);

	/* Disable user address space randomization */
	randomize_va_space = 0;

	/*
	 * If no SVOS memory is specified or svos@ is zero,
	 * act as if svos@ is set to max mem.
	 */
	if (som_goal_bytes == 0) {
		printk(KERN_CRIT
		       "No mem=svos@ parameter on kernel command line."
		       "  No SVOS targets will be available!\n");
		return;
	}

	/*
	 * Scan the e820 table to see if the mem=svos@ goals can be satisfied.
	 * If not, indicate an error and exit early with no changes.
	 */
	for (i = 0, accum = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		if ((entry->type == E820_TYPE_RAM) &&
		    (entry->addr >= 0x100000000)) {
			accum += entry->size;
		}
	}
	if (accum < som_goal_bytes) {
		printk(KERN_CRIT
		       "Insufficient memory to satisfy mem=svos@ requirements.\n"
		       "No carve-out performed.  No SVOS targets will be available!\n");
		return;
        }

	/*
	 * Carve out memory for SVOS targets, according to specifications
	 * indicated by command line arguments.
	 */

	goal = som_goal_bytes;
	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		if (entry->type != E820_TYPE_RAM) {
			continue;
		}

		addr = entry->addr;
		size = entry->size;

		if (addr < 0x100000000) {

			/* Low memory */

			if (addr < 0x100000) {
				/* Preserve trampoline space in SOM */
				; /* NULL statement */
			} else if ((addr <= kernel_start) && (kernel_end <= (addr + size))) {
				/* Split up the segment so non-kernel portions can be used. */
				/* First, reduce the current segment to only kernel footprint */
				entry->addr = kernel_start;
				entry->size = kernel_end - kernel_start;
				/* Add a new segment preceding the kernel, if that region is large enough */
				if ((kernel_start - addr) >= SVOS_MIN_TARGET_E820_SIZE) {
					e820__range_add(addr, kernel_start - addr, E820_TYPE_SVOS_TARGET);
				}
				/* Add a new segment following the kernel, if it's large enough. */
				/* This segment (and the others) will later be reduced to eliminate conflicts with kernel reservations */
				if ((addr + size - kernel_end) >= SVOS_MIN_TARGET_E820_SIZE) {
					e820__range_add(kernel_end, addr + size - kernel_end, E820_TYPE_SVOS_TARGET);
				}
			} else if (size >= SVOS_MIN_TARGET_E820_SIZE) {
				entry->type = E820_TYPE_SVOS_TARGET;
			}
		} else {

			/* High memory */

			/* Allocate memory to accommodate the mem=svos@ amount of non-target Standard OS Memory */

			if (goal) {
				if (goal < size) {
					/* Split the current e820 segment into two: current segment for som, next for targets */
					entry->size = goal;
					e820__range_add(addr + goal, size - goal, E820_TYPE_SVOS_TARGET);
					goal = 0;
				} else {
					/* Retain the entire current e820 segment as SOM == System DRAM */
					goal -= size;
				}
			} else if (size >= SVOS_MIN_TARGET_E820_SIZE) {
				entry->type = E820_TYPE_SVOS_TARGET;
			}
		}
	}

	/* Sort and adjust the newly modified (post-carveout) kernel e820 table. */
	e820__update_table(e820_table);

	/* Copy the new e820 table to the SVOS-specific e820 table that
	   communicates target regions to the svmem driver.  Note that
	   the target regions will be adjusted later, per information on
	   kernel reservations. */
	memcpy(&e820_svos, e820_table, sizeof(struct e820_table));

	/* Run through the kernel's e820 table, removing references to SVOS targets. */
	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		if (entry->type == E820_TYPE_SVOS_TARGET) {
			e820__range_remove(entry->addr, entry->size, entry->type, 1);
		}
	}

	e820__update_table(e820_table);
	e820__print_table(" SOM-e820");
}

static struct e820_table e820_temp;

/*
 * svos_setup_svos_e820()
 * Finalize the e820_svos table, which is SVOS's private table
 * communicating information about SVOS target regions to the SVFS svmem
 * driver.
 */
void __init svos_setup_svos_e820(void)
{
	phys_addr_t start, end;
	u64 i;

	if (som_goal_bytes == 0) {
		return;
	}

	/* Copy the kernel's e820 table to temporary, then SVOS's to primary. */
	/* Kernel e820 interfaces are hard-coded to work against the primary. */
	memcpy(&e820_temp, e820_table, sizeof(struct e820_table));
	memcpy(e820_table, &e820_svos, sizeof(struct e820_table));

	/* Remove target segments */
	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		if (entry->type == E820_TYPE_SVOS_TARGET) {
			e820__range_remove(entry->addr, entry->size, entry->type, 1);
		}
	}

	/* Add the target segments back into e820_svos, less any regions that
	   overlap with kernel reservations */
	for_each_free_svos_target_range(i, NUMA_NO_NODE, MEMBLOCK_NONE, &start, &end,
					NULL) {
		pr_info("SVOS target region: %pa - %pa, %llu MB, %s\n",
			&start, &end, (u64) (end - start) >> 20,
			(end - start) >= SVOS_MIN_TARGET_E820_SIZE ? "using" :
			"not using");
		if ((end - start) >= SVOS_MIN_TARGET_E820_SIZE) {
			e820__range_add(start, end - start, E820_TYPE_SVOS_TARGET);
		}
	}

	/* Update and print the newly modified targets e820 table then copy
	   to svos_e820 and restore e820_table. */
	e820__update_table(e820_table);
	e820__print_table("TGTS-e820");
	memcpy(&e820_svos, e820_table, sizeof(struct e820_table));
	memcpy(e820_table, &e820_temp, sizeof(struct e820_table));
}

/*
 * Called from the parse_memopt handling to initialize the svosmem 
 * parameter.
 */
void
svos_parse_mem(char *p)
{
	som_goal_bytes = memparse(p + 5, &p);
}

//
// Trap hook called from do_trap_no_signal on traps
//   the handler return code tells trap code whether to
//   continue the normal processing or return.
//
int (*svTrapHandlerKernelP)(int index, struct pt_regs *regs);
EXPORT_SYMBOL(svTrapHandlerKernelP);
int
svos_trap_hook(int trapnr, struct pt_regs *regs)
{
	int	trapResult = 0;
	if (svTrapHandlerKernelP != NULL) {
		trapResult = svTrapHandlerKernelP(trapnr, regs);
	}
	return trapResult;
}
EXPORT_SYMBOL(svos_trap_hook);

EXPORT_SYMBOL(init_mm);
struct mm_struct *svoskern_init_mm = &init_mm;
EXPORT_SYMBOL(svoskern_init_mm);

struct task_struct* svoskern_find_task_by_pid_ns(pid_t nr, struct pid_namespace *ns)
{
	return find_task_by_pid_ns(nr, ns);
}
EXPORT_SYMBOL(svoskern_find_task_by_pid_ns);

extern struct list_head pci_mmcfg_list;
struct list_head *svoskern_pci_mmcfg_list = &pci_mmcfg_list;
EXPORT_SYMBOL(svoskern_pci_mmcfg_list);

unsigned long
svoskern_ksys_mmap_pgoff(unsigned long addr, unsigned long len,
	unsigned long prot, unsigned long flags,
	unsigned long fd, unsigned long pgoff)
{
	return ksys_mmap_pgoff(addr, len, prot, flags, fd, pgoff);
}
EXPORT_SYMBOL(svoskern_ksys_mmap_pgoff);

EXPORT_SYMBOL(vector_irq);

int (*svoskern_svfs_callback_trap_handler)(int index, struct pt_regs *regs);
EXPORT_SYMBOL(svoskern_svfs_callback_trap_handler);

#ifdef CONFIG_DMAR_TABLE
// Hooks for syncing vtd state between the kernel's DMAR driver and the
// SVFS vt-d driver.
int (*svoskern_svfs_callback_vtd_submit_sync)(u64, void *) = NULL;
EXPORT_SYMBOL(svoskern_svfs_callback_vtd_submit_sync);

int (*svoskern_svfs_callback_vtd_fault_handler)(u64, void *) = NULL;
EXPORT_SYMBOL(svoskern_svfs_callback_vtd_fault_handler);

void svoskern_svfs_callback_reset_vtd_inval_que(u64 reg_phys_address)
{
	printk(KERN_CRIT "%s called to handle address - %LX\n", __FUNCTION__,
		reg_phys_address);
}
EXPORT_SYMBOL(svoskern_svfs_callback_reset_vtd_inval_que);
#endif

void
svoskern_lock_pci(void)
{
//	spin_lock_irq(&pci_lock);
	return;
}
EXPORT_SYMBOL(svoskern_lock_pci);

void
svoskern_unlock_pci(void)
{
//	spin_unlock_irq(&pci_lock);
	return;
}
EXPORT_SYMBOL(svoskern_unlock_pci);

void
svoskern_lock_pci_irqsave(unsigned long *flags)
{
//	spin_lock_irq(&pci_lock);
	return;
}
EXPORT_SYMBOL(svoskern_lock_pci_irqsave);

void
svoskern_unlock_pci_irqrestore(unsigned long *flags)
{
//	spin_unlock_irq(&pci_lock);
	return;
}
EXPORT_SYMBOL(svoskern_unlock_pci_irqrestore);

int
svoskern_pci_setup_device(struct pci_dev *dev)
{
	extern int pci_setup_device(struct pci_dev *dev);
	return pci_setup_device(dev);
}
EXPORT_SYMBOL(svoskern_pci_setup_device);

void
svoskern_pci_device_add(struct pci_dev *dev, struct pci_bus *bus)
{
	pci_device_add(dev, bus);
}
EXPORT_SYMBOL(svoskern_pci_device_add);

unsigned long
svoskern_get_cr4_features(void)
{
	return mmu_cr4_features;
}
EXPORT_SYMBOL(svoskern_get_cr4_features);

void
svoskern_clear_in_cr4(unsigned long mask)
{
	cr4_clear_bits(mask);
}
EXPORT_SYMBOL(svoskern_clear_in_cr4);

void
svoskern_set_in_cr4(unsigned long mask)
{
	cr4_set_bits(mask);
}
EXPORT_SYMBOL(svoskern_set_in_cr4);

unsigned long
svoskern_native_read_cr0(void)
{
	return native_read_cr0();
}
EXPORT_SYMBOL(svoskern_native_read_cr0);

unsigned long
svoskern_native_read_cr2(void)
{
	return native_read_cr2();
}
EXPORT_SYMBOL(svoskern_native_read_cr2);

unsigned long
svoskern_native_read_cr3(void)
{
	return __read_cr3();
}
EXPORT_SYMBOL(svoskern_native_read_cr3);

unsigned long
svoskern_native_read_cr4(void)
{
	return native_read_cr4();
}
EXPORT_SYMBOL(svoskern_native_read_cr4);

void
svoskern_native_write_cr0(unsigned long val)
{
	native_write_cr0(val);
}
EXPORT_SYMBOL(svoskern_native_write_cr0);

void
svoskern_native_write_cr2(unsigned long val)
{
	native_write_cr2(val);
}
EXPORT_SYMBOL(svoskern_native_write_cr2);

void
svoskern_native_write_cr3(unsigned long val)
{
	native_write_cr3(val);
}
EXPORT_SYMBOL(svoskern_native_write_cr3);

void
svoskern_native_write_cr4(unsigned long val)
{
	native_write_cr4(val);
}
EXPORT_SYMBOL(svoskern_native_write_cr4);

bool svoskern_pat_enabled(void)
{
	return pat_enabled();
}
EXPORT_SYMBOL(svoskern_pat_enabled);

u8 svoskern_mtrr_type_lookup(u64 start, u64 end, u8 *uniform)
{
	return mtrr_type_lookup(start, end, uniform);
}
EXPORT_SYMBOL(svoskern_mtrr_type_lookup);

int svoskern__irq_domain_alloc_irqs(struct irq_domain *domain, int irq_base,
	unsigned int nr_irqs, int node, void *arg,
	bool realloc)
{
#ifdef	CONFIG_IRQ_DOMAIN_HIERARCHY
	return __irq_domain_alloc_irqs(domain, irq_base, nr_irqs, node,
		arg, realloc, NULL);
#else
	return -1;
#endif
}
EXPORT_SYMBOL(svoskern__irq_domain_alloc_irqs);

void svoskern_flush_tlb_page(struct vm_area_struct *vma, unsigned long page_addr)
{
	flush_tlb_page(vma, page_addr);
}
EXPORT_SYMBOL(svoskern_flush_tlb_page);

void svoskern_flush_tlb_local(void)
{
	flush_tlb_local();
}
EXPORT_SYMBOL(svoskern_flush_tlb_local);

void svoskern_flush_tlb_all(void)
{
	flush_tlb_all();
}
EXPORT_SYMBOL(svoskern_flush_tlb_all);

void svoskern_set_cpu_online(unsigned int cpu, bool online)
{
	set_cpu_online(cpu, online);
}
EXPORT_SYMBOL(svoskern_set_cpu_online);

#ifdef CONFIG_KALLSYMS
unsigned long svoskern_kallsyms_lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
EXPORT_SYMBOL(svoskern_kallsyms_lookup_name);
#endif
