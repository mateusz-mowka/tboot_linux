// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hardware Feedback Interface Driver
 *
 * Copyright (c) 2021, Intel Corporation.
 *
 * Authors: Aubrey Li <aubrey.li@linux.intel.com>
 *          Ricardo Neri <ricardo.neri-calderon@linux.intel.com>
 *
 *
 * The Hardware Feedback Interface provides a performance and energy efficiency
 * capability information for each CPU in the system. Depending on the processor
 * model, hardware may periodically update these capabilities as a result of
 * changes in the operating conditions (e.g., power limits or thermal
 * constraints). On other processor models, there is a single HFI update
 * at boot.
 *
 * This file provides functionality to process HFI updates and relay these
 * updates to userspace.
 */

#define pr_fmt(fmt)  "intel-hfi: " fmt

#include <linux/bitops.h>
#include <linux/cpufeature.h>
#include <linux/cpumask.h>
#include <linux/debugfs.h>
#include <linux/gfp.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/math.h>
#include <linux/mutex.h>
#include <linux/percpu-defs.h>
#include <linux/printk.h>
#include <linux/processor.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/topology.h>
#include <linux/workqueue.h>

#include <asm/msr.h>
#include <asm/intel-family.h>

#include "../thermal_core.h"
#include "intel_hfi.h"

#define THERM_STATUS_CLEAR_PKG_MASK (BIT(1) | BIT(3) | BIT(5) | BIT(7) | \
				     BIT(9) | BIT(11) | BIT(26))

/* Hardware Feedback Interface MSR configuration bits */
#define HW_FEEDBACK_PTR_VALID_BIT		BIT(0)
#define HW_FEEDBACK_CONFIG_HFI_ENABLE_BIT	BIT(0)
#define HW_FEEDBACK_CONFIG_ITD_ENABLE_BIT	BIT(1)
#define HW_FEEDBACK_THREAD_CONFIG_ENABLE_BIT	BIT(0)

/* CPUID detection and enumeration definitions for HFI */

#define CPUID_HFI_LEAF 6

union hfi_capabilities {
	struct {
		u8	performance:1;
		u8	energy_efficiency:1;
		u8	__reserved:6;
	} split;
	u8 bits;
};

union cpuid6_edx {
	struct {
		union hfi_capabilities	capabilities;
		u32			table_pages:4;
		u32			__reserved:4;
		s32			index:16;
	} split;
	u32 full;
};

union cpuid6_ecx {
	struct {
		u32	dont_care0:8;
		u32	nr_classes:8;
		u32	dont_care1:16;
	} split;
	u32 full;
};

#ifdef CONFIG_INTEL_THREAD_DIRECTOR
union hfi_thread_feedback_char_msr {
	struct {
		u8	classid;
		u64	__reserved:55;
		u8	valid:1;
	} split;
	u64 full;
};
#endif

/**
 * struct hfi_cpu_data - HFI capabilities per CPU
 * @perf_cap:		Performance capability
 * @ee_cap:		Energy efficiency capability
 *
 * Capabilities of a logical processor in the HFI table. These capabilities are
 * unitless and specific to each HFI class.
 */
struct hfi_cpu_data {
	u8	perf_cap;
	u8	ee_cap;
} __packed;

/**
 * struct hfi_hdr - Header of the HFI table
 * @perf_updated:	Hardware updated performance capabilities
 * @ee_updated:		Hardware updated energy efficiency capabilities
 *
 * Properties of the data in an HFI table. There exists one header per each
 * HFI class.
 */
struct hfi_hdr {
	u8	perf_updated;
	u8	ee_updated;
} __packed;

/**
 * struct hfi_instance - Representation of an HFI instance (i.e., a table)
 * @local_table:	Base of the local copy of the HFI table
 * @timestamp:		Timestamp of the last update of the local table.
 *			Located at the base of the local table.
 * @hdr:		Base address of the header of the local table
 * @data:		Base address of the data of the local table
 * @cpus:		CPUs represented in this HFI table instance
 * @hw_table:		Pointer to the HFI table of this instance
 * @update_work:	Delayed work to process HFI updates
 * @table_lock:		Lock to protect acceses to the table of this instance
 * @event_lock:		Lock to process HFI interrupts
 *
 * DEBUG:
 * @debugfs_hw_table:	A binary blob to dump the hardware HFI table
 * @debugfs_local_table:A binary blob to dump the driver copy of the HFI table
 *
 * A set of parameters to parse and navigate a specific HFI table.
 */
struct hfi_instance {
	union {
		void			*local_table;
		u64			*timestamp;
	};
	void			*hdr;
	void			*data;
	cpumask_var_t		cpus;
	void			*hw_table;
	struct delayed_work	update_work;
	raw_spinlock_t		table_lock;
	raw_spinlock_t		event_lock;
#ifdef CONFIG_DEBUG_FS
	struct debugfs_blob_wrapper	*debugfs_hw_table;
	struct debugfs_blob_wrapper	*debugfs_local_table;
#endif
};

/**
 * struct hfi_features - Supported HFI features
 * @nr_classes:		Number of classes supported
 * @nr_table_pages:	Size of the HFI table in 4KB pages
 * @cpu_stride:		Stride size to locate the capability data of a logical
 *			processor within the table (i.e., row stride)
 * @class_stride:	Stride size to locate a class within the capability
 *			data of a logical processor or the HFI table header
 * @hdr_size:		Size of the table header
 *
 * Parameters and supported features that are common to all HFI instances
 */
struct hfi_features {
	int		nr_classes;
	size_t		nr_table_pages;
	unsigned int	cpu_stride;
	unsigned int	class_stride;
	unsigned int	hdr_size;
};

/**
 * struct hfi_cpu_info - Per-CPU attributes to consume HFI data
 * @index:		Row of this CPU in its HFI table
 * @hfi_instance:	Attributes of the HFI table to which this CPU belongs
 *
 * Parameters to link a logical processor to an HFI table and a row within it.
 */
struct hfi_cpu_info {
	s16			index;
	struct hfi_instance	*hfi_instance;
};

static DEFINE_PER_CPU(struct hfi_cpu_info, hfi_cpu_info) = { .index = -1 };

static int max_hfi_instances;
static struct hfi_instance *hfi_instances;

static struct hfi_features hfi_features;
static DEFINE_MUTEX(hfi_instance_lock);

static struct workqueue_struct *hfi_updates_wq;
#define HFI_UPDATE_INTERVAL		HZ
#define HFI_MAX_THERM_NOTIFY_COUNT	16

#ifdef CONFIG_DEBUG_FS

/* Received package-level interrupts that are not HFI events. */
static DEFINE_PER_CPU(u64, hfi_intr_not_hfi);
/* Received package-level interrupts when per-CPU data is not initialized. */
static DEFINE_PER_CPU(u64, hfi_intr_not_initialized);
/* Received package-level interrupts that are HFI events. */
static DEFINE_PER_CPU(u64, hfi_intr_received);
/* HFI events for which new delayed work was scheduled */
static DEFINE_PER_CPU(u64, hfi_intr_processed);
/* HFI events which delayed work was scheduled while there was previous work pending. */
static DEFINE_PER_CPU(u64, hfi_intr_skipped);
/* HFI events during which the event_lock was held by another CPU. */
static DEFINE_PER_CPU(u64, hfi_intr_ignored);
/* HFI events that did not have a newer timestamp */
static DEFINE_PER_CPU(u64, hfi_intr_bad_ts);

static u64 hfi_updates, hfi_updates_recovered;

static int hfi_features_show(struct seq_file *s, void *unused)
{
	union cpuid6_edx edx;

	edx.full = cpuid_edx(CPUID_HFI_LEAF);

	seq_printf(s, "ITD supported:\t\t%u\n", boot_cpu_has(X86_FEATURE_ITD));
	seq_printf(s, "HRESET supported:\t%u\n", boot_cpu_has(X86_FEATURE_HRESET));
	if (boot_cpu_has(X86_FEATURE_HRESET))
		seq_printf(s, "HRESET features:\t0x%x\n", cpuid_ebx(0x20));
	seq_printf(s, "Number of classes:\t%u\n", hfi_features.nr_classes);
	seq_printf(s, "Capabilities:\t\tP:%d EE:%d R:%d\n",
		   edx.split.capabilities.split.performance,
		   edx.split.capabilities.split.energy_efficiency,
		   edx.split.capabilities.split.__reserved);
	seq_printf(s, "Table pages:\t\t%zu\n", hfi_features.nr_table_pages);
	seq_printf(s, "CPU stride:\t\t0x%x\n", hfi_features.cpu_stride);
	seq_printf(s, "Class class stride:\t0x%x\n", hfi_features.class_stride);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(hfi_features);

static int hfi_state_show(struct seq_file *s, void *unused)
{
	struct hfi_instance *hfi_instance = s->private;
	struct hfi_hdr *hfi_hdr;
	int cpu, i, j;
	u64 msr_val;

	cpu = cpumask_first(hfi_instance->cpus);

	/* Dump the relevant registers */
	rdmsrl_on_cpu(cpu, MSR_IA32_PACKAGE_THERM_STATUS, &msr_val);
	seq_printf(s, "MSR_IA32_PACKAGE_THERM_STATUS:\t\t0x%llx HFI status:%lld\n",
		   msr_val, (msr_val & 0x4000000) >> 26);

	rdmsrl_on_cpu(cpu, MSR_IA32_PACKAGE_THERM_INTERRUPT, &msr_val);
	seq_printf(s, "MSR_IA32_PACKAGE_THERM_INTERRUPT:\t0x%llx HFI intr: %lld\n",
		   msr_val, (msr_val & 0x2000000) >> 25);

	rdmsrl_on_cpu(cpu, MSR_IA32_HW_FEEDBACK_PTR, &msr_val);
	seq_printf(s, "MSR_IA32_HW_FEEDBACK_PTR:\t\t0x%llx\n", msr_val);

	rdmsrl_on_cpu(cpu, MSR_IA32_HW_FEEDBACK_CONFIG, &msr_val);
	seq_printf(s, "MSR_IA32_HW_FEEDBACK_CONFIG:\t\t0x%llx\n", msr_val);
	if (boot_cpu_has(X86_FEATURE_ITD)) {
		seq_puts(s, "\nCPU\tMSR_IA32_HW_HRESET_ENABLE\tMSR_IA32_HW_FEEDBACK_THREAD_CONFIG\n");
		for_each_cpu(i, hfi_instance->cpus) {
			u64 hreset_en, thr_cfg;

			rdmsrl_on_cpu(i, MSR_IA32_HW_HRESET_ENABLE, &hreset_en);
			rdmsrl_on_cpu(i, MSR_IA32_HW_FEEDBACK_THREAD_CONFIG, &thr_cfg);
			seq_printf(s, "%4d\t\t0x%llx\t\t\t\t0x%llx\n", i, hreset_en, thr_cfg);
		}
		seq_puts(s, "\n");
	}

	/* Dump the HFI table parameters */
	seq_printf(s, "Table base:\t0x%px\n", hfi_instance->local_table);
	seq_printf(s, "Headers base:\t0x%px\n", hfi_instance->hdr);
	seq_printf(s, "Data base:\t0x%px\n", hfi_instance->data);
	seq_printf(s, "Die id:\t\t%u\n",
		   topology_logical_die_id(cpumask_first(hfi_instance->cpus)));
	seq_printf(s, "CPUs:\t\t%*pbl\n", cpumask_pr_args(hfi_instance->cpus));
	seq_printf(s, "Timestamp:\t%lld\n", *hfi_instance->timestamp);
	seq_puts(s, "\nPer-CPU data:\n");
	seq_puts(s, "CPU\tInstance data at:\t\t\t\t\tHFI interrupts:\n");
	seq_puts(s, "\t\t\t    received | not hfi | not initialized | processed | skipped | ignored | bad timestamp\n");
	for_each_cpu(i, hfi_instance->cpus) {
		seq_printf(s, "%4d\t%px", i, per_cpu(hfi_cpu_info, i).hfi_instance);
		seq_printf(s, "%12llu%10llu%18llu%12llu%10llu\t%8llu\t%8llu\n",
			   per_cpu(hfi_intr_received, i),
			   per_cpu(hfi_intr_not_hfi, i),
			   per_cpu(hfi_intr_not_initialized, i),
			   per_cpu(hfi_intr_processed, i),
			   per_cpu(hfi_intr_skipped, i),
			   per_cpu(hfi_intr_ignored, i),
			   per_cpu(hfi_intr_bad_ts, i));
	}

	/* Dump the performance capability change indication */
	seq_puts(s, "\nPerf Cap Change Indication:\n");
	hfi_hdr = hfi_instance->hdr;
	for (i = 0; i < hfi_features.nr_classes; i++) {
		struct hfi_hdr *hdr_data = hfi_hdr;

		seq_printf(s, "Class%d:%u\t", i, hdr_data->perf_updated);
		hfi_hdr++;
	}

	/* Dump the energy efficiency capability change indication */
	seq_puts(s, "\n\nEnergy Efficiency Cap Change Indication:\n");
	hfi_hdr = hfi_instance->hdr;
	for (i = 0; i < hfi_features.nr_classes; i++) {
		struct hfi_hdr *hdr_data = hfi_hdr;

		seq_printf(s, "Class%d:%u\t", i, hdr_data->ee_updated);
		hfi_hdr++;
	}

	/* Overall HFI updates in the system */
	seq_puts(s, "\n\nHFI table updates:\n");
	seq_printf(s, "\tscheduled: %llu\t recovered: %llu\n",
		   hfi_updates, hfi_updates_recovered);

	/* Dump the HFI table */
	seq_puts(s, "\nHFI table:\n");
	seq_puts(s, "CPU\tIndex");
	for (i = 0; i < hfi_features.nr_classes; i++)
		seq_printf(s, "\tPe%u Ef%u", i, i);
	seq_puts(s, "\n");

	for_each_cpu(i, hfi_instance->cpus) {
		s16 index = per_cpu(hfi_cpu_info, i).index;
		void *data_ptr = hfi_instance->data +
				       index * hfi_features.cpu_stride;

		seq_printf(s, "%4u\t%4d", i, index);
		for (j = 0; j < hfi_features.nr_classes; j++) {
			struct hfi_cpu_data *data = data_ptr +
						    j * hfi_features.class_stride;

			seq_printf(s, "\t%3u %3u", data->perf_cap, data->ee_cap);
		}

		seq_puts(s, "\n");
	}

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(hfi_state);

static int hfi_class_score_show(struct seq_file *s, void *unused)
{
#ifdef CONFIG_INTEL_THREAD_DIRECTOR
	struct hfi_instance *hfi_instance = s->private;
	int cpu, j;

	seq_puts(s, "CPU\t");
	for (j = 0; j < hfi_features.nr_classes; j++)
		seq_printf(s, " C%d\t", j);
	seq_puts(s, "\n");

	for_each_cpu(cpu, hfi_instance->cpus) {
		seq_printf(s, "%4d", cpu);
		for (j = 0; j < hfi_features.nr_classes; j++)
			seq_printf(s, "\t%3u",
				   intel_hfi_get_task_class_score(j, cpu));

		seq_puts(s, "\n");
	}
#else
	seq_puts(s, "ITD not enabled. Select CONFIG_INTEL_THREAD_DIRECTOR=y.\n");
#endif
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(hfi_class_score);

/*
 * Inject an HFI table:
 *
 * The file /sys/kernel/debug/intel_hw_feedback/inject_tableX provides
 * functionality to inject an HFI table to an HFI instance. It can accept up to
 * 128 numeric entries in the format n,n,n,...,n,n where n are numbers in the
 * range [0, 255].
 *
 * You need to inject the values sequentially per capability, per class, per
 * row in the HFI table. For instance, if your hardware supports 4 classes, and
 * performance and energy efficiency, inject the values for the first row of
 * the HFI table as follows:
 *
 *	Pe0,Ee0,Pe1,Ee1,Pe2,Ee2,Pe3,Ee3,

 * Then, append the subsequent rows of the table after the comma (no spaces)
 * until you have as many rows as you need in the table.

 * You can optionally only provide a few rows of the table. In such case, the
 * injection functionality will use the provided values preriodically to
 * populate the whole injected table.
 *
 * When composing your table, remember that more than one CPU can point to the
 * same row in the table.
 */
#define HFI_INJECT_TABLE_MAX_ENTRIES 128
static char hfi_inject_table_input_str[HFI_INJECT_TABLE_MAX_ENTRIES * 4];
static u8 hfi_inject_table_input_vals[HFI_INJECT_TABLE_MAX_ENTRIES];

static int hfi_inject_table(struct hfi_instance *hfi_instance,
			    u8 *inj_vals, int inj_len)
{
	void *fake_table, *fake_hdr, *fake_data;
	struct hfi_hdr *hfi_hdr;
	u64 *fake_timestamp;
	int i, k = 0;

	fake_table = kzalloc(hfi_features.nr_table_pages << PAGE_SHIFT,
			     GFP_KERNEL);
	if (!fake_table)
		return -ENOMEM;

	/* The timestamp is at the base of the HFI table. */
	fake_timestamp = (u64 *)fake_table;
	/* The HFI header is below the time-stamp. */
	fake_hdr = fake_table + sizeof(*fake_timestamp);
	/* The HFI data starts below the header. */
	fake_data = fake_hdr + hfi_features.hdr_size;

	/* Fake timestamp. */
	*fake_timestamp = *hfi_instance->timestamp + 1;

	/* Fake header. */
	hfi_hdr = fake_hdr;
	for (i = 0; i < hfi_features.nr_classes; i++) {
		hfi_hdr->perf_updated = 5;
		hfi_hdr->ee_updated = 5;
		hfi_hdr++;
	}

	/* Fake data. */
	for (i = 0; i < HFI_INJECT_TABLE_MAX_ENTRIES; i++) {
		void *data_ptr = fake_data + i * hfi_features.cpu_stride;
		int j;

		for (j = 0; j < hfi_features.nr_classes; j++) {
			struct hfi_cpu_data *data = data_ptr +
						    j * hfi_features.class_stride;

			/* Keep reusing the same inj_len values until done. */
			data->perf_cap = inj_vals[k++ % inj_len];
			data->ee_cap = inj_vals[k++ % inj_len];
		}
	}

	memcpy(hfi_instance->local_table, fake_table,
	       hfi_features.nr_table_pages << PAGE_SHIFT);

	queue_delayed_work(hfi_updates_wq, &hfi_instance->update_work,
			   HFI_UPDATE_INTERVAL);

	kfree(fake_table);

	return 0;
}

static int hfi_inject_table_parse_values(char *str, u8 *values)
{
	char *key;
	int i = 0, ret;

	while ((key = strsep(&str, ",")) != NULL) {
		ret = kstrtou8(key, 10, &values[i]);
		if (ret)
			return ret;

		i++;
	}

	return i;
}

static ssize_t hfi_inject_table_write(struct file *file, const char __user *ptr,
				      size_t len, loff_t *off)
{
	struct hfi_instance *hfi_instance;
	int ret;

	hfi_instance = ((struct seq_file *)file->private_data)->private;

	if (*off != 0)
		return 0;

	if (len > sizeof(hfi_inject_table_input_str))
		return -E2BIG;

	memset(hfi_inject_table_input_str, 0, sizeof(hfi_inject_table_input_str));
	memset(hfi_inject_table_input_vals, 0, sizeof(hfi_inject_table_input_vals));

	ret = strncpy_from_user(hfi_inject_table_input_str, ptr, len);
	if (ret < 0)
		return ret;

	ret = hfi_inject_table_parse_values(hfi_inject_table_input_str,
					    hfi_inject_table_input_vals);
	if (ret < 0)
		return ret;

	ret = hfi_inject_table(hfi_instance, hfi_inject_table_input_vals, ret);

	return ret ? ret : len;
}

static int hfi_inject_table_show(struct seq_file *s, void *unused)
{
	return 0;
}

static int hfi_inject_table_open(struct inode *inode, struct file *file)
{
	return single_open(file, hfi_inject_table_show, inode->i_private);
}

static const struct file_operations hfi_inject_table_fops = {
	.owner = THIS_MODULE,
	.open = hfi_inject_table_open,
	.read = seq_read,
	.write = hfi_inject_table_write,
	.llseek = seq_lseek,
	.release = single_release
};

static struct dentry *hfi_debugfs_dir;

static void hfi_debugfs_unregister(void)
{
	debugfs_remove_recursive(hfi_debugfs_dir);
}

static void hfi_debugfs_register(void)
{
	struct dentry *f;

	hfi_debugfs_dir = debugfs_create_dir("intel_hw_feedback", NULL);
	if (!hfi_debugfs_dir)
		return;

	f = debugfs_create_file("features", 0444, hfi_debugfs_dir,
				NULL, &hfi_features_fops);
	if (!f)
		goto err;

	return;
err:
	hfi_debugfs_unregister();
}

static void init_blob_wrapper(struct debugfs_blob_wrapper **blob, void *data,
			      char *name)
{
	*blob = kzalloc(sizeof(**blob), GFP_KERNEL);
	if (!*blob)
		return;

	(*blob)->data = data;
	(*blob)->size = hfi_features.nr_table_pages << PAGE_SHIFT;

	debugfs_create_blob(name, 0444, hfi_debugfs_dir, *blob);
}

static void hfi_debugfs_populate_instance(struct hfi_instance *hfi_instance,
					  int die_id)
{
	char name[64];

	if (!hfi_debugfs_dir)
		return;

	snprintf(name, 64, "hw_state%u", die_id);
	debugfs_create_file(name, 0444, hfi_debugfs_dir, hfi_instance,
			    &hfi_state_fops);

	snprintf(name, 64, "hw_table%u", die_id);
	init_blob_wrapper(&hfi_instance->debugfs_hw_table,
			  hfi_instance->hw_table, name);

	snprintf(name, 64, "local_table%u", die_id);
	init_blob_wrapper(&hfi_instance->debugfs_local_table,
			  hfi_instance->local_table, name);

	snprintf(name, 64, "class_score%d", die_id);
	debugfs_create_file(name, 0444, hfi_debugfs_dir, hfi_instance,
			    &hfi_class_score_fops);

	snprintf(name, 64, "inject_table%u", die_id);
	debugfs_create_file(name, 0444, hfi_debugfs_dir, hfi_instance,
			    &hfi_inject_table_fops);
}

#else
static void hfi_debugfs_register(void)
{
}

static void hfi_debugfs_populate_instance(struct hfi_instance *hfi_instance,
					  int die_id)
{
}
#endif /* CONFIG_DEBUG_FS */

#ifdef CONFIG_INTEL_THREAD_DIRECTOR

int intel_hfi_task_classes_nr(void)
{
	return hfi_features.nr_classes;
}

#define CLASS_DEBOUNCER_SKIPS 4

static void debounce_and_update_class(struct task_struct *p, int new_class)
{
	char debounce_skip;

	/* The class of @p changed, only restart the debounce counter. */
	if (p->class_candidate != new_class) {
		p->class_debounce_counter = 1;
		goto out;
	}

	/*
	 * The class of @p did not change. Update it if it has been the same
	 * for CLASS_DEBOUNCER_SKIPS user ticks.
	 */
	debounce_skip = p->class_debounce_counter + 1;
	if (debounce_skip < CLASS_DEBOUNCER_SKIPS)
		p->class_debounce_counter++;
	else
		p->class = new_class;

out:
	p->class_candidate = new_class;
}

static bool classification_is_reliable(u8 class, bool smt_siblings_idle)
{
	switch (boot_cpu_data.x86_model) {
	case INTEL_FAM6_ALDERLAKE:
	case INTEL_FAM6_ALDERLAKE_L:
	case INTEL_FAM6_RAPTORLAKE:
	case INTEL_FAM6_RAPTORLAKE_P:
	case 0xBF: /* INTEL_FAM6_RAPTORLAKE_S */
		if (class == 3 || class == 2 || smt_siblings_idle)
			return true;

		return false;

	default:
		return true;
	}
}

void intel_hfi_update_task_class(struct task_struct *curr, bool smt_siblings_idle)
{
	union hfi_thread_feedback_char_msr msr;

	/* We should not be here if ITD is not supported. */
	if (!cpu_feature_enabled(X86_FEATURE_ITD)) {
		pr_warn_once("task classification requested but not supported!");
		return;
	}

	rdmsrl(MSR_IA32_HW_FEEDBACK_CHAR, msr.full);
	if (!msr.split.valid)
		return;

	if (classification_is_reliable(msr.split.classid, smt_siblings_idle))
		debounce_and_update_class(curr, msr.split.classid);
}

static void get_one_hfi_cap(struct hfi_instance *hfi_instance, s16 index,
			    struct hfi_cpu_data *hfi_caps, int class)
{
	struct hfi_cpu_data *caps;

	/* Find the capabilities of @cpu */
	caps = hfi_instance->data + index * hfi_features.cpu_stride +
	       class * hfi_features.class_stride;
	memcpy(hfi_caps, caps, sizeof(*hfi_caps));
}

int intel_hfi_get_task_class_score(int class, int cpu)
{
	struct hfi_cpu_info *info = &per_cpu(hfi_cpu_info, cpu);
	struct hfi_instance *instance;
	struct hfi_cpu_data caps;
	unsigned long flags;
	int c, i = 1, cap;

	if (cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;

	if (class == TASK_CLASS_UNCLASSIFIED)
		return -EINVAL;

	if (class >= (int)hfi_features.nr_classes)
		return -EINVAL;

	instance = info->hfi_instance;
	if (!instance)
		return -ENOENT;

	raw_spin_lock_irqsave(&instance->table_lock, flags);
	/*
	 * TODO: Per CPU variables could be used here to avoid having to
	 * iterate the CPU's siblings mask.
	 */
	for_each_cpu(c, topology_sibling_cpumask(cpu)) {
		if (c == cpu) {
			get_one_hfi_cap(instance, info->index, &caps, class);
			break;
		}
		i++;
	}

	cap = caps.perf_cap / i;
	raw_spin_unlock_irqrestore(&instance->table_lock, flags);

	return cap;
}
#endif /* CONFIG_INTEL_THREAD_DIRECTOR */

static void get_hfi_caps(struct hfi_instance *hfi_instance,
			 struct thermal_genl_cpu_caps *cpu_caps)
{
	unsigned long flags;
	int cpu, i = 0;

	raw_spin_lock_irqsave(&hfi_instance->table_lock, flags);
	for_each_cpu(cpu, hfi_instance->cpus) {
		struct hfi_cpu_data *caps;
		s16 index;

		index = per_cpu(hfi_cpu_info, cpu).index;
		/*
		 * Only report the legacy (i.e., class 0) capabilities. No need
		 * of hfi_features.class_stride.
		 */
		caps = hfi_instance->data + index * hfi_features.cpu_stride;
		cpu_caps[i].cpu = cpu;

		/*
		 * Scale performance and energy efficiency to
		 * the [0, 1023] interval that thermal netlink uses.
		 */
		cpu_caps[i].performance = caps->perf_cap << 2;
		cpu_caps[i].efficiency = caps->ee_cap << 2;

		++i;
	}
	raw_spin_unlock_irqrestore(&hfi_instance->table_lock, flags);
}

/*
 * Call update_capabilities() when there are changes in the HFI table.
 */
static void update_capabilities(struct hfi_instance *hfi_instance)
{
	struct thermal_genl_cpu_caps *cpu_caps;
	int i = 0, cpu_count;

	/* CPUs may come online/offline while processing an HFI update. */
	mutex_lock(&hfi_instance_lock);

	cpu_count = cpumask_weight(hfi_instance->cpus);

	/* No CPUs to report in this hfi_instance. */
	if (!cpu_count)
		goto out;

	cpu_caps = kcalloc(cpu_count, sizeof(*cpu_caps), GFP_KERNEL);
	if (!cpu_caps)
		goto out;

	get_hfi_caps(hfi_instance, cpu_caps);

	if (cpu_count < HFI_MAX_THERM_NOTIFY_COUNT)
		goto last_cmd;

	/* Process complete chunks of HFI_MAX_THERM_NOTIFY_COUNT capabilities. */
	for (i = 0;
	     (i + HFI_MAX_THERM_NOTIFY_COUNT) <= cpu_count;
	     i += HFI_MAX_THERM_NOTIFY_COUNT)
		thermal_genl_cpu_capability_event(HFI_MAX_THERM_NOTIFY_COUNT,
						  &cpu_caps[i]);

	cpu_count = cpu_count - i;

last_cmd:
	/* Process the remaining capabilities if any. */
	if (cpu_count)
		thermal_genl_cpu_capability_event(cpu_count, &cpu_caps[i]);

	kfree(cpu_caps);
out:
	mutex_unlock(&hfi_instance_lock);
}

static void hfi_update_work_fn(struct work_struct *work)
{
	struct hfi_instance *hfi_instance;

	hfi_instance = container_of(to_delayed_work(work), struct hfi_instance,
				    update_work);

#ifdef CONFIG_DEBUG_FS
	/*
	 * Here we are misusing hfi_instance_lock, which is meant to protect accesses to
	 * HFI instsances. It, however, needlessly protect accesses to all instances at the
	 * same time. We explot this to protect hfi_updtes. If in the future there is a per-
	 * instance lock, we would need to have our own lock.
	 */
	mutex_lock(&hfi_instance_lock);
	hfi_updates++;
	mutex_unlock(&hfi_instance_lock);
#endif

	update_capabilities(hfi_instance);
}

void intel_hfi_process_event(__u64 pkg_therm_status_msr_val)
{
	struct hfi_instance *hfi_instance;
	int cpu = smp_processor_id();
	struct hfi_cpu_info *info;
	unsigned long flags;
	u64 new_timestamp;
#ifdef CONFIG_DEBUG_FS
	bool work_queued;

	per_cpu(hfi_intr_received, cpu)++;
#endif

	if (!pkg_therm_status_msr_val) {
#ifdef CONFIG_DEBUG_FS
		per_cpu(hfi_intr_not_hfi, cpu)++;
#endif
		return;
	}

	info = &per_cpu(hfi_cpu_info, cpu);
	if (!info) {
#ifdef CONFIG_DEBUG_FS
		per_cpu(hfi_intr_not_initialized, cpu)++;
#endif
		return;
	}

	/*
	 * A CPU is linked to its HFI instance before the thermal vector in the
	 * local APIC is unmasked. Hence, info->hfi_instance cannot be NULL
	 * when receiving an HFI event.
	 */
	hfi_instance = info->hfi_instance;
	if (unlikely(!hfi_instance)) {
		pr_debug("Received event on CPU %d but instance was null", cpu);
#ifdef CONFIG_DEBUG_FS
		per_cpu(hfi_intr_not_initialized, cpu)++;
#endif
		return;
	}

	/*
	 * On most systems, all CPUs in the package receive a package-level
	 * thermal interrupt when there is an HFI update. It is sufficient to
	 * let a single CPU to acknowledge the update and queue work to
	 * process it. The remaining CPUs can resume their work.
	 */
	if (!raw_spin_trylock(&hfi_instance->event_lock)) {
#ifdef CONFIG_DEBUG_FS
		per_cpu(hfi_intr_ignored, cpu)++;
#endif
		return;
	}

	/* Skip duplicated updates. */
	new_timestamp = *(u64 *)hfi_instance->hw_table;
	if (*hfi_instance->timestamp == new_timestamp) {
#ifdef CONFIG_DEBUG_FS
		per_cpu(hfi_intr_bad_ts, cpu)++;
#endif
		raw_spin_unlock(&hfi_instance->event_lock);
		return;
	}

	raw_spin_lock_irqsave(&hfi_instance->table_lock, flags);

	/*
	 * Copy the updated table into our local copy. This includes the new
	 * timestamp.
	 */
	memcpy(hfi_instance->local_table, hfi_instance->hw_table,
	       hfi_features.nr_table_pages << PAGE_SHIFT);

	raw_spin_unlock_irqrestore(&hfi_instance->table_lock, flags);
	raw_spin_unlock(&hfi_instance->event_lock);

	/*
	 * Let hardware know that we are done reading the HFI table and it is
	 * free to update it again.
	 */
	pkg_therm_status_msr_val &= THERM_STATUS_CLEAR_PKG_MASK &
				    ~PACKAGE_THERM_STATUS_HFI_UPDATED;
	wrmsrl(MSR_IA32_PACKAGE_THERM_STATUS, pkg_therm_status_msr_val);

#ifdef CONFIG_DEBUG_FS
	work_queued = queue_delayed_work(hfi_updates_wq,
					 &hfi_instance->update_work,
					 HFI_UPDATE_INTERVAL);
	if (work_queued)
		per_cpu(hfi_intr_processed, cpu)++;
	else
		per_cpu(hfi_intr_skipped, cpu)++;
#else
	queue_delayed_work(hfi_updates_wq, &hfi_instance->update_work,
			   HFI_UPDATE_INTERVAL);
#endif
}

static void init_hfi_cpu_index(struct hfi_cpu_info *info)
{
	union cpuid6_edx edx;

	/* Do not re-read @cpu's index if it has already been initialized. */
	if (info->index > -1)
		return;

	edx.full = cpuid_edx(CPUID_HFI_LEAF);
	info->index = edx.split.index;
}

/*
 * The format of the HFI table depends on the number of capabilities and classes
 * that the hardware supports. Keep a data structure to navigate the table.
 */
static void init_hfi_instance(struct hfi_instance *hfi_instance)
{
	/* The HFI header is below the time-stamp. */
	hfi_instance->hdr = hfi_instance->local_table +
			    sizeof(*hfi_instance->timestamp);

	/* The HFI data starts below the header. */
	hfi_instance->data = hfi_instance->hdr + hfi_features.hdr_size;
}

/**
 * intel_hfi_online() - Enable HFI on @cpu
 * @cpu:	CPU in which the HFI will be enabled
 *
 * Enable the HFI to be used in @cpu. The HFI is enabled at the die/package
 * level. The first CPU in the die/package to come online does the full HFI
 * initialization. Subsequent CPUs will just link themselves to the HFI
 * instance of their die/package.
 *
 * This function is called before enabling the thermal vector in the local APIC
 * in order to ensure that @cpu has an associated HFI instance when it receives
 * an HFI event.
 */
void intel_hfi_online(unsigned int cpu)
{
	struct hfi_instance *hfi_instance;
	struct hfi_cpu_info *info;
	phys_addr_t hw_table_pa;
	u64 msr_val;
	u16 die_id;

	/* Nothing to do if hfi_instances are missing. */
	if (!hfi_instances)
		return;

	/*
	 * Link @cpu to the HFI instance of its package/die. It does not
	 * matter whether the instance has been initialized.
	 */
	info = &per_cpu(hfi_cpu_info, cpu);
	die_id = topology_logical_die_id(cpu);
	hfi_instance = info->hfi_instance;
	if (!hfi_instance) {
		if (die_id < 0 || die_id >= max_hfi_instances)
			return;

		hfi_instance = &hfi_instances[die_id];
		info->hfi_instance = hfi_instance;
	}

	init_hfi_cpu_index(info);

	if (cpu_feature_enabled(X86_FEATURE_ITD)) {
		msr_val = HW_FEEDBACK_THREAD_CONFIG_ENABLE_BIT;
		wrmsrl(MSR_IA32_HW_FEEDBACK_THREAD_CONFIG, msr_val);
	}

	/*
	 * Now check if the HFI instance of the package/die of @cpu has been
	 * initialized (by checking its header). In such case, all we have to
	 * do is to add @cpu to this instance's cpumask.
	 */
	mutex_lock(&hfi_instance_lock);
	if (hfi_instance->hdr) {
		cpumask_set_cpu(cpu, hfi_instance->cpus);

		/*
		 * Both the HFI thermal interrupt and the local APIC thermal LVT
		 * are enabled when a CPU comes online. On some systems, all
		 * CPUs get the package thermak interrupt. On others, however,
		 * only a subset of CPU gets it. In the former case, we always
		 * get the interrupt as we enable the HFI after having enabled
		 * the thermal interrupt in the local APIC. However, in the
		 * latter case, we may miss the interrupt if hardware issues the
		 * interrupt to a CPU in which the thermal vector has not been
		 * enabled in the local APIC. We know that this is the case as
		 * the status bit will be set. In such a case, handle the
		 * interrupt.
		 */
		raw_spin_lock_irq(&hfi_instance->table_lock);
		rdmsrl(MSR_IA32_PACKAGE_THERM_STATUS, msr_val);
		if (msr_val & PACKAGE_THERM_STATUS_HFI_UPDATED) {
			memcpy(hfi_instance->local_table, hfi_instance->hw_table,
			       hfi_features.nr_table_pages << PAGE_SHIFT);

			msr_val &= THERM_STATUS_CLEAR_PKG_MASK &
				   ~PACKAGE_THERM_STATUS_HFI_UPDATED;
			wrmsrl(MSR_IA32_PACKAGE_THERM_STATUS, msr_val);

			raw_spin_unlock_irq(&hfi_instance->table_lock);

			queue_delayed_work(hfi_updates_wq,
					   &hfi_instance->update_work,
					   HFI_UPDATE_INTERVAL);
#ifdef CONFIG_DEBUG_FS
			hfi_updates_recovered++;
#endif

			goto unlock;
		}

		raw_spin_unlock_irq(&hfi_instance->table_lock);

		goto unlock;
	}

	/*
	 * Hardware is programmed with the physical address of the first page
	 * frame of the table. Hence, the allocated memory must be page-aligned.
	 */
	hfi_instance->hw_table = alloc_pages_exact(hfi_features.nr_table_pages,
						   GFP_KERNEL | __GFP_ZERO);
	if (!hfi_instance->hw_table)
		goto unlock;

	hw_table_pa = virt_to_phys(hfi_instance->hw_table);

	/*
	 * Allocate memory to keep a local copy of the table that
	 * hardware generates.
	 */
	hfi_instance->local_table = kzalloc(hfi_features.nr_table_pages << PAGE_SHIFT,
					    GFP_KERNEL);
	if (!hfi_instance->local_table)
		goto free_hw_table;

	/*
	 * Program the address of the feedback table of this die/package. On
	 * some processors, hardware remembers the old address of the HFI table
	 * even after having been reprogrammed and re-enabled. Thus, do not free
	 * the pages allocated for the table or reprogram the hardware with a
	 * new base address. Namely, program the hardware only once.
	 */
	msr_val = hw_table_pa | HW_FEEDBACK_PTR_VALID_BIT;
	wrmsrl(MSR_IA32_HW_FEEDBACK_PTR, msr_val);

	init_hfi_instance(hfi_instance);

	INIT_DELAYED_WORK(&hfi_instance->update_work, hfi_update_work_fn);
	raw_spin_lock_init(&hfi_instance->table_lock);
	raw_spin_lock_init(&hfi_instance->event_lock);

	cpumask_set_cpu(cpu, hfi_instance->cpus);

	hfi_debugfs_populate_instance(hfi_instance, die_id);

	/*
	 * Enable the hardware feedback interface and never disable it. See
	 * comment on programming the address of the table.
	 */
	rdmsrl(MSR_IA32_HW_FEEDBACK_CONFIG, msr_val);
	msr_val |= HW_FEEDBACK_CONFIG_HFI_ENABLE_BIT;

	if (cpu_feature_enabled(X86_FEATURE_ITD))
		msr_val |= HW_FEEDBACK_CONFIG_ITD_ENABLE_BIT;

	wrmsrl(MSR_IA32_HW_FEEDBACK_CONFIG, msr_val);

unlock:
	mutex_unlock(&hfi_instance_lock);
	return;

free_hw_table:
	free_pages_exact(hfi_instance->hw_table, hfi_features.nr_table_pages);
	goto unlock;
}

/**
 * intel_hfi_offline() - Disable HFI on @cpu
 * @cpu:	CPU in which the HFI will be disabled
 *
 * Remove @cpu from those covered by its HFI instance.
 *
 * On some processors, hardware remembers previous programming settings even
 * after being reprogrammed. Thus, keep HFI enabled even if all CPUs in the
 * die/package of @cpu are offline. See note in intel_hfi_online().
 */
void intel_hfi_offline(unsigned int cpu)
{
	struct hfi_cpu_info *info = &per_cpu(hfi_cpu_info, cpu);
	struct hfi_instance *hfi_instance;

	/*
	 * Check if @cpu as an associated, initialized (i.e., with a non-NULL
	 * header). Also, HFI instances are only initialized if X86_FEATURE_HFI
	 * is present.
	 */
	hfi_instance = info->hfi_instance;
	if (!hfi_instance)
		return;

	if (!hfi_instance->hdr)
		return;

	mutex_lock(&hfi_instance_lock);
	cpumask_clear_cpu(cpu, hfi_instance->cpus);
	mutex_unlock(&hfi_instance_lock);
}

static __init int hfi_parse_features(void)
{
	unsigned int nr_capabilities;
	union cpuid6_edx edx;

	if (!boot_cpu_has(X86_FEATURE_HFI))
		return -ENODEV;

	/*
	 * If we are here we know that CPUID_HFI_LEAF exists. Parse the
	 * supported capabilities and the size of the HFI table.
	 */
	edx.full = cpuid_edx(CPUID_HFI_LEAF);

	if (!edx.split.capabilities.split.performance) {
		pr_debug("Performance reporting not supported! Not using HFI\n");
		return -ENODEV;
	}

	/*
	 * The number of supported capabilities determines the number of
	 * columns in the HFI table. Exclude the reserved bits.
	 */
	edx.split.capabilities.split.__reserved = 0;
	nr_capabilities = hweight8(edx.split.capabilities.bits);

	/* The number of 4KB pages required by the table */
	hfi_features.nr_table_pages = edx.split.table_pages + 1;

	/*
	 * Capability fields of an HFI class are grouped together. Classes are
	 * contiguous in memory.  Hence, use the number of supported features to
	 * locate a specific class.
	 */
	hfi_features.class_stride = nr_capabilities;

	if (cpu_feature_enabled(X86_FEATURE_ITD)) {
		union cpuid6_ecx ecx;

		ecx.full = cpuid_ecx(CPUID_HFI_LEAF);
		hfi_features.nr_classes = ecx.split.nr_classes;
	} else {
		hfi_features.nr_classes = 1;
	}

	/*
	 * The header contains change indications for each supported feature.
	 * The size of the table header is rounded up to be a multiple of 8
	 * bytes.
	 */
	hfi_features.hdr_size = DIV_ROUND_UP(nr_capabilities *
					     hfi_features.nr_classes, 8) * 8;

	/*
	 * Data of each logical processor is also rounded up to be a multiple
	 * of 8 bytes.
	 */
	hfi_features.cpu_stride = DIV_ROUND_UP(nr_capabilities *
					       hfi_features.nr_classes, 8) * 8;

	return 0;
}

void __init intel_hfi_init(void)
{
	struct hfi_instance *hfi_instance;
	int i, j;

	if (hfi_parse_features())
		return;

	/* There is one HFI instance per die/package. */
	max_hfi_instances = topology_max_packages() *
			    topology_max_die_per_package();

	/*
	 * This allocation may fail. CPU hotplug callbacks must check
	 * for a null pointer.
	 */
	hfi_instances = kcalloc(max_hfi_instances, sizeof(*hfi_instances),
				GFP_KERNEL);
	if (!hfi_instances)
		return;

	for (i = 0; i < max_hfi_instances; i++) {
		hfi_instance = &hfi_instances[i];
		if (!zalloc_cpumask_var(&hfi_instance->cpus, GFP_KERNEL))
			goto err_nomem;
	}

	hfi_updates_wq = create_singlethread_workqueue("hfi-updates");
	if (!hfi_updates_wq)
		goto err_nomem;

	hfi_debugfs_register();

	return;

err_nomem:
	for (j = 0; j < i; ++j) {
		hfi_instance = &hfi_instances[j];
		free_cpumask_var(hfi_instance->cpus);
	}

	kfree(hfi_instances);
	hfi_instances = NULL;
}
