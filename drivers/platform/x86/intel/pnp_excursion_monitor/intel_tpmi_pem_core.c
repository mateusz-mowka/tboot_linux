// SPDX-License-Identifier: GPL-2.0-only
/*
 * intel-pem-tpmi: platform excursion monitor enabling
 *
 * Copyright (c) 2022, Intel Corporation.
 * All Rights Reserved.
 *
 */

#include <linux/auxiliary_bus.h>
#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/intel_tpmi.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/nospec.h>
#include <linux/perf_event.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <linux/rculist.h>
#include <linux/slab.h>

#include "intel_tpmi_pem_core.h"
#include "../tpmi_power_domains.h"
#include "../pmt/telemetry.h"

#define PEM_HEADER_VERSION	1
#define PEM_HEADER_INDEX	0
#define PEM_CONTROL_INDEX	8
#define PEM_STATUS_INDEX	16

/*
 * Store information of one instance (for a power domain).
 * PEM HW interface scope is per power domain. A package can have multiple
 * power domains.
 */
struct tpmi_pem_instance_info {
	int power_domain;
	int pmt_info_offset;
	u32 fet;
	u32 tw;
	void __iomem *pem_base;
	struct perf_event *owner;
	struct intel_tpmi_plat_info *plat_info;
	struct auxiliary_device *auxdev;
	struct pci_dev *pmt_pci_dev;
	u32 pmt_guid;
	u16 pmt_sample_id;
	u16 pmt_sample_count;
};

/* Each socket will have multiple power domain instances */
struct tpmi_pem_struct {
	int pkg_id;
	int number_of_instances;
	struct tpmi_pem_instance_info *instance_info;
};

/* Max number of possible sockets, one instance per socket */
#define	PEM_MAX_INSTANCES	16

struct tpmi_pem_common_struct {
	int max_instance_id;
	struct tpmi_pem_struct __rcu *pem_inst[PEM_MAX_INSTANCES];
};

/*
 * Lock to protect register/unregister of pem_core from the
 * client drivers.
 */
static DEFINE_MUTEX(pem_tpmi_dev_lock);

/* Usage counters to client registered with pem_core */
static int pem_core_usage_count;

/* Store all PEM instances */
static struct tpmi_pem_common_struct pem_common;

/* For CPU online/offline */
int pem_online_id;

/* Mask of CPUs representing a power domain */
static cpumask_t pem_power_domain_cpu_mask;

/* PMU struct for PEM */
static struct pmu pem_pmu;

/*
 * Similar macros are used in the other PMU drivers to create attributes.
 * Basically, it will create attributes:
 * /sys/devices/pnp_excursion_monitor/
 * ├── cpumask
 * ├── events
 * │   ├── any
 * │   ├── fast_rapl
 * ....
 * ....
 * ├── format
 * │   ├── duration
 * │   ├── event
 * │   └── frequency_threshold
 * ├── perf_event_mux_interval_ms
 */

#define EVENT_VAR(_id)		event_attr_##_id
#define EVENT_PTR(_id)		(&event_attr_##_id.attr.attr)

#define EVENT_ATTR(_name, _id)                                          \
static struct perf_pmu_events_attr EVENT_VAR(_id) = {                   \
	.attr           = __ATTR(_name, 0444, events_sysfs_show, NULL), \
	.id             = PERF_COUNT_HW_##_id,                          \
	.event_str      = NULL,                                         \
}

#define EVENT_ATTR_STR(_name, v, str)                                   \
static struct perf_pmu_events_attr event_attr_##v = {                   \
	.attr           = __ATTR(_name, 0444, events_sysfs_show, NULL), \
	.id             = 0,                                            \
	.event_str      = str,                                          \
}

#define __PMU_EVENT_GROUP(_name)			\
static struct attribute *attrs_##_name[] = {		\
	&attr_##_name.attr.attr,			\
	NULL,						\
}

#define PMU_EVENT_GROUP(_grp, _name)			\
__PMU_EVENT_GROUP(_name);				\
static struct attribute_group group_##_name = {		\
	.name  = #_grp,					\
	.attrs = attrs_##_name,				\
}

#define DEFINE_PEM_FORMAT_ATTR(_var, _name, _format)		\
static ssize_t __pem_##_var##_show(struct device *dev,	\
				struct device_attribute *attr,	\
				char *page)			\
{								\
	BUILD_BUG_ON(sizeof(_format) >= PAGE_SIZE);		\
	return sprintf(page, _format "\n");			\
}								\
static struct device_attribute format_attr_##_var =		\
	__ATTR(_name, 0444, __pem_##_var##_show, NULL)

/*
 * List of PERF excursion events. Index match the bit index of STATUS
 * register in hardware. There are reserved bits in STATUS register.
 */
enum pem_perf_events {
	PERF_PEM_PEM_ANY = 0,
	PEM_RSVD_1,
	PEM_RSVD_2,
	PEM_RSVD_3,
	PEM_RSVD_4,
	PEM_RSVD_5,
	PEM_ITBM3_0,
	PEM_SST_PP,
	PEM_PMAX,
	PEM_RSVD_9,
	PEM_FAST_RAPL,
	PEM_PKG_PL1_MSR_TPMI,
	PEM_PKG_PL1_MMIO,
	PEM_PKG_PL1_PECI,
	PEM_PKG_PL2_MSR_TPMI,
	PEM_PKG_PL2_MMIO,
	PEM_PKG_PL2_PECI,
	PEM_PSYS_PL1_MSR_TPMI,
	PEM_PSYS_PL1_MMIO,
	PEM_PSYS_PL1_PCS,
	PEM_PSYS_PL2_MSR_TPMI,
	PEM_PSYS_PL2_MMIO,
	PEM_PSYS_PL2_PECI,
	PEM_RSVD_23,
	PERF_PEM_PER_CORE_THERMAL,
	PEM_RSVD_25,
	PERF_PEM_EXT_PROCHOT,
	PERF_PEM_HOT_VR,
	PEM_RSVD_28,
	PEM_RSVD_29,
	PEM_PCS_PSTATE,
	PEM_RSVD_31,
	PERF_PEM_EVENT_MAX,
};

/* This mask is used to check unsupported event */
#define PEM_RESD_MASK (BIT(PEM_RSVD_1) | BIT(PEM_RSVD_2) | BIT(PEM_RSVD_3) |\
		       BIT(PEM_RSVD_4) | BIT(PEM_RSVD_5) | BIT(PEM_RSVD_9) |\
		       BIT(PEM_RSVD_23) | BIT(PEM_RSVD_25) | BIT(PEM_RSVD_28) |\
		       BIT(PEM_RSVD_29) | BIT(PEM_RSVD_31))

PMU_EVENT_ATTR_STRING(any, attr_pem_any, "event=0x00");
PMU_EVENT_ATTR_STRING(itbm_3, attr_pem_itbm_3, "event=0x06");
PMU_EVENT_ATTR_STRING(sst_pp, attr_pem_sst_pp, "event=0x07");
PMU_EVENT_ATTR_STRING(pmax, attr_pem_pmax, "event=0x08");
PMU_EVENT_ATTR_STRING(fast_rapl, attr_pem_fast_rapl, "event=0x0A");
PMU_EVENT_ATTR_STRING(pl1_msr_tpmi, attr_pem_pl1_msr_tpmi, "event=0x0B");
PMU_EVENT_ATTR_STRING(pl1_mmio, attr_pem_pl1_mmio, "event=0x0C");
PMU_EVENT_ATTR_STRING(pl1_peci, attr_pem_pl1_peci, "event=0x0D");
PMU_EVENT_ATTR_STRING(pl2_msr_tpmi, attr_pem_pl2_msr_tpmi, "event=0x0E");
PMU_EVENT_ATTR_STRING(pl2_mmio, attr_pem_pl2_mmio, "event=0x0F");
PMU_EVENT_ATTR_STRING(pl2_peci, attr_pem_pl2_peci, "event=0x10");
PMU_EVENT_ATTR_STRING(psys_pl1_msr_tpmi, attr_pem_psys_pl1_msr_tpmi, "event=0x11");
PMU_EVENT_ATTR_STRING(psys_pl1_mmio, attr_pem_psys_pl1_mmio, "event=0x12");
PMU_EVENT_ATTR_STRING(psys_pl1_peci, attr_pem_psys_pl1_peci, "event=0x13");
PMU_EVENT_ATTR_STRING(psys_pl2_msr_tpmi, attr_pem_psys_pl2_msr_tpmi, "event=0x14");
PMU_EVENT_ATTR_STRING(psys_pl2_mmio, attr_pem_psys_pl2_mmio, "event=0x15");
PMU_EVENT_ATTR_STRING(psys_pl2_peci, attr_pem_psys_pl2_peci, "event=0x16");
PMU_EVENT_ATTR_STRING(thermal, attr_pem_thermal, "event=0x18");
PMU_EVENT_ATTR_STRING(prochot, attr_pem_prochot, "event=0x1A");
PMU_EVENT_ATTR_STRING(hot_vr, attr_pem_hot_vr, "event=0x1B");
PMU_EVENT_ATTR_STRING(peci_pstate, attr_pem_peci_pstate, "event=0x1E");

PMU_EVENT_GROUP(events, pem_any);
PMU_EVENT_GROUP(events, pem_itbm_3);
PMU_EVENT_GROUP(events, pem_sst_pp);
PMU_EVENT_GROUP(events, pem_pmax);
PMU_EVENT_GROUP(events, pem_fast_rapl);
PMU_EVENT_GROUP(events, pem_pl1_msr_tpmi);
PMU_EVENT_GROUP(events, pem_pl1_mmio);
PMU_EVENT_GROUP(events, pem_pl1_peci);
PMU_EVENT_GROUP(events, pem_pl2_msr_tpmi);
PMU_EVENT_GROUP(events, pem_pl2_mmio);
PMU_EVENT_GROUP(events, pem_pl2_peci);
PMU_EVENT_GROUP(events, pem_psys_pl1_msr_tpmi);
PMU_EVENT_GROUP(events, pem_psys_pl1_mmio);
PMU_EVENT_GROUP(events, pem_psys_pl1_peci);
PMU_EVENT_GROUP(events, pem_psys_pl2_msr_tpmi);
PMU_EVENT_GROUP(events, pem_psys_pl2_mmio);
PMU_EVENT_GROUP(events, pem_psys_pl2_peci);
PMU_EVENT_GROUP(events, pem_thermal);
PMU_EVENT_GROUP(events, pem_prochot);
PMU_EVENT_GROUP(events, pem_hot_vr);
PMU_EVENT_GROUP(events, pem_peci_pstate);

/*
 * Scope of the control is per TPMI instance. So instead of creating storage
 * for each CPU, we can store at power_domain level. This API gives an instance
 * to get/store TPMI configuration parameters.
 */
static struct tpmi_pem_instance_info *pem_get_instance(int cpu)
{
	struct tpmi_pem_instance_info *instance;
	struct tpmi_pem_struct *pkg_instance;
	int power_domain, pkg;

	power_domain = tpmi_get_power_domain_id(cpu);
	pkg = topology_physical_package_id(cpu);

	pkg_instance = rcu_dereference(pem_common.pem_inst[pkg]);
	if (!pkg_instance)
		return NULL;

	if (!pkg_instance || power_domain >= pkg_instance->number_of_instances)
		return NULL;

	instance = &pkg_instance->instance_info[power_domain];
	if (!instance->pem_base)
		return NULL;

	return instance;
}

/* These values are from the spec */
#define PEM_VALID_TIME_WINDOW_MIN_MS	5
#define PEM_VALID_TIME_WINDOW_MAX_MS	302000

#define PEM_ENABLE_PEM_BIT	31

/* The offset and definitions are from TPMI PEM spec */
#define PEM_GENMASK_EVENT   GENMASK_ULL(6, 0)
#define PEM_GENMASK_FET     GENMASK_ULL(32, 7)
#define PEM_GENMASK_TW      GENMASK_ULL(51, 33)

static int pem_control_store(int cpu, u32 fet, u32 tm)
{
	struct tpmi_pem_instance_info *instance;
	int ret = -EIO;
	u64 val;

	if (tm < PEM_VALID_TIME_WINDOW_MIN_MS || tm > PEM_VALID_TIME_WINDOW_MAX_MS)
		return -EINVAL;

	if (!fet || fet > USHRT_MAX)
		return -EINVAL;

	fet /= 100; /* convert to ratio from MHz */

	/* tw is specified as 2.3*(2^TW) ms */
	tm = ilog2(tm * 10 / 23);
	if (tm > 17)
		return -EINVAL;

	rcu_read_lock();

	instance = pem_get_instance(cpu);
	if (!instance)
		goto control_store_unlock;

	ret = intel_tpmi_readq(instance->auxdev, (u8 __iomem *)instance->pem_base +
			       PEM_CONTROL_INDEX, &val);
	if (ret)
		goto control_store_unlock;

	val &= ~PEM_GENMASK_FET;
	val |= FIELD_PREP(PEM_GENMASK_FET, fet);

	val &= ~PEM_GENMASK_TW;
	val |= FIELD_PREP(PEM_GENMASK_TW, tm);

	ret = intel_tpmi_writeq(instance->auxdev, val, (u8 __iomem *)instance->pem_base +
				PEM_CONTROL_INDEX);

control_store_unlock:
	rcu_read_unlock();

	return ret;
}

/* Function to clear a status bit for an event */
static int pem_status_clear(int cpu, u32 bit_index)
{
	struct tpmi_pem_instance_info *instance;
	u64 val;
	int ret;

	rcu_read_lock();

	instance = pem_get_instance(cpu);
	if (!instance)
		goto status_store_unlock;

	ret = intel_tpmi_readq(instance->auxdev, (u8 __iomem *)instance->pem_base +
			       PEM_STATUS_INDEX, &val);
	if (ret)
		goto status_store_unlock;

	val &= ~BIT(bit_index);
	ret = intel_tpmi_writeq(instance->auxdev, val, (u8 __iomem *)instance->pem_base +
				PEM_STATUS_INDEX);

status_store_unlock:
	rcu_read_unlock();

	return ret;
}

static int pem_feature_enable(int cpu, unsigned int enable)
{
	struct tpmi_pem_instance_info *instance;
	int ret = -EIO;
	u64 val;

	rcu_read_lock();

	instance = pem_get_instance(cpu);
	if (!instance)
		goto enable_unlock;

	ret = intel_tpmi_readq(instance->auxdev, (u8 __iomem *)instance->pem_base +
			       PEM_CONTROL_INDEX, &val);
	if (ret)
		goto enable_unlock;

	if (enable)
		val |= BIT(PEM_ENABLE_PEM_BIT);
	else
		val &= ~BIT(PEM_ENABLE_PEM_BIT);

	ret = intel_tpmi_writeq(instance->auxdev, val, (u8 __iomem *)instance->pem_base +
				PEM_CONTROL_INDEX);

enable_unlock:
	rcu_read_unlock();

	return ret;
}

static struct attribute *attrs_empty[] = {
	NULL,
};

static struct attribute_group pkg_events_attr_group = {
	.name = "events",
	.attrs = attrs_empty,
};

DEFINE_PEM_FORMAT_ATTR(pkg_event, event, "config:0-6");
DEFINE_PEM_FORMAT_ATTR(fet, frequency_threshold, "config:7-32");
DEFINE_PEM_FORMAT_ATTR(tw, duration, "config:33-52");

static struct attribute *pkg_format_attrs[] = {
	&format_attr_pkg_event.attr,
	&format_attr_fet.attr,
	&format_attr_tw.attr,
	NULL,
};

static struct attribute_group pkg_format_attr_group = {
	.name = "format",
	.attrs = pkg_format_attrs,
};

static ssize_t cpumask_show(struct device *dev, struct device_attribute *attr,
			    char *buf);

/* cpumask returns a mask of cpus which represent each power_domain across the system */
static DEVICE_ATTR_RO(cpumask);

static struct attribute *pem_cpumask_attrs[] = {
	&dev_attr_cpumask.attr,
	NULL,
};

static struct attribute_group cpumask_attr_group = {
	.attrs = pem_cpumask_attrs,
};

static const struct attribute_group *pkg_attr_groups[] = {
	&pkg_events_attr_group,
	&pkg_format_attr_group,
	&cpumask_attr_group,
	NULL,
};

static ssize_t cpumask_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct pmu *pmu = dev_get_drvdata(dev);

	if (pmu == &pem_pmu)
		return cpumap_print_to_pagebuf(true, buf, &pem_power_domain_cpu_mask);
	else
		return 0;
}

static int pem_store_config(int cpu, struct perf_event *event)
{
	struct tpmi_pem_instance_info *instance;
	int ret = -EIO;

	rcu_read_lock();

	instance = pem_get_instance(cpu);
	if (!instance)
		goto config_store_unlock;

	if (event) {
		struct perf_event *_event = event->group_leader;

		instance->fet = FIELD_GET(PEM_GENMASK_FET, _event->attr.config);
		instance->tw  = FIELD_GET(PEM_GENMASK_TW, _event->attr.config);
		instance->owner = _event;
	} else {
		instance->owner = NULL;
	}
	ret = 0;

config_store_unlock:
	rcu_read_unlock();

	return ret;
}

static int pem_get_stored_config(int cpu, int *fet, int *tw, struct perf_event **event)
{
	struct tpmi_pem_instance_info *instance;
	int ret = -EIO;

	*fet = 0;
	*tw = 0;

	rcu_read_lock();

	instance = pem_get_instance(cpu);
	if (!instance)
		goto config_store_unlock;

	*fet = instance->fet;
	*tw = instance->tw;
	*event = instance->owner;
	ret = 0;

config_store_unlock:
	rcu_read_unlock();

	return ret;
}

/* Function to check configuration data mismatch with the group leader */
static bool validate_config(struct perf_event *event)
{
	u32 fet, tw;

	fet = FIELD_GET(PEM_GENMASK_FET, event->attr.config);
	tw = FIELD_GET(PEM_GENMASK_TW, event->attr.config);

	if (event->group_leader != event) {
		struct perf_event *_event = event->group_leader;
		u32 _fet, _tw;

		_fet = FIELD_GET(PEM_GENMASK_FET, _event->attr.config);
		_tw = FIELD_GET(PEM_GENMASK_TW, _event->attr.config);

		/* check for mismatch from the leader */
		if ((fet && _fet != fet) || (tw && _tw != tw))
			return false;

		fet = _fet;
		tw = _tw;
	}

	/* check for valid FET and TW */
	if (!fet || !tw)
		return false;

	return true;
}

static int pem_pmu_event_init(struct perf_event *event)
{
	u32 cfg = event->attr.config;
	int cpu = event->cpu;

	/* Only process of the type matches what we got from perf_pmu_register() */
	if (event->attr.type != pem_pmu.type)
		return -ENOENT;

	/* unsupported modes and filters */
	if (event->attr.sample_period) /* no sampling */
		return -EINVAL;

	if (event->cpu < 0)
		return -EINVAL;

	cfg = FIELD_GET(PEM_GENMASK_EVENT, event->attr.config);

	if (cfg >= PERF_PEM_EVENT_MAX)
		return -EINVAL;

	if (BIT(cfg) & PEM_RESD_MASK)
		return -EINVAL;

	if (!validate_config(event))
		return -EINVAL;

	if (event->pmu == &pem_pmu) {
		event->hw.event_base = cfg;
		cpu = cpumask_any_and(&pem_power_domain_cpu_mask,
				      tpmi_get_power_domain_mask(event->cpu));
	} else {
		return -ENOENT;
	}

	if (cpu >= nr_cpu_ids)
		return -ENODEV;

	event->cpu = cpu;
	event->hw.config = cfg;
	event->hw.idx = -1;

	return 0;
}

static int pmt_telem_read_counters(struct pci_dev *pci_dev, int instance, u32 guid,
				   u16 sample_id, u16 sample_count, u64 *samples)
{
	/* This function will call PMT interface function */
	return pmt_telem_read64(pci_dev, guid, 0, sample_id, sample_count, samples);
}

#define PEM_GENMASK_GUID		GENMASK_ULL(31, 0)
#define PEM_GENMASK_SAMPLE_ID		GENMASK_ULL(47, 32)
#define PEM_GENMASK_SAMPLE_COUNT	GENMASK_ULL(63, 48)

static int pem_store_pmt_pci_info(struct tpmi_pem_instance_info *instance)
{
	u16 sample_id, sample_count;
	struct pci_dev *pci_dev;
	int bus, dev, fn;
	u32 guid;
	u64 val;

	if (!instance->pmt_info_offset)
		return -EIO; /* No info offset field is available */

	val = readq((u8 __iomem *)instance->pem_base + instance->pmt_info_offset * 8);
	guid = FIELD_GET(PEM_GENMASK_GUID, val);
	sample_id = FIELD_GET(PEM_GENMASK_SAMPLE_ID, val);
	sample_count = FIELD_GET(PEM_GENMASK_SAMPLE_COUNT, val);

	bus = instance->plat_info->bus_number;
	dev = instance->plat_info->device_number;
	fn = instance->plat_info->function_number;

	pci_dev = pci_get_domain_bus_and_slot(0, bus, PCI_DEVFN(dev, fn));
	if (!pci_dev) {
		pr_err("No PCI device instance for B:%x D:%x F:%x\n", bus, dev, fn);
		return -EIO;
	}

	instance->pmt_pci_dev = pci_dev;
	instance->pmt_guid = guid;
	instance->pmt_sample_id = sample_id;
	instance->pmt_sample_count = sample_count;

	return 0;
}

static u32 pem_read_pmt_counter(struct tpmi_pem_instance_info *instance, int index)
{
	u64 counters[PERF_PEM_EVENT_MAX];
	int ret;

	if (!instance || index >= PERF_PEM_EVENT_MAX)
		return 0;

	if (!instance->pmt_pci_dev)
		return 0;

	ret = pmt_telem_read_counters(instance->pmt_pci_dev, 0, instance->pmt_guid,
				      instance->pmt_sample_id, instance->pmt_sample_count,
				      counters);
	if (ret)
		return 0;

	return counters[index];
}

static inline u64 pem_pmu_read_counter(struct perf_event *event)
{
	struct tpmi_pem_instance_info *instance;
	u64 counter = 0, val;
	int ret;

	rcu_read_lock();

	instance = pem_get_instance(event->cpu);
	if (!instance)
		goto read_counter_unlock;

	ret = intel_tpmi_readq(instance->auxdev,
			       (u8 __iomem *)instance->pem_base + PEM_STATUS_INDEX,
			       &val);
	if (ret)
		goto read_counter_unlock;

	if (val & BIT(event->hw.event_base))
		counter += pem_read_pmt_counter(instance, event->hw.event_base);

read_counter_unlock:
	rcu_read_unlock();

	return counter;
}

static void pem_pmu_event_update(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	u64 prev_raw_count, new_raw_count;

again:
	prev_raw_count = local64_read(&hwc->prev_count);
	new_raw_count = pem_pmu_read_counter(event);

	if (local64_cmpxchg(&hwc->prev_count, prev_raw_count,
			    new_raw_count) != prev_raw_count)
		goto again;

	/*
	 * Telemetry counters are not reset on enable/disable.
	 * Each counter size is 32 bit. So if overflows then
	 * need to account for that.
	 */
	if (prev_raw_count > new_raw_count) {
		local64_add((UINT_MAX - prev_raw_count) + new_raw_count, &event->count);
		return;
	}

	local64_add(new_raw_count - prev_raw_count, &event->count);
}

static void pem_pmu_event_start(struct perf_event *event, int mode)
{
	/* Reset the last excursion status */
	pem_status_clear(event->cpu, event->hw.event_base);

	local64_set(&event->hw.prev_count, pem_pmu_read_counter(event));
}

static void pem_pmu_event_stop(struct perf_event *event, int mode)
{
	pem_pmu_event_update(event);
}

static void pem_pmu_event_del(struct perf_event *event, int mode)
{
	pem_pmu_event_stop(event, PERF_EF_UPDATE);
	pem_store_config(event->cpu, NULL);
}

static int pem_pmu_event_add(struct perf_event *event, int mode)
{
	struct perf_event *owner;
	u32 _fet, _tw;
	int ret;

	ret = pem_get_stored_config(event->cpu, &_fet, &_tw, &owner);
	if (ret)
		return ret;

	if (owner && owner != event->group_leader)
		return -EBUSY;

	pem_store_config(event->cpu, event);

	if (mode & PERF_EF_START)
		pem_pmu_event_start(event, mode);

	return 0;
}

static void pem_pmu_enable(struct pmu *pmu)
{
	int cpu = raw_smp_processor_id();
	struct perf_event *owner;
	u32 fet, tw;
	int ret;

	ret = pem_get_stored_config(cpu, &fet, &tw, &owner);
	if (ret)
		return;

	ret = pem_control_store(cpu, fet, tw);
	if (ret)
		return;

	pem_feature_enable(cpu, 1);
}

static void pem_pmu_disable(struct pmu *pmu)
{
	int cpu = raw_smp_processor_id();

	pem_feature_enable(cpu, 0);
}

static const struct attribute_group *pkg_attr_update[] = {
	&group_pem_any,
	&group_pem_itbm_3,
	&group_pem_sst_pp,
	&group_pem_pmax,
	&group_pem_fast_rapl,

	&group_pem_pl1_msr_tpmi,
	&group_pem_pl1_mmio,
	&group_pem_pl1_peci,

	&group_pem_pl2_msr_tpmi,
	&group_pem_pl2_mmio,
	&group_pem_pl2_peci,

	&group_pem_psys_pl1_msr_tpmi,
	&group_pem_psys_pl1_mmio,
	&group_pem_psys_pl1_peci,

	&group_pem_psys_pl2_msr_tpmi,
	&group_pem_psys_pl2_mmio,
	&group_pem_psys_pl2_peci,

	&group_pem_thermal,
	&group_pem_prochot,
	&group_pem_hot_vr,

	&group_pem_peci_pstate,

	NULL,
};

static struct pmu pem_pmu = {
	.attr_groups	= pkg_attr_groups,
	.attr_update	= pkg_attr_update,
	.name		= "pnp_excursion_monitor",
	.task_ctx_nr	= perf_invalid_context,
	.event_init	= pem_pmu_event_init,
	.add		= pem_pmu_event_add,
	.del		= pem_pmu_event_del,
	.start		= pem_pmu_event_start,
	.stop		= pem_pmu_event_stop,
	.read		= pem_pmu_event_update,
	.pmu_enable	= pem_pmu_enable,
	.pmu_disable	= pem_pmu_disable,
	.capabilities	= PERF_PMU_CAP_NO_INTERRUPT | PERF_PMU_CAP_NO_EXCLUDE,
	.module		= THIS_MODULE,
};

/*
 * Check if exiting cpu is the designated reader for a power_domain. If so migrate the
 * events when there is a valid target available
 */
static int pem_cpu_exit(unsigned int cpu)
{
	unsigned int target;

	if (cpumask_test_and_clear_cpu(cpu, &pem_power_domain_cpu_mask)) {
		target = cpumask_any_but(tpmi_get_power_domain_mask(cpu), cpu);
		/* Migrate events if there is a valid target */
		if (target < nr_cpu_ids) {
			cpumask_set_cpu(target, &pem_power_domain_cpu_mask);
			perf_pmu_migrate_context(&pem_pmu, cpu, target);
		}
	}
	return 0;
}

static int pem_cpu_init(unsigned int cpu)
{
	unsigned int target;

	/*
	 * If this is the first online thread of that power_domain, set it
	 * in the power_domain cpu mask as the designated reader.
	 */
	target = cpumask_any_and(&pem_power_domain_cpu_mask,
				 tpmi_get_power_domain_mask(cpu));
	if (target >= nr_cpu_ids)
		cpumask_set_cpu(cpu, &pem_power_domain_cpu_mask);

	return 0;
}

#define PEM_AUTO_SUSPEND_DELAY_MS	2000
#define PEM_GENMASK_VERSION		GENMASK(7, 0)
#define PEM_GENMASK_PMT_OFFSET		GENMASK(7, 0)

int tpmi_pem_dev_add(struct auxiliary_device *auxdev)
{
	struct intel_tpmi_plat_info *plat_info;
	struct tpmi_pem_struct *tpmi_pem;
	int i, pkg = 0, inst = 0;
	int num_resources;

	plat_info = tpmi_get_platform_data(auxdev);
	if (!plat_info) {
		dev_info(&auxdev->dev, "No platform info\n");
		return -EINVAL;
	}

	pkg = plat_info->package_id;
	if (pkg >= PEM_MAX_INSTANCES) {
		dev_info(&auxdev->dev, "Invalid package id :%d\n", pkg);
		return -EINVAL;
	}

	if (pem_common.pem_inst[pkg])
		return -EEXIST;

	num_resources = tpmi_get_resource_count(auxdev);
	dev_dbg(&auxdev->dev, "Number of resources:%x\n", num_resources);

	if (!num_resources)
		return -EINVAL;

	tpmi_pem = devm_kzalloc(&auxdev->dev, sizeof(*tpmi_pem), GFP_KERNEL);
	if (!tpmi_pem)
		return -ENOMEM;

	tpmi_pem->instance_info = devm_kcalloc(&auxdev->dev, num_resources,
					       sizeof(*tpmi_pem->instance_info),
					       GFP_KERNEL);
	if (!tpmi_pem->instance_info)
		return -ENOMEM;

	tpmi_pem->number_of_instances = num_resources;

	if (plat_info)
		pkg = plat_info->package_id;

	tpmi_pem->pkg_id = pkg;

	for (i = 0; i < num_resources; ++i) {
		struct resource *res;
		int pem_header_ver;
		u32 val;

		res = tpmi_get_resource_at_index(auxdev, i);
		if (!res)
			continue;

		tpmi_pem->instance_info[i].pem_base = devm_ioremap_resource(&auxdev->dev, res);
		if (IS_ERR(tpmi_pem->instance_info[i].pem_base))
			return PTR_ERR(tpmi_pem->instance_info[i].pem_base);

		val = readl(tpmi_pem->instance_info[i].pem_base);

		pem_header_ver = val & PEM_GENMASK_VERSION;
		if (pem_header_ver != PEM_HEADER_VERSION) {
			dev_err(&auxdev->dev, "PEM: Unsupported version:%d at index:%d\n", pem_header_ver, i);
			devm_iounmap(&auxdev->dev, tpmi_pem->instance_info[i].pem_base);
			tpmi_pem->instance_info[i].pem_base = NULL;
			continue;
		}

		tpmi_pem->instance_info[i].pmt_info_offset = FIELD_GET(PEM_GENMASK_PMT_OFFSET, val);
		tpmi_pem->instance_info[i].power_domain = i;
		tpmi_pem->instance_info[i].plat_info = plat_info;
		tpmi_pem->instance_info[i].auxdev = auxdev;

		pem_store_pmt_pci_info(&tpmi_pem->instance_info[i]);

		++inst;
	}

	if (!inst)
		return -ENODEV;

	auxiliary_set_drvdata(auxdev, tpmi_pem);

	mutex_lock(&pem_tpmi_dev_lock);
	rcu_assign_pointer(pem_common.pem_inst[pkg], tpmi_pem);

	if (pem_common.max_instance_id < pkg)
		pem_common.max_instance_id = pkg;
	mutex_unlock(&pem_tpmi_dev_lock);

	pm_runtime_set_active(&auxdev->dev);
	pm_runtime_set_autosuspend_delay(&auxdev->dev, PEM_AUTO_SUSPEND_DELAY_MS);
	pm_runtime_use_autosuspend(&auxdev->dev);
	pm_runtime_enable(&auxdev->dev);
	pm_runtime_mark_last_busy(&auxdev->dev);
	/*
	 * All perf PMU callbacks are called with IRQs disabled.
	 * Also don't expect to call any function which can sleep
	 * under rcu read locks. Otherwise warning is printed for this.
	 * But pm_runtime_resume_and_get() and  pm_runtime_get_sync()
	 * calls can sleep. To read MMIO we have to wake OOBMSM PCI
	 * device as it can be put to sleep.
	 * Still trying to see if I can remove the call below.
	 */
	pm_runtime_irq_safe(&auxdev->dev);

	return 0;
}
EXPORT_SYMBOL_NS_GPL(tpmi_pem_dev_add, INTEL_TPMI_PEM);

void tpmi_pem_dev_remove(struct auxiliary_device *auxdev)
{
	struct tpmi_pem_struct *tpmi_pem = auxiliary_get_drvdata(auxdev);

	mutex_lock(&pem_tpmi_dev_lock);
	RCU_INIT_POINTER(pem_common.pem_inst[tpmi_pem->pkg_id], NULL);
	mutex_unlock(&pem_tpmi_dev_lock);

	synchronize_rcu();

	pm_runtime_disable(&auxdev->dev);
}
EXPORT_SYMBOL_NS_GPL(tpmi_pem_dev_remove, INTEL_TPMI_PEM);

int tpmi_pem_pmu_init(void)
{
	int ret = 0;

	mutex_lock(&pem_tpmi_dev_lock);

	if (pem_core_usage_count) {
		++pem_core_usage_count;
		goto init_done;
	}

	pem_online_id = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "perf/x86/pem:online",
					  pem_cpu_init, pem_cpu_exit);
	ret = perf_pmu_register(&pem_pmu, pem_pmu.name, -1);
	if (ret) {
		cpuhp_remove_state(pem_online_id);
		goto init_done;
	}

	++pem_core_usage_count;

init_done:
	mutex_unlock(&pem_tpmi_dev_lock);

	return ret;
}
EXPORT_SYMBOL_NS_GPL(tpmi_pem_pmu_init, INTEL_TPMI_PEM);

void tpmi_pem_pmu_exit(void)
{
	mutex_lock(&pem_tpmi_dev_lock);

	if (pem_core_usage_count)
		--pem_core_usage_count;

	if (!pem_core_usage_count) {
		cpuhp_remove_state(pem_online_id);
		perf_pmu_unregister(&pem_pmu);
	}

	mutex_unlock(&pem_tpmi_dev_lock);
}
EXPORT_SYMBOL_NS_GPL(tpmi_pem_pmu_exit, INTEL_TPMI_PEM);

MODULE_IMPORT_NS(INTEL_TPMI);
MODULE_IMPORT_NS(INTEL_TPMI_POWER_DOMAIN);

MODULE_LICENSE("GPL");
