// SPDX-License-Identifier: GPL-2.0
/*
 * intel-rapl-tpmi: Intel RAPL driver via TPMI interface
 *
 * Copyright (c) 2022, Intel Corporation.
 * All Rights Reserved.
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/auxiliary_bus.h>
#include <linux/io.h>
#include <linux/intel_tpmi.h>
#include <linux/intel_rapl.h>
#include <linux/module.h>
#include <linux/nospec.h>
#include <linux/perf_event.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>

/* 1 header, 10 registers, 5 reserved. 8 bytes for each */
#define TPMI_RAPL_DOMAIN_SIZE 128

enum tpmi_rapl_domain_type {
	TPMI_RAPL_DOMAIN_INVALID,
	TPMI_RAPL_DOMAIN_SYSTEM,
	TPMI_RAPL_DOMAIN_PACKAGE,
	TPMI_RAPL_DOMAIN_RESERVED,
	TPMI_RAPL_DOMAIN_MEMORY = 4,
	TPMI_RAPL_DOMAIN_MAX,
};

enum tpmi_rapl_register {
	TPMI_RAPL_REG_HEADER,
	TPMI_RAPL_REG_UNIT,
	TPMI_RAPL_REG_PL1,
	TPMI_RAPL_REG_PL2,
	TPMI_RAPL_REG_PL3,
	TPMI_RAPL_REG_PL4,
	TPMI_RAPL_REG_RESERVED,
	TPMI_RAPL_REG_ENERGY_STATUS,
	TPMI_RAPL_REG_PERF_STATUS,
	TPMI_RAPL_REG_POWER_INFO,
	TPMI_RAPL_REG_INTERRUPT,
	TPMI_RAPL_REG_MAX = 15,
};

struct pmu_info {
	raw_spinlock_t lock;
	int n_active;
	int cpu;
	struct list_head active_list;
	ktime_t timer_interval;
	struct hrtimer hrtimer;
	bool initialized;
};

struct tpmi_rapl_package {
	struct rapl_if_priv priv;
	struct intel_tpmi_plat_info *tpmi_info;
	struct rapl_package *rp;
	struct auxiliary_device *auxdev;
	void __iomem *base;
	u8 energy_units[RAPL_DOMAIN_MAX];
	struct pmu_info *pmu_info;
};

struct tpmi_rapl_package **tpmi_rapl_packages;

static struct powercap_control_type *tpmi_control_type;

static DEFINE_MUTEX(tpmi_rapl_lock);

static int tpmi_rapl_count;

/* For CPU online/offline */
int rapl_online_id;

/* Mask of CPUs representing a RAPL package, aka, CPU package */
static cpumask_t rapl_cpu_mask;

static struct pmu tpmi_rapl_pmu;

static inline int event_to_domain(struct perf_event *event,
				  struct tpmi_rapl_package *trp)
{
	int domain;

	switch (event->attr.config) {
	case 1:
		domain = RAPL_DOMAIN_PACKAGE;
		break;
	case 2:
		domain = RAPL_DOMAIN_DRAM;
		break;
	case 3:
		domain = RAPL_DOMAIN_PLATFORM;
		break;
	default:
		return -EINVAL;
	}

	/* Check for invalid domains */
	if (trp->priv.regs[domain][RAPL_DOMAIN_REG_STATUS])
		return domain;
	return -EINVAL;
}

static inline u64 rapl_pmu_read_counter(struct perf_event *event)
{
	unsigned int id = topology_physical_package_id(event->cpu);
	struct tpmi_rapl_package *trp = tpmi_rapl_packages[id];
	u64 val;

	if (!trp || !trp->auxdev)
		return 0;

	if (intel_tpmi_readq(trp->auxdev,
			     (u8 __iomem *) trp->priv.regs[event->hw.
							   config]
			     [RAPL_DOMAIN_REG_STATUS], &val))
		return 0;

	return val;
}

static inline u64 rapl_scale(u64 v, struct perf_event *event)
{
	unsigned int id = topology_physical_package_id(event->cpu);
	struct tpmi_rapl_package *trp = tpmi_rapl_packages[id];

	if (!trp || !trp->auxdev)
		return -ENODEV;

	/*
	 * scale delta to smallest unit (1/2^32)
	 * users must then scale back: count * 1/(1e9*2^32) to get Joules
	 * or use ldexp(count, -32).
	 * Watts = Joules/Time delta
	 */
	return v << (32 - trp->energy_units[event->hw.config]);
}

#define RAPL_EVENT_MASK 0xFFULL
#define RAPL_CNTR_WIDTH 32

static u64 rapl_event_update(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	u64 prev_raw_count, new_raw_count;
	s64 delta, sdelta;
	int shift = RAPL_CNTR_WIDTH;

again:
	prev_raw_count = local64_read(&hwc->prev_count);
	new_raw_count = rapl_pmu_read_counter(event);

	if (local64_cmpxchg(&hwc->prev_count, prev_raw_count,
			    new_raw_count) != prev_raw_count) {
		cpu_relax();
		goto again;
	}

	/*
	 * Now we have the new raw value and have updated the prev
	 * timestamp already. We can now calculate the elapsed delta
	 * (event-)time and add that to the generic event.
	 *
	 * Careful, not all hw sign-extends above the physical width
	 * of the count.
	 */
	delta = (new_raw_count << shift) - (prev_raw_count << shift);
	delta >>= shift;

	sdelta = rapl_scale(delta, event);

	local64_add(sdelta, &event->count);

	return new_raw_count;
}

static void rapl_start_hrtimer(struct pmu_info *pmu)
{
	hrtimer_start(&pmu->hrtimer, pmu->timer_interval,
		      HRTIMER_MODE_REL_PINNED);
}

static enum hrtimer_restart rapl_hrtimer_handle(struct hrtimer *hrtimer)
{
	struct pmu_info *pmu = container_of(hrtimer, struct pmu_info, hrtimer);
	struct perf_event *event;
	unsigned long flags;

	if (!pmu->n_active)
		return HRTIMER_NORESTART;

	raw_spin_lock_irqsave(&pmu->lock, flags);

	list_for_each_entry(event, &pmu->active_list, active_entry)
	    rapl_event_update(event);

	raw_spin_unlock_irqrestore(&pmu->lock, flags);

	hrtimer_forward_now(hrtimer, pmu->timer_interval);

	return HRTIMER_RESTART;
}

static void rapl_hrtimer_init(struct pmu_info *pmu)
{
	struct hrtimer *hr = &pmu->hrtimer;

	hrtimer_init(hr, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hr->function = rapl_hrtimer_handle;
}

static void __rapl_pmu_event_start(struct pmu_info *pmu,
				   struct perf_event *event)
{
	if (WARN_ON_ONCE(!(event->hw.state & PERF_HES_STOPPED)))
		return;

	event->hw.state = 0;

	list_add_tail(&event->active_entry, &pmu->active_list);

	local64_set(&event->hw.prev_count, rapl_pmu_read_counter(event));

	pmu->n_active++;
	if (pmu->n_active == 1)
		rapl_start_hrtimer(pmu);
}

static void rapl_pmu_event_start(struct perf_event *event, int mode)
{
	struct pmu_info *pmu = event->pmu_private;
	unsigned long flags;

	raw_spin_lock_irqsave(&pmu->lock, flags);
	__rapl_pmu_event_start(pmu, event);
	raw_spin_unlock_irqrestore(&pmu->lock, flags);
}

static void rapl_pmu_event_stop(struct perf_event *event, int mode)
{
	struct pmu_info *pmu = event->pmu_private;
	struct hw_perf_event *hwc = &event->hw;
	unsigned long flags;

	raw_spin_lock_irqsave(&pmu->lock, flags);

	/* mark event as deactivated and stopped */
	if (!(hwc->state & PERF_HES_STOPPED)) {
		WARN_ON_ONCE(pmu->n_active <= 0);
		pmu->n_active--;
		if (pmu->n_active == 0)
			hrtimer_cancel(&pmu->hrtimer);

		list_del(&event->active_entry);

		WARN_ON_ONCE(hwc->state & PERF_HES_STOPPED);
		hwc->state |= PERF_HES_STOPPED;
	}

	/* check if update of sw counter is necessary */
	if ((mode & PERF_EF_UPDATE) && !(hwc->state & PERF_HES_UPTODATE)) {
		/*
		 * Drain the remaining delta count out of a event
		 * that we are disabling:
		 */
		rapl_event_update(event);
		hwc->state |= PERF_HES_UPTODATE;
	}

	raw_spin_unlock_irqrestore(&pmu->lock, flags);
}

static int rapl_pmu_event_add(struct perf_event *event, int mode)
{
	struct pmu_info *pmu = event->pmu_private;
	struct hw_perf_event *hwc = &event->hw;
	unsigned long flags;

	raw_spin_lock_irqsave(&pmu->lock, flags);

	hwc->state = PERF_HES_UPTODATE | PERF_HES_STOPPED;

	if (mode & PERF_EF_START)
		__rapl_pmu_event_start(pmu, event);

	raw_spin_unlock_irqrestore(&pmu->lock, flags);

	return 0;
}

static void rapl_pmu_event_del(struct perf_event *event, int flags)
{
	rapl_pmu_event_stop(event, PERF_EF_UPDATE);
}

static int rapl_pmu_event_init(struct perf_event *event)
{
	unsigned int id;
	struct tpmi_rapl_package *trp;
	int domain;

	/* only look at RAPL events */
	if (event->attr.type != tpmi_rapl_pmu.type)
		return -ENOENT;

	/* check only supported bits are set */
	if (event->attr.config & ~RAPL_EVENT_MASK)
		return -EINVAL;

	if (event->cpu < 0)
		return -EINVAL;

	id = topology_physical_package_id(event->cpu);
	trp = tpmi_rapl_packages[id];
	if (!trp)
		return -ENODEV;

	/* RAPL Package is not ready yet */
	if (!trp->pmu_info)
		return -ENODEV;

	event->event_caps |= PERF_EV_CAP_READ_ACTIVE_PKG;

	domain = event_to_domain(event, trp);
	if (domain < 0)
		return -EINVAL;

	/* unsupported modes and filters */
	if (event->attr.sample_period)	/* no sampling */
		return -EINVAL;

	event->cpu =
	    cpumask_any_and(&rapl_cpu_mask, topology_core_cpumask(event->cpu));
	if (event->cpu >= nr_cpu_ids)
		return -ENODEV;
	event->pmu_private = trp->pmu_info;
	event->hw.config = domain;
	event->hw.idx = event->attr.config - 1;

	return 0;
}

static void rapl_pmu_event_read(struct perf_event *event)
{
	rapl_event_update(event);
}

static ssize_t rapl_get_attr_cpumask(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	return cpumap_print_to_pagebuf(true, buf, &rapl_cpu_mask);
}

static DEVICE_ATTR(cpumask, S_IRUGO, rapl_get_attr_cpumask, NULL);

static struct attribute *rapl_pmu_attrs[] = {
	&dev_attr_cpumask.attr,
	NULL,
};

static struct attribute_group rapl_pmu_attr_group = {
	.attrs = rapl_pmu_attrs,
};

#define RAPL_EVENT_ATTR_STR(_name, v, str)					\
static struct perf_pmu_events_attr event_attr_##v = {				\
	.attr		= __ATTR(_name, 0444, perf_event_sysfs_show, NULL),	\
	.id		= 0,							\
	.event_str	= str,							\
};

#define EVENT_PTR(_id)          (&event_attr_##_id.attr.attr)

RAPL_EVENT_ATTR_STR(energy-pkg, rapl_pkg, "event=0x01");
RAPL_EVENT_ATTR_STR(energy-ram, rapl_ram, "event=0x02");
RAPL_EVENT_ATTR_STR(energy-psys, rapl_psys, "event=0x03");

RAPL_EVENT_ATTR_STR(energy-pkg.unit, rapl_pkg_unit, "Joules");
RAPL_EVENT_ATTR_STR(energy-ram.unit, rapl_ram_unit, "Joules");
RAPL_EVENT_ATTR_STR(energy-psys.unit, rapl_psys_unit, "Joules");

/*
 * we compute in 0.23 nJ increments regardless of MSR
 */
RAPL_EVENT_ATTR_STR(energy-pkg.scale, rapl_pkg_scale, "2.3283064365386962890625e-10");
RAPL_EVENT_ATTR_STR(energy-ram.scale, rapl_ram_scale, "2.3283064365386962890625e-10");
RAPL_EVENT_ATTR_STR(energy-psys.scale, rapl_psys_scale, "2.3283064365386962890625e-10");

/*
 * There are no default events, but we need to create
 * "events" group (with empty attrs) before updating
 * it with detected events.
 */
static struct attribute *attrs_empty[] = {
	NULL,
};

static struct attribute_group rapl_pmu_events_group = {
	.name = "events",
	.attrs = attrs_empty,
};

PMU_FORMAT_ATTR(event, "config:0-7");
static struct attribute *rapl_formats_attr[] = {
	&format_attr_event.attr,
	NULL,
};

static struct attribute_group rapl_pmu_format_group = {
	.name = "format",
	.attrs = rapl_formats_attr,
};

static const struct attribute_group *rapl_attr_groups[] = {
	&rapl_pmu_attr_group,
	&rapl_pmu_format_group,
	&rapl_pmu_events_group,
	NULL,
};

static struct attribute *rapl_events_pkg[] = {
	EVENT_PTR(rapl_pkg),
	EVENT_PTR(rapl_pkg_unit),
	EVENT_PTR(rapl_pkg_scale),
	NULL,
};

static struct attribute_group rapl_events_pkg_group = {
	.name = "events",
	.attrs = rapl_events_pkg,
};

static struct attribute *rapl_events_ram[] = {
	EVENT_PTR(rapl_ram),
	EVENT_PTR(rapl_ram_unit),
	EVENT_PTR(rapl_ram_scale),
	NULL,
};

static struct attribute_group rapl_events_ram_group = {
	.name = "events",
	.attrs = rapl_events_ram,
};

static struct attribute *rapl_events_psys[] = {
	EVENT_PTR(rapl_psys),
	EVENT_PTR(rapl_psys_unit),
	EVENT_PTR(rapl_psys_scale),
	NULL,
};

static struct attribute_group rapl_events_psys_group = {
	.name = "events",
	.attrs = rapl_events_psys,
};

static const struct attribute_group *rapl_attr_update[] = {
	&rapl_events_pkg_group,
	&rapl_events_ram_group,
	&rapl_events_psys_group,
	NULL,
};

static struct pmu tpmi_rapl_pmu = {
	.attr_groups = rapl_attr_groups,
	.attr_update = rapl_attr_update,
	.name = "tpmi_rapl",
	.task_ctx_nr = perf_invalid_context,
	.event_init = rapl_pmu_event_init,
	.add = rapl_pmu_event_add,
	.del = rapl_pmu_event_del,
	.start = rapl_pmu_event_start,
	.stop = rapl_pmu_event_stop,
	.read = rapl_pmu_event_read,
	.capabilities = PERF_PMU_CAP_NO_INTERRUPT | PERF_PMU_CAP_NO_EXCLUDE,
	.module = THIS_MODULE,
};

#define ENERGY_UNIT_SHIFT	0x6
#define ENERGY_UNIT_MASK	0x1F
static int rapl_init_energy_units(struct tpmi_rapl_package *trp)
{
	u64 val;
	enum rapl_domain_type domain;
	int ret;

	for (domain = RAPL_DOMAIN_PACKAGE; domain < RAPL_DOMAIN_MAX; domain++) {
		if (!trp->priv.regs[domain][RAPL_DOMAIN_REG_STATUS])
			continue;
		ret = intel_tpmi_readq(trp->auxdev,
				       (u8 __iomem *) trp->priv.
				       regs[domain][RAPL_DOMAIN_REG_UNIT],
				       &val);
		if (!ret)
			trp->energy_units[domain] =
			    (val >> ENERGY_UNIT_SHIFT) & ENERGY_UNIT_MASK;
	}

	/*
	 * Calculate the timer rate:
	 * Use reference of 200W for scaling the timeout to avoid counter
	 * overflows. 200W = 200 Joules/sec
	 * Divide interval by 2 to avoid lockstep (2 * 100)
	 * if hw unit is 32, then we use 2 ms 1/200/2
	 */
	ret = 2;
	if (trp->energy_units[0] < 32) {
		ret = (1000 / (2 * 100));
		ret *= (1ULL << (32 - trp->energy_units[0] - 1));
	}
	return ret;
}

/*
 * Check if exiting cpu is the designated reader for a power_domain. If so migrate the
 * events when there is a valid target available
 */
static int rapl_pmu_cpu_offline(unsigned int cpu)
{
	unsigned int target;

	if (cpumask_test_and_clear_cpu(cpu, &rapl_cpu_mask)) {
		target = cpumask_any_but(topology_core_cpumask(cpu), cpu);
		/* Migrate events if there is a valid target */
		if (target < nr_cpu_ids) {
			cpumask_set_cpu(target, &rapl_cpu_mask);
			perf_pmu_migrate_context(&tpmi_rapl_pmu, cpu, target);
		}
	}
	return 0;
}

static int rapl_pmu_cpu_online(unsigned int cpu)
{
	unsigned int target;

	/*
	 * If this is the first online thread of that package, set it in the
	 * power_domain cpu mask as the designated reader.
	 */
	target = cpumask_any_and(&rapl_cpu_mask, topology_core_cpumask(cpu));
	if (target >= nr_cpu_ids)
		cpumask_set_cpu(cpu, &rapl_cpu_mask);

	return 0;
}

static int tpmi_rapl_add_package(struct auxiliary_device *auxdev,
				 struct tpmi_rapl_package *trp)
{
	int cpu;

	/* TPMI RAPL I/F is package scope */
	for_each_present_cpu(cpu) {
		int id = topology_physical_package_id(cpu);

		if (id != trp->tpmi_info->package_id)
			continue;

		trp->rp = rapl_find_package_domain(cpu, &trp->priv);
		if (trp->rp) {
			dev_err(&auxdev->dev,
				"RAPL Domain for Package%d already exists\n",
				id);
			return -EINVAL;
		}

		/*
		 * Must set auxdevice before registering RAPL package
		 * in order to make .read_raw/.write_raw callbacks functional
		 */
		tpmi_rapl_packages[id] = trp;
		trp->auxdev = auxdev;
		trp->rp = rapl_add_package(cpu, &trp->priv);
		if (IS_ERR(trp->rp)) {
			dev_err(&auxdev->dev,
				"Failed to add RAPL Domain for Package%d, %ld\n",
				id, PTR_ERR(trp->rp));
			tpmi_rapl_packages[id] = NULL;
			trp->auxdev = NULL;
			return PTR_ERR(trp->rp);
		}
		return 0;
	}

	dev_err(&auxdev->dev, "No CPU on Package%d\n",
		trp->tpmi_info->package_id);
	return -ENODEV;
}

static int tpmi_rapl_pmu_init(struct tpmi_rapl_package *trp)
{
	int rapl_timer_ms;

	trp->pmu_info = kzalloc(sizeof(struct pmu_info), GFP_KERNEL);
	if (!trp->pmu_info)
		return -ENOMEM;
	/* Initialize for TPMI RAPL PMU */
	raw_spin_lock_init(&trp->pmu_info->lock);
	INIT_LIST_HEAD(&trp->pmu_info->active_list);

	/* Must be done after rapl_add_package() */
	rapl_timer_ms = rapl_init_energy_units(trp);
	trp->pmu_info->timer_interval = ms_to_ktime(rapl_timer_ms);
	rapl_hrtimer_init(trp->pmu_info);
	return 0;
}

static void tpmi_rapl_pmu_exit(struct tpmi_rapl_package *trp)
{
	kfree(trp->pmu_info);
}

static int tpmi_rapl_add(struct auxiliary_device *auxdev,
			 struct tpmi_rapl_package *trp)
{
	int ret;

	mutex_lock(&tpmi_rapl_lock);

	if (!tpmi_rapl_count) {
		tpmi_control_type =
		    powercap_register_control_type(NULL, "intel-rapl-tpmi",
						   NULL);
		if (IS_ERR(tpmi_control_type)) {
			ret = PTR_ERR(tpmi_control_type);
			pr_err
			    ("failed to register powercap control_type, %d.\n",
			     ret);
			goto out;
		}

	}

	trp->priv.control_type = tpmi_control_type;

	ret = tpmi_rapl_add_package(auxdev, trp);
	if (ret)
		goto unregister_control_type;

	ret = tpmi_rapl_pmu_init(trp);
	if (ret)
		goto unregister_rapl_package;

	if (!tpmi_rapl_count) {
		ret =
		    cpuhp_setup_state(CPUHP_AP_PERF_X86_RAPL_ONLINE,
				      "perf/x86/rapl:online",
				      rapl_pmu_cpu_online,
				      rapl_pmu_cpu_offline);
		if (ret)
			goto unregister_rapl_pmu;

		ret = perf_pmu_register(&tpmi_rapl_pmu, tpmi_rapl_pmu.name, -1);
		if (ret)
			goto remove_cpuhp_state;
	}

	++tpmi_rapl_count;
	goto out;

remove_cpuhp_state:
	cpuhp_remove_state(CPUHP_AP_PERF_X86_RAPL_ONLINE);
unregister_rapl_pmu:
	tpmi_rapl_pmu_exit(trp);
unregister_rapl_package:
	rapl_remove_package(trp->rp);
unregister_control_type:
	if (!tpmi_rapl_count)
		powercap_unregister_control_type(tpmi_control_type);
out:
	mutex_unlock(&tpmi_rapl_lock);

	return ret;
}

static void tpmi_rapl_remove(struct tpmi_rapl_package *trp)
{
	mutex_lock(&tpmi_rapl_lock);

	rapl_remove_package(trp->rp);

	if (tpmi_rapl_count)
		--tpmi_rapl_count;

	if (!tpmi_rapl_count) {
		cpuhp_remove_state_nocalls(CPUHP_AP_PERF_X86_RAPL_ONLINE);
		perf_pmu_unregister(&tpmi_rapl_pmu);
		powercap_unregister_control_type(tpmi_control_type);
	}

	tpmi_rapl_pmu_exit(trp);

	mutex_unlock(&tpmi_rapl_lock);
}

static int tpmi_rapl_read_raw(int cpu, struct reg_action *ra)
{
	unsigned int id = topology_physical_package_id(cpu);
	struct tpmi_rapl_package *trp = tpmi_rapl_packages[id];
	int ret;

	if (!ra->reg || !trp->auxdev)
		return -EINVAL;

	ret =
	    intel_tpmi_readq(trp->auxdev, (void __iomem *)ra->reg, &ra->value);
	if (ret)
		return ret;

	pr_debug("Read 0x%llx at 0x%llx, with mask 0x%llx\n", ra->value,
		 ra->reg, ra->mask);
	ra->value &= ra->mask;
	return 0;
}

static int tpmi_rapl_write_raw(int cpu, struct reg_action *ra)
{
	unsigned int id = topology_physical_package_id(cpu);
	struct tpmi_rapl_package *trp = tpmi_rapl_packages[id];
	u64 val;
	int ret;

	if (!ra->reg || !trp->auxdev)
		return -EINVAL;

	ret = intel_tpmi_readq(trp->auxdev, (void __iomem *)ra->reg, &val);
	if (ret)
		return ret;

	val &= ~ra->mask;
	val |= ra->value;
	intel_tpmi_writeq(trp->auxdev, val, (void __iomem *)ra->reg);
	pr_info("Write 0x%llx at 0x%llx\n", val, ra->reg);
	return 0;
}

static int intel_rapl_tpmi_probe(struct auxiliary_device *auxdev,
				 const struct auxiliary_device_id *id)
{
	struct tpmi_rapl_package *trp;
	struct resource *res;
	int ret;
	u32 offset = 0;

	if (tpmi_get_resource_count(auxdev) > 1) {
		dev_err(&auxdev->dev, "does not support multiple resources\n");
		return -EINVAL;
	}

	res = tpmi_get_resource_at_index(auxdev, 0);
	if (!res) {
		dev_err(&auxdev->dev, "can't fetch device resource info\n");
		return -EIO;
	}

	trp = devm_kzalloc(&auxdev->dev, sizeof(*trp), GFP_KERNEL);
	if (!trp)
		return -ENOMEM;

	trp->base = devm_ioremap_resource(&auxdev->dev, res);
	if (!trp->base)
		return -ENOMEM;

	while (offset < resource_size(res)) {
		enum rapl_domain_type domain_type;
		enum tpmi_rapl_domain_type tpmi_domain_type;
		enum tpmi_rapl_register reg_index;
		enum rapl_domain_reg_id reg_id;
		int tpmi_domain_size, tpmi_domain_flags;
		u64 *tpmi_rapl_regs = trp->base + offset;
		u64 tpmi_domain_header = readq((void __iomem *)tpmi_rapl_regs);

		/* Domain Version and Parent bits are ignored for now */
		tpmi_domain_type = tpmi_domain_header >> 8 & 0xff;
		tpmi_domain_size = tpmi_domain_header >> 16 & 0xff;
		tpmi_domain_flags = tpmi_domain_header >> 32 & 0xffff;
		pr_info("Read Domain header: 0x%llx\n", tpmi_domain_header);
		pr_info("Read Domain type %d, size %d, flags 0x%x\n",
			tpmi_domain_type, tpmi_domain_size, tpmi_domain_flags);

		offset += TPMI_RAPL_DOMAIN_SIZE;
		/* Domain size: in unit of 128 Bytes */
		if (tpmi_domain_size != 1) {
			dev_err(&auxdev->dev,
				"Invalid TPMI RAPL Domain size %d\n",
				tpmi_domain_size);
			continue;
		}

		if (!(tpmi_domain_flags & BIT(TPMI_RAPL_REG_UNIT)) ||
		    !(tpmi_domain_flags & BIT(TPMI_RAPL_REG_ENERGY_STATUS))) {
			dev_err(&auxdev->dev,
				"Invalid TPMI RAPL Domain registers supported, 0x%x\n",
				tpmi_domain_flags);
			continue;
		}

		switch (tpmi_domain_type) {
		case TPMI_RAPL_DOMAIN_PACKAGE:
			domain_type = RAPL_DOMAIN_PACKAGE;
			break;
		case TPMI_RAPL_DOMAIN_SYSTEM:
			domain_type = RAPL_DOMAIN_PLATFORM;
			break;
		case TPMI_RAPL_DOMAIN_MEMORY:
			domain_type = RAPL_DOMAIN_DRAM;
			break;
		default:
			dev_warn(&auxdev->dev,
				 "Unsupported TPMI RAPL Domain type %d\n",
				 tpmi_domain_type);
			continue;
		}

		reg_index = TPMI_RAPL_REG_HEADER;
		while (++reg_index != TPMI_RAPL_REG_MAX) {
			if (!(tpmi_domain_flags & BIT(reg_index)))
				continue;

			switch (reg_index) {
			case TPMI_RAPL_REG_UNIT:
				reg_id = RAPL_DOMAIN_REG_UNIT;
				break;
			case TPMI_RAPL_REG_PL1:
				reg_id = RAPL_DOMAIN_REG_LIMIT;
				trp->priv.limits[domain_type] |=
				    BIT(POWER_LIMIT1);
				break;
			case TPMI_RAPL_REG_PL2:
				reg_id = RAPL_DOMAIN_REG_PL2;
				trp->priv.limits[domain_type] |=
				    BIT(POWER_LIMIT2);
				break;
			case TPMI_RAPL_REG_PL4:
				reg_id = RAPL_DOMAIN_REG_PL4;
				trp->priv.limits[domain_type] |=
				    BIT(POWER_LIMIT4);
				break;
			case TPMI_RAPL_REG_ENERGY_STATUS:
				reg_id = RAPL_DOMAIN_REG_STATUS;
				break;
			case TPMI_RAPL_REG_PERF_STATUS:
				reg_id = RAPL_DOMAIN_REG_PERF;
				break;
			case TPMI_RAPL_REG_POWER_INFO:
				reg_id = RAPL_DOMAIN_REG_INFO;
				break;
			default:
				reg_id = RAPL_DOMAIN_REG_MAX;
				break;
			}

			if (reg_id != RAPL_DOMAIN_REG_MAX)
				trp->priv.regs[domain_type][reg_id] =
				    (u64)&tpmi_rapl_regs[reg_index];
		}
	}

	trp->tpmi_info = tpmi_get_platform_data(auxdev);
	trp->priv.type = RAPL_IF_TPMI;
	trp->priv.read_raw = tpmi_rapl_read_raw;
	trp->priv.write_raw = tpmi_rapl_write_raw;

	/*
	 * Enable Runtime PM earlier in order to access the TPMI registers
	 * when registering a RAPL Package.
	 */
	pm_runtime_set_active(&auxdev->dev);
	pm_runtime_set_autosuspend_delay(&auxdev->dev, 2000);
	pm_runtime_use_autosuspend(&auxdev->dev);
	pm_runtime_enable(&auxdev->dev);
	pm_runtime_mark_last_busy(&auxdev->dev);

	ret = tpmi_rapl_add(auxdev, trp);
	if (ret)
		goto err;

	auxiliary_set_drvdata(auxdev, trp);
	return 0;

err:
	pm_runtime_disable(&auxdev->dev);
	return ret;
}

static void intel_rapl_tpmi_remove(struct auxiliary_device *auxdev)
{
	struct tpmi_rapl_package *trp = auxiliary_get_drvdata(auxdev);

	tpmi_rapl_remove(trp);
	tpmi_rapl_packages[trp->tpmi_info->package_id] = NULL;

	pm_runtime_disable(&auxdev->dev);
}

static const struct auxiliary_device_id intel_rapl_id_table[] = {
	{.name = "intel_vsec.tpmi-rapl" },
	{ }
};

MODULE_DEVICE_TABLE(auxiliary, intel_rapl_id_table);

static struct auxiliary_driver intel_rapl_aux_driver = {
	.id_table = intel_rapl_id_table,
	.remove = intel_rapl_tpmi_remove,
	.probe = intel_rapl_tpmi_probe,
};

static int intel_rapl_tpmi_init(void)
{
	int ret;
	int nr_pkgs = topology_max_packages();

	tpmi_rapl_packages =
	    kcalloc(nr_pkgs, sizeof(struct tpmi_rapl_package *), GFP_KERNEL);
	if (!tpmi_rapl_packages)
		return -ENOMEM;

	ret = auxiliary_driver_register(&intel_rapl_aux_driver);
	if (ret < 0) {
		pr_err("Failed to register platform driver\n");
		kfree(tpmi_rapl_packages);
	}
	return ret;
}

static void intel_rapl_tpmi_exit(void)
{
	auxiliary_driver_unregister(&intel_rapl_aux_driver);
	kfree(tpmi_rapl_packages);
}

module_init(intel_rapl_tpmi_init);
module_exit(intel_rapl_tpmi_exit);

MODULE_IMPORT_NS(INTEL_TPMI);

MODULE_DESCRIPTION("Intel TPMI RAPL Driver");
MODULE_LICENSE("GPL");
