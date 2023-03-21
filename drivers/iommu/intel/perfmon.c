/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Support Intel IOMMU PerfMon
 * Copyright(c) 2021 Intel Corporation.
 */

#include <linux/dmar.h>
#include <linux/perf_event.h>
#include "iommu.h"

#define ECMD_CMD_ENABLE		0xf0
#define ECMD_CMD_DISABLE	0xf1
#define ECMD_CMD_FREEZE		0xf4
#define ECMD_CMD_UNFREEZE	0xf5

#define ECMD_OA_SHIFT		16

#define ECMD_ECRSP_IP		0x1

#define ECMD_ECCAP3_ECNTS	(1ULL << 48)
#define ECMD_ECCAP3_DCNTS	(1ULL << 49)
#define ECMD_ECCAP3_FCNTS	(1ULL << 52)
#define ECMD_ECCAP3_UFCNTS	(1ULL << 53)

#define ECMD_ECCAP3_ESSENTIAL	(ECMD_ECCAP3_ECNTS |	\
				 ECMD_ECCAP3_DCNTS |	\
				 ECMD_ECCAP3_FCNTS |	\
				 ECMD_ECCAP3_UFCNTS)

#define IOMMU_PMU_FILTER_REQUESTER_ID	0x01
#define IOMMU_PMU_FILTER_DOMAIN		0x02
#define IOMMU_PMU_FILTER_PASID		0x04
#define IOMMU_PMU_FILTER_ATS		0x08
#define IOMMU_PMU_FILTER_PAGE_TABLE	0x10
#define IOMMU_PMU_FILTER_VC		0x20

#define IOMMU_PMU_FILTER_EN		(1 << 31)

#define IOMMU_PMU_CFG_OFFSET		0x100
#define IOMMU_PMU_CFG_CNTRCAP_OFFSET	0x80
#define IOMMU_PMU_CFG_CNTREVCAP_OFFSET	0x84
#define IOMMU_PMU_CFG_SIZE		0x8
#define IOMMU_PMU_CFG_FILTERS_OFFSET	0x4

#define iommu_cntrcap_pcc(p)		((p) & 0x1)
#define iommu_cntrcap_cw(p)		((p >> 8) & 0xff)
#define iommu_cntrcap_ios(p)		((p >> 16) & 0x1)
#define iommu_cntrcap_egcnt(p)		((p >> 28) & 0xf)

#define IOMMU_EVENT_CFG_INT		(1ULL << 1)	/* Interrupt on overflow */

#define IOMMU_EVENT_CFG_EGI_SHIFT	8
#define IOMMU_EVENT_CFG_ES_SHIFT	32

#define iommu_event_select(p)	((p) & 0xfffffff)
#define iommu_event_group(p)	((p >> 28) & 0xf)

PMU_FORMAT_ATTR(event,		"config:0-27");		/* ES: Events Select */
PMU_FORMAT_ATTR(event_group,	"config:28-31");	/* EGI: Event Group Index */

static struct attribute *iommu_pmu_format_attrs[] = {
	&format_attr_event_group.attr,
	&format_attr_event.attr,
	NULL,
};

static struct attribute_group iommu_pmu_format_attr_group = {
	.name = "format",
	.attrs = iommu_pmu_format_attrs,
};

static cpumask_t iommu_pmu_cpu_mask;

static ssize_t iommu_pmu_cpumask_show(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
	return cpumap_print_to_pagebuf(true, buf, &iommu_pmu_cpu_mask);
}

static DEVICE_ATTR(cpumask, S_IRUGO, iommu_pmu_cpumask_show, NULL);

static struct attribute *iommu_pmu_cpumask_attrs[] = {
	&dev_attr_cpumask.attr,
	NULL,
};

static struct attribute_group iommu_pmu_cpumask_attr_group = {
	.attrs = iommu_pmu_cpumask_attrs,
};

PMU_EVENT_ATTR_STRING(iommu_clocks, iommu_clocks, "event_group=0x0,event=0x01")
PMU_EVENT_ATTR_STRING(iommu_requests, iommu_requests, "event_group=0x0,event=0x02")
PMU_EVENT_ATTR_STRING(pw_occupancy, pw_occupancy, "event_group=0x0,event=0x04")
PMU_EVENT_ATTR_STRING(ats_blocked, ats_blocked, "event_group=0x0,event=0x08")
PMU_EVENT_ATTR_STRING(iommu_mrds, iommu_mrds, "event_group=0x1,event=0x01")
PMU_EVENT_ATTR_STRING(iommu_mem_blocked, iommu_mem_blocked, "event_group=0x1,event=0x20")
PMU_EVENT_ATTR_STRING(pg_req_posted, pg_req_posted, "event_group=0x1,event=0x40")
PMU_EVENT_ATTR_STRING(ctxt_cache_lookup, ctxt_cache_lookup, "event_group=0x2,event=0x01")
PMU_EVENT_ATTR_STRING(ctxt_cache_hit, ctxt_cache_hit, "event_group=0x2,event=0x02")
PMU_EVENT_ATTR_STRING(pasid_cache_lookup, pasid_cache_lookup, "event_group=0x2,event=0x04")
PMU_EVENT_ATTR_STRING(pasid_cache_hit, pasid_cache_hit, "event_group=0x2,event=0x08")
PMU_EVENT_ATTR_STRING(sl_nonleaf_lookup, sl_nonleaf_lookup, "event_group=0x2,event=0x10")
PMU_EVENT_ATTR_STRING(sl_nonleaf_hit, sl_nonleaf_hit, "event_group=0x2,event=0x20")
PMU_EVENT_ATTR_STRING(fl_nonleaf_lookup, fl_nonleaf_lookup, "event_group=0x2,event=0x40")
PMU_EVENT_ATTR_STRING(fl_nonleaf_hit, fl_nonleaf_hit, "event_group=0x2,event=0x80")
PMU_EVENT_ATTR_STRING(iotlb_lookup, iotlb_lookup, "event_group=0x3,event=0x01")
PMU_EVENT_ATTR_STRING(iotlb_hit, iotlb_hit, "event_group=0x3,event=0x02")
PMU_EVENT_ATTR_STRING(int_cache_lookup, int_cache_lookup, "event_group=0x4,event=0x01")
PMU_EVENT_ATTR_STRING(int_cache_hit_nonposted, int_cache_hit_nonposted, "event_group=0x4,event=0x02")
PMU_EVENT_ATTR_STRING(int_cache_hit_posted, int_cache_hit_posted, "event_group=0x4,event=0x04")

static struct attribute *iommu_pmu_events_attrs[] = {
	&iommu_clocks.attr.attr,
	&iommu_requests.attr.attr,
	&pw_occupancy.attr.attr,
	&ats_blocked.attr.attr,
	&iommu_mrds.attr.attr,
	&iommu_mem_blocked.attr.attr,
	&pg_req_posted.attr.attr,
	&ctxt_cache_lookup.attr.attr,
	&ctxt_cache_hit.attr.attr,
	&pasid_cache_lookup.attr.attr,
	&pasid_cache_hit.attr.attr,
	&sl_nonleaf_lookup.attr.attr,
	&sl_nonleaf_hit.attr.attr,
	&fl_nonleaf_lookup.attr.attr,
	&fl_nonleaf_hit.attr.attr,
	&iotlb_lookup.attr.attr,
	&iotlb_hit.attr.attr,
	&int_cache_lookup.attr.attr,
	&int_cache_hit_nonposted.attr.attr,
	&int_cache_hit_posted.attr.attr,
	NULL,
};

static struct attribute_group iommu_pmu_events_attr_group = {
	.name = "events",
	.attrs = iommu_pmu_events_attrs,
};

static const struct attribute_group *iommu_pmu_attr_groups[] = {
	&iommu_pmu_format_attr_group,
	&iommu_pmu_cpumask_attr_group,
	&iommu_pmu_events_attr_group,
	NULL,
};

static inline struct iommu_pmu *dev_to_iommu_pmu(struct device *dev)
{
	return container_of(dev_get_drvdata(dev), struct iommu_pmu, pmu);
}

#define IOMMU_PMU_ATTR(_name, _format, _filter)				\
	PMU_FORMAT_ATTR(_name, _format);				\
									\
static struct attribute *_name##_attr[] = {				\
	&format_attr_##_name.attr,					\
	NULL,								\
};									\
									\
static umode_t								\
_name##_is_visible(struct kobject *kobj, struct attribute *attr, int i)	\
{									\
	struct device *dev = kobj_to_dev(kobj);				\
	struct iommu_pmu *iommu_pmu = dev_to_iommu_pmu(dev);		\
									\
	if (!iommu_pmu)							\
		return 0;						\
	return (iommu_pmu->filter & _filter) ? attr->mode : 0;		\
}									\
									\
static struct attribute_group _name = {					\
	.name		= "format",					\
	.attrs		= _name##_attr,					\
	.is_visible	= _name##_is_visible,				\
};

IOMMU_PMU_ATTR(filter_requester_id,	"config1:0-15",		IOMMU_PMU_FILTER_REQUESTER_ID);
IOMMU_PMU_ATTR(filter_domain,		"config1:16-31",	IOMMU_PMU_FILTER_DOMAIN);
IOMMU_PMU_ATTR(filter_pasid,		"config1:32-53",	IOMMU_PMU_FILTER_PASID);
IOMMU_PMU_ATTR(filter_ats,		"config2:0-2",		IOMMU_PMU_FILTER_ATS);
IOMMU_PMU_ATTR(filter_page_table,	"config2:3-7",		IOMMU_PMU_FILTER_PAGE_TABLE);
IOMMU_PMU_ATTR(filter_vc,		"config2:8-15",		IOMMU_PMU_FILTER_VC);

#define iommu_pmu_get_requester_id(filter)	((filter) & 0xffff)
#define iommu_pmu_get_domain(filter)		(((filter) >> 16) & 0xffff)
#define iommu_pmu_get_pasid(filter)		(((filter) >> 32) & 0x3fffff)
#define iommu_pmu_get_ats(filter)		((filter) & 0x7)
#define iommu_pmu_get_page_table(filter)	(((filter) >> 3) & 0x1f)
#define iommu_pmu_get_vc(filter)		(((filter) >> 8) & 0xff)

#define iommu_pmu_set_filter(_name, _config, _filter, _idx)			\
{										\
	if ((iommu_pmu->filter & _filter) && iommu_pmu_get_##_name(_config)) {	\
		iowrite32(iommu_pmu_get_##_name(_config) | IOMMU_PMU_FILTER_EN,	\
			  iommu_pmu->cfg + _idx * IOMMU_PMU_CFG_OFFSET +	\
			  IOMMU_PMU_CFG_SIZE +					\
			  (ffs(_filter) - 1) * IOMMU_PMU_CFG_FILTERS_OFFSET);	\
	}									\
}

#define iommu_pmu_clear_filter(_filter, _idx)					\
{										\
	if (iommu_pmu->filter & _filter) {					\
		iowrite32(0,							\
			  iommu_pmu->cfg + _idx * IOMMU_PMU_CFG_OFFSET +	\
			  IOMMU_PMU_CFG_SIZE +					\
			  (ffs(_filter) - 1) * IOMMU_PMU_CFG_FILTERS_OFFSET);	\
	}									\
}

static const struct attribute_group *iommu_pmu_attr_update[] = {
	&filter_requester_id,
	&filter_domain,
	&filter_pasid,
	&filter_ats,
	&filter_page_table,
	&filter_vc,
	NULL,
};

static inline void __iomem *
iommu_event_base(struct iommu_pmu *iommu_pmu, int idx)
{
	return iommu_pmu->cntr + idx * iommu_pmu->cntr_stride;
}

static inline void __iomem *
iommu_config_base(struct iommu_pmu *iommu_pmu, int idx)
{
	return iommu_pmu->cfg + idx * IOMMU_PMU_CFG_OFFSET;
}

static inline struct iommu_pmu *iommu_event_to_pmu(struct perf_event *event)
{
	return container_of(event->pmu, struct iommu_pmu, pmu);
}

static inline u64 iommu_event_config(struct perf_event *event)
{
	u64 config = event->attr.config;

	return (iommu_event_select(config) << IOMMU_EVENT_CFG_ES_SHIFT) |
	       (iommu_event_group(config) << IOMMU_EVENT_CFG_EGI_SHIFT) |
	       IOMMU_EVENT_CFG_INT;
}

static inline bool is_iommu_pmu_event(struct iommu_pmu *iommu_pmu,
				      struct perf_event *event)
{
	return event->pmu == &iommu_pmu->pmu;
}

static int iommu_pmu_validate_event(struct perf_event *event)
{
	struct iommu_pmu *iommu_pmu = iommu_event_to_pmu(event);
	u32 event_group = iommu_event_group(event->attr.config);

	if (event_group >= iommu_pmu->num_eg)
		return -EINVAL;

	return 0;
}

static int iommu_pmu_validate_group(struct perf_event *event)
{
	struct iommu_pmu *iommu_pmu = iommu_event_to_pmu(event);
	struct perf_event *sibling;
	int nr = 0;

	for_each_sibling_event(sibling, event->group_leader) {
		if (!is_iommu_pmu_event(iommu_pmu, sibling) ||
		    sibling->state <= PERF_EVENT_STATE_OFF)
			continue;

		if (++nr > iommu_pmu->num_cntr)
			return -EINVAL;
	}

	return 0;
}

static int iommu_pmu_event_init(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	/* sampling not supported */
	if (event->attr.sample_period)
		return -EINVAL;

	if (event->cpu < 0)
		return -EINVAL;

	if (iommu_pmu_validate_event(event))
		return -EINVAL;

	hwc->config = iommu_event_config(event);

	return iommu_pmu_validate_group(event);
}

static void iommu_pmu_event_update(struct perf_event *event)
{
	struct iommu_pmu *iommu_pmu = iommu_event_to_pmu(event);
	struct hw_perf_event *hwc = &event->hw;
	u64 prev_count, new_count, delta;
	int shift = 64 - iommu_pmu->cntr_width;

again:
	prev_count = local64_read(&hwc->prev_count);
	new_count = ioread64(iommu_event_base(iommu_pmu, hwc->idx));
	if (local64_xchg(&hwc->prev_count, new_count) != prev_count)
		goto again;

	delta = (new_count << shift) - (prev_count << shift);
	delta >>= shift;

	local64_add(delta, &event->count);
}

static void iommu_pmu_start(struct perf_event *event, int flags)
{
	struct iommu_pmu *iommu_pmu = iommu_event_to_pmu(event);
	struct intel_iommu *iommu = iommu_pmu->iommu;
	struct hw_perf_event *hwc = &event->hw;
	unsigned long iflags;
	u64 res;

	if (WARN_ON_ONCE(!(hwc->state & PERF_HES_STOPPED)))
		return;

	if (WARN_ON_ONCE(hwc->idx < 0 || hwc->idx >= IOMMU_PMU_IDX_MAX))
		return;

	if (flags & PERF_EF_RELOAD)
		WARN_ON_ONCE(!(event->hw.state & PERF_HES_UPTODATE));

	hwc->state = 0;

	/* Always reprogram the period */
	local64_set((&hwc->prev_count), ioread64(iommu_event_base(iommu_pmu, hwc->idx)));

	raw_spin_lock_irqsave(&iommu->register_lock, iflags);
	iowrite64(ECMD_CMD_ENABLE | (hwc->idx << ECMD_OA_SHIFT),
		  iommu->reg + DMAR_ECMD_REG);
	IOMMU_WAIT_OP(iommu, DMAR_ECRSP_REG, ioread64, !(res & ECMD_ECRSP_IP), res);
	raw_spin_unlock_irqrestore(&iommu->register_lock, iflags);

	perf_event_update_userpage(event);
}

static void iommu_pmu_stop(struct perf_event *event, int flags)
{
	struct iommu_pmu *iommu_pmu = iommu_event_to_pmu(event);
	struct intel_iommu *iommu = iommu_pmu->iommu;
	struct hw_perf_event *hwc = &event->hw;
	unsigned long iflags;
	u64 res;

	if (!(hwc->state & PERF_HES_STOPPED)) {
		raw_spin_lock_irqsave(&iommu->register_lock, iflags);
		iowrite64(ECMD_CMD_DISABLE | (hwc->idx << ECMD_OA_SHIFT),
			  iommu->reg + DMAR_ECMD_REG);
		IOMMU_WAIT_OP(iommu, DMAR_ECRSP_REG, ioread64, !(res & ECMD_ECRSP_IP), res);
		raw_spin_unlock_irqrestore(&iommu->register_lock, iflags);

		iommu_pmu_event_update(event);

		hwc->state |= PERF_HES_STOPPED | PERF_HES_UPTODATE;
	}
}

static inline int
iommu_pmu_validate_per_cntr_event(struct iommu_pmu *iommu_pmu,
				  int idx, struct perf_event *event)
{
	u32 event_group = iommu_event_group(event->attr.config);
	u32 select = iommu_event_select(event->attr.config);

	if (~iommu_pmu->cntr_evcap[idx][event_group] & select)
		return -EINVAL;

	return 0;
}

static int iommu_pmu_assign_event(struct iommu_pmu *iommu_pmu,
				  struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	int idx;

	/*
	 * The counters which support limited events are usually at the end.
	 * Schedule them first to accommodate more events.
	 */
	for (idx = iommu_pmu->num_cntr - 1; idx >= 0; idx--) {
		if (test_and_set_bit(idx, iommu_pmu->used_mask))
			continue;
		/* Check per-counter event capabilities */
		if (!iommu_pmu_validate_per_cntr_event(iommu_pmu, idx, event))
			break;
		clear_bit(idx, iommu_pmu->used_mask);
	}
	if (idx < 0)
		return -EINVAL;

	iommu_pmu->event_list[idx] = event;
	hwc->idx = idx;

	/* config events */
	iowrite64(hwc->config, iommu_config_base(iommu_pmu, idx));

	iommu_pmu_set_filter(requester_id, event->attr.config1,
			     IOMMU_PMU_FILTER_REQUESTER_ID, idx);
	iommu_pmu_set_filter(domain, event->attr.config1,
			     IOMMU_PMU_FILTER_DOMAIN, idx);
	iommu_pmu_set_filter(pasid, event->attr.config1,
			     IOMMU_PMU_FILTER_PASID, idx);
	iommu_pmu_set_filter(ats, event->attr.config2,
			     IOMMU_PMU_FILTER_ATS, idx);
	iommu_pmu_set_filter(page_table, event->attr.config2,
			     IOMMU_PMU_FILTER_PAGE_TABLE, idx);
	iommu_pmu_set_filter(vc, event->attr.config2,
			     IOMMU_PMU_FILTER_VC, idx);

	return 0;
}

static int iommu_pmu_add(struct perf_event *event, int flags)
{
	struct iommu_pmu *iommu_pmu = iommu_event_to_pmu(event);
	struct hw_perf_event *hwc = &event->hw;
	int ret;

	/* assign event */
	ret = iommu_pmu_assign_event(iommu_pmu, event);
	if (ret < 0)
		return ret;

	hwc->state = PERF_HES_UPTODATE | PERF_HES_STOPPED;

	if (flags & PERF_EF_START)
		iommu_pmu_start(event, 0);

	return 0;
}

static void iommu_pmu_del(struct perf_event *event, int flags)
{
	struct iommu_pmu *iommu_pmu = iommu_event_to_pmu(event);
	int idx = event->hw.idx;

	iommu_pmu_stop(event, PERF_EF_UPDATE);

	iommu_pmu_clear_filter(IOMMU_PMU_FILTER_REQUESTER_ID, idx);
	iommu_pmu_clear_filter(IOMMU_PMU_FILTER_DOMAIN, idx);
	iommu_pmu_clear_filter(IOMMU_PMU_FILTER_PASID, idx);
	iommu_pmu_clear_filter(IOMMU_PMU_FILTER_ATS, idx);
	iommu_pmu_clear_filter(IOMMU_PMU_FILTER_PAGE_TABLE, idx);
	iommu_pmu_clear_filter(IOMMU_PMU_FILTER_VC, idx);

	iommu_pmu->event_list[idx] = NULL;
	event->hw.idx = -1;
	clear_bit(idx, iommu_pmu->used_mask);

	perf_event_update_userpage(event);
}

static void iommu_pmu_enable(struct pmu *pmu)
{
	struct iommu_pmu *iommu_pmu = container_of(pmu, struct iommu_pmu, pmu);
	struct intel_iommu *iommu = iommu_pmu->iommu;
	unsigned long flags;
	u64 res;

	raw_spin_lock_irqsave(&iommu->register_lock, flags);
	iowrite64(ECMD_CMD_UNFREEZE, iommu->reg + DMAR_ECMD_REG);
	IOMMU_WAIT_OP(iommu, DMAR_ECRSP_REG, ioread64, !(res & ECMD_ECRSP_IP), res);
	raw_spin_unlock_irqrestore(&iommu->register_lock, flags);
}

static void iommu_pmu_disable(struct pmu *pmu)
{
	struct iommu_pmu *iommu_pmu = container_of(pmu, struct iommu_pmu, pmu);
	struct intel_iommu *iommu = iommu_pmu->iommu;
	unsigned long flags;
	u64 res;

	raw_spin_lock_irqsave(&iommu->register_lock, flags);
	iowrite64(ECMD_CMD_FREEZE, iommu->reg + DMAR_ECMD_REG);
	IOMMU_WAIT_OP(iommu, DMAR_ECRSP_REG, ioread64, !(res & ECMD_ECRSP_IP), res);
	raw_spin_unlock_irqrestore(&iommu->register_lock, flags);
}

static void iommu_pmu_counter_overflow(struct iommu_pmu *iommu_pmu)
{
	u64 status = ioread64(iommu_pmu->overflow);
	struct perf_event *event;
	int i, handled = 0;

	if (!status)
		return;
again:
	for_each_set_bit(i, (unsigned long *)&status, iommu_pmu->num_cntr) {
		handled++;
		event = iommu_pmu->event_list[i];
		if (WARN_ON_ONCE(!event))
			continue;
		iommu_pmu_event_update(event);
	}

	iowrite64(status, iommu_pmu->overflow);

	WARN_ON_ONCE(handled > iommu_pmu->num_cntr);

	status = ioread64(iommu_pmu->overflow);
	if (status)
		goto again;
}

static irqreturn_t iommu_pmu_irq_handler(int irq, void *dev_id)
{
	struct intel_iommu *iommu = dev_id;

	if (!ioread32(iommu->reg + DMAR_PERFINTRSTS_REG))
		return IRQ_NONE;

	iommu_pmu_counter_overflow(iommu->pmu);

	iowrite32(DMA_PERFINTRSTS_PIS, iommu->reg + DMAR_PERFINTRSTS_REG);

	return IRQ_HANDLED;
}

static int __iommu_pmu_register(struct intel_iommu *iommu,
				struct iommu_pmu *iommu_pmu)
{
	iommu_pmu->pmu.name		= iommu->name;
	iommu_pmu->pmu.task_ctx_nr	= perf_invalid_context;
	iommu_pmu->pmu.event_init	= iommu_pmu_event_init;
	iommu_pmu->pmu.pmu_enable	= iommu_pmu_enable;
	iommu_pmu->pmu.pmu_disable	= iommu_pmu_disable;
	iommu_pmu->pmu.add		= iommu_pmu_add;
	iommu_pmu->pmu.del		= iommu_pmu_del;
	iommu_pmu->pmu.start		= iommu_pmu_start;
	iommu_pmu->pmu.stop		= iommu_pmu_stop;
	iommu_pmu->pmu.read		= iommu_pmu_event_update;
	iommu_pmu->pmu.attr_groups	= iommu_pmu_attr_groups;
	iommu_pmu->pmu.attr_update	= iommu_pmu_attr_update;
	iommu_pmu->pmu.capabilities	= PERF_PMU_CAP_NO_EXCLUDE;
	iommu_pmu->pmu.module		= THIS_MODULE;

	return perf_pmu_register(&iommu_pmu->pmu, iommu_pmu->pmu.name, -1);
}

static inline void __iomem *get_perf_reg_address(struct intel_iommu *iommu,
					 struct iommu_pmu *iommu_pmu,
					 u32 offset)
{
	u32 off;

	if (offset >= VTD_PAGE_SIZE)
		off = ioread32(iommu_pmu->base + offset - VTD_PAGE_SIZE);
	else
		off = ioread32(iommu->reg + offset);

	if (off >= VTD_PAGE_SIZE)
		return iommu_pmu->base + off - VTD_PAGE_SIZE;

	return iommu->reg + off;
}

static inline bool is_enhanced_command_support(struct intel_iommu *iommu)
{
	u64 cap3 = ioread64(iommu->reg + DMAR_ECCAP3_REG);

	return (cap3 & ECMD_ECCAP3_ESSENTIAL) == ECMD_ECCAP3_ESSENTIAL;
}

static int iommu_pmu_set_interrupt(struct intel_iommu *iommu, struct iommu_pmu *iommu_pmu)
{
	int irq, ret;

	irq = dmar_alloc_hwirq(IOMMU_IRQ_ID_OFFSET_PERF + iommu->seq_id, iommu->node, iommu);
	if (irq <= 0)
		return -EINVAL;

	snprintf(iommu_pmu->irq_name, sizeof(iommu_pmu->irq_name), "dmar%d-perf", iommu->seq_id);

	iommu->perf_irq = irq;
	ret = request_threaded_irq(irq, NULL, iommu_pmu_irq_handler, IRQF_ONESHOT, iommu_pmu->irq_name, iommu);
	if (ret) {
		dmar_free_hwirq(irq);
		iommu->perf_irq = 0;
		return ret;
	}
	return 0;
}

static void iommu_pmu_unset_interrupt(struct intel_iommu *iommu)
{
	if (!iommu->perf_irq)
		return;

	free_irq(iommu->perf_irq, iommu);
	dmar_free_hwirq(iommu->perf_irq);
	iommu->perf_irq = 0;
}

static int iommu_pmu_cpu_online(unsigned int cpu)
{
	if (cpumask_empty(&iommu_pmu_cpu_mask))
		cpumask_set_cpu(cpu, &iommu_pmu_cpu_mask);

	return 0;
}

static int iommu_pmu_cpu_offline(unsigned int cpu)
{
	struct dmar_drhd_unit *drhd;
	struct intel_iommu *iommu;
	int target;

	if (!cpumask_test_and_clear_cpu(cpu, &iommu_pmu_cpu_mask))
		return 0;

	target = cpumask_any_but(cpu_online_mask, cpu);

	if (target < nr_cpu_ids)
		cpumask_set_cpu(target, &iommu_pmu_cpu_mask);
	else
		target = -1;

	down_write(&dmar_global_lock);

	for_each_iommu(iommu, drhd) {
		if (!iommu->pmu)
			continue;
		perf_pmu_migrate_context(&iommu->pmu->pmu, cpu, target);
	}
	up_write(&dmar_global_lock);

	return 0;
}

static int nr_iommu_pmu;

static int iommu_pmu_cpuhp_setup(struct iommu_pmu *iommu_pmu)
{
	int ret;

	if (nr_iommu_pmu++)
		return 0;

	ret = cpuhp_setup_state(CPUHP_AP_PERF_X86_IOMMU_PERF_ONLINE,
				"driver/iommu/intel/perfmon:online",
				iommu_pmu_cpu_online,
				iommu_pmu_cpu_offline);
	if (ret)
		nr_iommu_pmu = 0;

	return ret;
}

static void iommu_pmu_cpuhp_free(struct iommu_pmu *iommu_pmu)
{
	if (--nr_iommu_pmu)
		return;

	cpuhp_remove_state(CPUHP_AP_PERF_X86_IOMMU_PERF_ONLINE);
}

int iommu_pmu_register(struct intel_iommu *iommu)
{
	u64 perfcap = ioread64(iommu->reg + DMAR_PERFCAP_REG);
	struct iommu_pmu *iommu_pmu;
	u32 offset, size, cap;
	int i, j, ret;

	/* The performance monitoring is not supported. */
	if (!perfcap)
		return -ENODEV;

	/* Sanity check for the number of the counters and event groups */
	if (!pcap_num_cntr(perfcap) || !pcap_num_event_group(perfcap))
		return -ENODEV;

	/* The interrupt on overflow is required */
	if (!pcap_interrupt(perfcap))
		return -ENODEV;

	/* Check required Enhanced Command Capability */
	if (!is_enhanced_command_support(iommu))
		return -ENODEV;

	iommu_pmu = kzalloc(sizeof(*iommu_pmu), GFP_KERNEL);
	if (!iommu_pmu)
		return -ENOMEM;

	iommu_pmu->num_cntr = pcap_num_cntr(perfcap);
	iommu_pmu->cntr_width = pcap_cntr_width(perfcap);
	iommu_pmu->filter = pcap_filters_mask(perfcap);
	/* The counter stride is calculated as 2 ^ (x+10) bytes */
	iommu_pmu->cntr_stride = 1 << (pcap_cntr_stride(perfcap) + 10);
	iommu_pmu->num_eg = pcap_num_event_group(perfcap);

	iommu_pmu->evcap = kcalloc(iommu_pmu->num_eg, sizeof(u64), GFP_KERNEL);
	if (!iommu_pmu->evcap) {
		ret = -ENOMEM;
		goto free_iommu_pmu;
	}

	/* Parse event group capabilities */
	for (i = 0; i < iommu_pmu->num_eg; i++)
		iommu_pmu->evcap[i] = pecap_es(ioread64(iommu->reg + DMAR_PERFEVNTCAP_REG + i * 8));

	iommu_pmu->cntr_evcap = kcalloc(iommu_pmu->num_cntr, sizeof(u32 *), GFP_KERNEL);
	if (!iommu_pmu->cntr_evcap) {
		ret = -ENOMEM;
		goto free_iommu_pmu_evcap;
	}
	for (i = 0; i < iommu_pmu->num_cntr; i++) {
		iommu_pmu->cntr_evcap[i] = kcalloc(iommu_pmu->num_eg, sizeof(u32), GFP_KERNEL);
		if (!iommu_pmu->cntr_evcap[i]) {
			ret = -ENOMEM;
			iommu_pmu->num_cntr = i;
			goto free_iommu_pmu_cntr_evcap;
		}
		/* Initialize counter event capabilities */
		for (j = 0; j < iommu_pmu->num_eg; j++)
			iommu_pmu->cntr_evcap[i][j] = (u32)iommu_pmu->evcap[j];
	}

	/*
	 * Check all the Offset Registers and find the lagest offset.
	 * Map the PerfMon registers space as a whole.
	 */
	size = ioread32(iommu->reg + DMAR_PERFCNTROFF_REG) +
			(iommu_pmu->num_cntr - 1) * iommu_pmu->cntr_stride;

	for (i = 0; i < 3; i++) {
		offset = ioread32(iommu->reg + DMAR_PERFCFGOFF_REG + i * 4);
		if (offset > size)
			size = offset;
	}

	iommu_pmu->base = ioremap(iommu->reg_phys + VTD_PAGE_SIZE, size);
	if (!iommu_pmu->base) {
		ret = -ENOMEM;
		goto free_iommu_pmu_cntr_evcap;
	}

	/* Set interrupt for overflow */
	ret = iommu_pmu_set_interrupt(iommu, iommu_pmu);
	if (ret)
		goto unmap_base;

	/* Register PMU */
	ret = __iommu_pmu_register(iommu, iommu_pmu);
	if (ret)
		goto unset_interrupt;

	/* Setup CPU hotplug */
	ret = iommu_pmu_cpuhp_setup(iommu_pmu);
	if (ret)
		goto unregister_pmu;

	iommu_pmu->cfg = get_perf_reg_address(iommu, iommu_pmu, DMAR_PERFCFGOFF_REG);
	iommu_pmu->cntr = get_perf_reg_address(iommu, iommu_pmu, DMAR_PERFCNTROFF_REG);
	iommu_pmu->overflow = get_perf_reg_address(iommu, iommu_pmu, DMAR_PERFOVFOFF_REG);

	/*
	 * Check per-counter capabilities
	 * All counters should have the same capabilities on
	 * Interrupt on Overflow Support and Counter Width
	 */
	for (i = 0; i < iommu_pmu->num_cntr; i++) {
		cap = ioread32(iommu_pmu->cfg + i * IOMMU_PMU_CFG_OFFSET + IOMMU_PMU_CFG_CNTRCAP_OFFSET);
		if (!iommu_cntrcap_pcc(cap))
			continue;
		if ((iommu_cntrcap_cw(cap) != iommu_pmu->cntr_width) ||
		    !iommu_cntrcap_ios(cap))
			iommu_pmu->num_cntr = i;

		/* Clear the pre-defined events group */
		for (j = 0; j < iommu_pmu->num_eg; j++)
			iommu_pmu->cntr_evcap[i][j] = 0;

		/* Override with per-counter event capabilities */
		for (j = 0; j < iommu_cntrcap_egcnt(cap); j++) {
			cap = ioread32(iommu_pmu->cfg + i * IOMMU_PMU_CFG_OFFSET +
				       IOMMU_PMU_CFG_CNTREVCAP_OFFSET + (j * 4));
			iommu_pmu->cntr_evcap[i][iommu_event_group(cap)] = iommu_event_select(cap);
		}
	}

	if (!i)
		goto free_cpuhp;

	iommu_pmu->iommu = iommu;
	iommu->pmu = iommu_pmu;

	return 0;

free_cpuhp:
	iommu_pmu_cpuhp_free(iommu_pmu);
unregister_pmu:
	perf_pmu_unregister(&iommu_pmu->pmu);
unset_interrupt:
	iommu_pmu_unset_interrupt(iommu);
unmap_base:
	iounmap(iommu_pmu->base);
free_iommu_pmu_cntr_evcap:
	for (i = 0; i < iommu_pmu->num_cntr; i--)
		kfree(iommu_pmu->cntr_evcap[i]);
	kfree(iommu_pmu->cntr_evcap);
free_iommu_pmu_evcap:
	kfree(iommu_pmu->evcap);
free_iommu_pmu:
	kfree(iommu_pmu);

	return ret;
}

void iommu_pmu_unregister(struct intel_iommu *iommu)
{
	struct iommu_pmu *iommu_pmu = iommu->pmu;

	if (!iommu_pmu)
		return;

	iommu_pmu_cpuhp_free(iommu_pmu);
	perf_pmu_unregister(&iommu_pmu->pmu);
	iommu_pmu_unset_interrupt(iommu);
	iounmap(iommu_pmu->base);
	kfree(iommu_pmu);
	iommu->pmu = NULL;
}
