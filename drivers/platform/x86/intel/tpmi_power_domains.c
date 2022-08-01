// SPDX-License-Identifier: GPL-2.0-only
/*
 * tpmi_power_domains: Mapping of TPMI power domains CPU mapping
 *
 * Copyright (c) 2022, Intel Corporation.
 * All Rights Reserved.
 *
 */

#include <linux/cpuhotplug.h>
#include <linux/hashtable.h>
#include <linux/module.h>
#include <linux/topology.h>

#include <asm/cpu_device_id.h>
#include <asm/intel-family.h>

#include "tpmi_power_domains.h"

struct tpmi_cpu_info {
	struct hlist_node hnode;
	int linux_cpu;
	u8 punit_thread_id;
	u8 punit_core_id;
	u8 punit_domain_id;
	u8 pkg_id;
};

/* The dynamically assigned cpu hotplug state for module_exit() */
static enum cpuhp_state tpmi_hp_state __read_mostly;
static DEFINE_PER_CPU(struct tpmi_cpu_info, tpmi_cpu_info);

#define MAX_PACKAGES		16
#define MAX_POWER_DOMAINS	8
static cpumask_t tpmi_power_domain_mask[MAX_PACKAGES][MAX_POWER_DOMAINS];

static DEFINE_MUTEX(tpmi_lock);

static const struct x86_cpu_id tpmi_cpu_ids[] = {
	X86_MATCH_INTEL_FAM6_MODEL(GRANITERAPIDS_X,	NULL),
	X86_MATCH_INTEL_FAM6_MODEL(SIERRAFOREST_X,	NULL),
	{}
};

static DECLARE_HASHTABLE(tpmi_cpu_hash, 8);

int tpmi_get_linux_cpu_number(int package_id, int domain_id, int punit_core_id)
{
	struct tpmi_cpu_info *info;
	int ret = -EINVAL;

	mutex_lock(&tpmi_lock);
	hash_for_each_possible(tpmi_cpu_hash, info, hnode, punit_core_id) {
		if (info->punit_domain_id == domain_id && info->pkg_id == package_id) {
			ret = info->linux_cpu;
			break;
		}
	}
	mutex_unlock(&tpmi_lock);

	return ret;
}
EXPORT_SYMBOL_NS_GPL(tpmi_get_linux_cpu_number, INTEL_TPMI_POWER_DOMAIN);

int tpmi_get_punit_core_number(int cpu_no)
{
	struct tpmi_cpu_info *info = &per_cpu(tpmi_cpu_info, cpu_no);

	if (!info)
		return -EINVAL;

	return info->punit_core_id;
}
EXPORT_SYMBOL_NS_GPL(tpmi_get_punit_core_number, INTEL_TPMI_POWER_DOMAIN);

int tpmi_get_power_domain_id(int cpu_no)
{
	struct tpmi_cpu_info *info = &per_cpu(tpmi_cpu_info, cpu_no);

	if (!info)
		return -EINVAL;

	return info->punit_domain_id;
}
EXPORT_SYMBOL_NS_GPL(tpmi_get_power_domain_id, INTEL_TPMI_POWER_DOMAIN);

cpumask_t *tpmi_get_power_domain_mask(int cpu_no)
{
	struct tpmi_cpu_info *info = &per_cpu(tpmi_cpu_info, cpu_no);
	cpumask_t *mask;

	if (!info || info->pkg_id >= MAX_PACKAGES ||
	    info->punit_domain_id >= MAX_POWER_DOMAINS ||
	    info->punit_domain_id < 0)
		return NULL;

	mutex_lock(&tpmi_lock);
	mask = &tpmi_power_domain_mask[info->pkg_id][info->punit_domain_id];
	mutex_unlock(&tpmi_lock);

	return mask;
}
EXPORT_SYMBOL_NS_GPL(tpmi_get_power_domain_mask, INTEL_TPMI_POWER_DOMAIN);

#define MSR_THREAD_ID_INFO	0x53
#define MSR_PM_LOGICAL_ID	0x54

/*
 * Struct of MSR 0x54
 * [15:11] PM_DOMAIN_ID
 * [10:3] MODULE_ID (aka IDI_AGENT_ID)
 * [2:0] LP_ID
 * For Atom:
 *   [2] Always 0
 *   [1:0] core ID within module
 * For Core
 *   [2:1] Always 0
 *   [0] thread ID
 */
static int tpmi_get_logical_id(unsigned int cpu, struct tpmi_cpu_info *info)
{
	u64 data;
	int ret;

	ret = rdmsrl_safe(MSR_PM_LOGICAL_ID, &data);
	if (ret) {
		pr_info("MSR MSR_PM_LOGICAL_ID:0x54 is not supported\n");
		return ret;
	}

	/* We don't have use case to differentiate Atom/Core thread id */
	info->punit_thread_id = data & 0x07;
	info->punit_core_id = (data >> 3) & 0xff;
	info->punit_domain_id = (data >> 11) & 0x1f;
	info->pkg_id = topology_physical_package_id(cpu);
	pr_debug("using MSR 0x54 cpu:%d core_id:%d domain_id:%d pkg_id:%d\n",
		 cpu, info->punit_core_id, info->punit_domain_id, info->pkg_id);

	return 0;
}

static int tpmi_cpu_online(unsigned int cpu)
{
	struct tpmi_cpu_info *info = &per_cpu(tpmi_cpu_info, cpu);
	u64 data;
	int ret;

	info->linux_cpu = cpu;

	if (!tpmi_get_logical_id(cpu, info))
		goto update_mask;

	/* The part below will be deleted till update_mask after test */
	ret = rdmsrl_safe(MSR_THREAD_ID_INFO, &data);
	if (ret) {
		info->punit_core_id = -1;
		return 0;
	}

	/*
	 * Format
	 *	Bit 0 – thread ID
	 *	Bit 8:1 – module ID (aka IDI agent ID)
	 *	Bit 13:9 – Compute domain ID (aka die ID)
	 *	Bits 38:32 – co-located CHA ID
	 */
	info->punit_thread_id = data & 0x01;
	info->punit_core_id = (data >> 1) & 0xff;
	info->punit_domain_id = (data >> 9) & 0x1f;
	info->pkg_id = topology_physical_package_id(cpu);
	pr_debug("cpu:%d core_id:%d domain_id:%d pkg_id:%d\n", cpu, info->punit_core_id, info->punit_domain_id, info->pkg_id);

update_mask:
	mutex_lock(&tpmi_lock);
	if (info->pkg_id < MAX_PACKAGES && info->punit_domain_id < MAX_POWER_DOMAINS)
		cpumask_set_cpu(cpu, &tpmi_power_domain_mask[info->pkg_id][info->punit_domain_id]);
	hash_add(tpmi_cpu_hash, &info->hnode, info->punit_core_id);
	mutex_unlock(&tpmi_lock);

	return 0;
}

static int tpmi_cpu_offline(unsigned int cpu)
{
	struct tpmi_cpu_info *info = &per_cpu(tpmi_cpu_info, cpu);

	mutex_lock(&tpmi_lock);
	if (info->pkg_id < MAX_PACKAGES && info->punit_domain_id < MAX_POWER_DOMAINS)
		cpumask_clear_cpu(cpu, &tpmi_power_domain_mask[info->pkg_id][info->punit_domain_id]);
	mutex_unlock(&tpmi_lock);

	return 0;
}

static int __init tpmi_init(void)
{
	const struct x86_cpu_id *id;
	int ret;

	id = x86_match_cpu(tpmi_cpu_ids);
	if (!id)
		return -ENODEV;

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
				"platform/x86/tpmi_power_domains:online",
				tpmi_cpu_online,	tpmi_cpu_offline);
	if (ret < 0)
		return ret;

	tpmi_hp_state = ret;

	return 0;
}
module_init(tpmi_init)

static void __exit tpmi_exit(void)
{
	cpuhp_remove_state(tpmi_hp_state);
}
module_exit(tpmi_exit)

MODULE_DESCRIPTION("TPMI Power Domains Mapping");
MODULE_LICENSE("GPL");
