// SPDX-License-Identifier: GPL-2.0-only
/*
 * tpmi_power_domains: Mapping of TPMI power domains CPU mapping
 *
 * Copyright (c) 2023, Intel Corporation.
 * All Rights Reserved.
 *
 */

#include <linux/cpuhotplug.h>
#include <linux/hashtable.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/topology.h>

#include <asm/cpu_device_id.h>
#include <asm/intel-family.h>

#include "tpmi_power_domains.h"

/**
 * struct tpmi_cpu_info - Mapping information for a CPU
 * @hnode: Used to add mapping information to hash list
 * @linux_cpu:	Linux CPU number
 * @pkg_id: Package ID of this CPU
 * @punit_thread_id: Punit thread id of this CPU
 * @punit_core_id: Punit core id
 * @punit_domain_id: Power domain id from Punit
 *
 * Structure to store mapping information for a Linux CPU
 * to a Punit core, thread and power domain.
 */
struct tpmi_cpu_info {
	struct hlist_node hnode;
	int linux_cpu;
	u8 pkg_id;
	u8 punit_thread_id;
	u8 punit_core_id;
	u8 punit_domain_id;
};

static DEFINE_PER_CPU(struct tpmi_cpu_info, tpmi_cpu_info);

/* The dynamically assigned cpu hotplug state to free later */
static enum cpuhp_state tpmi_hp_state __read_mostly;

#define MAX_POWER_DOMAINS	8

static cpumask_t *tpmi_power_domain_mask;

static DEFINE_MUTEX(tpmi_lock);

static bool power_domains_ready;

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

	if (!power_domains_ready) {
		ret = -EAGAIN;
		goto fail_get_linux_cpu;
	}

	hash_for_each_possible(tpmi_cpu_hash, info, hnode, punit_core_id) {
		if (info->punit_domain_id == domain_id && info->pkg_id == package_id) {
			ret = info->linux_cpu;
			break;
		}
	}

fail_get_linux_cpu:
	mutex_unlock(&tpmi_lock);

	return ret;
}
EXPORT_SYMBOL_NS_GPL(tpmi_get_linux_cpu_number, INTEL_TPMI_POWER_DOMAIN);

int tpmi_get_punit_core_number(int cpu_no)
{
	struct tpmi_cpu_info *info;
	int ret;

	if (cpu_no >= num_possible_cpus())
		return -EINVAL;

	mutex_lock(&tpmi_lock);

	if (!power_domains_ready) {
		ret = -EAGAIN;
		goto fail_get_punit_core;
	}

	info = &per_cpu(tpmi_cpu_info, cpu_no);
	if (!info) {
		ret = -EINVAL;
		goto fail_get_punit_core;
	}

	ret = info->punit_core_id;

fail_get_punit_core:
	mutex_unlock(&tpmi_lock);

	return ret;
}
EXPORT_SYMBOL_NS_GPL(tpmi_get_punit_core_number, INTEL_TPMI_POWER_DOMAIN);

int tpmi_get_power_domain_id(int cpu_no)
{
	struct tpmi_cpu_info *info;
	int ret;

	if (cpu_no >= num_possible_cpus())
		return -EINVAL;

	mutex_lock(&tpmi_lock);

	if (!power_domains_ready) {
		ret = -EAGAIN;
		goto fail_get_domain_id;
	}

	info = &per_cpu(tpmi_cpu_info, cpu_no);
	if (!info) {
		ret = -EINVAL;
		goto fail_get_domain_id;
	}

	ret = info->punit_domain_id;

fail_get_domain_id:
	mutex_unlock(&tpmi_lock);

	return ret;
}
EXPORT_SYMBOL_NS_GPL(tpmi_get_power_domain_id, INTEL_TPMI_POWER_DOMAIN);

cpumask_t *tpmi_get_power_domain_mask(int cpu_no)
{
	struct tpmi_cpu_info *info;
	cpumask_t *mask;
	int index;

	if (cpu_no >= num_possible_cpus())
		return NULL;

	mutex_lock(&tpmi_lock);

	if (!power_domains_ready) {
		mask = NULL;
		goto fail_get_mask;
	}

	info = &per_cpu(tpmi_cpu_info, cpu_no);
	if (!info || info->pkg_id >= topology_max_packages() ||
	    info->punit_domain_id >= MAX_POWER_DOMAINS) {
		mask = NULL;
		goto fail_get_mask;
	}

	index = (info->pkg_id * MAX_POWER_DOMAINS) + info->punit_domain_id;

	mask = &tpmi_power_domain_mask[index];

fail_get_mask:
	mutex_unlock(&tpmi_lock);

	return mask;
}
EXPORT_SYMBOL_NS_GPL(tpmi_get_power_domain_mask, INTEL_TPMI_POWER_DOMAIN);

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

	info->punit_thread_id = data & 0x07;
	info->punit_core_id = (data >> 3) & 0xff;
	info->punit_domain_id = (data >> 11) & 0x1f;
	info->pkg_id = topology_physical_package_id(cpu);
	info->linux_cpu = cpu;

	return 0;
}

static int tpmi_cpu_online(unsigned int cpu)
{
	struct tpmi_cpu_info *info = &per_cpu(tpmi_cpu_info, cpu);
	int ret;

	ret = tpmi_get_logical_id(cpu, info);
	if (!ret)
		return ret;

	mutex_lock(&tpmi_lock);
	if (info->pkg_id < topology_max_packages() &&
	    info->punit_domain_id < MAX_POWER_DOMAINS) {
		int index = (info->pkg_id * MAX_POWER_DOMAINS) + info->punit_domain_id;

		cpumask_set_cpu(cpu, &tpmi_power_domain_mask[index]);
		hash_add(tpmi_cpu_hash, &info->hnode, info->punit_core_id);
	}
	mutex_unlock(&tpmi_lock);

	return 0;
}

static int tpmi_cpu_offline(unsigned int cpu)
{
	struct tpmi_cpu_info *info = &per_cpu(tpmi_cpu_info, cpu);

	mutex_lock(&tpmi_lock);
	if (info->pkg_id < topology_max_packages() && info->punit_domain_id < MAX_POWER_DOMAINS) {
		int index = (info->pkg_id * MAX_POWER_DOMAINS) + info->punit_domain_id;

		cpumask_clear_cpu(cpu, &tpmi_power_domain_mask[index]);
		hash_del(&info->hnode);
	}
	mutex_unlock(&tpmi_lock);

	return 0;
}

static int __init tpmi_init(void)
{
	const struct x86_cpu_id *id;
	u64 data;
	int ret;

	id = x86_match_cpu(tpmi_cpu_ids);
	if (!id)
		return -ENODEV;

	/* Check for MSR 0x54 presence */
	ret = rdmsrl_safe(MSR_PM_LOGICAL_ID, &data);
	if (ret)
		return ret;

	tpmi_power_domain_mask = kcalloc(topology_max_packages() * MAX_POWER_DOMAINS,
					 sizeof(*tpmi_power_domain_mask),
					 GFP_KERNEL);
	if (!tpmi_power_domain_mask)
		return -ENOMEM;

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
				"platform/x86/tpmi_power_domains:online",
				tpmi_cpu_online, tpmi_cpu_offline);
	if (ret < 0) {
		kfree(tpmi_power_domain_mask);
		return ret;
	}

	tpmi_hp_state = ret;

	mutex_lock(&tpmi_lock);
	power_domains_ready = true;
	mutex_unlock(&tpmi_lock);

	return 0;
}
module_init(tpmi_init)

static void __exit tpmi_exit(void)
{
	mutex_lock(&tpmi_lock);
	power_domains_ready = false;
	mutex_unlock(&tpmi_lock);

	cpuhp_remove_state(tpmi_hp_state);
	kfree(tpmi_power_domain_mask);
}
module_exit(tpmi_exit)

MODULE_DESCRIPTION("TPMI Power Domains Mapping");
MODULE_LICENSE("GPL");
