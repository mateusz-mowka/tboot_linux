// SPDX-License-Identifier: GPL-2.0-only
/*
 * intel-ufs-tpmi: Intel x86 platform uncore frequency scaling
 *
 * Copyright (c) 2022, Intel Corporation.
 * All Rights Reserved.
 *
 * The hardware interface to read/write is basically substitution of
 * MSR 0x620 and 0x621.
 * There are specific MMIO offset and bits to get/set minimum and
 * maximum uncore ratio, similar to MSRs.
 * The scope of the uncore MSRs was package scope. But TPMI allows
 * new gen CPUs to have multiple uncore controls at uncore-cluster
 * level. Each package can have multiple power domains which further
 * can have multiple clusters.
 * Here number of power domains = number of resources in this aux
 * device. There are offsets and bits to discover number of clusters
 * and offset for each cluster level controls.
 */

#include <linux/auxiliary_bus.h>
#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <linux/intel_tpmi.h>

#include "uncore-frequency-common.h"

#define	UNCORE_HEADER_VERSION		1
#define UNCORE_HEADER_INDEX		0
#define UNCORE_FABRIC_CLUSTER_OFFSET	8

/* status + control +adv_ctl1 + adv_ctl2 */
#define UNCORE_FABRIC_CLUSTER_SIZE	(4 * 8)

#define UNCORE_STATUS_INDEX		0
#define UNCORE_CONTROL_INDEX		8

#define UNCORE_FREQ_KHZ_MULTIPLIER	100000

/* Information for each cluster */
struct tpmi_uncore_cluster_info {
	void __iomem *cluster_base;
	struct uncore_data uncore_data;
	struct auxiliary_device *auxdev;
};

/* Information for each power domain */
struct tpmi_uncore_power_domain_info {
	void __iomem *uncore_base;
	int ufs_header_ver;
	int cluster_count;
	struct tpmi_uncore_cluster_info *cluster_infos;
};

/* Information for each power domain */
struct tpmi_uncore_struct {
	int power_domain_count;
	struct tpmi_uncore_power_domain_info *pd_info;
};

#define UNCORE_GENMASK_MIN_RATIO	GENMASK_ULL(21, 15)
#define UNCORE_GENMASK_MAX_RATIO	GENMASK_ULL(14, 8)
#define UNCORE_GENMASK_CURRENT_RATIO	GENMASK_ULL(6, 0)

static int uncore_read_control_freq(struct uncore_data *data, unsigned int *min,
				    unsigned int *max)
{
	struct tpmi_uncore_cluster_info *cluster_info;
	u64 control;
	int ret;

	cluster_info = container_of(data, struct tpmi_uncore_cluster_info, uncore_data);
	ret = intel_tpmi_readq(cluster_info->auxdev,
			       (u8 __iomem *)cluster_info->cluster_base + UNCORE_CONTROL_INDEX,
			       &control);
	if (ret)
		return ret;

	*max = FIELD_GET(UNCORE_GENMASK_MAX_RATIO, control) * UNCORE_FREQ_KHZ_MULTIPLIER;
	*min = FIELD_GET(UNCORE_GENMASK_MIN_RATIO, control) * UNCORE_FREQ_KHZ_MULTIPLIER;

	return 0;
}

#define UNCORE_MAX_RATIO	0x7F

static int uncore_write_control_freq(struct uncore_data *data, unsigned int input,
				     unsigned int min_max)
{
	struct tpmi_uncore_cluster_info *cluster_info;
	u64 control;
	int ret;

	input /= UNCORE_FREQ_KHZ_MULTIPLIER;
	if (!input || input > UNCORE_MAX_RATIO)
		return -EINVAL;

	cluster_info = container_of(data, struct tpmi_uncore_cluster_info, uncore_data);
	ret = intel_tpmi_readq(cluster_info->auxdev,
			       (u8 __iomem *)cluster_info->cluster_base + UNCORE_CONTROL_INDEX,
			       &control);
	if (ret)
		return ret;

	if (min_max) {
		control &= ~UNCORE_GENMASK_MAX_RATIO;
		control |= FIELD_PREP(UNCORE_GENMASK_MAX_RATIO, input);
	} else {
		control &= ~UNCORE_GENMASK_MIN_RATIO;
		control |= FIELD_PREP(UNCORE_GENMASK_MIN_RATIO, input);
	}

	ret = intel_tpmi_writeq(cluster_info->auxdev, control,
				((u8 __iomem *)cluster_info->cluster_base + UNCORE_CONTROL_INDEX));

	return ret;
}

static int uncore_read_freq(struct uncore_data *data, unsigned int *freq)
{
	struct tpmi_uncore_cluster_info *cluster_info;
	u64 status;
	int ret;

	cluster_info = container_of(data, struct tpmi_uncore_cluster_info, uncore_data);
	ret = intel_tpmi_readq(cluster_info->auxdev,
			       (u8 __iomem *)cluster_info->cluster_base + UNCORE_STATUS_INDEX,
			       &status);
	if (ret)
		return ret;

	*freq = FIELD_GET(UNCORE_GENMASK_CURRENT_RATIO, status) * UNCORE_FREQ_KHZ_MULTIPLIER;

	return 0;
}

#define UNCORE_AUTO_SUSPEND_DELAY_MS		2000
#define UNCORE_GENMASK_VERSION			GENMASK_ULL(7, 0)
#define UNCORE_LOCAL_FABRIC_CLUSTER_ID_MASK	GENMASK_ULL(15, 8)
#define UNCORE_CLUSTER_OFF_MASK			GENMASK_ULL(7, 0)
#define UNCORE_MAX_CLUSTER_PER_DOMAIN		8

static int tpmi_uncore_init(struct auxiliary_device *auxdev)
{
	struct intel_tpmi_plat_info *plat_info;
	struct tpmi_uncore_struct *tpmi_uncore;
	int ret, i, pkg = 0, inst = 0;
	int num_resources;

	num_resources = tpmi_get_resource_count(auxdev);
	if (!num_resources)
		return -EINVAL;

	ret = uncore_freq_common_init(uncore_read_control_freq, uncore_write_control_freq,
				      uncore_read_freq);
	if (ret)
		return ret;

	tpmi_uncore = devm_kzalloc(&auxdev->dev, sizeof(*tpmi_uncore), GFP_KERNEL);
	if (!tpmi_uncore) {
		ret = -ENOMEM;
		goto err_rem_common;
	}

	tpmi_uncore->pd_info = devm_kcalloc(&auxdev->dev, num_resources,
					    sizeof(*tpmi_uncore->pd_info),
					    GFP_KERNEL);
	if (!tpmi_uncore->pd_info) {
		ret = -ENOMEM;
		goto err_rem_common;
	}

	tpmi_uncore->power_domain_count = num_resources;

	plat_info = dev_get_platdata(&auxdev->dev);
	if (plat_info)
		pkg = plat_info->package_id;

	for (i = 0; i < num_resources; ++i) {
		struct tpmi_uncore_power_domain_info *pd_info;
		struct resource *res;
		u64 cluster_offset;
		u8 cluster_mask;
		int mask, j;
		u64 header;

		res = tpmi_get_resource_at_index(auxdev, i);
		if (!res)
			continue;

		pd_info = &tpmi_uncore->pd_info[i];

		pd_info->uncore_base = devm_ioremap_resource(&auxdev->dev, res);
		if (IS_ERR(pd_info->uncore_base)) {
			ret = PTR_ERR(pd_info->uncore_base);
			pd_info->uncore_base = NULL;
			goto err_rem_common;
		}

		/* Check for version and skip this resource if ther is mismatch */
		header = readq(pd_info->uncore_base);
		pd_info->ufs_header_ver = header & UNCORE_GENMASK_VERSION;
		if (pd_info->ufs_header_ver != UNCORE_HEADER_VERSION) {
			dev_err(&auxdev->dev, "Uncore: Unsupported version:%d\n", pd_info->ufs_header_ver);
			continue;
		}

		/* Get Cluster ID Mask */
		cluster_mask = FIELD_GET(UNCORE_LOCAL_FABRIC_CLUSTER_ID_MASK, header);
		if (!cluster_mask) {
			dev_err(&auxdev->dev, "Uncore: Invalid cluster mask:%x\n", cluster_mask);
			continue;
		}

		/* Find out number of clusters in this resource */
		mask = 0x01;
		for (j = 0; j < UNCORE_MAX_CLUSTER_PER_DOMAIN; ++j) {
			if (cluster_mask & mask)
				pd_info->cluster_count++;
			mask <<= 1;
		}

		pd_info->cluster_infos = devm_kcalloc(&auxdev->dev, pd_info->cluster_count,
						      sizeof(struct tpmi_uncore_cluster_info),
						      GFP_KERNEL);

		/*
		 * Each byte in the register point to status and control
		 * registers belonging to cluster id 0-8.
		 */
		cluster_offset = readq((u8 __iomem *)pd_info->uncore_base + UNCORE_FABRIC_CLUSTER_OFFSET);

		for (j = 0; j < pd_info->cluster_count; ++j) {
			struct tpmi_uncore_cluster_info *cluster_info;

			/* Get the offset for this cluster */
			mask = (cluster_offset & UNCORE_CLUSTER_OFF_MASK);
			/* Offset in QWORD, so change to bytes */
			mask <<= 3;

			cluster_info = &pd_info->cluster_infos[j];

			cluster_info->cluster_base = (u8 __iomem *)pd_info->uncore_base + mask;

			cluster_info->uncore_data.package_id = pkg;
			/* There are no dies like Cascade Lake */
			cluster_info->uncore_data.die_id = 0;
			cluster_info->uncore_data.domain_id = i;
			cluster_info->uncore_data.cluster_id = j;

			cluster_info->auxdev = auxdev;

			ret = uncore_freq_add_entry(&cluster_info->uncore_data, 0);
			if (ret)
				goto err_rem_common;

			/* Point to next cluster offset */
			cluster_offset >>= UNCORE_MAX_CLUSTER_PER_DOMAIN;
		}
		++inst;
	}

	if (!inst) {
		/* Not even a single valid resource */
		ret = -ENODEV;
		goto err_rem_common;
	}

	auxiliary_set_drvdata(auxdev, tpmi_uncore);

	pm_runtime_set_active(&auxdev->dev);
	pm_runtime_set_autosuspend_delay(&auxdev->dev, UNCORE_AUTO_SUSPEND_DELAY_MS);
	pm_runtime_use_autosuspend(&auxdev->dev);
	pm_runtime_enable(&auxdev->dev);
	pm_runtime_mark_last_busy(&auxdev->dev);

	return 0;

err_rem_common:
	uncore_freq_common_exit();

	return ret;
}

static int tpmi_uncore_remove(struct auxiliary_device *auxdev)
{
	struct tpmi_uncore_struct *tpmi_uncore = auxiliary_get_drvdata(auxdev);
	int i;

	for (i = 0; i < tpmi_uncore->power_domain_count; ++i) {
		struct tpmi_uncore_power_domain_info *pd_info;
		int j;

		pd_info = &tpmi_uncore->pd_info[i];
		if (!pd_info->uncore_base)
			continue;

		for (j = 0; j < pd_info->cluster_count; ++j) {
			struct tpmi_uncore_cluster_info *cluster_info;

			cluster_info = &pd_info->cluster_infos[j];
			uncore_freq_remove_die_entry(&cluster_info->uncore_data);
		}
	}

	pm_runtime_disable(&auxdev->dev);

	uncore_freq_common_exit();

	return 0;
}

static int intel_uncore_probe(struct auxiliary_device *auxdev, const struct auxiliary_device_id *id)
{
	return tpmi_uncore_init(auxdev);
}

static void intel_uncore_remove(struct auxiliary_device *auxdev)
{
	tpmi_uncore_remove(auxdev);
}

static const struct auxiliary_device_id intel_uncore_id_table[] = {
	{ .name = "intel_vsec.tpmi-uncore" },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, intel_uncore_id_table);

static struct auxiliary_driver intel_uncore_aux_driver = {
	.id_table       = intel_uncore_id_table,
	.remove         = intel_uncore_remove,
	.probe          = intel_uncore_probe,
};

module_auxiliary_driver(intel_uncore_aux_driver);

MODULE_IMPORT_NS(INTEL_TPMI);
MODULE_IMPORT_NS(INTEL_UNCORE_FREQUENCY);
MODULE_DESCRIPTION("Intel TPMI UFS Driver");
MODULE_LICENSE("GPL");
