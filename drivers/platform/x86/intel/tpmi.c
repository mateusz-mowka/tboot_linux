// SPDX-License-Identifier: GPL-2.0-only
/*
 * intel-tpmi : Driver to enumerate TPMI features and create devices
 *
 * Copyright (c) 2022, Intel Corporation.
 * All Rights Reserved.
 *
 */

#include <linux/auxiliary_bus.h>
#include <linux/intel_tpmi.h>
#include <linux/intel_vsec.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>

/**
 * struct intel_tpmi_pfs - TPMI PM Feature Structure (PFS)
 * @tpmi_id:	This field indicates the nature and format of the TPMI feature
 *		structure.
 * @num_entries: Number of entries. Describes the number of feature interface
 *		 instances that exist in the PFS. This represents the maximum
 *		 number of Power domains.
 * @entry_size:	Describe the entry size for each interface instance in
 *		32-bit words.
 * @cap_offset:	Specify the upper 16 bits of the 26 bits Cap Offset
 *		(i.e. Cap Offset is in KB unit) from the PM_Features base
 *		address to point to the base of the PM VSEC register bank.
 * @attribute:	Specify the attribute of this feature. 0x0=BIOS. 0x1=OS. 0x2-
 *		0x3=Reserved.
 * @resd:	Bits for future additions by hardware.
 *
 * Stores data for one PFS entry.
 */
struct intel_tpmi_pfs {
	u64 tpmi_id :8;
	u64 num_entries :8;
	u64 entry_size :16;
	u64 cap_offset :16;
	u64 attribute :2;
	u64 resd :14;
};

/**
 * struct intel_tpmi_pm_feature - TPMI PM Feature information for a TPMI ID
 * @pfs_header:	Stores pfs header struct bits as exported by hardware
 * @vsec_offset: Start of memory address in MMIO from VSEC offset in the
 *		 PCI header
 *
 * Stores TPMI instance information for a single TPMI ID. This will be used
 * to get MMIO offset and full information from PFS header.
 */
struct intel_tpmi_pm_feature {
	struct intel_tpmi_pfs pfs_header;
	unsigned int vsec_offset;
};

/**
 * struct intel_tpmi_info - Stores TPMI info for all IDs for an instance
 * @tpmi_features:	Pointer to a list of TPMI feature instances
 * @vsec_dev:		Pointer to intel_vsec_device structure for this TPMI device
 * @feature_count:	Number of TPMI of TPMI instances pointed by tpmi_features
 * @pfs_start:		Start of PFS offset for the TPMI instances in this device
 * @plat_info:		Stores platform info which can be used by the client drivers
 *
 * Stores the information for all TPMI devices enumerated from a single PCI device.
 */
struct intel_tpmi_info {
	struct intel_tpmi_pm_feature *tpmi_features;
	struct intel_vsec_device *vsec_dev;
	int feature_count;
	u64 pfs_start;
	struct intel_tpmi_plat_info plat_info;
};

/**
 * struct tpmi_info_header - TPMI_INFO ID header
 * @fn:		PCI function number
 * @dev:	PCI device number
 * @bus:	PCI bus number
 * @pkg:	CPU Package id
 * @resd:	Reserved for future use
 * @lock:	locked
 *
 * This structure is used parse TPMI_INFO contents. This is packed to the
 * same format as defined in the specifications.
 */
struct tpmi_info_header {
	u64 fn :3;
	u64 dev :5;
	u64 bus :8;
	u64 pkg :8;
	u64 resd :39;
	u64 lock :1;
};

/*
 * Supported list of TPMI IDs.
 * Since there is no use case for some TPMI features in Linux
 * there are holes in IDs
 */
enum intel_tpmi_id {
	TPMI_ID_RAPL = 0, /* Running Average Power Limit */
	TPMI_ID_PEM = 1, /* Power and Perf excursion Monitor */
	TPMI_ID_UNCORE = 2, /* Uncore Frequency Scaling */
	TPMI_ID_SST = 5, /* Speed Select Technology */
};

/* Used during auxbus device creation */
static DEFINE_IDA(intel_vsec_tpmi_ida);

struct intel_tpmi_plat_info *tpmi_get_platform_data(struct auxiliary_device *auxdev)
{
	struct intel_vsec_device *vsec_dev = auxdev_to_ivdev(auxdev);

	return vsec_dev->priv_data;
}
EXPORT_SYMBOL_NS_GPL(tpmi_get_platform_data, INTEL_TPMI);

/* Read one PFS entry and fill pfs structure */
static int tpmi_update_pfs(struct intel_tpmi_pm_feature *pfs, u64 start, int size)
{
	void __iomem *pfs_mem;
	u64 header;

	pfs_mem = ioremap(start, size);
	if (!pfs_mem)
		return -ENOMEM;

	header = readq(pfs_mem);
	pfs->pfs_header = *(struct intel_tpmi_pfs *) &header;
	iounmap(pfs_mem);

	return 0;
}

static const char *intel_tpmi_name(enum intel_tpmi_id id)
{
	switch (id) {
	case TPMI_ID_RAPL:
		return "rapl";
	case TPMI_ID_PEM:
		return "pem";
	case TPMI_ID_UNCORE:
		return "uncore";
	case TPMI_ID_SST:
		return "sst";
	default:
		return NULL;
	}
}

/* String Length for tpmi-"feature_name(upto 8 bytes)"*/
#define TPMI_FEATURE_NAME_LEN	14

static int tpmi_create_device(struct intel_tpmi_info *tpmi_info,
			      struct intel_tpmi_pm_feature *pfs,
			      u64 pfs_start)
{
	struct intel_vsec_device *vsec_dev = tpmi_info->vsec_dev;
	struct intel_vsec_device *feature_vsec_dev;
	struct resource *res, *tmp;
	char feature_id_name[TPMI_FEATURE_NAME_LEN];
	const char *name;
	int ret, i;

	name = intel_tpmi_name(pfs->pfs_header.tpmi_id);
	if (!name)
		return -EOPNOTSUPP;

	feature_vsec_dev = kzalloc(sizeof(*feature_vsec_dev), GFP_KERNEL);
	if (!feature_vsec_dev)
		return -ENOMEM;

	res = kcalloc(pfs->pfs_header.num_entries, sizeof(*res), GFP_KERNEL);
	if (!res) {
		ret = -ENOMEM;
		goto free_vsec;
	}

	snprintf(feature_id_name, sizeof(feature_id_name), "tpmi-%s", name);

	for (i = 0, tmp = res; i < pfs->pfs_header.num_entries; i++, tmp++) {
		tmp->start = pfs->vsec_offset + (pfs->pfs_header.entry_size * 4) * i;
		tmp->end = tmp->start + (pfs->pfs_header.entry_size * 4) - 1;
		tmp->flags = IORESOURCE_MEM;
	}

	feature_vsec_dev->pcidev = vsec_dev->pcidev;
	feature_vsec_dev->resource = res;
	feature_vsec_dev->num_resources = pfs->pfs_header.num_entries;
	feature_vsec_dev->priv_data = &tpmi_info->plat_info;
	feature_vsec_dev->priv_data_size = sizeof(tpmi_info->plat_info);
	feature_vsec_dev->ida = &intel_vsec_tpmi_ida;

	/*
	 * intel_vsec_add_aux() is resource managed, no explicit
	 * delete is required on error or on module unload.
	 */
	ret = intel_vsec_add_aux(vsec_dev->pcidev, &vsec_dev->auxdev.dev,
				 feature_vsec_dev, feature_id_name);
	if (ret)
		goto free_res;

	return 0;

free_res:
	kfree(res);
free_vsec:
	kfree(feature_vsec_dev);

	return ret;
}

static int tpmi_create_devices(struct intel_tpmi_info *tpmi_info)
{
	struct intel_vsec_device *vsec_dev = tpmi_info->vsec_dev;
	int ret, i;

	for (i = 0; i < vsec_dev->num_resources; i++) {
		ret = tpmi_create_device(tpmi_info, &tpmi_info->tpmi_features[i],
					 tpmi_info->pfs_start);
		/*
		 * Fail, if the supported features fails to create device,
		 * otherwise, continue
		 */
		if (ret && ret != -EOPNOTSUPP)
			return ret;
	}

	return 0;
}

#define TPMI_INFO_ID 0x81
#define TPMI_INFO_BUS_INFO_OFFSET 0x08

static int tpmi_process_info(struct intel_tpmi_info *tpmi_info,
			     struct intel_tpmi_pm_feature *pfs)
{
	struct tpmi_info_header *header;
	void __iomem *info_mem;
	u64 info;

	info_mem = ioremap(pfs->vsec_offset + TPMI_INFO_BUS_INFO_OFFSET,
			   pfs->pfs_header.entry_size * 4 - TPMI_INFO_BUS_INFO_OFFSET);
	if (!info_mem)
		return -ENOMEM;

	info = readq(info_mem);

	header = (struct tpmi_info_header *)&info;

	tpmi_info->plat_info.package_id = header->pkg;
	tpmi_info->plat_info.bus_number = header->bus;
	tpmi_info->plat_info.device_number = header->dev;
	tpmi_info->plat_info.function_number = header->fn;

	iounmap(info_mem);

	return 0;
}

static int tpmi_get_resource(struct intel_vsec_device *vsec_dev, int index,
			     u64 *resource_start)
{
	struct resource *res;
	int size;

	res = &vsec_dev->resource[index];
	if (!res)
		return -EINVAL;

	size = resource_size(res);

	*resource_start = res->start;

	return size;
}

#define TPMI_AUTO_SUSPEND_DELAY_MS	2000

static int intel_vsec_tpmi_init(struct auxiliary_device *auxdev)
{
	struct intel_vsec_device *vsec_dev = auxdev_to_ivdev(auxdev);
	struct pci_dev *pci_dev = vsec_dev->pcidev;
	struct intel_tpmi_info *tpmi_info;
	u64 pfs_start = 0;
	int ret, i;

	tpmi_info = devm_kzalloc(&auxdev->dev, sizeof(*tpmi_info), GFP_KERNEL);
	if (!tpmi_info)
		return -ENOMEM;

	tpmi_info->vsec_dev = vsec_dev;
	tpmi_info->feature_count = vsec_dev->num_resources;
	tpmi_info->plat_info.bus_number = pci_dev->bus->number;

	tpmi_info->tpmi_features = devm_kcalloc(&auxdev->dev, vsec_dev->num_resources,
						sizeof(*tpmi_info->tpmi_features),
						GFP_KERNEL);
	if (!tpmi_info->tpmi_features)
		return -ENOMEM;

	for (i = 0; i < vsec_dev->num_resources; i++) {
		struct intel_tpmi_pm_feature *pfs;
		u64 res_start;
		int size, ret;

		pfs = &tpmi_info->tpmi_features[i];

		size = tpmi_get_resource(vsec_dev, i, &res_start);
		if (size < 0)
			continue;

		ret = tpmi_update_pfs(pfs, res_start, size);
		if (ret)
			continue;

		if (!pfs_start)
			pfs_start = res_start;

		pfs->pfs_header.cap_offset *= 1024;

		pfs->vsec_offset = pfs_start + pfs->pfs_header.cap_offset;

		/* Process TPMI_INFO to get BDF to package mapping */
		if (pfs->pfs_header.tpmi_id == TPMI_INFO_ID)
			tpmi_process_info(tpmi_info, pfs);
	}

	tpmi_info->pfs_start = pfs_start;

	auxiliary_set_drvdata(auxdev, tpmi_info);

	ret = tpmi_create_devices(tpmi_info);
	if (ret)
		return ret;

	pm_runtime_set_active(&auxdev->dev);
	pm_runtime_set_autosuspend_delay(&auxdev->dev, TPMI_AUTO_SUSPEND_DELAY_MS);
	pm_runtime_use_autosuspend(&auxdev->dev);
	pm_runtime_enable(&auxdev->dev);
	pm_runtime_mark_last_busy(&auxdev->dev);

	return 0;
}

static int tpmi_probe(struct auxiliary_device *auxdev,
		      const struct auxiliary_device_id *id)
{
	return intel_vsec_tpmi_init(auxdev);
}

static void tpmi_remove(struct auxiliary_device *auxdev)
{
	pm_runtime_disable(&auxdev->dev);
}

static const struct auxiliary_device_id tpmi_id_table[] = {
	{ .name = "intel_vsec.tpmi" },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, tpmi_id_table);

static struct auxiliary_driver tpmi_aux_driver = {
	.id_table	= tpmi_id_table,
	.remove		= tpmi_remove,
	.probe		= tpmi_probe,
};

module_auxiliary_driver(tpmi_aux_driver);

MODULE_DESCRIPTION("Intel TPMI enumeration module");
MODULE_LICENSE("GPL");
