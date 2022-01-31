// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Platform Monitory Technology Telemetry driver
 *
 * Copyright (c) 2020, Intel Corporation.
 * All Rights Reserved.
 *
 * Author: "David E. Box" <david.e.box@linux.intel.com>
 */

#include <linux/auxiliary_bus.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/overflow.h>
#include <linux/pm_runtime.h>

#include "class.h"
#include "telemetry.h"

#define TELEM_SIZE_OFFSET	0x0
#define TELEM_GUID_OFFSET	0x4
#define TELEM_BASE_OFFSET	0x8
#define TELEM_ACCESS(v)		((v) & GENMASK(3, 0))
#define TELEM_TYPE(v)		(((v) & GENMASK(7, 4)) >> 4)
/* size is in bytes */
#define TELEM_SIZE(v)		(((v) & GENMASK(27, 12)) >> 10)

/* Used by client hardware to identify a fixed telemetry entry*/
#define TELEM_CLIENT_FIXED_BLOCK_GUID	0x10000000

#define NUM_BYTES_QWORD(v)	((v) << 3)
#define SAMPLE_ID_OFFSET(v)	((v) << 3)

#define PMT_XA_START		0
#define PMT_XA_MAX		INT_MAX
#define PMT_XA_LIMIT		XA_LIMIT(PMT_XA_START, PMT_XA_MAX)

static DEFINE_MUTEX(list_lock);

enum telem_type {
	TELEM_TYPE_PUNIT = 0,
	TELEM_TYPE_CRASHLOG,
	TELEM_TYPE_PUNIT_FIXED,
};

struct pmt_telem_priv {
	int				num_entries;
	struct intel_pmt_entry		entry[];
};

static bool pmt_telem_region_overlaps(struct intel_pmt_entry *entry,
				      struct device *dev)
{
	u32 guid = readl(entry->disc_table + TELEM_GUID_OFFSET);

	if (intel_pmt_is_early_client_hw(dev)) {
		u32 type = TELEM_TYPE(readl(entry->disc_table));

		if ((type == TELEM_TYPE_PUNIT_FIXED) ||
		    (guid == TELEM_CLIENT_FIXED_BLOCK_GUID))
			return true;
	}

	return false;
}

static int pmt_telem_header_decode(struct intel_pmt_entry *entry,
				   struct intel_pmt_header *header,
				   struct device *dev)
{
	void __iomem *disc_table = entry->disc_table;

	if (pmt_telem_region_overlaps(entry, dev))
		return 1;

	header->access_type = TELEM_ACCESS(readl(disc_table));
	header->guid = readl(disc_table + TELEM_GUID_OFFSET);
	header->base_offset = readl(disc_table + TELEM_BASE_OFFSET);

	/* Size is measured in DWORDS, but accessor returns bytes */
	header->size = TELEM_SIZE(readl(disc_table));

	/*
	 * Some devices may expose non-functioning entries that are
	 * reserved for future use. They have zero size. Do not fail
	 * probe for these. Just ignore them.
	 */
	if (header->size == 0)
		return 1;

	return 0;
}

static DEFINE_XARRAY_ALLOC(telem_array);
static struct intel_pmt_namespace pmt_telem_ns = {
	.name = "telem",
	.xa = &telem_array,
	.pmt_header_decode = pmt_telem_header_decode,
};

static DEFINE_XARRAY_ALLOC(auxdev_array);

/* Driver API */
int pmt_telem_read(struct pci_dev *pdev, u32 guid, u16 pos, u16 id, u16 count, u64 *data)
{
	struct intel_vsec_device *intel_vsec_dev;
	struct intel_pmt_entry *entry;
	struct pmt_telem_priv *priv;
	unsigned long index;
	bool found = false;
	int i, inst = 0;
	u32 offset;

	xa_for_each(&auxdev_array, index, intel_vsec_dev) {
		if (pdev == intel_vsec_dev->pcidev) {
			found = true;
			break;
		}
	}
	if (!found)
		return -ENODEV;

	priv = auxiliary_get_drvdata(&intel_vsec_dev->auxdev);
	found = false;

	for (entry = priv->entry, i = 0; i < priv->num_entries; entry++, i++) {
		if (entry->guid != guid)
			continue;

		if (++inst == pos) {
			found = true;
			break;
		}
	}

	if (!found)
		return -ENODEV;

	offset = SAMPLE_ID_OFFSET(id);

	if ((offset + NUM_BYTES_QWORD(count)) > entry->size)
		return -EINVAL;

	pr_debug("%s: Reading id %d, offset 0x%x, count %d, base %px\n",
		 __func__, id, SAMPLE_ID_OFFSET(id), count, entry->base);

	pm_runtime_get_sync(&entry->pdev->dev);
	memcpy_fromio(data, entry->base + offset, NUM_BYTES_QWORD(count));
	pm_runtime_mark_last_busy(&entry->pdev->dev);
	pm_runtime_put_autosuspend(&entry->pdev->dev);

	return 0;
}
EXPORT_SYMBOL_GPL(pmt_telem_read);

static void pmt_telem_remove(struct auxiliary_device *auxdev)
{
	struct pmt_telem_priv *priv = auxiliary_get_drvdata(auxdev);
	int i;

	for (i = 0; i < priv->num_entries; i++)
		intel_pmt_dev_destroy(&priv->entry[i], &pmt_telem_ns);

	// remove the auxdev list
	xa_destroy(&auxdev_array);
}

static int pmt_telem_probe(struct auxiliary_device *auxdev, const struct auxiliary_device_id *id)
{
	struct intel_vsec_device *intel_vsec_dev = auxdev_to_ivdev(auxdev);
	struct pmt_telem_priv *priv;
	size_t size;
	int i, ret, pmt_id;

	size = struct_size(priv, entry, intel_vsec_dev->num_resources);
	priv = devm_kzalloc(&auxdev->dev, size, GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	auxiliary_set_drvdata(auxdev, priv);

	for (i = 0; i < intel_vsec_dev->num_resources; i++) {
		struct intel_pmt_entry *entry = &priv->entry[priv->num_entries];

		ret = intel_pmt_dev_create(entry, &pmt_telem_ns, intel_vsec_dev, i);
		if (ret < 0)
			goto abort_probe;
		if (ret)
			continue;

		priv->num_entries++;
	}
	// store the auxdev here
	ret = xa_alloc(&auxdev_array, &pmt_id, intel_vsec_dev, PMT_XA_LIMIT, GFP_KERNEL);
	if (ret)
		return ret;

	return 0;
abort_probe:
	pmt_telem_remove(auxdev);
	return ret;
}

static const struct auxiliary_device_id pmt_telem_id_table[] = {
	{ .name = "intel_vsec.telemetry" },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, pmt_telem_id_table);

static struct auxiliary_driver pmt_telem_aux_driver = {
	.id_table	= pmt_telem_id_table,
	.remove		= pmt_telem_remove,
	.probe		= pmt_telem_probe,
};

static int __init pmt_telem_init(void)
{
	return auxiliary_driver_register(&pmt_telem_aux_driver);
}
module_init(pmt_telem_init);

static void __exit pmt_telem_exit(void)
{
	auxiliary_driver_unregister(&pmt_telem_aux_driver);
	xa_destroy(&telem_array);
}
module_exit(pmt_telem_exit);

MODULE_AUTHOR("David E. Box <david.e.box@linux.intel.com>");
MODULE_DESCRIPTION("Intel PMT Telemetry driver");
MODULE_LICENSE("GPL v2");
