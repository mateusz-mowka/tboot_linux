// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Vendor Specific Extended Capabilities auxiliary bus driver
 *
 * Copyright (c) 2021, Intel Corporation.
 * All Rights Reserved.
 *
 * Author: David E. Box <david.e.box@linux.intel.com>
 *
 * This driver discovers and creates auxiliary devices for Intel defined PCIe
 * "Vendor Specific" and "Designated Vendor Specific" Extended Capabilities,
 * VSEC and DVSEC respectively. The driver supports features on specific PCIe
 * endpoints that exist primarily to expose them.
 */

#include <linux/auxiliary_bus.h>
#include <linux/bits.h>
#include <linux/kernel.h>
#include <linux/idr.h>
#include <linux/intel_vsec.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <linux/types.h>


/* Intel Virtual DVSEC capability vendor space offsets */
#define PWRMBASE_OFFSET			0x14
#define READ_LPM_TELEM_OFFSET		0x1C
#define PWRMBASE_MASK			GENMASK(31, 3)
static DEFINE_IDA(intel_vsec_ida);
static DEFINE_IDA(intel_vsec_sdsi_ida);

static enum intel_vsec_id intel_vsec_allow_list[] = {
	VSEC_ID_TELEMETRY,
	VSEC_ID_WATCHER,
	VSEC_ID_CRASHLOG,
	VSEC_ID_SDSI,
	VSEC_ID_TPMI,
};

static const char *intel_vsec_name(enum intel_vsec_id id)
{
	switch (id) {
	case VSEC_ID_TELEMETRY:
		return "telemetry";

	case VSEC_ID_WATCHER:
		return "watcher";

	case VSEC_ID_CRASHLOG:
		return "crashlog";

	case VSEC_ID_SDSI:
		return "sdsi";

	case VSEC_ID_TPMI:
		return "tpmi";

	default:
		return NULL;
	}
}

static bool intel_vsec_allowed(u16 id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(intel_vsec_allow_list); i++)
		if (intel_vsec_allow_list[i] == id)
			return true;

	return false;
}

static bool intel_vsec_disabled(u16 id, unsigned long quirks)
{
	switch (id) {
	case VSEC_ID_WATCHER:
		return !!(quirks & VSEC_QUIRK_NO_WATCHER);

	case VSEC_ID_CRASHLOG:
		return !!(quirks & VSEC_QUIRK_NO_CRASHLOG);

	default:
		return false;
	}
}

static void intel_vsec_remove_aux(void *data)
{
	auxiliary_device_delete(data);
	auxiliary_device_uninit(data);
}

static void intel_vsec_dev_release(struct device *dev)
{
	struct intel_vsec_device *intel_vsec_dev = dev_to_ivdev(dev);

	ida_free(intel_vsec_dev->ida, intel_vsec_dev->auxdev.id);
	kfree(intel_vsec_dev->resource);
	kfree(intel_vsec_dev);
}

int intel_vsec_add_aux(struct pci_dev *pdev, struct device *parent,
		       struct intel_vsec_device *intel_vsec_dev,
		       const char *name)
{
	struct auxiliary_device *auxdev = &intel_vsec_dev->auxdev;
	int ret;

	ret = ida_alloc(intel_vsec_dev->ida, GFP_KERNEL);
	if (ret < 0) {
		kfree(intel_vsec_dev);
		return ret;
	}

	if (!parent)
		parent = &pdev->dev;

	auxdev->id = ret;
	auxdev->name = name;
	auxdev->dev.parent = parent;
	auxdev->dev.release = intel_vsec_dev_release;

	ret = auxiliary_device_init(auxdev);
	if (ret < 0) {
		ida_free(intel_vsec_dev->ida, auxdev->id);
		kfree(intel_vsec_dev->resource);
		kfree(intel_vsec_dev);
		return ret;
	}

	ret = auxiliary_device_add(auxdev);
	if (ret < 0) {
		auxiliary_device_uninit(auxdev);
		return ret;
	}

	return devm_add_action_or_reset(parent, intel_vsec_remove_aux, auxdev);
}
EXPORT_SYMBOL_GPL(intel_vsec_add_aux);

static int intel_vsec_add_dev(struct pci_dev *pdev, struct intel_vsec_header *header,
			      struct intel_vsec_platform_info *info)
{
	struct intel_vsec_device *intel_vsec_dev;
	struct resource *res, *tmp;
	unsigned long quirks = info->quirks;
	int i;

	if (!intel_vsec_allowed(header->id) || intel_vsec_disabled(header->id, quirks))
		return -EINVAL;

	if (!header->num_entries) {
		dev_dbg(&pdev->dev, "Invalid 0 entry count for header id %d\n", header->id);
		return -EINVAL;
	}

	if (!header->entry_size) {
		dev_dbg(&pdev->dev, "Invalid 0 entry size for header id %d\n", header->id);
		return -EINVAL;
	}

	intel_vsec_dev = kzalloc(sizeof(*intel_vsec_dev), GFP_KERNEL);
	if (!intel_vsec_dev)
		return -ENOMEM;

	res = kcalloc(header->num_entries, sizeof(*res), GFP_KERNEL);
	if (!res) {
		kfree(intel_vsec_dev);
		return -ENOMEM;
	}

	if (quirks & VSEC_QUIRK_TABLE_SHIFT)
		header->offset >>= TABLE_OFFSET_SHIFT;

	/*
	 * The DVSEC/VSEC contains the starting offset and count for a block of
	 * discovery tables. Create a resource array of these tables to the
	 * auxiliary device driver.
	 */
	for (i = 0, tmp = res; i < header->num_entries; i++, tmp++) {
		tmp->start = pdev->resource[header->tbir].start +
			     header->offset + i * (header->entry_size * sizeof(u32));
		tmp->end = tmp->start + (header->entry_size * sizeof(u32)) - 1;
		tmp->flags = IORESOURCE_MEM;
	}

	intel_vsec_dev->pcidev = pdev;
	intel_vsec_dev->resource = res;
	intel_vsec_dev->num_resources = header->num_entries;
	intel_vsec_dev->info = info;

	if (header->id == VSEC_ID_SDSI)
		intel_vsec_dev->ida = &intel_vsec_sdsi_ida;
	else
		intel_vsec_dev->ida = &intel_vsec_ida;

	return intel_vsec_add_aux(pdev, &pdev->dev, intel_vsec_dev, intel_vsec_name(header->id));
}

static bool intel_vsec_walk_header(struct pci_dev *pdev,
				   struct intel_vsec_platform_info *info)
{
	struct intel_vsec_header **header = info->capabilities;
	bool have_devices = false;
	int ret;

	for ( ; *header; header++) {
		ret = intel_vsec_add_dev(pdev, *header, info);
		if (ret)
			dev_info(&pdev->dev, "Could not add device for DVSEC id %d\n",
				 (*header)->id);
		else
			have_devices = true;
	}

	return have_devices;
}

static bool intel_vsec_walk_dvsec(struct pci_dev *pdev,
				  struct intel_vsec_platform_info *info)
{
	bool have_devices = false;
	int pos = 0;

	do {
		struct intel_vsec_header header;
		u32 table, hdr;
		u16 vid;
		int ret;

		pos = pci_find_next_ext_capability(pdev, pos, PCI_EXT_CAP_ID_DVSEC);
		if (!pos)
			break;

		pci_read_config_dword(pdev, pos + PCI_DVSEC_HEADER1, &hdr);
		vid = PCI_DVSEC_HEADER1_VID(hdr);
		if (vid != PCI_VENDOR_ID_INTEL)
			continue;

		/* Support only revision 1 */
		header.rev = PCI_DVSEC_HEADER1_REV(hdr);
		if (header.rev != 1) {
			dev_info(&pdev->dev, "Unsupported DVSEC revision %d\n", header.rev);
			continue;
		}

		header.length = PCI_DVSEC_HEADER1_LEN(hdr);

		pci_read_config_byte(pdev, pos + INTEL_DVSEC_ENTRIES, &header.num_entries);
		pci_read_config_byte(pdev, pos + INTEL_DVSEC_SIZE, &header.entry_size);
		pci_read_config_dword(pdev, pos + INTEL_DVSEC_TABLE, &table);

		header.tbir = INTEL_DVSEC_TABLE_BAR(table);
		header.offset = INTEL_DVSEC_TABLE_OFFSET(table);

		pci_read_config_dword(pdev, pos + PCI_DVSEC_HEADER2, &hdr);
		header.id = PCI_DVSEC_HEADER2_ID(hdr);

		ret = intel_vsec_add_dev(pdev, &header, info);
		if (ret)
			continue;

		have_devices = true;
	} while (true);

	return have_devices;
}

static bool intel_vsec_walk_vsec(struct pci_dev *pdev,
				 struct intel_vsec_platform_info *info)
{
	bool have_devices = false;
	int pos = 0;

	do {
		struct intel_vsec_header header;
		u32 table, hdr;
		int ret;

		pos = pci_find_next_ext_capability(pdev, pos, PCI_EXT_CAP_ID_VNDR);
		if (!pos)
			break;

		pci_read_config_dword(pdev, pos + PCI_VNDR_HEADER, &hdr);

		/* Support only revision 1 */
		header.rev = PCI_VNDR_HEADER_REV(hdr);
		if (header.rev != 1) {
			dev_info(&pdev->dev, "Unsupported VSEC revision %d\n", header.rev);
			continue;
		}

		header.id = PCI_VNDR_HEADER_ID(hdr);
		header.length = PCI_VNDR_HEADER_LEN(hdr);

		/* entry, size, and table offset are the same as DVSEC */
		pci_read_config_byte(pdev, pos + INTEL_DVSEC_ENTRIES, &header.num_entries);
		pci_read_config_byte(pdev, pos + INTEL_DVSEC_SIZE, &header.entry_size);
		pci_read_config_dword(pdev, pos + INTEL_DVSEC_TABLE, &table);

		header.tbir = INTEL_DVSEC_TABLE_BAR(table);
		header.offset = INTEL_DVSEC_TABLE_OFFSET(table);

		ret = intel_vsec_add_dev(pdev, &header, info);
		if (ret)
			continue;

		have_devices = true;
	} while (true);

	return have_devices;
}

static bool intel_vsec_walk_vdvsec(struct pci_dev *pdev,
				   struct intel_vsec_platform_info *info)
{
	struct resource mem = {0};
	void __iomem *sram_header;
	u32 table, hdr, offset = 0x00;
	u32 lpm_telemetry_offset;
	u32 pmwrbase_addr;
	bool have_devices = false;
	int count = 0;
	u16 vid;

	mem.start = pdev->resource[0].start;
	mem.end = mem.start + 0x20;
	mem.flags = IORESOURCE_MEM;

	dev_dbg(&pdev->dev, "Entry  %pr", &mem);
	sram_header = devm_ioremap_resource(&pdev->dev, &mem);
	if (IS_ERR(sram_header))
		return PTR_ERR(sram_header);

	pmwrbase_addr = readl(sram_header + PWRMBASE_OFFSET) & PWRMBASE_MASK;
	lpm_telemetry_offset = readl(sram_header + READ_LPM_TELEM_OFFSET);
	dev_dbg(&pdev->dev, " PMWRBASE ADDRESS is 0x%x\n", pmwrbase_addr);
	dev_dbg(&pdev->dev, " lpm_telemetry_offset is 0x%x\n",
		lpm_telemetry_offset);

	do {
		struct intel_vsec_header header;
		void __iomem *dvsec_addr = NULL;
		struct resource res = {0};
		int ret;

		res.start = pdev->resource[0].start + lpm_telemetry_offset +
			    offset;
		res.end = res.start + 0x10 - 1;
		res.flags = IORESOURCE_MEM;

		dev_dbg(&pdev->dev, "Entry  %pr", &res);
		dvsec_addr = devm_ioremap_resource(&pdev->dev, &res);
		if (IS_ERR(dvsec_addr)){
			dev_dbg(&pdev->dev, "No virtual dvsec is supported\n");
			return PTR_ERR(dvsec_addr);
		}

		hdr = readl(dvsec_addr + PCI_DVSEC_HEADER1);
		vid = PCI_DVSEC_HEADER1_VID(hdr);
		if (vid != PCI_VENDOR_ID_INTEL)
			continue;

		header.id = readw(dvsec_addr + PCI_DVSEC_HEADER2);
		header.rev = PCI_DVSEC_HEADER1_REV(hdr);
		header.length = PCI_DVSEC_HEADER1_LEN(hdr);
		table = readl(dvsec_addr + INTEL_DVSEC_TABLE);
		header.num_entries = readb(dvsec_addr + INTEL_DVSEC_ENTRIES);
		header.entry_size = readb(dvsec_addr + INTEL_DVSEC_SIZE);
		header.tbir = INTEL_DVSEC_TABLE_BAR(table);
		header.offset = INTEL_DVSEC_TABLE_OFFSET(table);
		header.offset >>= TABLE_OFFSET_SHIFT;

		dev_dbg(&pdev->dev, "header id = %d\n", header.id);
		dev_dbg(&pdev->dev, "header rev = %d\n", header.rev);
		dev_dbg(&pdev->dev, "header length = 0x%x\n", header.length);
		dev_dbg(&pdev->dev, "header num_entries = %d\n",
			header.num_entries);
		dev_dbg(&pdev->dev, "header entry_size = 0x%x\n",
			header.entry_size);
		dev_dbg(&pdev->dev, "header bar = %d\n", header.tbir);
		dev_dbg(&pdev->dev, "header disc offset = 0x%x\n",
			header.offset);

		ret = intel_vsec_add_dev(pdev, &header, info);
		if (ret)
			continue;

		offset = 0x10;
		count++;
		have_devices = true;
	} while(count < 2);

	return have_devices;
}

void intel_vsec_register(struct pci_dev *pdev,
			 struct intel_vsec_platform_info *info)
{
	if (!pdev || !info)
		return;

	intel_vsec_walk_header(pdev, info);
}
EXPORT_SYMBOL_NS(intel_vsec_register, INTEL_VSEC);

static int intel_vsec_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct intel_vsec_platform_info *info;
	bool have_devices = false;
	int ret;

	ret = pcim_enable_device(pdev);
	if (ret)
		return ret;

	info = (struct intel_vsec_platform_info *)id->driver_data;
	if (!info)
		return -EINVAL;

	if (intel_vsec_walk_dvsec(pdev, info))
		have_devices = true;

	if (intel_vsec_walk_vsec(pdev, info))
		have_devices = true;

	if (info && (info->quirks & VSEC_QUIRK_NO_DVSEC) &&
	    intel_vsec_walk_header(pdev, info))
		have_devices = true;

	if (info && (info->quirks & VSEC_QUIRK_VDVSEC) &&
	    intel_vsec_walk_vdvsec(pdev, info))
		have_devices = true;

	if (!have_devices)
		return -ENODEV;

	pm_runtime_put(&pdev->dev);
	pm_runtime_use_autosuspend(&pdev->dev);
	pm_runtime_set_autosuspend_delay(&pdev->dev, 1000);
	pm_runtime_allow(&pdev->dev);

	return 0;
}

static void intel_vsec_pci_remove(struct pci_dev *pdev)
{
	pm_runtime_forbid(&pdev->dev);
	pm_runtime_dont_use_autosuspend(&pdev->dev);
	pm_runtime_get(&pdev->dev);
}

/* TGL info */
static const struct intel_vsec_platform_info tgl_info = {
	.quirks = VSEC_QUIRK_NO_WATCHER | VSEC_QUIRK_NO_CRASHLOG |
		  VSEC_QUIRK_TABLE_SHIFT| VSEC_QUIRK_EARLY_HW,
};

/* MTL info */
static const struct intel_vsec_platform_info mtl_info = {
	.quirks = VSEC_QUIRK_TABLE_SHIFT,
};

/* MTL PCH info */
static const struct intel_vsec_platform_info mtl_pch_info = {
	.quirks = VSEC_QUIRK_VDVSEC | VSEC_QUIRK_TABLE_SHIFT,
};

/* DG1 info */
static struct intel_vsec_header dg1_telemetry = {
	.length = 0x10,
	.id = 2,
	.num_entries = 1,
	.entry_size = 3,
	.tbir = 0,
	.offset = 0x466000,
};

static struct intel_vsec_header *dg1_capabilities[] = {
	&dg1_telemetry,
	NULL
};

static const struct intel_vsec_platform_info dg1_info = {
	.capabilities = dg1_capabilities,
	.quirks = VSEC_QUIRK_NO_DVSEC | VSEC_QUIRK_EARLY_HW,
};

/* ADL_PCH Shared SRAM */
static const struct intel_vsec_platform_info adl_pch_info = {
	.quirks = VSEC_QUIRK_VDVSEC | VSEC_QUIRK_TABLE_SHIFT,
};

#ifdef CONFIG_PM_SLEEP
static const struct dev_pm_ops intel_vsec_pm_ops = {};
#endif

#define PCI_DEVICE_ID_INTEL_VSEC_ADL		0x467d
#define PCI_DEVICE_ID_INTEL_VSEC_ADL_PCH	0x51ef
#define PCI_DEVICE_ID_INTEL_VSEC_DG1		0x490e
#define PCI_DEVICE_ID_INTEL_VSEC_MTL_M		0x7d0d
#define PCI_DEVICE_ID_INTEL_VSEC_MTL_PCH	0x7e7f
#define PCI_DEVICE_ID_INTEL_VSEC_MTL_S		0xad0d
#define PCI_DEVICE_ID_INTEL_VSEC_OOBMSM		0x09a7
#define PCI_DEVICE_ID_INTEL_VSEC_RPL		0xa77d
#define PCI_DEVICE_ID_INTEL_VSEC_TGL		0x9a0d
static const struct pci_device_id intel_vsec_pci_ids[] = {
	{ PCI_DEVICE_DATA(INTEL, VSEC_ADL, &tgl_info) },
	{ PCI_DEVICE_DATA(INTEL, VSEC_ADL_PCH, &adl_pch_info) },
	{ PCI_DEVICE_DATA(INTEL, VSEC_DG1, &dg1_info) },
	{ PCI_DEVICE_DATA(INTEL, VSEC_MTL_M, &mtl_info) },
	{ PCI_DEVICE_DATA(INTEL, VSEC_MTL_PCH, &mtl_pch_info) },
	{ PCI_DEVICE_DATA(INTEL, VSEC_MTL_S, &mtl_info) },
	{ PCI_DEVICE_DATA(INTEL, VSEC_OOBMSM, &(struct intel_vsec_platform_info) {}) },
	{ PCI_DEVICE_DATA(INTEL, VSEC_RPL, &tgl_info) },
	{ PCI_DEVICE_DATA(INTEL, VSEC_TGL, &tgl_info) },
	{ }
};
MODULE_DEVICE_TABLE(pci, intel_vsec_pci_ids);

static struct pci_driver intel_vsec_pci_driver = {
	.name = "intel_vsec",
	.id_table = intel_vsec_pci_ids,
	.probe = intel_vsec_pci_probe,
	.remove = intel_vsec_pci_remove,
	.driver = {
#ifdef CONFIG_PM_SLEEP
		.pm = &intel_vsec_pm_ops,
#endif
	},
};
module_pci_driver(intel_vsec_pci_driver);

MODULE_AUTHOR("David E. Box <david.e.box@linux.intel.com>");
MODULE_DESCRIPTION("Intel Extended Capabilities auxiliary bus driver");
MODULE_LICENSE("GPL v2");
