// SPDX-License-Identifier: GPL-2.0
/*
 * This file contains platform specific structure definitions
 * and init function used by Meteor Lake PCH.
 *
 * Copyright (c) 2022, Intel Corporation.
 * All Rights Reserved.
 *
 */

#include <linux/pci.h>

#include "core.h"
#include "../vsec.h"
#include "../pmt/telemetry.h"

#define SSRAM_HDR_SIZE		0x100
#define SSRAM_PWRM_OFFSET	0x14
#define SSRAM_DVSEC_OFFSET	0x1C
#define SSRAM_DVSEC_SIZE	0x10
#define SSRAM_PCH_OFFSET	0x60
#define SSRAM_IOE_OFFSET	0x68

#define SOCS_LPM_REQ_GUID	0x2625030
#define LPM_REG_INDEX_OFFSET	2
#define LPM_REG_NUM		28
#define LPM_SUBSTATE_NUM	1

static const u8 MTL_LPM_REG_INDEX[] = {0, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20};

static struct intel_vsec_header *headers[2];

static struct intel_vsec_header socs_hdr = {
	.id = 2,
};

static struct intel_vsec_header ioe_hdr = {
	.id = 2,
};

static struct intel_vsec_header pch_hdr = {
	.id = 2,
};

const struct pmc_reg_map mtl_reg_map = {
	.pfear_sts = ext_tgl_pfear_map,
	.slp_s0_offset = CNP_PMC_SLP_S0_RES_COUNTER_OFFSET,
	.slp_s0_res_counter_step = TGL_PMC_SLP_S0_RES_COUNTER_STEP,
	.ltr_show_sts = adl_ltr_show_map,
	.msr_sts = msr_map,
	.ltr_ignore_offset = CNP_PMC_LTR_IGNORE_OFFSET,
	.regmap_length = CNP_PMC_MMIO_REG_LEN,
	.ppfear0_offset = CNP_PMC_HOST_PPFEAR0A,
	.ppfear_buckets = ICL_PPFEAR_NUM_ENTRIES,
	.pm_cfg_offset = CNP_PMC_PM_CFG_OFFSET,
	.pm_read_disable_bit = CNP_PMC_READ_DISABLE_BIT,
	.ltr_ignore_max = ADL_NUM_IP_IGN_ALLOWED,
	.lpm_num_modes = ADL_LPM_NUM_MODES,
	.lpm_num_maps = ADL_LPM_NUM_MAPS,
	.lpm_res_counter_step_x2 = TGL_PMC_LPM_RES_COUNTER_STEP_X2,
	.etr3_offset = ETR3_OFFSET,
	.lpm_sts_latch_en_offset = MTL_LPM_STATUS_LATCH_EN_OFFSET,
	.lpm_priority_offset = MTL_LPM_PRI_OFFSET,
	.lpm_en_offset = MTL_LPM_EN_OFFSET,
	.lpm_residency_offset = MTL_LPM_RESIDENCY_OFFSET,
	.lpm_sts = adl_lpm_maps,
	.lpm_status_offset = MTL_LPM_STATUS_OFFSET,
	.lpm_live_status_offset = MTL_LPM_LIVE_STATUS_OFFSET,
	.lpm_reg_index = MTL_LPM_REG_INDEX,
};

static int pmc_core_get_mtl_lpm_reqs(struct pmc_dev *pmcdev)
{
	const u8 *reg_index = pmcdev->map->lpm_reg_index;
	const int num_maps = pmcdev->map->lpm_num_maps;
	u32 lpm_size = LPM_MAX_NUM_MODES * num_maps;
	struct telem_endpoint *ep;
	struct pci_dev *pcidev = pmcdev->ssram_pcidev;
	int i, j, mode, map_offset = 0;
	int ret = 0;
	u32 *lpm_req_regs;

	if (!pcidev)
		return -ENODEV;

	ep = pmt_telem_find_and_register_endpoint(pcidev, SOCS_LPM_REQ_GUID, 0);
	if (IS_ERR(ep)) {
		dev_err(&pmcdev->pdev->dev, "pmc_core: couldn't get telem endpoint %d", ret);
		return PTR_ERR(ep);
	}

	lpm_req_regs = devm_kzalloc(&pmcdev->pdev->dev, lpm_size * sizeof(u32),
				     GFP_KERNEL);

	for (j = 0, mode = pmcdev->lpm_en_modes[j]; j < pmcdev->num_lpm_modes; j++,
		 mode = pmcdev->lpm_en_modes[j]) {
		u32 *ptr;

		ptr = lpm_req_regs;
		ptr += mode * num_maps;
		for (i = 0; i < num_maps; ++i) {
			u8 index = reg_index[i] + LPM_REG_INDEX_OFFSET + map_offset;

			ret = pmt_telem_read32(ep, index, ptr, 1);
			if (ret) {
				dev_err(&pmcdev->pdev->dev,
						"pmc_core: couldn't read 32 bit data %d", ret);
				return ret;
			}
			++ptr;
		}
		map_offset += LPM_REG_NUM + LPM_SUBSTATE_NUM;
	}
	pmcdev->lpm_req_regs = lpm_req_regs;
	pmt_telem_unregister_endpoint(ep);

	return ret;
}

static void
mtl_pmc_add_pmt(struct pmc_dev *pmcdev, struct pci_dev *pdev, u64 ssram_base,
		struct intel_vsec_header *header)
{
	struct intel_vsec_platform_info info = {};
	void __iomem *ssram, *dvsec;
	u32 dvsec_offset;
	u32 table, hdr;

	ssram = ioremap(ssram_base, SSRAM_HDR_SIZE);
	if (!ssram)
		return;

	dvsec_offset = readl(ssram + SSRAM_DVSEC_OFFSET);
	iounmap(ssram);

	dvsec = ioremap(ssram_base + dvsec_offset, SSRAM_DVSEC_SIZE);
	if (!dvsec)
		return;

	hdr = readl(dvsec + PCI_DVSEC_HEADER1);
	header->id = readw(dvsec + PCI_DVSEC_HEADER2);
	header->rev = PCI_DVSEC_HEADER1_REV(hdr);
	header->length = PCI_DVSEC_HEADER1_LEN(hdr);
	header->num_entries = readb(dvsec + INTEL_DVSEC_ENTRIES);
	header->entry_size = readb(dvsec + INTEL_DVSEC_SIZE);

	table = readl(dvsec + INTEL_DVSEC_TABLE);
	header->tbir = INTEL_DVSEC_TABLE_BAR(table);
	header->offset = INTEL_DVSEC_TABLE_OFFSET(table);
	iounmap(dvsec);

	headers[0] = header;
	info.caps = VSEC_CAP_TELEMETRY;
	info.headers = headers;
	info.base_addr = ssram_base;

	intel_vsec_register(pdev, &info);
}

static inline u64 get_ssram_base(void __iomem *addr, u32 offset)
{
	u64 low, high;

	low = readl(addr + offset) & GENMASK(31, 3);
	high = readl(addr + offset + 4);

	return (high << 32) + low;
}

static void mtl_pmc_ssram_init(struct pmc_dev *pmcdev)
{
	void __iomem *ssram;
	struct pci_dev *pcidev;
	u64 socs_ssram_base;
	u64 ioe_ssram_base;
	u64 pch_ssram_base;
	int ret;
 
	pcidev = pci_get_domain_bus_and_slot(0, 0, PCI_DEVFN(20, 2));
	if (!pcidev) {
		dev_err(&pmcdev->pdev->dev, "pci_dev is not found.");
		return;
	}

	ret = pcim_enable_device(pcidev);
	if (ret) {
		pci_dev_put(pcidev);
		return;
	}

	socs_ssram_base = pcidev->resource[0].start;
	ssram = ioremap(socs_ssram_base, SSRAM_HDR_SIZE);
	if (!ssram) {
		pci_dev_put(pcidev);
		pci_disable_device(pcidev);
		return;
	}

	pmcdev->ssram_pcidev = pcidev;

	ioe_ssram_base = get_ssram_base(ssram, SSRAM_IOE_OFFSET);
	pch_ssram_base = get_ssram_base(ssram, SSRAM_PCH_OFFSET);
	iounmap(ssram);

	mtl_pmc_add_pmt(pmcdev, pcidev, socs_ssram_base, &socs_hdr);
	if (ioe_ssram_base)
		mtl_pmc_add_pmt(pmcdev, pcidev, ioe_ssram_base, &ioe_hdr);
	if (pch_ssram_base)
		mtl_pmc_add_pmt(pmcdev, pcidev, pch_ssram_base, &pch_hdr);
}

int mtl_core_init(struct pmc_dev *pmcdev)
{
	int ret;

	pmcdev->map = &mtl_reg_map;
	ret = get_primary_reg_base(pmcdev);
	if (ret)
		return ret;

	mtl_pmc_ssram_init(pmcdev);

	pmc_core_get_low_power_modes(pmcdev->pdev);
	ret = pmc_core_get_mtl_lpm_reqs(pmcdev);
	if (ret) {
		iounmap(pmcdev->regbase);
		return ret;
	}

	/* Due to a hardware limitation, the GBE LTR blocks PC10
	 * when a cable is attached. Tell the PMC to ignore it.
	 */
	dev_dbg(&pmcdev->pdev->dev, "ignoring GBE LTR\n");
	pmc_core_send_ltr_ignore(pmcdev, 3);

	return ret;
}
