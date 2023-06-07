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

struct tpmi_rapl_package {
	struct rapl_if_priv priv;
	struct intel_tpmi_plat_info *tpmi_info;
	struct rapl_package *rp;
	void __iomem *base;
	int index;		/* index in the RAPL Domain */
};

struct auxiliary_device **tpmi_rapl_devices;

static struct powercap_control_type *tpmi_control_type;

static int tpmi_rapl_read_raw(int cpu, struct reg_action *ra)
{
	unsigned int id = topology_physical_package_id(cpu);
	struct auxiliary_device *auxdev = tpmi_rapl_devices[id];
	int ret;

	if (!ra->reg || !auxdev)
		return -EINVAL;

	ret = intel_tpmi_readq(auxdev, (void __iomem *)ra->reg, &ra->value);
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
	struct auxiliary_device *auxdev = tpmi_rapl_devices[id];
	u64 val;
	int ret;

	if (!ra->reg || !auxdev)
		return -EINVAL;

	ret = intel_tpmi_readq(auxdev, (void __iomem *)ra->reg, &val);
	if (ret)
		return ret;

	val &= ~ra->mask;
	val |= ra->value;
	intel_tpmi_writeq(auxdev, val, (void __iomem *)ra->reg);
	pr_info("Write 0x%llx at 0x%llx\n", val, ra->reg);
	return 0;
}

static int intel_rapl_tpmi_probe(struct auxiliary_device *auxdev,
				 const struct auxiliary_device_id *id)
{
	struct tpmi_rapl_package *trp;
	struct resource *res;
	int cpu, ret;
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
	trp->priv.control_type = tpmi_control_type;

	/*
	 * Enable Runtime PM earlier in order to access the TPMI registers
	 * when registering a RAPL Package.
	 */
	pm_runtime_set_active(&auxdev->dev);
	pm_runtime_set_autosuspend_delay(&auxdev->dev, 2000);
	pm_runtime_use_autosuspend(&auxdev->dev);
	pm_runtime_enable(&auxdev->dev);
	pm_runtime_mark_last_busy(&auxdev->dev);

	/* TPMI RAPL I/F is package scope */
	for_each_present_cpu(cpu) {
		unsigned int id = topology_physical_package_id(cpu);

		if (id == trp->tpmi_info->package_id) {
			/*
			 * Must set auxdevice before registering RAPL package
			 * in order to make .read_raw/.write_raw callbacks functional
			 */
			tpmi_rapl_devices[id] = auxdev;
			trp->rp = rapl_add_package(cpu, &trp->priv);
			if (IS_ERR(trp->rp)) {
				ret = PTR_ERR(trp->rp);
				dev_err(&auxdev->dev,
					"Failed to add RAPL package, %d\n",
					ret);
				goto err;
			}
			break;
		}
	}

	if (!trp->rp) {
		dev_err(&auxdev->dev, "No CPU on Package %d\n",
			trp->tpmi_info->package_id);
		ret = -ENODEV;
		goto err;
	}

	auxiliary_set_drvdata(auxdev, trp);
	return 0;

err:
	pm_runtime_disable(&auxdev->dev);
	return ret;
}

static void intel_rapl_tpmi_remove(struct auxiliary_device *auxdev)
{
	struct tpmi_rapl_package *trp = auxiliary_get_drvdata(auxdev);

	rapl_remove_package(trp->rp);
	tpmi_rapl_devices[trp->tpmi_info->package_id] = NULL;

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

	tpmi_rapl_devices =
	    kcalloc(nr_pkgs, sizeof(struct auxiliary_device *), GFP_KERNEL);
	if (!tpmi_rapl_devices)
		return -ENOMEM;

	tpmi_control_type =
	    powercap_register_control_type(NULL, "intel-rapl-tpmi", NULL);
	if (IS_ERR(tpmi_control_type)) {
		pr_err("failed to register powercap control_type.\n");
		kfree(tpmi_rapl_devices);
		return PTR_ERR(tpmi_control_type);
	}

	ret = auxiliary_driver_register(&intel_rapl_aux_driver);
	if (ret < 0) {
		pr_err("Failed to register platform driver\n");
		powercap_unregister_control_type(tpmi_control_type);
		kfree(tpmi_rapl_devices);
	}
	return ret;
}

static void intel_rapl_tpmi_exit(void)
{
	auxiliary_driver_unregister(&intel_rapl_aux_driver);
	powercap_unregister_control_type(tpmi_control_type);
	kfree(tpmi_rapl_devices);
}

module_init(intel_rapl_tpmi_init);
module_exit(intel_rapl_tpmi_exit);

MODULE_IMPORT_NS(INTEL_TPMI);

MODULE_DESCRIPTION("Intel TPMI RAPL Driver");
MODULE_LICENSE("GPL");
