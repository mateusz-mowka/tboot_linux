// SPDX-License-Identifier: GPL-2.0-only
/*
 * intel-pem-tpmi: platform excursion monitor enabling
 *
 * Copyright (c) 2022, Intel Corporation.
 * All Rights Reserved.
 *
 */

#include <linux/auxiliary_bus.h>
#include <linux/intel_tpmi.h>
#include <linux/module.h>

#include "intel_tpmi_pem_core.h"

static int intel_pem_probe(struct auxiliary_device *auxdev, const struct auxiliary_device_id *id)
{
	int ret;

	ret = tpmi_pem_dev_add(auxdev);
	if (ret)
		return ret;

	ret = tpmi_pem_pmu_init();
	if (ret)
		tpmi_pem_dev_remove(auxdev);

	return ret;
}

static void intel_pem_remove(struct auxiliary_device *auxdev)
{
	tpmi_pem_pmu_exit();
	tpmi_pem_dev_remove(auxdev);
}

static const struct auxiliary_device_id intel_pem_id_table[] = {
	{ .name = "intel_vsec.tpmi-pem" },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, intel_pem_id_table);

static struct auxiliary_driver intel_pem_aux_driver = {
	.id_table       = intel_pem_id_table,
	.remove         = intel_pem_remove,
	.probe          = intel_pem_probe,
};

module_auxiliary_driver(intel_pem_aux_driver);

MODULE_IMPORT_NS(INTEL_TPMI_PEM);
MODULE_DESCRIPTION("Intel TPMI PEM Driver");
MODULE_LICENSE("GPL");
