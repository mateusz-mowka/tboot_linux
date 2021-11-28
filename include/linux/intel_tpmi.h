/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * intel_tpmi.h: Intel TPMI core external interface
 */

#ifndef _INTEL_TPMI_H_
#define _INTEL_TPMI_H_

struct intel_tpmi_plat_info {
	int package_id;
	int bus_number;
	int device_number;
	int function_number;
};

struct intel_tpmi_plat_info *tpmi_get_platform_data(struct auxiliary_device *auxdev);

#endif
