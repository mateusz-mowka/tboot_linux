// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Intel Corporation. */

#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/semaphore.h>

#include <asm/cpu_device_id.h>

#include "ifs.h"

enum test_types {
	IFS_SAF,
	IFS_ARRAY,
	IFS_SBFT
};

#define X86_MATCH(model, test_gen)				\
	X86_MATCH_VENDOR_FAM_MODEL_FEATURE(INTEL, 6,	\
		INTEL_FAM6_##model, X86_FEATURE_CORE_CAPABILITIES, test_gen)

static const struct x86_cpu_id ifs_cpu_ids[] __initconst = {
	X86_MATCH(SAPPHIRERAPIDS_X, 0),
	X86_MATCH(GRANITERAPIDS_X, 1),
	X86_MATCH(EMERALDRAPIDS_X, 0),
	{}
};
MODULE_DEVICE_TABLE(x86cpu, ifs_cpu_ids);

static struct ifs_device ifs_devices[] = {
	[IFS_SAF] = {
		.data = {
			.integrity_cap_bit = MSR_INTEGRITY_CAPS_PERIODIC_BIST_BIT,
			.test_name = "SCAN",
		},
		.misc = {
			.name = "intel_ifs_0",
			.nodename = "intel_ifs/0",
			.minor = MISC_DYNAMIC_MINOR,
		},
	},
	[IFS_ARRAY] = {
		.data = {
			.integrity_cap_bit = MSR_INTEGRITY_CAPS_ARRAY_BIST_BIT,
			.test_name = "ARRAY",
		},
		.misc = {
			.name = "intel_ifs_1",
			.nodename = "intel_ifs/1",
			.minor = MISC_DYNAMIC_MINOR,
		},
	},
	[IFS_SBFT] = {
		.data = {
			.integrity_cap_bit = MSR_INTEGRITY_CAPS_SBFT_AT_FIELD,
			.test_name = "SBFT",
		},
		.misc = {
			.name = "intel_ifs_2",
			.nodename = "intel_ifs/2",
			.minor = MISC_DYNAMIC_MINOR,
		},
	},
};

#define IFS_NUMTESTS ARRAY_SIZE(ifs_devices)

static int __init ifs_init(void)
{
	const struct x86_cpu_id *m;
	int ndevices = 0;
	u64 msrval;
	int i;

	m = x86_match_cpu(ifs_cpu_ids);
	if (!m)
		return -ENODEV;

	if (rdmsrl_safe(MSR_IA32_CORE_CAPS, &msrval))
		return -ENODEV;

	if (!(msrval & MSR_IA32_CORE_CAPS_INTEGRITY_CAPS))
		return -ENODEV;

	if (rdmsrl_safe(MSR_INTEGRITY_CAPS, &msrval))
		return -ENODEV;

	for (i = 0; i < IFS_NUMTESTS; i++) {
		if (!(msrval & BIT(ifs_devices[i].data.integrity_cap_bit)))
			continue;

		ifs_devices[i].misc.groups = ifs_get_groups();
		if (!misc_register(&ifs_devices[i].misc)) {
			ndevices++;
			ifs_devices[i].data.test_gen = (u32)m->driver_data;
			down(&ifs_sem);
			ifs_load_firmware(ifs_devices[i].misc.this_device);
			up(&ifs_sem);
		}
	}

	return ndevices ? 0 : -ENODEV;
}

static void __exit ifs_exit(void)
{
	int i;

	for (i = 0; i < IFS_NUMTESTS; i++)
		if (ifs_devices[i].misc.this_device)
			misc_deregister(&ifs_devices[i].misc);
}

module_init(ifs_init);
module_exit(ifs_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Intel In Field Scan (IFS) device");
