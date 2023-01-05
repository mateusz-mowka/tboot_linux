// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2022 Intel Corporation. */

#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/semaphore.h>
#include <linux/slab.h>

#include <asm/cpu_device_id.h>

#include "ifs.h"

enum test_types {
	IFS_SAF,
	IFS_ARRAY,
};

#define X86_MATCH(model)				\
	X86_MATCH_VENDOR_FAM_MODEL_FEATURE(INTEL, 6,	\
		INTEL_FAM6_##model, X86_FEATURE_CORE_CAPABILITIES, NULL)

static const struct x86_cpu_id ifs_cpu_ids[] __initconst = {
	X86_MATCH(SAPPHIRERAPIDS_X),
	X86_MATCH(EMERALDRAPIDS_X),
	X86_MATCH(GRANITERAPIDS_X),
	X86_MATCH(SIERRAFOREST_X),
	{}
};
MODULE_DEVICE_TABLE(x86cpu, ifs_cpu_ids);

static struct ifs_device ifs_devices[] = {
	[IFS_SAF] = {
		.data = {
			.integrity_cap_bit = MSR_INTEGRITY_CAPS_PERIODIC_BIST_BIT,
			.test_num = IFS_SAF,
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
			.test_num = IFS_ARRAY,
		},
		.misc = {
			.name = "intel_ifs_1",
			.nodename = "intel_ifs/1",
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

		ifs_devices[i].data.test_gen = (msrval & MSR_INTEGRITY_CAPS_SAF_GEN_REV_MASK)
							>> MSR_INTEGRITY_CAPS_SAF_GEN_REV_SHIFT;

		pr_info("intel_ifs device: %d gen_rev: %d integrity caps: %llx\n",
			i, ifs_devices[i].data.test_gen, msrval);

		ifs_devices[i].data.test_gen = (msrval & MSR_INTEGRITY_CAPS_SAF_GEN_REV_MASK)
							>> MSR_INTEGRITY_CAPS_SAF_GEN_REV_SHIFT;

		pr_info("intel_ifs device: %d gen_rev: %d integrity caps: %llx\n",
			i, ifs_devices[i].data.test_gen, msrval);

		ifs_devices[i].data.pkg_auth = kmalloc_array(topology_max_packages(),
							     sizeof(bool), GFP_KERNEL);
		if (!ifs_devices[i].data.pkg_auth)
			continue;

		switch (ifs_devices[i].data.test_num) {
		case IFS_SAF:
			ifs_devices[i].misc.groups = ifs_get_groups();
			break;
		case IFS_ARRAY:
			ifs_devices[i].misc.groups = ifs_get_array_groups();
		}

		if (misc_register(&ifs_devices[i].misc))
			kfree(ifs_devices[i].data.pkg_auth);
		else
			ndevices++;
	}

	return ndevices ? 0 : -ENODEV;
}

static void __exit ifs_exit(void)
{
	int i;

	for (i = 0; i < IFS_NUMTESTS; i++) {
		if (ifs_devices[i].misc.this_device) {
			misc_deregister(&ifs_devices[i].misc);
			kfree(ifs_devices[i].data.pkg_auth);
		}
	}
}

module_init(ifs_init);
module_exit(ifs_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Intel In Field Scan (IFS) device");
