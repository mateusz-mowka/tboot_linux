// SPDX-License-Identifier: GPL-2.0
#include <linux/vdsm.h>

#include "vdsm_ioctl.h"

DEFINE_XARRAY(vdsm_driver_backend_xa);
EXPORT_SYMBOL(vdsm_driver_backend_xa);

int vdsm_register_driver_backend(struct vdsm_driver_backend *be)
{
	int ret;
	uint64_t index;
	const struct pci_device_id *id;

	for (id = be->dev_ids; id->vendor; id++) {
		/* This combination is unique per-driver. */
		index = UNIQUE_BE_IDX(id->vendor, id->device);
		ret = xa_insert(&vdsm_driver_backend_xa, index, be, GFP_KERNEL);
		if (ret) {
			pr_err("%s: backend registration with index %llu failed\n", __func__, index);
			return ret;
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(vdsm_register_driver_backend);

void vdsm_unregister_driver_backend(struct vdsm_driver_backend *be)
{
	unsigned long index;
	const struct pci_device_id *id;

	for (id = be->dev_ids; id->vendor; id++) {
		index = UNIQUE_BE_IDX(id->vendor, id->device);
		xa_erase(&vdsm_driver_backend_xa, index);
	}
}
EXPORT_SYMBOL_GPL(vdsm_unregister_driver_backend);
