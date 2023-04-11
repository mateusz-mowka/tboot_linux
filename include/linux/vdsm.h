/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __VDSM_H__
#define __VDSM_H__

#include <linux/types.h>
#include <linux/pci.h>
#include <linux/mod_devicetable.h>
#include <linux/xarray.h>
#include <linux/pci-doe.h>

#ifdef CONFIG_VDSM_KERNEL_STUB
extern bool enable_vdsm;
#else
#define enable_vdsm 0
#endif

extern struct xarray vdsm_driver_backend_xa;

struct vdsm_prot_ide_km_backend {
	void *(*init)(struct pci_dev *pdev, uint8_t stream_id);
	int (*query)(void *private_data);
	int (*key_prog)(void *private_data, uint32_t sub_stream,
			uint8_t direction, uint32_t *key, uint32_t *iv_key);
	int (*key_set_go)(void *private_data);
	int (*key_set_stop)(void *private_data);
	void (*deinit)(void *private_data);
};

struct vdsm_driver_backend {
	const struct pci_device_id *dev_ids;
	struct vdsm_prot_ide_km_backend *ide_be;
};

int vdsm_register_driver_backend(struct vdsm_driver_backend *be);
void vdsm_unregister_driver_backend(struct vdsm_driver_backend *be);

struct pci_doe_mb *vdsm_doe_create_mb(struct pci_dev *pdev);
int vdsm_doe_submit_task(struct pci_doe_mb *doe_mb, struct pci_doe_task *task,
			 struct pci_dev *pdev);
bool is_registered_to_vdsm(struct pci_dev *pdev);

#endif /* __VDSM_H__ */
