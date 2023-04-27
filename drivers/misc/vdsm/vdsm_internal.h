// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022-2023 Intel Corporation */

#ifndef __VDSM_INTERNAL_H__
#define __VDSM_INTERNAL_H__

#include <linux/cdev.h>
#include <linux/eventfd.h>
#include <linux/pci-doe.h>
#include <linux/xarray.h>

#define VDSM_MAX_MINORS 256
#define PCI_DOE_HEADER_SIZE 8

#define UNIQUE_BE_IDX(vid, did) (((uint64_t)vid << 32) | did)

#pragma pack(push, 1)
struct doe_header {
        u16 vendor_id;
        u8 type;
        u8 reserved;
        u32 length;
};

typedef struct vdsm_spdm_request {
	struct doe_header doe_h;
} spdm_request_t;

typedef struct vdsm_spdm_response {
	struct doe_header doe_h;
} spdm_response_t;

struct vdsm_doe_mb {
	struct pci_doe_mb mb;
	struct eventfd_ctx *evfd_ctx;
	struct pci_doe_task *task;
};

/*
 * struct ide_stream_info - keeps the private IDE stream data for device
 *
 * @stream_id: The stream id of the incoming IDE stream
 * @private: Private data passed to the device
 */
struct ide_stream_info {
	uint8_t stream_id;
	void *private_data;
};

/*
 * struct vdsm_kernel_stub - one-to-one mapping of a actual device
 *
 * @pdev: The actual IDE capable device
 * @be: The device backend of this type of device
 * @vdmb: The vDSM Fake DOE Mailbox instance
 * @ide_stream_info_xa: Keep stream id and the private stream data of the device
 *
 * NOTE there can be multiple IDE streams in a single device.
 */
struct vdsm_kernel_stub {
	struct pci_dev *pdev;
	struct cdev cdev;
	struct vdsm_driver_backend *be;
	struct vdsm_doe_mb vdmb;
	struct xarray ide_stream_info_xa;
};
#pragma pack(pop)

inline void *vdsm_alloc(struct pci_dev *pdev, size_t size);

#endif /* __VDSM_INTERNAL_H__ */
