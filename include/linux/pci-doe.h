/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Data Object Exchange
 *	PCIe r6.0, sec 6.30 DOE
 *
 * Copyright (C) 2021 Huawei
 *     Jonathan Cameron <Jonathan.Cameron@huawei.com>
 *
 * Copyright (C) 2022 Intel Corporation
 *	Ira Weiny <ira.weiny@intel.com>
 */

#ifndef LINUX_PCI_DOE_H
#define LINUX_PCI_DOE_H

struct pci_doe_protocol {
	u16 vid;
	u8 type;
};

/**
 * struct pci_doe_mb - State for a single DOE mailbox
 *
 * This state is used to manage a single DOE mailbox capability.  All fields
 * should be considered opaque to the consumers and the structure passed into
 * the helpers below after being created by devm_pci_doe_create()
 *
 * @pdev: PCI device this mailbox belongs to
 * @cap_offset: Capability offset
 * @prots: Array of protocols supported (encoded as long values)
 * @wq: Wait queue for work item
 * @work_queue: Queue of pci_doe_work items
 * @flags: Bit array of PCI_DOE_FLAG_* flags
 */
struct pci_doe_mb {
	struct pci_dev *pdev;
	u16 cap_offset;
	struct xarray prots;

	wait_queue_head_t wq;
	struct workqueue_struct *work_queue;
	unsigned long flags;
};

/**
 * struct pci_doe_task - represents a single query/response
 *
 * @prot: DOE Protocol
 * @request_pl: The request payload
 * @request_pl_sz: Size of the request payload (bytes)
 * @response_pl: The response payload
 * @response_pl_sz: Size of the response payload (bytes)
 * @rv: Return value.  Length of received response or error (bytes)
 * @complete: Called when task is complete
 * @private: Private data for the consumer
 * @work: Used internally by the mailbox
 * @doe_mb: Used internally by the mailbox
 *
 * The payload sizes and rv are specified in bytes with the following
 * restrictions concerning the protocol.
 *
 *	1) The request_pl_sz must be a multiple of double words (4 bytes)
 *	2) The response_pl_sz must be >= a single double word (4 bytes)
 *	3) rv is returned as bytes but it will be a multiple of double words
 *
 * NOTE there is no need for the caller to initialize work or doe_mb.
 */
struct pci_doe_task {
	struct pci_doe_protocol prot;
	u32 *request_pl;
	size_t request_pl_sz;
	u32 *response_pl;
	size_t response_pl_sz;
	int rv;
	void (*complete)(struct pci_doe_task *task);
	void *private;

	/* No need for the user to initialize these fields */
	struct work_struct work;
	struct pci_doe_mb *doe_mb;
};

/**
 * pci_doe_for_each_off - Iterate each DOE capability
 * @pdev: struct pci_dev to iterate
 * @off: u16 of config space offset of each mailbox capability found
 */
#define pci_doe_for_each_off(pdev, off) \
	for (off = pci_find_next_ext_capability(pdev, off, \
					PCI_EXT_CAP_ID_DOE); \
		off > 0; \
		off = pci_find_next_ext_capability(pdev, off, \
					PCI_EXT_CAP_ID_DOE))

struct pci_doe_mb *pcim_doe_create_mb(struct pci_dev *pdev, u16 cap_offset);
bool pci_doe_supports_prot(struct pci_doe_mb *doe_mb, u16 vid, u8 type);
int pci_doe_submit_task(struct pci_doe_mb *doe_mb, struct pci_doe_task *task);
int pci_doe_msg_exchange_sync(struct pci_doe_mb *doe_mb, u32 *request,
			      u32 *response, size_t response_buf_sz);

#endif
