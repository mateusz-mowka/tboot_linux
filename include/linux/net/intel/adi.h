/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2021, Intel Corporation. */

#ifndef _ADI_H_
#define _ADI_H_

#include <linux/auxiliary_bus.h>
#include <net/devlink.h>
#include <linux/mutex.h>

struct adi_aux_dev;

/**
 * struct adi_drv_ops - ADI driver operations
 * @pre_rebuild_irqctx: Inform ADI driver that IRQ context will be rebuilt
 * @rebuild_irqctx: Ask ADI driver to rebuild IRQ context
 * @zap_vma_map: Tell ADI driver to zap all previously setup VMA maps
 *
 * The operations implemented by the ADI auxiliary driver. They are called by
 * the driver which registered the ADI auxiliary device. Primarily they are
 * used during the parent device reset flow.
 *
 * They are passed from the ADI driver to the ADI device by the init_drv_ops
 * callback.
 */
struct adi_drv_ops {
	void (*pre_rebuild_irqctx)(struct adi_aux_dev *adi);
	int (*rebuild_irqctx)(struct adi_aux_dev *adi);
	int (*zap_vma_map)(struct adi_aux_dev *adi);
};

/**
 * struct adi_dev_ops - Assignable Device Interface operations
 * @init_drv_ops: Called to initialize ADI driver operations during probe
 * @assign_vfio_dev: Called to inform ADI device of the associated VFIO device
 * @get_vector_num: get number of vectors assigned to this device
 * @get_vector_irq: get OS IRQ number per vector
 * @reset: Request the PF to reset this ADI
 * @cfg_pasid: Configure device PASID for this ADI
 * @close: Close the ADI device
 * @read_reg32: Read a 32 bit device register
 * @write_reg32: Write a 32 bit device register
 * @get_sparse_mmap_hpa: Get the sparse HPA map
 * @get_sparse_mmap_num: Get the number of sparse memory areas
 * @get_sparse_mmap_area: Get the layout of sparse memory
 *
 * The operations implemented by the ADI auxiliary device registrant. They are
 * called by the ADI auxiliary driver to perform necessary setup for the
 * assignable device.
 */
struct adi_dev_ops {
	void (*init_drv_ops)(struct adi_aux_dev *adi,
			     const struct adi_drv_ops *ops);
	int (*get_vector_num)(struct adi_aux_dev *adi);
	int (*get_vector_irq)(struct adi_aux_dev *adi, u32 vector);
	int (*reset)(struct adi_aux_dev *adi);
	int (*cfg_pasid)(struct adi_aux_dev *adi, u32 pasid, bool ena);
	int (*close)(struct adi_aux_dev *adi);
	u32 (*read_reg32)(struct adi_aux_dev *adi, size_t offs);
	void (*write_reg32)(struct adi_aux_dev *adi, size_t offs, u32 val);
	int (*get_sparse_mmap_hpa)(struct adi_aux_dev *adi, u32 index,
				   u64 pg_off, u64 *addr);
	int (*get_sparse_mmap_num)(struct adi_aux_dev *adi);
	int (*get_sparse_mmap_area)(struct adi_aux_dev *adi, int index,
				    u64 *offset, u64 *size);
};

/**
 * struct adi_aux_dev - Assignable Device Interface structure
 * @adev: auxiliary device structure
 * @ops: ADI ops table implemented by registering PF driver
 * @cfg_lock: lock protecting VF device reset
 *
 * The Assignable Device Interface defines the communication between a PF
 * driver exposing a portion of its device and a peer driver which exposes
 * that device to user space via VFIO. The two drivers connect over auxiliary
 * bus.
 *
 * The PF driver will allocate this structure when registering a new
 * auxiliary device as part of creating a new port. It must implement the
 * adi_dev_ops structure.
 *
 * To communicate from the PF driver to the peer ADI driver, the adi_drv_ops
 * structure is used. This is initialized by the ADI driver calling
 * init_drv_ops() during probe.
 *
 * This structure defines the explicit interface between the ADI peer driver
 * and a PF driver registering an ADI.
 *
 * The PF driver can hold private data by embedding the adi_aux_dev structure
 * inside its own private structure and using container_of.
 *
 * The VDCM driver can hold private data by using auxiliary_set_drvdata to
 * store a private data variable for the auxiliary device.
 */
struct adi_aux_dev {
	struct auxiliary_device adev;
	const struct adi_dev_ops *ops;
	struct mutex *cfg_lock;
};

#endif /* _ADI_H_ */
