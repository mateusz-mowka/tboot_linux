/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2021, Intel Corporation. */

#ifndef _INET_VDCM_H_
#define _INET_VDCM_H_

#include <linux/iommufd.h>
#include <linux/pci-ats.h>
#include <linux/sched/mm.h>
#include <linux/vfio.h>
#include <linux/eventfd.h>
#include <linux/auxiliary_bus.h>
#if IS_ENABLED(CONFIG_IRQ_BYPASS_MANAGER)
#include <linux/irqbypass.h>
#endif /* CONFIG_IRQ_BYPASS_MANAGER */
#include <linux/net/intel/adi.h>

#define INET_VDCM_CFG_SIZE 256
#define INET_VDCM_BAR0_SIZE SZ_64M

struct inet_vdcm_irq_ctx {
	struct eventfd_ctx *trigger;
	char *name;
	unsigned int irq;
#if IS_ENABLED(CONFIG_IRQ_BYPASS_MANAGER)
	struct irq_bypass_producer producer;
#endif /* CONFIG_IRQ_BYPASS_MANAGER */
};

/**
 * struct inet_vdcm - The abstraction for VDCM
 *
 * @dev:		linux device for this VDCM
 * @parent_dev:		linux parent device for this VDCM
 * @vfio_group:		vfio group for this device
 * @pci_cfg_space:	PCI configuration space buffer
 * @vma_lock:		protects access to vma_list
 * @vma_list:		linked list for VMA
 * @ctx:		IRQ context
 * @num_ctx:		number of requested IRQ context
 * @irq_type:		IRQ type
 * @adi:		ADI attribute
 */
struct inet_vdcm {
	/* Common attribute */
	struct vfio_device vdev;
	struct device *dev;
	struct device *parent_dev;
	ioasid_t pasid;
	int iommufd;
	struct mutex idev_lock;		/* protects access to iommufd dev */
	struct iommufd_device *idev;
	struct xarray pasid_xa;


	u8 pci_cfg_space[INET_VDCM_CFG_SIZE];
	struct mutex vma_lock;		/* protects access to vma_list */
	struct list_head vma_list;

	/* IRQ context */
	struct inet_vdcm_irq_ctx *ctx;
	unsigned int num_ctx;
	unsigned int irq_type;

	/* Device Specific */
	struct adi_aux_dev *adi;
};

#endif /* _INET_VDCM_H_ */
