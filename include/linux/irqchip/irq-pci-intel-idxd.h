/* SPDX-License-Identifier: GPL-2.0 */
/* (C) Copyright 2022 Thomas Gleixner <tglx@linutronix.de> */

#ifndef _LINUX_IRQCHIP_IRQ_PCI_INTEL_IDXD_H
#define _LINUX_IRQCHIP_IRQ_PCI_INTEL_IDXD_H

#include <linux/msi_api.h>
#include <linux/bits.h>
#include <linux/types.h>

/*
 * Convenience macro to wrap the PASID for interrupt allocation
 * via pci_ims_alloc_irq(pdev, &INTEL_IDXD_DEV_COOKIE(pasid))
 */
#define INTEL_IDXD_DEV_COOKIE(pasid)	(union msi_instance_cookie) { .value = (pasid), }

struct pci_dev;

bool pci_intel_idxd_create_ims_domain(struct pci_dev *pdev, void __iomem *slots,
				      unsigned int nr_slots);
void idxd_ims_set_pasid(struct device *dev, int irq, u32 pasid);

#endif
