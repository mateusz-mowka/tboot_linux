/* SPDX-License-Identifier: GPL-2.0 */

#ifndef LINUX_PCI_TDISP_H
#define LINUX_PCI_TDISP_H

#include <linux/pci.h>

struct kvm;

struct pci_tdisp_dev {
	struct pci_dev *pdev;
	unsigned int flags;
	struct kvm *kvm;
	struct pci_doe_mb *doe_mb;
	void *private;
};

static inline bool pci_tdisp_supported(struct pci_dev *pdev)
{
	u32 cap;

	pcie_capability_read_dword(pdev, PCI_EXP_DEVCAP, &cap);

	return !!(cap & PCI_EXP_DEVCAP_TEE_IO);
}

#ifdef CONFIG_PCI_TDISP
struct pci_tdisp_dev *pci_tdisp_init(struct pci_dev *pdev, struct kvm *kvm, unsigned int flags);
void pci_tdisp_uinit(struct pci_tdisp_dev *tdev);
#else
static inline struct pci_tdisp_dev *pci_tdisp_init(struct pci_dev *pdev, unsigned int flags)
{ return ERR_PTR(-ENODEV); }
void pci_tdisp_uinit(struct pci_tdisp_dev *tdev) {}
#endif
#endif /* LINUX_PCI_TDISP_H */
