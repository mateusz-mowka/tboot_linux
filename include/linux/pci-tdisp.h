/* SPDX-License-Identifier: GPL-2.0 */

#ifndef LINUX_PCI_TDISP_H
#define LINUX_PCI_TDISP_H

#include <linux/pci.h>
#include <uapi/linux/pci_tdisp.h>
#include <uapi/linux/kvm.h>

struct kvm;

struct pci_tdisp_dev {
	struct pci_dev *pdev;
	unsigned int flags;
	struct kvm *kvm;
	struct pci_doe_mb *doe_mb;
	void *private;
};

struct pci_tdisp_req {
	struct tdisp_req_parm parm;
	struct tdisp_req_info info;
};

static inline const char *tdisp_message_to_string(u8 message)
{
	switch (message) {
	case TDISP_LOCK_INTF_REQ:
		return "TDISP_LOCK_INTF_REQ";
	case TDISP_STOP_INTF_REQ:
		return "TDISP_STOP_INTF_REQ";
	case TDISP_GET_DEVIF_REPORT:
		return "TDISP_GET_DEVIF_REPORT";
	case TDISP_START_DEVIF_MMIO_REQ:
		return "TDISP_START_DEVIF_MMIO_REQ";
	case TDISP_START_DEVIF_DMA_REQ:
		return "TDISP_START_DEVIF_DMA_REQ";
	default:
		return "unknown";
	}
}

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
