// SPDX-License-Identifier: GPL-2.0
#include <linux/pci-tdisp.h>

/**
 * pci_tdisp_init - Initialize a PCI device for TEE-IO
 */
struct pci_tdisp_dev *pci_tdisp_init(struct pci_dev *pdev, struct kvm *kvm,
				     unsigned int flags)
{
	struct pci_tdisp_dev *tdev;

	/*
	 * Steps to initialize a TDI for attachment to a TEE
	 *
	 * 0. Check if target device support TDISP or not.
	 * 1. Request a SPDM session for TEE mode - FIXME
	 * 2. PCIe IDE Setup
	 * 3. Bind device with TEE
	 * 4. Lock device interface
	 */
	if (!pci_tdisp_supported(pdev))
		return ERR_PTR(-ENODEV);

	tdev = kzalloc(sizeof(*tdev), GFP_KERNEL);
	if (!tdev)
		return ERR_PTR(-ENOMEM);

	tdev->flags = flags;
	tdev->pdev = pdev;

	/*
	 * TODO: Request a SPDM session for TEE-IO.
	 */

	/*
	 * TODO: Request a selective IDE stream with same SPDM session.
	 */

	return 0;
}
EXPORT_SYMBOL_GPL(pci_tdisp_init);

/**
 * pci_tdisp_init - Uninitialize a TDISP Device Interface used for TEE-IO
 */
void pci_tdisp_uinit(struct pci_tdisp_dev *tdev)
{
	/*
	 * Steps to detach a TDI from a TEE VM
	 *
	 * 0. Stop TDI
	 * 1. unbind device from TEE
	 * 2. PCIe IDE remove
	 * 3. SPDM session release - FIXME
	 */

	kfree(tdev);
	return;
}
EXPORT_SYMBOL_GPL(pci_tdisp_uinit);
