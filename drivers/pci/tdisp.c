// SPDX-License-Identifier: GPL-2.0
#include <linux/workqueue.h>
#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/pci-tdisp.h>
#include <linux/kvm_host.h>

static int tdisp_kvm_bind_tdisp_dev(struct kvm *kvm,
				    struct pci_tdisp_dev *tdev)
{
	int (*fn)(struct kvm *kvm, struct pci_tdisp_dev *tdev);
	int ret;

	fn = symbol_get(kvm_bind_tdisp_dev);
	if (!fn)
		return -ENOENT;

	ret = fn(kvm, tdev);

	symbol_put(kvm_bind_tdisp_dev);

	return ret;
}

static int tdisp_kvm_unbind_tdisp_dev(struct kvm *kvm,
				      struct pci_tdisp_dev *tdev)
{
	int (*fn)(struct kvm *kvm, struct pci_tdisp_dev *tdev);
	int ret;

	fn = symbol_get(kvm_unbind_tdisp_dev);
	if (!fn)
		return -ENOENT;

	ret = fn(kvm, tdev);

	symbol_put(kvm_unbind_tdisp_dev);

	return ret;
}

static int tdisp_kvm_tdisp_request(struct kvm *kvm,
				   struct pci_tdisp_dev *tdev,
				   struct pci_tdisp_req *req)
{
	int (*fn)(struct kvm *kvm, struct pci_tdisp_dev *tdev,
		  struct pci_tdisp_req *req);
	int ret;

	fn = symbol_get(kvm_tdisp_request);
	if (!fn)
		return -ENOENT;

	ret = fn(kvm, tdev, req);

	symbol_put(kvm_tdisp_request);

	return ret;
}

#define PCI_DOE_PROTOCOL_SPDM		1
#define PCI_DOE_PROTOCOL_SECURED_SPDM	2

static struct pci_doe_mb *pci_tdisp_create_doe_mb(struct pci_dev *pdev)
{
	struct pci_doe_mb *doe_mb;
	int pos;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_DOE);
	if (!pos)
		return NULL;

	doe_mb = pcim_doe_create_mb(pdev, pos);
	if (!doe_mb)
		return NULL;

	if (!pci_doe_supports_prot(doe_mb, PCI_VENDOR_ID_PCI_SIG,
				   PCI_DOE_PROTOCOL_SPDM))
		return NULL;

	if (!pci_doe_supports_prot(doe_mb, PCI_VENDOR_ID_PCI_SIG,
				   PCI_DOE_PROTOCOL_SECURED_SPDM))
		return NULL;

	return doe_mb;
}

/**
 * pci_tdisp_init - Initialize a PCI device for TEE-IO
 */
struct pci_tdisp_dev *pci_tdisp_init(struct pci_dev *pdev, struct kvm *kvm,
				     unsigned int flags)
{
	struct pci_tdisp_req req = { 0 };
	struct pci_ide_stream *stm;
	struct pci_tdisp_dev *tdev;
	struct pci_doe_mb* doe_mb;
	int ret;

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
	 * Use DOE mailbox directly as workaround for now.
	 */
	doe_mb = pci_tdisp_create_doe_mb(pdev);
	if (!doe_mb) {
		ret = -ENODEV;
		goto exit_free_tdev;
	}

	tdev->doe_mb = doe_mb;

	/* Request a selective IDE stream with same SPDM session */
	stm = pci_ide_stream_setup(pdev, doe_mb, PCI_IDE_FLAG_TEE);
	if (IS_ERR(stm)) {
		ret = PTR_ERR(stm);
		goto exit_free_tdev;
	}

	tdev->stm = stm;

	/* Bind TDISP Device Interface with target TEE VM */
	ret = tdisp_kvm_bind_tdisp_dev(kvm, tdev);
	if (ret)
		goto exit_ide_remove;

	tdev->kvm = kvm;

	/* Move TDISP Device Interface state from UNLOCKED to LOCKED */
	req.parm.message = TDISP_LOCK_INTF_REQ;
	ret = tdisp_kvm_tdisp_request(kvm, tdev, &req);
	if (ret)
		goto exit_unbind_dev;

	return 0;

exit_unbind_dev:
	tdisp_kvm_unbind_tdisp_dev(kvm, tdev);
exit_ide_remove:
	pci_ide_stream_remove(stm);
exit_free_tdev:
	kfree(tdev);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(pci_tdisp_init);

/**
 * pci_tdisp_init - Uninitialize a TDISP Device Interface used for TEE-IO
 */
void pci_tdisp_uinit(struct pci_tdisp_dev *tdev)
{
	struct pci_tdisp_req req = { 0 };

	/*
	 * Steps to detach a TDI from a TEE VM
	 *
	 * 0. Stop TDI
	 * 1. unbind device from TEE
	 * 2. PCIe IDE remove
	 * 3. SPDM session release - FIXME
	 */
	if (!tdev->kvm)
		return;

	/* Move TDISP Device Interface state from LOCKED to UNLOCKED */
	req.parm.message = TDISP_STOP_INTF_REQ;
	tdisp_kvm_tdisp_request(tdev->kvm, tdev, &req);
	tdisp_kvm_unbind_tdisp_dev(tdev->kvm, tdev);
	pci_ide_stream_remove(tdev->stm);
	kfree(tdev);
	return;
}
EXPORT_SYMBOL_GPL(pci_tdisp_uinit);
