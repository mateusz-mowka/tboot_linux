/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LINUX_RPB_H
#define LINUX_RPB_H

#define PCIE_DEVICE_ID_CAMBRIA	0x0d52

static inline bool is_rpb_device(struct pci_dev *pdev)
{
	return (pdev->vendor == PCI_VENDOR_ID_INTEL &&
		pdev->device == PCIE_DEVICE_ID_CAMBRIA);
}

int rpb_set_stream_key(struct pci_dev *pdev, u32 sub_stream,
		       u8 direction, u32 *key, u32 *iv_key);
int rpb_set_sel_stream_id(struct pci_dev *pdev, int stream_id);
int rpb_enable_sel_stream(struct pci_dev *pdev);
void rpb_disable_sel_stream(struct pci_dev *pdev);
int rpb_set_trust_bit(struct pci_dev *pdev, bool trust);

#endif /* LINUX_RPB_H */
