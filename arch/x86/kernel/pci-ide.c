// SPDX-License-Identifier: GPL-2.0
#include <linux/acpi.h>
#include <linux/intel-iommu.h>
#include <linux/kvm_host.h>
#include <linux/pci.h>
#include <linux/spinlock.h>

int pci_arch_ide_dev_init(struct pci_dev *dev)
{
	return 0;
}

void pci_arch_ide_dev_release(struct pci_dev *dev)
{
	return;
}

int pci_arch_ide_stream_id_alloc(struct pci_dev *dev1, struct pci_dev *dev2)
{
	return 0;
}

void pci_arch_ide_stream_id_free(struct pci_dev *dev1, struct pci_dev *dev2, int stream_id)
{
	return;
}

int pci_arch_ide_dev_tee_enter(struct pci_dev *dev)
{
	return 0;
}

int pci_arch_ide_dev_tee_exit(struct pci_dev *dev)
{
	return 0;
}

int pci_arch_ide_stream_setup(struct pci_ide_stream *stm)
{
	return 0;
}

void pci_arch_ide_stream_remove(struct pci_ide_stream *stm)
{
	return;
}
