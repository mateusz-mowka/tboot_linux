// SPDX-License-Identifier: GPL-2.0-only
/*
 * common IMS library code
 *
 * Copyright (c) 2021,2022 Intel Corp. All rights reserved.
 *
 */

#include <linux/module.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/irqchip/irq-ims-msi.h>
#include <linux/eventfd.h>
#include <linux/irqreturn.h>
#include <linux/msi.h>
#include <linux/vfio.h>
#include <linux/irqbypass.h>
#include <linux/mdev.h>

static irqreturn_t vfio_ims_irq_handler(int irq, void *arg)
{
	struct eventfd_ctx *trigger = arg;

	eventfd_signal(trigger, 1);
	return IRQ_HANDLED;
}

/*
 * Common helper routine to send signal to the eventfd that has been setup.
 *
 * @vdev [in]		: vfio_device context
 * @vector [in]		: vector index for eventfd
 *
 * No return value.
 */
void vfio_ims_send_signal(struct vfio_device *vdev, int vector)
{
	struct vfio_ims *ims = &vdev->ims;
	struct eventfd_ctx *trigger = ims->ims_entries[vector].trigger;

	if (!ims->ims_entries || !trigger) {
		dev_warn(&vdev->device, "EventFD %d trigger not setup, can't send!\n", vector);
		return;
	}
	vfio_ims_irq_handler(0, (void *)trigger);
}
EXPORT_SYMBOL_GPL(vfio_ims_send_signal);

static int vfio_ims_set_vector_signal(struct vfio_ims *ims, int vector, int fd)
{
	int rc, irq;
	struct vfio_device *vdev = ims_to_vdev(ims);
	struct vfio_ims_entry *entry;
	struct device *dev = &vdev->device;
	struct eventfd_ctx *trigger;
	char *name;
	u64 auxval;

	if (vector < 0 || vector >= ims->num)
		return -EINVAL;

	entry = &ims->ims_entries[vector];

	/*
	 * The entry->ims dictate whether the vector is emulated or IMS backed. If emualted,
	 * irq will be set to 0, otherwise it is the Linux irq number.
	 */
	if (entry->ims)
		irq = dev_msi_irq_vector(dev, entry->ims_id);
	else
		irq = 0;

	if (entry->trigger) {
		if (irq) {
			irq_bypass_unregister_producer(&entry->producer);
			free_irq(irq, entry->trigger);
		}
		kfree(entry->name);
		eventfd_ctx_put(entry->trigger);
		entry->trigger = NULL;
	}

	if (fd < 0)
		return 0;

	name = kasprintf(GFP_KERNEL, "vfio-ims[%d](%s)", vector, dev_name(dev));
	if (!name)
		return -ENOMEM;

	trigger = eventfd_ctx_fdget(fd);
	if (IS_ERR(trigger)) {
		kfree(name);
		return PTR_ERR(trigger);
	}

	entry->name = name;
	entry->trigger = trigger;

	/* When irq == 0, this is an emulated vector does not need to request irq */
	if (!irq)
		return 0;

	auxval = ims_ctrl_pasid_aux(vfio_device_get_pasid(vdev), true);
	irq_set_auxdata(irq, IMS_AUXDATA_CONTROL_WORD, auxval);
	rc = request_irq(irq, vfio_ims_irq_handler, 0, name, trigger);
	if (rc < 0)
		goto err;

	entry->producer.token = trigger;
	entry->producer.irq = irq;
	rc = irq_bypass_register_producer(&entry->producer);
	if (unlikely(rc)) {
		dev_warn(dev, "irq bypass producer (token %p) registration fails: %d\n",
			 &entry->producer.token, rc);
		entry->producer.token = NULL;
	}

	return 0;

 err:
	kfree(name);
	eventfd_ctx_put(trigger);
	entry->trigger = NULL;
	return rc;
}

static int vfio_ims_set_vector_signals(struct vfio_ims *ims, unsigned int start,
					unsigned int count, int *fds)
{
	int i, j, rc = 0;

	if (start >= ims->num || start + count > ims->num)
		return -EINVAL;

	for (i = 0, j = start; j < count && !rc; i++, j++) {
		int fd = fds ? fds[i] : -1;

		rc = vfio_ims_set_vector_signal(ims, j, fd);
	}

	if (rc) {
		for (--j; j >= (int)start; j--)
			vfio_ims_set_vector_signal(ims, j, -1);
	}

	return rc;
}

static int vfio_ims_enable(struct vfio_ims *ims, int nvec)
{
	struct vfio_device *vdev = ims_to_vdev(ims);
	struct device *dev = &vdev->device;
	int rc;

	if (ims->ims_num && !ims->ims_en) {
		rc = dev_msi_domain_alloc_irqs(dev_get_msi_domain(dev), dev, ims->ims_num);
		if (rc < 0)
			return rc;
		ims->ims_en = true;
	}

	ims->irq_type = VFIO_PCI_MSIX_IRQ_INDEX;
	return 0;
}

static int vfio_ims_disable(struct vfio_ims *ims)
{
	struct vfio_device *vdev = ims_to_vdev(ims);
	struct device *dev = &vdev->device;
	struct irq_domain *irq_domain;

	vfio_ims_set_vector_signals(ims, 0, ims->num, NULL);
	irq_domain = dev_get_msi_domain(dev);

	if (irq_domain) {
		struct msi_domain_info *info = msi_get_domain_info(irq_domain);

		info->flags |= MSI_FLAG_FREE_MSI_DESCS;
		dev_msi_domain_free_irqs(irq_domain, dev);
	}
	ims->ims_en = false;
	ims->irq_type = VFIO_PCI_NUM_IRQS;
	return 0;
}

/*
 * Common helper function that sets up the MSIX vectors for the vfio device that are
 * Interrupt Message Store (IMS) backed. Certain devices can have some emulated vector
 * rather than backed by IMS.
 *
 *  @vdev [in]		: vfio device
 *  @index [in]		: type of VFIO vectors to setup
 *  @start [in]		: start position of the vector index
 *  @count [in]		: number of vectors
 *  @flags [in]		: VFIO_IRQ action to be taken
 *  @data [in]		: data accompanied for the call
 *  Return error code on failure or 0 on success.
 */
int vfio_set_ims_trigger(struct vfio_device *vdev, unsigned int index,
			 unsigned int start, unsigned int count, u32 flags,
			 void *data)
{
	struct vfio_ims *ims = &vdev->ims;
	int i, rc = 0;

	if (count > ims->num)
		count = ims->num;

	if (!count && (flags & VFIO_IRQ_SET_DATA_NONE)) {
		vfio_ims_disable(ims);
		return 0;
	}

	if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
		int *fds = data;

		if (ims->irq_type == index)
			return vfio_ims_set_vector_signals(ims, start, count, fds);

		rc = vfio_ims_enable(ims, start + count);
		if (rc < 0)
			return rc;

		rc = vfio_ims_set_vector_signals(ims, start, count, fds);
		if (rc < 0)
			vfio_ims_disable(ims);

		return rc;
	}

	if (start + count > ims->num)
		return -EINVAL;

	for (i = start; i < start + count; i++) {
		if (!ims->ims_entries[i].trigger)
			continue;
		if (flags & VFIO_IRQ_SET_DATA_NONE) {
			eventfd_signal(ims->ims_entries[i].trigger, 1);
		} else if (flags & VFIO_IRQ_SET_DATA_BOOL) {
			u8 *bools = data;

			if (bools[i - start])
				eventfd_signal(ims->ims_entries[i].trigger, 1);
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(vfio_set_ims_trigger);

/*
 * Initialize and setup the ims context under vfio device.
 *
 * @vdev [in]		: vfio device
 * @num [in]		: number of vectors
 * @ims_map [in]	: bool array that indicates whether a guest MSIX vector is
 *			  backed by an IMS vector or emulated
 * Return error code on failure or 0 on success.
 */
int vfio_ims_init(struct vfio_device *vdev, int num, bool *ims_map)
{
	struct vfio_ims *ims = &vdev->ims;
	int i;

	if (num < 1)
		return -EINVAL;

	ims->irq_type = VFIO_PCI_NUM_IRQS;
	ims->num = num;
	ims->ims_entries = kcalloc(num, sizeof(*ims->ims_entries), GFP_KERNEL);
	if (!ims->ims_entries)
		return -ENOMEM;

	for (i = 0; i < num; i++) {
		ims->ims_entries[i].ims = ims_map[i];
		if (ims_map[i]) {
			ims->ims_entries[i].ims_id = ims->ims_num;
			ims->ims_num++;
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(vfio_ims_init);

/*
 * Free allocated memory in ims context
 *
 * @vdev [in]		: vfio device
 */
void vfio_ims_free(struct vfio_device *vdev)
{
	kfree(vdev->ims.ims_entries);
	memset(&vdev->ims, 0, sizeof(vdev->ims));
}
EXPORT_SYMBOL_GPL(vfio_ims_free);

MODULE_LICENSE("GPL v2");
