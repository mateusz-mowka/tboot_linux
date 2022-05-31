// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 Intel Corporation. All rights rsvd. */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/vfio.h>
#include <linux/iommufd.h>
#include "registers.h"
#include "idxd.h"
#include "vidxd.h"

enum {
	IDXD_VDEV_TYPE_1DWQ = 0,
	IDXD_VDEV_TYPE_MAX
};

static int idxd_vdcm_open(struct vfio_device *vdev)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	struct idxd_device *idxd = vidxd->wq->idxd;
	struct device *dev = vdev->dev;
	struct device *pasid_dev = &idxd->pdev->dev;
	ioasid_t pasid;

	if (!device_user_pasid_enabled(idxd))
		return -ENODEV;

	pasid = ioasid_alloc(NULL, 1, pasid_dev->iommu->max_pasids, vidxd, 0);
	if (pasid == INVALID_IOASID) {
		dev_err(dev, "Unable to allocate pasid\n");
		return -ENODEV;
	}

	mutex_lock(&vidxd->dev_lock);
	vidxd->pasid = pasid;
	vfio_device_set_pasid(vdev, pasid);
	vidxd_init(vidxd);
	mutex_unlock(&vidxd->dev_lock);
	return 0;
}

static void idxd_vdcm_close(struct vfio_device *vdev)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);

	mutex_lock(&vidxd->dev_lock);
	vidxd_shutdown(vidxd);
	vfio_device_set_pasid(vdev, IOMMU_PASID_INVALID);
	ioasid_put(NULL, vidxd->pasid);
	mutex_unlock(&vidxd->dev_lock);
}

static int idxd_vdcm_bind_iommufd(struct vfio_device *vdev,
				  struct vfio_device_bind_iommufd *bind)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	struct idxd_device *idxd = vidxd->idxd;
	struct iommufd_device *idev;
	int rc = 0;
	u32 id;

	mutex_lock(&vidxd->dev_lock);

	/* Allow only one iommufd per vfio_device */
	if (vidxd->idev) {
		rc = -EBUSY;
		goto out;
	}

	idev = iommufd_bind_device(bind->iommufd, idxd->pdev,
				       IOMMUFD_BIND_FLAGS_BYPASS_DMA_OWNERSHIP, &id);
	if (IS_ERR(idev)) {
		rc = PTR_ERR(idev);
		goto out;
	}

	vidxd->iommufd = bind->iommufd;
	vidxd->idev = idev;
	bind->out_devid = id;

out:
	mutex_unlock(&vidxd->dev_lock);
	return rc;
}

static void idxd_vdcm_unbind_iommufd(struct vfio_device *vdev)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);

	mutex_lock(&vidxd->dev_lock);
	if (vidxd->idev) {
		iommufd_device_detach(vidxd->idev, vidxd->pt_id);
		iommufd_unbind_device(vidxd->idev);
		vidxd->idev = NULL;
	}
	mutex_unlock(&vidxd->dev_lock);
}

static int idxd_vdcm_attach_ioas(struct vfio_device *vdev,
				 struct vfio_device_attach_ioas *attach)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	u32 pasid, pt_id = attach->ioas_id;
	int rc = 0;

	mutex_lock(&vidxd->dev_lock);

	if (!vidxd->idev || vidxd->iommufd != attach->iommufd) {
		rc = -EINVAL;
		goto out;
	}

	pasid = vfio_device_get_pasid(vdev);
	if (pasid == IOMMU_PASID_INVALID) {
		rc = -ENODEV;
		goto out;
	}

	rc = iommufd_device_attach_pasid(vidxd->idev, &pt_id, pasid,
					 IOMMUFD_ATTACH_FLAGS_ALLOW_UNSAFE_INTERRUPT);
	if (rc)
		goto out;

	WARN_ON(attach->ioas_id == pt_id);
	vidxd->pt_id = pt_id;
	attach->out_hwpt_id = pt_id;

out:
	mutex_unlock(&vidxd->dev_lock);
	return rc;
}

static ssize_t idxd_vdcm_rw(struct vfio_device *vdev, char *buf, size_t count,
			    loff_t *ppos, int mode)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	u64 pos = *ppos & VFIO_PCI_OFFSET_MASK;
	struct device *dev = vdev->dev;
	int rc = -EINVAL;

	if (index >= VFIO_PCI_NUM_REGIONS) {
		dev_err(dev, "invalid index: %u\n", index);
		return -EINVAL;
	}

	switch (index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		if (mode == IDXD_VDCM_WRITE)
			rc = vidxd_cfg_write(vidxd, pos, buf, count);
		else
			rc = vidxd_cfg_read(vidxd, pos, buf, count);
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
	case VFIO_PCI_BAR1_REGION_INDEX:
		if (mode == IDXD_VDCM_WRITE)
			rc = vidxd_mmio_write(vidxd, vidxd->bar_val[0] + pos, buf, count);
		else
			rc = vidxd_mmio_read(vidxd, vidxd->bar_val[0] + pos, buf, count);
		break;
	case VFIO_PCI_BAR2_REGION_INDEX:
	case VFIO_PCI_BAR3_REGION_INDEX:
	case VFIO_PCI_BAR4_REGION_INDEX:
	case VFIO_PCI_BAR5_REGION_INDEX:
	case VFIO_PCI_VGA_REGION_INDEX:
	case VFIO_PCI_ROM_REGION_INDEX:
	default:
		dev_err(dev, "unsupported region: %u\n", index);
	}

	return rc == 0 ? count : rc;
}

static ssize_t idxd_vdcm_read(struct vfio_device *vdev, char __user *buf, size_t count,
			      loff_t *ppos)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	unsigned int done = 0;
	int rc;

	mutex_lock(&vidxd->dev_lock);
	while (count) {
		size_t filled;

		if (count >= 4 && !(*ppos % 4)) {
			u32 val;

			rc = idxd_vdcm_rw(vdev, (char *)&val, sizeof(val),
					  ppos, IDXD_VDCM_READ);
			if (rc <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			rc = idxd_vdcm_rw(vdev, (char *)&val, sizeof(val),
					  ppos, IDXD_VDCM_READ);
			if (rc <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 2;
		} else {
			u8 val;

			rc = idxd_vdcm_rw(vdev, &val, sizeof(val), ppos,
					  IDXD_VDCM_READ);
			if (rc <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 1;
		}

		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	mutex_unlock(&vidxd->dev_lock);
	return done;

 read_err:
	mutex_unlock(&vidxd->dev_lock);
	return -EFAULT;
}

static ssize_t idxd_vdcm_write(struct vfio_device *vdev, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct vdcm_idxd *vidxd = vdev_to_vidxd(vdev);
	unsigned int done = 0;
	int rc;

	mutex_lock(&vidxd->dev_lock);
	while (count) {
		size_t filled;

		if (count >= 4 && !(*ppos % 4)) {
			u32 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = idxd_vdcm_rw(vdev, (char *)&val, sizeof(val),
					  ppos, IDXD_VDCM_WRITE);
			if (rc <= 0)
				goto write_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = idxd_vdcm_rw(vdev, (char *)&val,
					  sizeof(val), ppos, IDXD_VDCM_WRITE);
			if (rc <= 0)
				goto write_err;

			filled = 2;
		} else {
			u8 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			rc = idxd_vdcm_rw(vdev, &val, sizeof(val),
					  ppos, IDXD_VDCM_WRITE);
			if (rc <= 0)
				goto write_err;

			filled = 1;
		}

		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	mutex_unlock(&vidxd->dev_lock);
	return done;

write_err:
	mutex_unlock(&vidxd->dev_lock);
	return -EFAULT;
}

static int idxd_vdcm_mmap(struct vfio_device *vdev, struct vm_area_struct *vma)
{
	unsigned int wq_idx;
	unsigned long req_size, pgoff = 0, offset;
	pgprot_t pg_prot;
	struct vdcm_idxd *vidxd = container_of(vdev, struct vdcm_idxd, vdev);
	struct idxd_wq *wq = vidxd->wq;
	struct idxd_device *idxd = vidxd->idxd;
	enum idxd_portal_prot virt_portal, phys_portal;
	phys_addr_t base = pci_resource_start(idxd->pdev, IDXD_WQ_BAR);
	struct device *dev = vidxd_dev(vidxd);

	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	pg_prot = vma->vm_page_prot;
	req_size = vma->vm_end - vma->vm_start;
	if (req_size > PAGE_SIZE)
		return -EINVAL;

	vma->vm_flags |= VM_DONTCOPY;

	offset = (vma->vm_pgoff << PAGE_SHIFT) &
		 ((1ULL << VFIO_PCI_OFFSET_SHIFT) - 1);

	wq_idx = offset >> (PAGE_SHIFT + 2);
	if (wq_idx >= 1) {
		dev_err(dev, "mapping invalid wq %d off %lx\n",
			wq_idx, offset);
		return -EINVAL;
	}

	/*
	 * Check and see if the guest wants to map to the limited or unlimited portal.
	 * The driver will allow mapping to unlimited portal only if the wq is a
	 * dedicated wq. Otherwise, it goes to limited.
	 */
	virt_portal = ((offset >> PAGE_SHIFT) & 0x3) == 1;
	phys_portal = IDXD_PORTAL_LIMITED;
	if (virt_portal == IDXD_PORTAL_UNLIMITED && wq_dedicated(wq))
		phys_portal = IDXD_PORTAL_UNLIMITED;

	/* We always map IMS portals to the guest */
	pgoff = (base + idxd_get_wq_portal_offset(wq->id, phys_portal,
						  IDXD_IRQ_IMS)) >> PAGE_SHIFT;

	dev_dbg(dev, "mmap %lx %lx %lx %lx\n", vma->vm_start, pgoff, req_size,
		pgprot_val(pg_prot));
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_pgoff = pgoff;

	return remap_pfn_range(vma, vma->vm_start, pgoff, req_size, pg_prot);
}

static const struct vfio_device_ops idxd_vdev_ops = {
	.name = "vfio-vdev",
	.open_device = idxd_vdcm_open,
	.close_device = idxd_vdcm_close,
	.bind_iommufd = idxd_vdcm_bind_iommufd,
	.unbind_iommufd = idxd_vdcm_unbind_iommufd,
	.attach_ioas = idxd_vdcm_attach_ioas,
	.read = idxd_vdcm_read,
	.write = idxd_vdcm_write,
	.mmap = idxd_vdcm_mmap,
};

static struct idxd_wq *find_wq_by_type(struct idxd_device *idxd, u32 type)
{
	struct idxd_wq *wq;
	bool found = false;
	int i;

	for (i = 0; i < idxd->max_wqs; i++) {
		wq = idxd->wqs[i];

		mutex_lock(&wq->wq_lock);

		if (wq->type != IDXD_WQT_VDEV) {
			mutex_unlock(&wq->wq_lock);
			continue;
		}

		if (wq->state != IDXD_WQ_ENABLED) {
			mutex_unlock(&wq->wq_lock);
			continue;
		}

		if (type == IDXD_VDEV_TYPE_1DWQ && wq_dedicated(wq) &&
		    !idxd_wq_refcount(wq)) {
			found = true;
			break;
		}
		mutex_unlock(&wq->wq_lock);
	}

	if (found) {
		idxd_wq_get(wq);
		mutex_unlock(&wq->wq_lock);
		return wq;
	}

	return NULL;
}

static int idxd_vfio_dev_drv_probe(struct idxd_dev *idxd_dev)
{
	bool ims_map[VIDXD_MAX_MSIX_VECS];
	struct vdcm_idxd *vidxd;
	struct idxd_device *idxd;
	struct idxd_wq *wq;
	int rc;

	idxd = idxd_dev->idxd;
	wq = find_wq_by_type(idxd, idxd_dev->vdev_type);
	if (!wq)
		return -ENODEV;

	vidxd = vfio_alloc_device(vdcm_idxd, vdev, &idxd_dev->conf_dev, &idxd_vdev_ops);
	if (!vidxd) {
		rc = -ENOMEM;
		goto err_vfio_dev;
	}

	ims_map[0] = false;
	ims_map[1] = true;
	rc = vfio_ims_init(&vidxd->vdev, VIDXD_MAX_MSIX_VECS, ims_map);
	if (rc < 0)
		goto err_ims;

	mutex_init(&vidxd->dev_lock);
	vidxd->wq = wq;
	vidxd->idxd = wq->idxd;
	vidxd->parent = idxd_dev;

	/* Set the IMS domain to the vfio_device 'struct device' */
	vfio_device_set_msi_domain(&vidxd->vdev, wq->idxd->ims_domain);

	rc = vfio_register_emulated_iommu_dev(&vidxd->vdev);
	if (rc < 0)
		goto err_vfio_register;

	dev_set_drvdata(&idxd_dev->conf_dev, vidxd);
	return 0;

err_vfio_register:
	vfio_ims_free(&vidxd->vdev);
err_ims:
	vfio_put_device(&vidxd->vdev);
err_vfio_dev:
	mutex_lock(&wq->wq_lock);
	idxd_wq_put(wq);
	mutex_unlock(&wq->wq_lock);
	return rc;
}

static void idxd_vfio_dev_drv_remove(struct idxd_dev *idxd_dev)
{
	struct vdcm_idxd *vidxd = dev_get_drvdata(&idxd_dev->conf_dev);
	struct vfio_device *vdev = &vidxd->vdev;
	struct idxd_wq *wq = vidxd->wq;

	vfio_unregister_group_dev(vdev);
	vfio_ims_free(vdev);
	vfio_put_device(vdev);
	mutex_lock(&wq->wq_lock);
	idxd_wq_put(wq);
	mutex_unlock(&wq->wq_lock);
}

static enum idxd_dev_type idxd_vfio_dev_types[] = {
	IDXD_DEV_VDEV,
	IDXD_DEV_NONE,
};

static struct idxd_device_driver idxd_vfio_dev_driver = {
	.probe = idxd_vfio_dev_drv_probe,
	.remove = idxd_vfio_dev_drv_remove,
	.name = "idxd_vfio",
	.type = idxd_vfio_dev_types,
};

static void idxd_vdev_release(struct device *dev)
{
	struct idxd_dev *idev = container_of(dev, struct idxd_dev, conf_dev);

	kfree(idev);
}

struct device_type idxd_vdev_device_type = {
	.name = "vdev",
	.release = idxd_vdev_release,
};

static int vdev_device_create(struct idxd_device *idxd, u32 type)
{
	struct idxd_dev *parent;
	struct device *dev;
	int rc;

	lockdep_assert_held(&idxd->vdev_lock);

	if (type >= IDXD_VDEV_TYPE_MAX)
		return -EINVAL;

	parent = kzalloc(sizeof(*parent), GFP_KERNEL);
	if (!parent)
		return -ENOMEM;

	idxd_dev_set_type(parent, IDXD_DEV_VDEV);
	dev = &parent->conf_dev;
	device_initialize(dev);
	dev->parent = idxd_confdev(idxd);
	dev->bus = &dsa_bus_type;
	dev->type = &idxd_vdev_device_type;

	/*
	 * Here it's set to vdev0, however, with swq support, this needs an
	 * ida to enumerate the devices.
	 */
	parent->id = 0;
	rc = dev_set_name(dev, "vdev%u", parent->id);
	if (rc < 0) {
		put_device(dev);
		return rc;
	}
	parent->vdev_type = type;
	parent->idxd = idxd;

	rc = device_add(dev);
	if (rc < 0) {
		put_device(dev);
		return rc;
	}

	list_add_tail(&parent->list, &idxd->vdev_list);

	return 0;
}


static int vdev_device_remove(struct idxd_device *idxd, int id)
{
	struct idxd_dev *pos, *n;

	lockdep_assert_held(&idxd->vdev_lock);

	list_for_each_entry_safe(pos, n, &idxd->vdev_list, list) {
		if (pos->id == id) {
			list_del(&pos->list);
			device_unregister(&pos->conf_dev);
			return 0;
		}
	}

	return -ENODEV;
}

struct vdev_device_ops vidxd_device_ops = {
	.device_create = vdev_device_create,
	.device_remove = vdev_device_remove,
};

static int idxd_vdev_drv_probe(struct idxd_dev *idxd_dev)
{
	struct device *dev = &idxd_dev->conf_dev;
	struct idxd_wq *wq = idxd_dev_to_wq(idxd_dev);
	struct idxd_device *idxd = wq->idxd;
	int rc;

	if (!is_idxd_wq_dev(idxd_dev))
		return -ENODEV;

	if (idxd->state != IDXD_DEV_ENABLED)
		return -ENXIO;

	mutex_lock(&wq->wq_lock);
	if (!idxd_wq_driver_name_match(wq, dev)) {
		idxd->cmd_status = IDXD_SCMD_WQ_NO_DRV_NAME;
		rc = -ENODEV;
		goto err_drv_name;
	}

	wq->type = IDXD_WQT_VDEV;
	rc = __drv_enable_wq(wq);
	if (rc < 0)
		goto err_enable_wq;

	idxd->cmd_status = 0;

	mutex_lock(&idxd->vdev_lock);
	idxd->vdev_ops = &vidxd_device_ops;
	mutex_unlock(&idxd->vdev_lock);

	mutex_unlock(&wq->wq_lock);
	return 0;

err_enable_wq:
err_drv_name:
	wq->type = IDXD_WQT_NONE;
	mutex_unlock(&wq->wq_lock);
	return rc;
}

static void idxd_vdev_drv_remove(struct idxd_dev *idxd_dev)
{
	struct idxd_wq *wq = idxd_dev_to_wq(idxd_dev);

	mutex_lock(&wq->wq_lock);
	__drv_disable_wq(wq);
	wq->type = IDXD_WQT_NONE;
	mutex_unlock(&wq->wq_lock);
}

static enum idxd_dev_type dev_types[] = {
	IDXD_DEV_WQ,
	IDXD_DEV_NONE
};

static struct idxd_device_driver idxd_vdev_driver = {
	.probe = idxd_vdev_drv_probe,
	.remove = idxd_vdev_drv_remove,
	.name = "vdev",
	.type = dev_types,
};

static int __init idxd_vdev_init(void)
{
	int rc;

	rc = idxd_driver_register(&idxd_vdev_driver);
	if (rc < 0)
		return rc;

	rc = idxd_driver_register(&idxd_vfio_dev_driver);
	if (rc < 0) {
		idxd_driver_unregister(&idxd_vdev_driver);
		return rc;
	}

	return 0;
}

static void __exit idxd_vdev_exit(void)
{
	idxd_driver_unregister(&idxd_vfio_dev_driver);
	idxd_driver_unregister(&idxd_vdev_driver);
}

module_init(idxd_vdev_init);
module_exit(idxd_vdev_exit);

MODULE_IMPORT_NS(IDXD);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Intel Corporation");
MODULE_ALIAS_IDXD_DEVICE(0);
