// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES
 */
#include <linux/vfio.h>
#include <linux/iommufd.h>

#include "vfio.h"

MODULE_IMPORT_NS(IOMMUFD);
MODULE_IMPORT_NS(IOMMUFD_VFIO);

/* @pt_id == NULL impplies detach */
int vfio_iommufd_attach(struct vfio_device *vdev, u32 *pt_id)
{
	lockdep_assert_held(&vdev->dev_set->lock);

	return vdev->ops->attach_ioas(vdev, pt_id);
}

int vfio_iommufd_attach_pasid(struct vfio_device *vdev, u32 *pt_id,
			      ioasid_t pasid)
{
	lockdep_assert_held(&vdev->dev_set->lock);

	return vdev->ops->attach_hwpt(vdev, pt_id, pasid);
}

int vfio_iommufd_bind(struct vfio_device *vdev, struct iommufd_ctx *ictx,
		      u32 *dev_id, u32 *pt_id)
{
	u32 device_id;
	int ret;

	lockdep_assert_held(&vdev->dev_set->lock);

	/*
	 * If the driver doesn't provide this op then it means the device does
	 * not do DMA at all. So nothing to do.
	 */
	if (!vdev->ops->bind_iommufd)
		return 0;

	ret = vdev->ops->bind_iommufd(vdev, ictx, &device_id);
	if (ret)
		return ret;

	if (pt_id) {
		ret = vfio_iommufd_attach(vdev, pt_id);
		if (ret)
			goto err_unbind;
	}

	if (dev_id)
		*dev_id = device_id;
	return 0;

err_unbind:
	if (vdev->ops->unbind_iommufd)
		vdev->ops->unbind_iommufd(vdev);
	return ret;
}

void vfio_iommufd_unbind(struct vfio_device *vdev)
{
	lockdep_assert_held(&vdev->dev_set->lock);

	if (vdev->ops->unbind_iommufd)
		vdev->ops->unbind_iommufd(vdev);
}

/*
 * The physical standard ops mean that the iommufd_device is bound to the
 * physical device vdev->dev that was provided to vfio_init_group_dev(). Drivers
 * using this ops set should call vfio_register_group_dev()
 */
int vfio_iommufd_physical_bind(struct vfio_device *vdev,
			       struct iommufd_ctx *ictx, u32 *out_device_id)
{
	struct iommufd_device *idev;

	idev = iommufd_device_bind(ictx, vdev->dev, out_device_id, 0);
	if (IS_ERR(idev))
		return PTR_ERR(idev);
	vdev->iommufd_device = idev;
	return 0;
}
EXPORT_SYMBOL_GPL(vfio_iommufd_physical_bind);

static void __vfio_iommufd_detach(struct vfio_device *vdev)
{
	iommufd_device_detach(vdev->iommufd_device, INVALID_IOASID);
	vdev->iommufd_attached = false;
}

void vfio_iommufd_physical_unbind(struct vfio_device *vdev)
{
	lockdep_assert_held(&vdev->dev_set->lock);

	if (vdev->iommufd_attached)
		__vfio_iommufd_detach(vdev);
	iommufd_device_unbind(vdev->iommufd_device);
	vdev->iommufd_device = NULL;
}
EXPORT_SYMBOL_GPL(vfio_iommufd_physical_unbind);

int vfio_iommufd_physical_attach_ioas(struct vfio_device *vdev, u32 *pt_id)
{
	int rc;

	lockdep_assert_held(&vdev->dev_set->lock);

	if (!vdev->iommufd_device)
		return -EINVAL;

	if (!pt_id) {
		if (vdev->iommufd_attached)
			__vfio_iommufd_detach(vdev);
		return 0;
	}

	if (vdev->iommufd_attached)
		return -EBUSY;

	rc = iommufd_device_attach(vdev->iommufd_device, pt_id, INVALID_IOASID);
	if (rc)
		return rc;
	vdev->iommufd_attached = true;
	return 0;
}
EXPORT_SYMBOL_GPL(vfio_iommufd_physical_attach_ioas);

static void __vfio_iommufd_detach_hwpt(struct vfio_device *vdev, ioasid_t pasid)
{
	struct vfio_pci_hwpt *hwpt;

	/* userspace needs to detach a hwpt before attaching a new */
	hwpt = xa_load(&vdev->pasid_xa, pasid);
	if (!hwpt)
		return;
	xa_erase(&vdev->pasid_xa, hwpt->pasid);
	iommufd_device_detach(vdev->iommufd_device, pasid);
	kfree(hwpt);
}

int vfio_iommufd_physical_attach_hwpt(struct vfio_device *vdev, u32 *pt_id,
				      ioasid_t pasid)
{
	int rc;
	struct vfio_pci_hwpt *hwpt, *tmp;

	lockdep_assert_held(&vdev->dev_set->lock);

	if (!vdev->iommufd_device)
		return -EINVAL;

	if (!pt_id) {
		__vfio_iommufd_detach_hwpt(vdev, pasid);
		return 0;
	}

	/* userspace needs to detach a hwpt before attaching a new */
	hwpt = xa_load(&vdev->pasid_xa, pasid);
	if (hwpt)
		return -EBUSY;

	hwpt = kzalloc(sizeof(*hwpt), GFP_KERNEL);
	if (!hwpt)
		return -ENOMEM;

	rc = iommufd_device_attach(vdev->iommufd_device, pt_id, pasid);
	if (rc)
		goto out_free;

	hwpt->hwpt_id = *pt_id;
	hwpt->pasid = pasid;
	tmp = xa_store(&vdev->pasid_xa, hwpt->pasid, hwpt, GFP_KERNEL);
	if (IS_ERR(tmp)) {
		rc = PTR_ERR(tmp);
		goto out_detach;
	}

	return 0;

out_detach:
	iommufd_device_detach(vdev->iommufd_device, hwpt->pasid);
out_free:
	kfree(hwpt);

	return rc;
}
EXPORT_SYMBOL_GPL(vfio_iommufd_physical_attach_hwpt);

/*
 * The emulated standard ops mean that vfio_device is going to use the
 * "mdev path" and will call vfio_pin_pages()/vfio_dma_rw(). Drivers using this
 * ops set should call vfio_register_emulated_iommu_dev().
 */

static void vfio_emulated_unmap(void *data, unsigned long iova,
				unsigned long length)
{
	struct vfio_device *vdev = data;

	vdev->ops->dma_unmap(vdev, iova, length);
}

static const struct iommufd_access_ops vfio_user_ops = {
	.needs_pin_pages = 1,
	.unmap = vfio_emulated_unmap,
};

int vfio_iommufd_emulated_bind(struct vfio_device *vdev,
			       struct iommufd_ctx *ictx, u32 *out_device_id)
{
	lockdep_assert_held(&vdev->dev_set->lock);

	vdev->iommufd_ictx = ictx;
	iommufd_ctx_get(ictx);
	return 0;
}
EXPORT_SYMBOL_GPL(vfio_iommufd_emulated_bind);

static void __vfio_iommufd_access_destroy(struct vfio_device *vdev)
{
	iommufd_access_destroy(vdev->iommufd_access);
	vdev->iommufd_access = NULL;
}

void vfio_iommufd_emulated_unbind(struct vfio_device *vdev)
{
	lockdep_assert_held(&vdev->dev_set->lock);

	if (vdev->iommufd_access)
		__vfio_iommufd_access_destroy(vdev);
	iommufd_ctx_put(vdev->iommufd_ictx);
	vdev->iommufd_ictx = NULL;
}
EXPORT_SYMBOL_GPL(vfio_iommufd_emulated_unbind);

int vfio_iommufd_emulated_attach_ioas(struct vfio_device *vdev, u32 *pt_id)
{
	struct iommufd_access *user;

	lockdep_assert_held(&vdev->dev_set->lock);

	if (!vdev->iommufd_ictx)
		return -EINVAL;

	if (!pt_id) {
		if (vdev->iommufd_access)
			__vfio_iommufd_access_destroy(vdev);
		return 0;
	}

	if (vdev->iommufd_access)
		return -EBUSY;

	user = iommufd_access_create(vdev->iommufd_ictx, *pt_id, &vfio_user_ops,
				     vdev);
	if (IS_ERR(user))
		return PTR_ERR(user);
	vdev->iommufd_access = user;
	return 0;
}
EXPORT_SYMBOL_GPL(vfio_iommufd_emulated_attach_ioas);
