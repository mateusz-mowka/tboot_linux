// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES
 */
#include <linux/iommu.h>
#include <uapi/linux/iommufd.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/circ_buf.h>
#include <linux/eventfd.h>

#include "iommufd_private.h"

static void
iommufd_hw_pagetable_dma_fault_destroy(struct iommufd_hw_pagetable *hwpt);
static int
iommufd_hw_pagetable_dma_fault_init(struct iommufd_hw_pagetable *hwpt,
				    int eventfd);
static enum iommu_page_response_code
iommufd_hw_pagetable_iopf_handler(struct iommu_fault *fault,
				  void *data);

void iommufd_hw_pagetable_destroy(struct iommufd_object *obj)
{
	struct iommufd_hw_pagetable *hwpt =
		container_of(obj, struct iommufd_hw_pagetable, obj);

	WARN_ON(!list_empty(&hwpt->devices));

	iommu_domain_free(hwpt->domain);
	refcount_dec(&hwpt->ioas->obj.users);
	if (hwpt->parent) {
		kfree(hwpt->cache);
		refcount_dec(&hwpt->parent->obj.users);
		/* parent is valid so this is s1 hwpt which need be destroyed */
		iommufd_hw_pagetable_dma_fault_destroy(hwpt);
	} else {
		WARN_ON(!refcount_dec_if_one(hwpt->devices_users));
		mutex_destroy(hwpt->devices_lock);
		kfree(hwpt->devices_lock);
	}
}

static struct iommufd_hw_pagetable *
__iommufd_hw_pagetable_alloc(struct iommufd_ctx *ictx, struct device *dev,
			     struct iommufd_ioas *ioas, u32 data_type,
			     struct iommufd_hw_pagetable *parent,
			     void *user_data, size_t data_len,
			     struct iommu_hwpt_user_data __user *uptr)
{
	struct iommu_domain *parent_domain = NULL;
	struct iommufd_hw_pagetable *hwpt;
	struct iommu_hwpt_user_data *data =
			(struct iommu_hwpt_user_data *)user_data;
	void *config_data = NULL;
	int rc;

	if (WARN_ON(!parent && !ioas))
		return ERR_PTR(-EINVAL);

	if (data && data->config_len) {
		config_data = kzalloc(data->config_len, GFP_KERNEL);
		if (!config_data)
			return ERR_PTR(-ENOMEM);

		rc = copy_struct_from_user(config_data, data->config_len,
					   (void __user *)data->config_uptr,
					   data->config_len);
		if (rc) {
			kfree(config_data);
			return ERR_PTR(rc);
		}

		data_len = data->config_len;
	}

	hwpt = iommufd_object_alloc(ictx, hwpt, IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(hwpt))
		return hwpt;

	hwpt->fault = NULL;

	if (parent)
		parent_domain = parent->domain;

	hwpt->domain = iommu_domain_alloc_user(dev, data_type, parent_domain,
					       config_data, data_len);
	if (!hwpt->domain) {
		rc = -ENOMEM;
		goto out_abort;
	}

	INIT_LIST_HEAD(&hwpt->devices);
	INIT_LIST_HEAD(&hwpt->hwpt_item);
	hwpt->parent = parent;
	if (parent) {
		if (data && uptr) {
			rc = iommufd_hw_pagetable_dma_fault_init(hwpt, data->eventfd);
			if (rc)
				goto out_free_domain;

			rc = put_user((__s32)hwpt->fault->fault_fd, &uptr->out_fault_fd);
			if (rc)
				goto out_destroy_dma_fault;

			hwpt->domain->iopf_handler = iommufd_hw_pagetable_iopf_handler;
			hwpt->domain->fault_data = hwpt;
		}

		/* Always reuse parent's devices_lock and devices_users... */
		hwpt->devices_lock = parent->devices_lock;
		hwpt->devices_users = parent->devices_users;
		refcount_inc(&parent->obj.users);
	} else {
		/* ...otherwise, allocate a new pair */
		hwpt->devices_lock = kzalloc(sizeof(*hwpt->devices_lock) +
					     sizeof(*hwpt->devices_users),
					     GFP_KERNEL);
		if (!hwpt->devices_lock) {
			rc = -ENOMEM;
			goto out_free_domain;
		}
		mutex_init(hwpt->devices_lock);
		hwpt->devices_users = (refcount_t *)&hwpt->devices_lock[1];
		refcount_set(hwpt->devices_users, 1);
	}

	/* Pairs with iommufd_hw_pagetable_destroy() */
	refcount_inc(&ioas->obj.users);
	hwpt->ioas = ioas;
	return hwpt;

out_destroy_dma_fault:
	iommufd_hw_pagetable_dma_fault_destroy(hwpt);
out_free_domain:
	iommu_domain_free(hwpt->domain);
out_abort:
	iommufd_object_abort(ictx, &hwpt->obj);
	return ERR_PTR(rc);
}

/**
 * iommufd_hw_pagetable_alloc() - Get an iommu_domain for a device
 * @ictx: iommufd context
 * @ioas: IOAS to associate the domain with
 * @dev: Device to get an iommu_domain for
 *
 * Allocate a new iommu_domain and return it as a hw_pagetable.
 */
struct iommufd_hw_pagetable *
iommufd_hw_pagetable_alloc(struct iommufd_ctx *ictx, struct iommufd_ioas *ioas,
			   struct device *dev)
{
	return __iommufd_hw_pagetable_alloc(ictx, dev, ioas,
					    IOMMU_DEVICE_DATA_NONE,
					    NULL, NULL, 0, NULL);
}

union iommufd_invalidate_buffer {
	struct iommu_hwpt_invalidate_intel_vtd vtd;
};

int iommufd_hwpt_alloc(struct iommufd_ucmd *ucmd)
{
	struct iommufd_hw_pagetable *hwpt, *parent = NULL;
	struct iommu_hwpt_alloc *cmd = ucmd->cmd;
	struct iommufd_ctx *ictx = ucmd->ictx;
	struct iommufd_object *pt_obj = NULL;
	struct iommufd_ioas *ioas = NULL;
	struct iommufd_device *idev;
	struct iommu_hwpt_user_data __user *uptr = (void __user *)cmd->data_uptr;
	void *data = NULL, *cache = NULL;
	int rc;

	if (cmd->__reserved || cmd->flags ||
	    cmd->data_len > PAGE_SIZE)
		return -EOPNOTSUPP;

	idev = iommufd_device_get_by_id(ictx, cmd->dev_id);
	if (IS_ERR(idev))
		return PTR_ERR(idev);

	pt_obj = iommufd_get_object(ictx, cmd->pt_id, IOMMUFD_OBJ_ANY);
	if (IS_ERR(pt_obj)) {
		rc = -EINVAL;
		goto out_put_dev;
	}

	switch (pt_obj->type) {
	case IOMMUFD_OBJ_HW_PAGETABLE:
		parent = container_of(pt_obj, struct iommufd_hw_pagetable, obj);
		if (parent->auto_domain) {
			rc = -EINVAL;
			goto out_put_pt;
		}
		ioas = parent->ioas;
		break;
	case IOMMUFD_OBJ_IOAS:
		ioas = container_of(pt_obj, struct iommufd_ioas, obj);
		break;
	default:
		rc = -EINVAL;
		goto out_put_pt;
	}

	if (cmd->data_len && cmd->data_type != IOMMU_DEVICE_DATA_NONE) {
		data = kzalloc(cmd->data_len, GFP_KERNEL);
		if (!data) {
			rc = -ENOMEM;
			goto out_put_pt;
		}

		cache = kzalloc(sizeof(union iommufd_invalidate_buffer),
				GFP_KERNEL);
		if (!cache) {
			rc = -ENOMEM;
			goto out_free_data;
		}

		rc = copy_struct_from_user(data, cmd->data_len,
					   (void __user *)cmd->data_uptr,
					   cmd->data_len);
		if (rc)
			goto out_free_cache;
	}

	mutex_lock(&ioas->mutex);
	hwpt = __iommufd_hw_pagetable_alloc(ictx, idev->dev, ioas,
					    cmd->data_type, parent,
					    data, cmd->data_len, uptr);
	mutex_unlock(&ioas->mutex);
	if (IS_ERR(hwpt)) {
		rc = PTR_ERR(hwpt);
		goto out_free_data;
	}

	cmd->out_hwpt_id = hwpt->obj.id;

	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_destroy_hwpt;

	hwpt->cache = cache;
	iommufd_object_finalize(ucmd->ictx, &hwpt->obj);
	kfree(data);
	iommufd_put_object(pt_obj);
	iommufd_put_object(&idev->obj);
	return 0;
out_destroy_hwpt:
	iommufd_object_abort_and_destroy(ucmd->ictx, &hwpt->obj);
out_free_cache:
	kfree(cache);
out_free_data:
	kfree(data);
out_put_pt:
	iommufd_put_object(pt_obj);
out_put_dev:
	iommufd_put_object(&idev->obj);
	return rc;
}

int iommufd_hwpt_invalidate(struct iommufd_ucmd *ucmd)
{
	struct iommu_hwpt_invalidate *cmd = ucmd->cmd;
	struct iommufd_hw_pagetable *hwpt;
	int rc = 0;

	/*
	 * No invalidation needed for type==IOMMU_DEVICE_DATA_NONE;
	 * data_len should not exceed the size of iommufd_invalidate_buffer.
	 */
	if (cmd->data_type == IOMMU_DEVICE_DATA_NONE ||
	    cmd->data_len > sizeof(union iommufd_invalidate_buffer))
		return -EOPNOTSUPP;

	hwpt = iommufd_get_hwpt(ucmd, cmd->hwpt_id);
	if (IS_ERR(hwpt))
		return PTR_ERR(hwpt);

	rc = copy_struct_from_user(hwpt->cache, cmd->data_len,
				   (void __user *)cmd->data_uptr,
				   cmd->data_len);
	if (rc)
		goto out_put_hwpt;

	iommu_iotlb_sync_user(hwpt->domain, hwpt->cache, cmd->data_len);
out_put_hwpt:
	iommufd_put_object(&hwpt->obj);
	return rc;
}

int iommufd_hwpt_page_response(struct iommufd_ucmd *ucmd)
{
	struct iommu_hwpt_page_response *cmd = ucmd->cmd;
	struct iommufd_object *obj, *dev_obj;
	struct iommufd_hw_pagetable *hwpt;
	struct iommufd_device *idev;
	int rc = 0;

	if (cmd->flags)
		return -EOPNOTSUPP;

	/* TODO: more sanity check when the struct is finalized */
	obj = iommufd_get_object(ucmd->ictx, cmd->hwpt_id,
				 IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(obj))
		return PTR_ERR(obj);

	hwpt = container_of(obj, struct iommufd_hw_pagetable, obj);

	/* It is not s1 hwpt which doesn't support PRQ */
	if (!hwpt->parent) {
		rc = -EINVAL;
		goto out_put_hwpt;
	}

	dev_obj = iommufd_get_object(ucmd->ictx,
				     cmd->dev_id, IOMMUFD_OBJ_DEVICE);
	if (IS_ERR(dev_obj)) {
		rc = PTR_ERR(obj);
		goto out_put_hwpt;
	}

	idev = container_of(dev_obj, struct iommufd_device, obj);
	rc = iommu_page_response(idev->dev, &cmd->resp);
	iommufd_put_object(dev_obj);
out_put_hwpt:
	iommufd_put_object(obj);
	return rc;
}

static int iommufd_hw_pagetable_eventfd_setup(struct eventfd_ctx **ctx, int fd)
{
	struct eventfd_ctx *efdctx;

	efdctx = eventfd_ctx_fdget(fd);
	if (IS_ERR(efdctx))
		return PTR_ERR(efdctx);
	if (*ctx)
		eventfd_ctx_put(*ctx);
	*ctx = efdctx;
	return 0;
}

static void iommufd_hw_pagetable_eventfd_destroy(struct eventfd_ctx **ctx)
{
	eventfd_ctx_put(*ctx);
	*ctx = NULL;
}

static ssize_t hwpt_fault_fops_read(struct file *filep, char __user *buf,
				    size_t count, loff_t *ppos)
{
	struct iommufd_hw_pagetable *hwpt = filep->private_data;
	loff_t pos = *ppos;
	void *base;
	size_t size;
	int ret = -EFAULT;

	if (WARN_ON(!hwpt->fault))
		return -EINVAL;

	base = hwpt->fault->fault_pages;
	size = hwpt->fault->fault_region_size;

	if (pos >= size)
		return -EINVAL;

	count = min(count, (size_t)(size - pos));

	mutex_lock(&hwpt->fault->fault_queue_lock);
	if (!copy_to_user(buf, base + pos, count)) {
		*ppos += count;
		ret = count;
	}
	mutex_unlock(&hwpt->fault->fault_queue_lock);

	return ret;
}

static ssize_t hwpt_fault_fops_write(struct file *filep,
				     const char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct iommufd_hw_pagetable *hwpt = filep->private_data;
	loff_t pos = *ppos;
	void *base;
	struct iommufd_dma_fault *header;
	size_t size;
	u32 new_tail;
	int ret = -EFAULT;

	if (WARN_ON(!hwpt->fault))
		return -EINVAL;

	base = hwpt->fault->fault_pages;
	header = (struct iommufd_dma_fault *)base;
	size = hwpt->fault->fault_region_size;

	if (pos >= size)
		return -EINVAL;

	count = min(count, (size_t)(size - pos));

	mutex_lock(&hwpt->fault->fault_queue_lock);

	/* Only allows write to the tail which locates at offset 0 */
	if (pos != 0 || count != 4) {
		ret = -EINVAL;
		goto unlock;
	}

	if (copy_from_user((void *)&new_tail, buf, count))
		goto unlock;

	/* new tail should not exceed the maximum index */
	if (new_tail > header->nb_entries) {
		ret = -EINVAL;
		goto unlock;
	}

	/* update the tail value */
	header->tail = new_tail;
	ret = count;

unlock:
	mutex_unlock(&hwpt->fault->fault_queue_lock);
	return ret;
}

static const struct file_operations hwpt_fault_fops = {
	.owner		= THIS_MODULE,
	.read		= hwpt_fault_fops_read,
	.write		= hwpt_fault_fops_write,
};

static int iommufd_hw_pagetable_get_fault_fd(struct iommufd_hw_pagetable *hwpt)
{
	struct file *filep;
	int fdno, ret;

	if (WARN_ON(!hwpt->fault))
		return -EINVAL;

	fdno = ret = get_unused_fd_flags(O_CLOEXEC);
	if (ret < 0)
		return ret;

	filep = anon_inode_getfile("[hwpt-fault]", &hwpt_fault_fops,
				   hwpt, O_RDWR);
	if (IS_ERR(filep)) {
		put_unused_fd(fdno);
		return PTR_ERR(filep);
	}

	filep->f_mode |= (FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);
	fd_install(fdno, filep);

	hwpt->fault->fault_file = filep;
	hwpt->fault->fault_fd = fdno;

	return 0;
}

static enum iommu_page_response_code
iommufd_hw_pagetable_iopf_handler(struct iommu_fault *fault,
				  void *data)
{
	struct iommufd_hw_pagetable *hwpt =
				(struct iommufd_hw_pagetable *)data;
	struct iommufd_dma_fault *header;
	struct iommu_fault *new;
	int head, tail, size;
	enum iommu_page_response_code resp = IOMMU_PAGE_RESP_ASYNC;

	if (WARN_ON(!hwpt->fault))
		return IOMMU_PAGE_RESP_FAILURE;

	header = (struct iommufd_dma_fault *)hwpt->fault->fault_pages;

	if (WARN_ON(!header))
		return IOMMU_PAGE_RESP_FAILURE;

	mutex_lock(&hwpt->fault->fault_queue_lock);

	new = (struct iommu_fault *)(hwpt->fault->fault_pages + header->offset +
				     header->head * header->entry_size);

	pr_debug("%s, enque fault event\n", __func__);
	head = header->head;
	tail = header->tail;
	size = header->nb_entries;

	if (CIRC_SPACE(head, tail, size) < 1) {
		resp = IOMMU_PAGE_RESP_FAILURE;
		goto unlock;
	}

	*new = *fault;
	header->head = (head + 1) % size;
unlock:
	mutex_unlock(&hwpt->fault->fault_queue_lock);
	if (resp != IOMMU_PAGE_RESP_ASYNC)
		return resp;

	mutex_lock(&hwpt->fault->notify_gate);
	pr_debug("%s, signal userspace!\n", __func__);
	if (hwpt->fault->trigger)
		eventfd_signal(hwpt->fault->trigger, 1);
	mutex_unlock(&hwpt->fault->notify_gate);

	return resp;
}

#define DMA_FAULT_RING_LENGTH 512

static int
iommufd_hw_pagetable_dma_fault_init(struct iommufd_hw_pagetable *hwpt,
				    int eventfd)
{
	struct iommufd_dma_fault *header;
	size_t size;
	int rc;

	if (WARN_ON(hwpt->fault))
		return -EINVAL;

	hwpt->fault = kzalloc(sizeof(struct iommufd_fault), GFP_KERNEL);
	if (!hwpt->fault)
		return -ENOMEM;

	mutex_init(&hwpt->fault->fault_queue_lock);
	mutex_init(&hwpt->fault->notify_gate);

	/*
	 * We provision 1 page for the header and space for
	 * DMA_FAULT_RING_LENGTH fault records in the ring buffer.
	 */
	size = ALIGN(sizeof(struct iommu_fault) *
		     DMA_FAULT_RING_LENGTH, PAGE_SIZE) + PAGE_SIZE;

	hwpt->fault->fault_pages = kzalloc(size, GFP_KERNEL);
	if (!hwpt->fault->fault_pages)
		return -ENOMEM;

	header = (struct iommufd_dma_fault *)hwpt->fault->fault_pages;
	header->entry_size = sizeof(struct iommu_fault);
	header->nb_entries = DMA_FAULT_RING_LENGTH;
	header->offset = PAGE_SIZE;
	hwpt->fault->fault_region_size = size;

	rc = iommufd_hw_pagetable_eventfd_setup(&hwpt->fault->trigger, eventfd);
	if (rc)
		goto out_free;

	rc = iommufd_hw_pagetable_get_fault_fd(hwpt);
	if (rc)
		goto out_destroy_eventfd;

	return rc;

out_destroy_eventfd:
	iommufd_hw_pagetable_eventfd_destroy(&hwpt->fault->trigger);
out_free:
	kfree(hwpt->fault->fault_pages);
	return rc;
}

static void
iommufd_hw_pagetable_dma_fault_destroy(struct iommufd_hw_pagetable *hwpt)
{
	struct iommufd_dma_fault *header;

	if (WARN_ON(!hwpt->fault))
		return;

	header = (struct iommufd_dma_fault *)hwpt->fault->fault_pages;
	WARN_ON(header->tail != header->head);
	iommufd_hw_pagetable_eventfd_destroy(&hwpt->fault->trigger);
	kfree(hwpt->fault->fault_pages);
	mutex_destroy(&hwpt->fault->fault_queue_lock);
	mutex_destroy(&hwpt->fault->notify_gate);
}

int iommufd_hwpt_set_dirty(struct iommufd_ucmd *ucmd)
{
	struct iommu_hwpt_set_dirty *cmd = ucmd->cmd;
	struct iommufd_hw_pagetable *hwpt;
	struct iommufd_ioas *ioas;
	int rc = -EOPNOTSUPP;
	bool enable;

	hwpt = iommufd_get_hwpt(ucmd, cmd->hwpt_id);
	if (IS_ERR(hwpt))
		return PTR_ERR(hwpt);

	ioas = hwpt->ioas;
	enable = cmd->flags & IOMMU_DIRTY_TRACKING_ENABLED;

	rc = iopt_set_dirty_tracking(&ioas->iopt, hwpt->domain, enable);

	iommufd_put_object(&hwpt->obj);
	return rc;
}

int iommufd_check_iova_range(struct iommufd_ioas *ioas,
			     struct iommufd_dirty_data *bitmap)
{
	unsigned long pgshift, npages;
	size_t iommu_pgsize;
	int rc = -EINVAL;
	u64 bitmap_size;

	pgshift = __ffs(bitmap->page_size);
	npages = bitmap->length >> pgshift;
	bitmap_size = dirty_bitmap_bytes(npages);

	if (!npages || (bitmap_size > DIRTY_BITMAP_SIZE_MAX))
		return rc;

	if (!access_ok((void __user *) bitmap->data, bitmap_size))
		return rc;

	iommu_pgsize = 1 << __ffs(ioas->iopt.iova_alignment);

	/* allow only smallest supported pgsize */
	if (bitmap->page_size != iommu_pgsize)
		return rc;

	if (bitmap->iova & (iommu_pgsize - 1))
		return rc;

	if (!bitmap->length || bitmap->length & (iommu_pgsize - 1))
		return rc;

	return 0;
}

int iommufd_hwpt_get_dirty_iova(struct iommufd_ucmd *ucmd)
{
	struct iommu_hwpt_get_dirty_iova *cmd = ucmd->cmd;
	struct iommufd_hw_pagetable *hwpt;
	struct iommufd_ioas *ioas;
	int rc = -EOPNOTSUPP;

	hwpt = iommufd_get_hwpt(ucmd, cmd->hwpt_id);
	if (IS_ERR(hwpt))
		return PTR_ERR(hwpt);

	ioas = hwpt->ioas;
	rc = iommufd_check_iova_range(ioas, &cmd->bitmap);
	if (rc)
		goto out_put;

	rc = iopt_read_and_clear_dirty_data(&ioas->iopt, hwpt->domain,
					    &cmd->bitmap);

out_put:
	iommufd_put_object(&hwpt->obj);
	return rc;
}
