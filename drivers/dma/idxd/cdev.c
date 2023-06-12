// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights rsvd. */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/sched/task.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/iommu.h>
#include <linux/anon_inodes.h>
#include <linux/mmu_notifier.h>
#include <linux/highmem.h>
#include <linux/sizes.h>
#include <uapi/linux/idxd.h>
#include <linux/xarray.h>
#include "registers.h"
#include "idxd.h"

struct idxd_cdev_context {
	const char *name;
	dev_t devt;
	struct ida minor_ida;
};

/*
 * Since user file names are global in DSA devices, define their ida's as
 * global to avoid conflict file names.
 */
static DEFINE_IDA(file_ida);
static DEFINE_MUTEX(ida_lock);

/*
 * ictx is an array based off of accelerator types. enum idxd_type
 * is used as index
 */
static struct idxd_cdev_context ictx[IDXD_TYPE_MAX] = {
	{ .name = "dsa" },
	{ .name = "iax" }
};

struct idxd_user_context {
	struct idxd_wq *wq;
	struct task_struct *task;
	unsigned int pasid;
	struct mm_struct *mm;
	unsigned int flags;
	struct iommu_sva *sva;
	struct idxd_dev idxd_dev;
	u64 counters[COUNTER_MAX];
	int id;
	pid_t pid;
};

static void idxd_cdev_evl_drain_pasid(struct idxd_wq *wq, u32 pasid);
static void idxd_xa_pasid_remove(struct idxd_user_context *ctx);

static inline struct idxd_user_context *dev_to_uctx(struct device *dev)
{
	struct idxd_dev *idxd_dev = confdev_to_idxd_dev(dev);

	return container_of(idxd_dev, struct idxd_user_context, idxd_dev);
}

static ssize_t cr_faults_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct idxd_user_context *ctx = dev_to_uctx(dev);

	return sysfs_emit(buf, "%llu\n", ctx->counters[COUNTER_FAULTS]);
}
static DEVICE_ATTR_RO(cr_faults);

static ssize_t cr_fault_failures_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	struct idxd_user_context *ctx = dev_to_uctx(dev);

	return sysfs_emit(buf, "%llu\n", ctx->counters[COUNTER_FAULT_FAILS]);
}
static DEVICE_ATTR_RO(cr_fault_failures);

static ssize_t pid_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct idxd_user_context *ctx = dev_to_uctx(dev);

	return sysfs_emit(buf, "%u\n", ctx->pid);
}
static DEVICE_ATTR_RO(pid);

static struct attribute *cdev_file_attributes[] = {
	&dev_attr_cr_faults.attr,
	&dev_attr_cr_fault_failures.attr,
	&dev_attr_pid.attr,
	NULL
};

static umode_t cdev_file_attr_visible(struct kobject *kobj, struct attribute *a, int n)
{
	struct device *dev = container_of(kobj, typeof(*dev), kobj);
	struct idxd_user_context *ctx = dev_to_uctx(dev);
	struct idxd_wq *wq = ctx->wq;

	if (!wq_pasid_enabled(wq))
		return 0;

	return a->mode;
}

static const struct attribute_group cdev_file_attribute_group = {
	.attrs = cdev_file_attributes,
	.is_visible = cdev_file_attr_visible,
};

static const struct attribute_group *cdev_file_attribute_groups[] = {
	&cdev_file_attribute_group,
	NULL
};

static void idxd_file_dev_release(struct device *dev)
{
	struct idxd_user_context *ctx = dev_to_uctx(dev);
	struct idxd_wq *wq = ctx->wq;
	struct idxd_device *idxd = wq->idxd;
	int rc;

	mutex_lock(&ida_lock);
	ida_free(&file_ida, ctx->id);
	mutex_unlock(&ida_lock);

	/* Wait for in-flight operations to complete. */
	if (wq_shared(wq)) {
		idxd_device_drain_pasid(idxd, ctx->pasid);
	} else {
		if (device_user_pasid_enabled(idxd)) {
			/* The wq disable in the disable pasid function will drain the wq */
			rc = idxd_wq_disable_pasid(wq);
			if (rc < 0)
				dev_err(dev, "wq disable pasid failed.\n");
		} else {
			idxd_wq_drain(wq);
		}
	}

	if (ctx->sva) {
		idxd_cdev_evl_drain_pasid(wq, ctx->pasid);
		iommu_sva_unbind_device(ctx->sva);
		idxd_xa_pasid_remove(ctx);
	}
	kfree(ctx);
	mutex_lock(&wq->wq_lock);
	idxd_wq_put(wq);
	mutex_unlock(&wq->wq_lock);
}

static struct device_type idxd_cdev_file_type = {
	.name = "idxd_file",
	.release = idxd_file_dev_release,
	.groups = cdev_file_attribute_groups,
};

struct idxd_submit_node {
	struct list_head list;
	struct idxd_idpt_entry_data *idpte_data;
	struct files_struct *submit_id;
	struct iommu_sva *submit_sva;
	struct mmu_notifier mmu_notifier;
	struct mm_struct *mm;
	bool mmu_notify;
};

static void idxd_cdev_dev_release(struct device *dev)
{
	struct idxd_cdev *idxd_cdev = dev_to_cdev(dev);
	struct idxd_cdev_context *cdev_ctx;
	struct idxd_wq *wq = idxd_cdev->wq;

	cdev_ctx = &ictx[wq->idxd->data->type];
	ida_simple_remove(&cdev_ctx->minor_ida, idxd_cdev->minor);
	kfree(idxd_cdev);
}

static struct device_type idxd_cdev_device_type = {
	.name = "idxd_cdev",
	.release = idxd_cdev_dev_release,
};

static inline u32 bitmap_pos(u32 index)
{
	/*
	 * Determine the page number from the index. It would be index / PAGE_SIZE * 8,
	 * which is also >> PAGE_SHIFT + 3, 15.
	 */
	return index >> (PAGE_SHIFT + 3);
}

static inline struct idxd_cdev *inode_idxd_cdev(struct inode *inode)
{
	struct cdev *cdev = inode->i_cdev;

	return container_of(cdev, struct idxd_cdev, cdev);
}

static inline struct idxd_wq *inode_wq(struct inode *inode)
{
	struct idxd_cdev *idxd_cdev = inode_idxd_cdev(inode);

	return idxd_cdev->wq;
}

static void idxd_xa_pasid_remove(struct idxd_user_context *ctx)
{
	struct idxd_wq *wq = ctx->wq;
	void *ptr;

	mutex_lock(&wq->uc_lock);
	ptr = xa_cmpxchg(&wq->upasid_xa, ctx->pasid, ctx, NULL, GFP_KERNEL);
	if (ptr != (void *)ctx)
		dev_warn(&wq->idxd->pdev->dev, "xarray cmpxchg failed for pasid %u\n",
			 ctx->pasid);
	mutex_unlock(&wq->uc_lock);
}

void idxd_user_counter_increment(struct idxd_wq *wq, u32 pasid, int index)
{
	struct idxd_user_context *ctx;

	if (index >= COUNTER_MAX)
		return;

	mutex_lock(&wq->uc_lock);
	ctx = xa_load(&wq->upasid_xa, pasid);
	if (!ctx) {
		mutex_unlock(&wq->uc_lock);
		return;
	}
	ctx->counters[index]++;
	mutex_unlock(&wq->uc_lock);
}

static int idxd_cdev_open(struct inode *inode, struct file *filp)
{
	struct idxd_user_context *ctx;
	struct idxd_device *idxd;
	struct idxd_wq *wq;
	struct device *dev, *fdev;
	int rc = 0;
	struct iommu_sva *sva;
	unsigned int pasid;
	struct idxd_cdev *idxd_cdev;

	wq = inode_wq(inode);
	idxd = wq->idxd;
	dev = &idxd->pdev->dev;

	dev_dbg(dev, "%s called: %d\n", __func__, idxd_wq_refcount(wq));

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	mutex_lock(&wq->wq_lock);

	if (idxd_wq_refcount(wq) > 0 && wq_dedicated(wq)) {
		rc = -EBUSY;
		goto failed;
	}

	ctx->wq = wq;
	filp->private_data = ctx;
	ctx->pid = current->pid;

	if (device_user_pasid_enabled(idxd)) {
		sva = iommu_sva_bind_device(dev, current->mm);
		if (IS_ERR(sva)) {
			rc = PTR_ERR(sva);
			dev_err(dev, "pasid allocation failed: %d\n", rc);
			goto failed;
		}

		pasid = iommu_sva_get_pasid(sva);
		if (pasid == IOMMU_PASID_INVALID) {
			rc = -EINVAL;
			goto failed_get_pasid;
		}

		ctx->sva = sva;
		ctx->pasid = pasid;
		ctx->mm = current->mm;

		mutex_lock(&wq->uc_lock);
		rc = xa_insert(&wq->upasid_xa, pasid, ctx, GFP_KERNEL);
		mutex_unlock(&wq->uc_lock);
		if (rc < 0)
			dev_warn(dev, "PASID entry already exist in xarray.\n");

		if (wq_dedicated(wq)) {
			rc = idxd_wq_set_pasid(wq, pasid);
			if (rc < 0) {
				iommu_sva_unbind_device(sva);
				dev_err(dev, "wq set pasid failed: %d\n", rc);
				goto failed_set_pasid;
			}
		}
	}

	idxd_cdev = wq->idxd_cdev;
	mutex_lock(&ida_lock);
	ctx->id = ida_alloc(&file_ida, GFP_KERNEL);
	mutex_unlock(&ida_lock);
	if (ctx->id < 0) {
		dev_warn(dev, "ida alloc failure\n");
		goto failed_ida;
	}
	ctx->idxd_dev.type  = IDXD_DEV_CDEV_FILE;
	fdev = user_ctx_dev(ctx);
	device_initialize(fdev);
	fdev->parent = cdev_dev(idxd_cdev);
	fdev->bus = &dsa_bus_type;
	fdev->type = &idxd_cdev_file_type;

	rc = dev_set_name(fdev, "file%d", ctx->id);
	if (rc < 0) {
		dev_warn(dev, "set name failure\n");
		goto failed_dev_name;
	}

	rc = device_add(fdev);
	if (rc < 0) {
		dev_warn(dev, "file device add failure\n");
		goto failed_dev_add;
	}

	idxd_wq_get(wq);
	mutex_unlock(&wq->wq_lock);
	return 0;

failed_dev_add:
failed_dev_name:
	put_device(fdev);
failed_ida:
failed_set_pasid:
	if (device_user_pasid_enabled(idxd))
		idxd_xa_pasid_remove(ctx);
failed_get_pasid:
	if (device_user_pasid_enabled(idxd))
		iommu_sva_unbind_device(sva);
failed:
	mutex_unlock(&wq->wq_lock);
	kfree(ctx);
	return rc;
}

static void idxd_cdev_evl_drain_pasid(struct idxd_wq *wq, u32 pasid)
{
	struct idxd_device *idxd = wq->idxd;
	struct device *dev = &idxd->pdev->dev;
	struct idxd_evl *evl = idxd->evl;
	union evl_status_reg status;
	u16 h, t, size;
	int ent_size = evl_ent_size(idxd);
	struct __evl_entry *entry_head;

	if (!evl)
		return;

	dev_dbg(dev, "%s starts\n", __func__);
	spin_lock(&evl->lock);
	status.bits = ioread64(idxd->reg_base + IDXD_EVLSTATUS_OFFSET);
	t = status.tail;
	h = evl->head;
	size = evl->size;

	while (h != t) {
		entry_head = (struct __evl_entry *)(evl->log + (h * ent_size));
		if (entry_head->pasid == pasid && entry_head->wq_idx == wq->id)
			set_bit(h, evl->bmap);
		h = (h + 1) % size;
	}
	spin_unlock(&evl->lock);
	dev_dbg(dev, "%s drain workqueue\n", __func__);

	drain_workqueue(wq->wq);
	dev_dbg(dev, "%s exit\n", __func__);
}

static int idxd_cdev_release(struct inode *node, struct file *filep)
{
	struct idxd_user_context *ctx = filep->private_data;
	struct idxd_wq *wq = ctx->wq;
	struct idxd_device *idxd = wq->idxd;
	struct device *dev = &idxd->pdev->dev;

	dev_dbg(dev, "%s called\n", __func__);
	filep->private_data = NULL;

	device_unregister(user_ctx_dev(ctx));

	return 0;
}

static int check_vma(struct idxd_wq *wq, struct vm_area_struct *vma,
		     const char *func)
{
	struct device *dev = &wq->idxd->pdev->dev;

	if ((vma->vm_end - vma->vm_start) > PAGE_SIZE) {
		dev_info_ratelimited(dev,
				     "%s: %s: mapping too large: %lu\n",
				     current->comm, func,
				     vma->vm_end - vma->vm_start);
		return -EINVAL;
	}

	return 0;
}

static int idxd_cdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct idxd_user_context *ctx = filp->private_data;
	struct idxd_wq *wq = ctx->wq;
	struct idxd_device *idxd = wq->idxd;
	struct pci_dev *pdev = idxd->pdev;
	phys_addr_t base = pci_resource_start(pdev, IDXD_WQ_BAR);
	unsigned long pfn;
	int rc;

	dev_dbg(&pdev->dev, "%s called\n", __func__);
	rc = check_vma(wq, vma, __func__);
	if (rc < 0)
		return rc;

	vma->vm_flags |= VM_DONTCOPY;
	pfn = (base + idxd_get_wq_portal_offset(wq->id, IDXD_PORTAL_LIMITED,
						IDXD_IRQ_MSIX)) >> PAGE_SHIFT;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_private_data = ctx;

	return io_remap_pfn_range(vma, vma->vm_start, pfn, PAGE_SIZE,
			vma->vm_page_prot);
}

static __poll_t idxd_cdev_poll(struct file *filp,
			       struct poll_table_struct *wait)
{
	struct idxd_user_context *ctx = filp->private_data;
	struct idxd_wq *wq = ctx->wq;
	struct idxd_device *idxd = wq->idxd;
	__poll_t out = 0;

	poll_wait(filp, &wq->err_queue, wait);
	spin_lock(&idxd->dev_lock);
	if (idxd->sw_err.valid)
		out = EPOLLIN | EPOLLRDNORM;
	spin_unlock(&idxd->dev_lock);

	return out;
}

static inline u32 submitter_pasid(struct idxd_submit_node *sn)
{
	return iommu_sva_get_pasid(sn->submit_sva);
}

static inline u32 idxd_idpte_offset(struct idxd_device *idxd, int index)
{
	return idxd->idpt_offset + index * sizeof(union idpte);
}

static int idxd_idpte_set_bit(struct idxd_idpt_entry_data *idpte_data, u32 index)
{
//	int pos, rc;
//	struct page *page;
//	struct page *pages[1];
//	u64 addr;

	lockdep_assert_held(&idpte_data->lock);
#if 0
	pos = bitmap_pos(index);
	if (!__test_and_set_bit(pos, idpte_data->page_bitmap)) {
		page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!page) {
			__clear_bit(pos, idpte_data->page_bitmap);
			return -ENOMEM;
		}
		addr = (u64)idpte_data->bitmap + pos * PAGE_SIZE;
		pages[0] = page;
		rc = vmap_pages_range(addr, addr + PAGE_SIZE,
				      PAGE_KERNEL, pages, PAGE_SHIFT);
		if (rc < 0) {
			__clear_bit(pos, idpte_data->page_bitmap);
			__free_page(page);
			return rc;
		}

		idpte_data->bitmap_vma->pages[pos] = page;
		idpte_data->bitmap_vma->nr_pages++;
	}
#endif

	__set_bit(index, idpte_data->bitmap);
	return 0;
}

static void idxd_idpte_clear_bit(struct idxd_idpt_entry_data *idpte_data, int index)
{
//	int pos;

	mutex_lock(&idpte_data->lock);
#if 0
	pos = index >> (PAGE_SHIFT + 3);
	if (!test_bit(pos, idpte_data->page_bitmap)) {
		mutex_unlock(&idpte_data->lock);
		return;
	}
#endif
	if (idpte_data->owner_mm != NULL)
		__clear_bit(index, idpte_data->bitmap);
	mutex_unlock(&idpte_data->lock);
}

static int idxd_idpte_setup_bitmap(struct idxd_idpt_entry_data *idpte_data)
{
//	struct vm_struct *vma;
//	unsigned long *page_bitmap;
//	struct page **pages;
	struct idxd_device *idxd = idpte_data->idxd;
	struct device *dev = &idxd->pdev->dev;
//	int pages_num = SZ_128K / PAGE_SIZE;
//	int rc;

#if 0
	vma = get_vm_area(SZ_128K, VM_MAP_PUT_PAGES);
	if (!vma)
		return -ENOMEM;

	page_bitmap = bitmap_zalloc(pages_num, GFP_KERNEL);
	if (!page_bitmap) {
		rc = -ENOMEM;
		goto err_bitmap_alloc;
	}

	pages = kcalloc_node(pages_num, sizeof(struct page *), GFP_KERNEL, dev_to_node(dev));
	if (!pages) {
		rc = -ENOMEM;
		goto err_pages_alloc;
	}

	idpte_data->page_bitmap = page_bitmap;
	vma->pages = pages;
	idpte_data->bitmap_vma = vma;
	idpte_data->bitmap = vma->addr;
#else

#endif
	idpte_data->bitmap = dma_alloc_coherent(dev, SZ_4K,
						&idpte_data->bitmap_dma, GFP_KERNEL);
	if (!idpte_data->bitmap)
		return -ENOMEM;

	return 0;

#if 0
err_pages_alloc:
	bitmap_free(page_bitmap);
err_bitmap_alloc:
	free_vm_area(vma);
	return rc;
#endif
}

static void idxd_idpte_free_bitmap(struct idxd_idpt_entry_data *idpte_data)
{
	struct idxd_device *idxd = idpte_data->idxd;
	struct device *dev = &idxd->pdev->dev;

	iommu_flush_iotlb_all_dev_pasid(dev, idxd->pasid);
#if 0
	vfree(idpte_data->bitmap);
	kfree(idpte_data->page_bitmap);
	idpte_data->bitmap_vma = NULL;
	idpte_data->bitmap = NULL;
	idpte_data->page_bitmap = NULL;
#else
	dma_free_coherent(dev, SZ_4K, idpte_data->bitmap,
			  idpte_data->bitmap_dma);
#endif
}

static void idxd_idpte_flush_submitter_node(struct idxd_submit_node *sn)
{
	struct idxd_idpt_entry_data *idpte_data;
	struct idxd_device *idxd;
	struct device *dev;
	union idpte idpte;
	u32 offset;

	if (!sn)
		return;

	idpte_data = sn->idpte_data;
	idxd = idpte_data->idxd;
	dev = &idxd->pdev->dev;

	if (idpte_data->multi_user && idpte_data->bitmap)
		idxd_idpte_clear_bit(idpte_data, submitter_pasid(sn));

	if (list_empty(&idpte_data->submit_list) && idpte_data->handle_valid) {
		offset = idxd_idpte_offset(idxd, idpte_data->handle);
		mutex_lock(&idxd->idpt_lock);
		idpte.bits[0] = ioread64(idxd->reg_base + offset);
		idpte.usable = 0;
		iowrite64(idpte.bits[0], idxd->reg_base + offset);
		mutex_unlock(&idxd->idpt_lock);
	}

	if (sn->mmu_notify)
		mmu_notifier_unregister(&sn->mmu_notifier, sn->mm);
}

static int idxd_idpte_flush_submitter(struct idxd_idpt_entry_data *idpte_data, fl_owner_t id)
{
	struct idxd_device *idxd = idpte_data->idxd;
	struct idxd_submit_node *sn = NULL, *tmp;
	bool found = false;

	mutex_lock(&idpte_data->lock);

	if (list_empty(&idpte_data->submit_list)) {
		mutex_unlock(&idpte_data->lock);
		return 0;
	}

	list_for_each_entry_safe(sn, tmp, &idpte_data->submit_list, list) {
		if (sn->submit_id != id)
			continue;

		list_del(&sn->list);
		found = true;
		break;
	}
	mutex_unlock(&idpte_data->lock);

	if (!found)
		return 0;

	if (sn->idpte_data->handle_valid)
		idxd_device_drain_pasid(idxd, submitter_pasid(sn));
	idxd_idpte_flush_submitter_node(sn);

	iommu_sva_unbind_device(sn->submit_sva);
	kfree(sn);
	return 0;
}

static void idxd_idpte_flush_owner(struct idxd_idpt_entry_data *idpte_data)
{
	struct idxd_device *idxd = idpte_data->idxd;
	u32 offset;
	int i;

	idxd_device_drain_pasid(idxd, iommu_sva_get_pasid(idpte_data->owner_sva));

	mutex_lock(&idpte_data->lock);
	idpte_data->handle_valid = 0;
	mutex_unlock(&idpte_data->lock);
	idxd->idpte_data[idpte_data->handle] = NULL;

	offset = idxd_idpte_offset(idxd, idpte_data->handle);
	for (i = 0; i < IDPT_STRIDES; i++)
		iowrite64(0, idxd->reg_base + offset + i * sizeof(u64));

	mutex_lock(&idxd->idpt_lock);
	ida_free(&idxd->idpt_ida, idpte_data->handle);
	mutex_unlock(&idxd->idpt_lock);

	iommu_sva_unbind_device(idpte_data->owner_sva);
	mmdrop(idpte_data->owner_mm);
	if (idpte_data->multi_user && idpte_data->bitmap)
		idxd_idpte_free_bitmap(idpte_data);
	idpte_data->owner_mm = NULL;
	put_device(idxd_confdev(idxd));
}

static int idxd_idpte_flush(struct file *filp, fl_owner_t id)
{
	struct idxd_idpt_entry_data *idpte_data = filp->private_data;

	if (idpte_data->owner_id != id)
		return idxd_idpte_flush_submitter(idpte_data, id);

	idxd_idpte_flush_owner(idpte_data);
	return 0;
}

static int idxd_idpte_release(struct inode *i, struct file *filp)
{
	struct idxd_idpt_entry_data *idpte_data = filp->private_data;

	ioasid_put(NULL, idpte_data->access_pasid);
	kfree(idpte_data);
	return 0;
}

static long idxd_idpte_win_fault(struct file *filp, struct idxd_win_fault *win_fault)
{
	struct idxd_idpt_entry_data *idpte_data = filp->private_data;
	struct idxd_device *idxd = idpte_data->idxd;
	struct device *dev = &idxd->pdev->dev;
	struct iommu_sva *submit_sva;
	struct mm_struct *mm = NULL;
	u64 addr, start_va, end_va;
	union idpte idpte;
	u32 offset;
	int i, rc = 0;

	mutex_lock(&idpte_data->lock);

	submit_sva = iommu_sva_bind_device(dev, current->mm);
	if (IS_ERR(submit_sva)) {
		rc = PTR_ERR(submit_sva);
		goto out;
	}

	if (!idpte_data->handle_valid) {
		rc = -EINVAL;
		goto out;
	}

	offset = idxd_idpte_offset(idxd, idpte_data->handle);
	for (i = 0; i < 4; i++)
		idpte.bits[i] = ioread64(idxd->reg_base + offset + i * sizeof(u64));

	start_va = win_fault->offset + idpte.base_addr;
	end_va = start_va + win_fault->len - 1;

	if (!idpte.rd_perm || (!idpte.wr_perm && win_fault->write_fault) ||
	    start_va >= end_va || end_va >= start_va + idpte.range_size ||
	    win_fault->len == 0) {
		rc = -EINVAL;
		goto out;
	}

	mm = idpte_data->owner_mm;
	for (addr = start_va; addr <= end_va; addr += PAGE_SIZE) {
		u8 b;
		int cnt;

		cnt = access_remote_vm(mm, addr, &b, 1, FOLL_REMOTE);
		if (cnt == 0) {
			rc = -EFAULT;
			goto out;
		}

		if (win_fault->write_fault) {
			cnt = access_remote_vm(mm, addr, &b, 1, FOLL_WRITE | FOLL_REMOTE);
			if (cnt == 0) {
				rc = -EFAULT;
				goto out;
			}
		}

		if (addr == start_va)
			addr = ALIGN_DOWN(start_va, PAGE_SIZE);
	}

out:
	if (!IS_ERR_OR_NULL(submit_sva))
		iommu_sva_unbind_device(submit_sva);

	mutex_unlock(&idpte_data->lock);
	return rc;
}

static long idxd_idpte_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct idxd_win_fault win_fault;

	switch (cmd) {
	case IDXD_WIN_FAULT:
		if (copy_from_user(&win_fault, (void __user *)arg, sizeof(win_fault)))
			return -EFAULT;

		return idxd_idpte_win_fault(filp, &win_fault);

	default:
		break;
	}

	return -EOPNOTSUPP;
}

static const struct file_operations idxd_idpte_fops = {
	.owner = THIS_MODULE,
	.flush = idxd_idpte_flush,
	.release = idxd_idpte_release,
	.unlocked_ioctl = idxd_idpte_ioctl,
};

void dump_idpte(struct idxd_device *idxd, union idpte *idpte)
{
	struct device *dev = &idxd->pdev->dev;

	dev_dbg(dev, "valid %u\n", idpte->usable);
	dev_dbg(dev, "modify %u\n", idpte->allow_update);
	dev_dbg(dev, "read %u\n", idpte->rd_perm);
	dev_dbg(dev, "write %u\n", idpte->wr_perm);
	dev_dbg(dev, "type %u\n", idpte->type);
	dev_dbg(dev, "access privilege %u\n", idpte->access_priv);
	dev_dbg(dev, "window enable %u\n", idpte->win_en);
	dev_dbg(dev, "window mode %u\n", idpte->win_mode);
	dev_dbg(dev, "access pasid %u\n", idpte->access_pasid);
	dev_dbg(dev, "base addr %#llx\n", idpte->base_addr);
	dev_dbg(dev, "range_size %#llx\n", idpte->range_size);
}

static long idxd_idpt_win_create(struct file *filp, struct idxd_win_param *win_param,
				 u16 __user *uhandle)
{
	struct idxd_user_context *ctx = filp->private_data;
	struct idxd_wq *wq = ctx->wq;
	struct idxd_device *idxd = wq->idxd;
	struct device *dev = &idxd->pdev->dev;
	struct idxd_idpt_entry_data *idpte_data;
	union idpte idpte = {0};
	unsigned int flags;
	unsigned int type;
	int index, fd, i;
	u32 offset;
	u16 khandle;
	long rc;

	type = win_param->type;
	flags = win_param->flags;

	dev_dbg(dev, "%s with pid %u flags %#x\n", __func__, current->pid, flags);

	if (!idxd->hw.gen_cap.inter_domain || !idxd->idpt_size ||
	    !(BIT(type) & idxd->hw.id_cap.idpte_support_mask) ||
	    type == IDPTE_TYPE_AASS)
		return -EOPNOTSUPP;

	if (flags & ~IDXD_WIN_FLAGS_MASK) {
		dev_dbg(dev, "%s: invalid flags\n", __func__);
		return -EINVAL;
	}

	idpte.win_mode = !!(flags & IDXD_WIN_FLAGS_OFFSET_MODE);
	idpte.win_en = !!(flags & IDXD_WIN_FLAGS_WIN_CHECK);

	/* No window offset mode support */
	if (idpte.win_mode && !idxd->hw.id_cap.ofs_mode) {
		dev_dbg(dev, "%s: device does not support window mode 1\n", __func__);
		return -EOPNOTSUPP;
	}

	/* Window check disabled, but window mode is in offset mode */
	if (!idpte.win_en && idpte.win_mode) {
		dev_dbg(dev, "%s: window check disabled, window set to offset mode\n", __func__);
		return -EINVAL;
	}

	if (!idpte.win_en && (win_param->base || win_param->size)) {
		dev_dbg(dev, "%s: win check enabled, base or size are non-zero\n", __func__);
		return -EINVAL;
	}

	if (win_param->base + win_param->size < win_param->base) {
		dev_dbg(dev, "%s: invalid window size: base: %#llx size: %#llx\n",
			__func__, win_param->base, win_param->size);
		return -EINVAL;
	}

	mutex_lock(&idxd->idpt_lock);
	index = ida_alloc(&idxd->idpt_ida, GFP_KERNEL);
	mutex_unlock(&idxd->idpt_lock);
	if (index < 0)
		return index;

	idpte_data = kzalloc(sizeof(*idpte_data), GFP_KERNEL);
	if (!idpte_data) {
		rc = -ENOMEM;
		goto idpted_failed;
	}

	idpte_data->owner_sva = iommu_sva_bind_device(dev, current->mm);
	if (IS_ERR(idpte_data->owner_sva)) {
		rc = PTR_ERR(idpte_data->owner_sva);
		goto sva_bind_fail;
	}

	idpte.usable = 0;
	idpte.allow_update = 1;
	idpte.rd_perm = !!(flags & IDXD_WIN_FLAGS_PROT_READ);
	idpte.wr_perm = !!(flags & IDXD_WIN_FLAGS_PROT_WRITE);
	idpte.type = type;

	mmgrab(current->mm);
	idpte_data->owner_mm = current->mm;
	idpte_data->idxd = idxd;
	idpte_data->handle = index;
	idpte_data->handle_valid = 1;
	idpte_data->owner_id = current->files;
	INIT_LIST_HEAD(&idpte_data->submit_list);
	mutex_init(&idpte_data->lock);
	khandle = idpte_data->handle;
	idpte_data->multi_user = type == IDXD_WIN_TYPE_SA_MS;

	if (type == IDXD_WIN_TYPE_SA_MS) {
		rc = idxd_idpte_setup_bitmap(idpte_data);
		if (rc < 0)
			goto bitmap_fail;
		idpte.bmap_addr = idpte_data->bitmap_dma;
	}

	/* non priviledged access */
	idpte.access_priv = 0;

	rc = ioasid_get(NULL, ctx->pasid);
	if (rc)
		goto ioasid_get_fail;

	idpte_data->access_pasid = idpte.access_pasid = ctx->pasid;
	idpte.submit_pasid = 0;
	idpte.base_addr = win_param->base;
	idpte.range_size = win_param->size;

	offset = idxd_idpte_offset(idxd, index);

	dump_idpte(idxd, &idpte);

	dev_dbg(dev, "IDPTE from create\n");
	/* Write allow_update bit in the last step. */
	for (i = IDPT_STRIDES - 1; i >= 0; i--) {
		iowrite64(idpte.bits[i], idxd->reg_base + offset + i * sizeof(u64));
		dev_dbg(dev, "IDPTE[%#x][%u]: %#llx\n",
			offset - idxd->idpt_offset , i, idpte.bits[i]);
	}

	idxd->idpte_data[index] = idpte_data;

	fd = anon_inode_getfd("ipt", &idxd_idpte_fops, idpte_data, 0);
	if (fd < 0) {
		dev_dbg(dev, "Failed getting anon inode fd: %d\n", fd);
		rc = fd;
		goto getfd_fail;
	}

	if (put_user(khandle, uhandle)) {
		rc = -EFAULT;
		goto cp_user_fail;
	}

	get_device(idxd_confdev(idxd));

	return fd;

cp_user_fail:
getfd_fail:
ioasid_get_fail:
	idxd->idpte_data[index] = NULL;
bitmap_fail:
	iommu_sva_unbind_device(idpte_data->owner_sva);
sva_bind_fail:
	kfree(idpte_data);
idpted_failed:
	mutex_lock(&idxd->idpt_lock);
	ida_free(&idxd->idpt_ida, index);
	mutex_unlock(&idxd->idpt_lock);
	return rc;

}

static struct file *idxd_idpte_data_get_file(int fd)
{
	struct file *file;

	file = fget(fd);

	if (!file)
		return ERR_PTR(-EBADF);

	if (file->f_op != &idxd_idpte_fops) {
		fput(file);
		return ERR_PTR(-EINVAL);
	}

	return file;
}

static bool idxd_submitter_exist(struct idxd_idpt_entry_data *idpte_data,
				 struct iommu_sva *submit_sva)
{
	struct idxd_submit_node *sn;
	u32 pasid;

	lockdep_assert_held(&idpte_data->lock);

	if (idpte_data->multi_user) {
		pasid = iommu_sva_get_pasid(submit_sva);
		if (pasid == IOMMU_PASID_INVALID)
			return false;

#if 0
		if (!test_bit(bitmap_pos(pasid), idpte_data->page_bitmap))
			return false;
#endif

		if (!test_bit(pasid, idpte_data->bitmap))
			return false;

	} else {
		sn = list_first_entry_or_null(&idpte_data->submit_list,
					      struct idxd_submit_node, list);
		if (!sn)
			return false;

		if (sn->submit_sva != submit_sva)
			return false;
	}

	return true;
}

static bool idxd_new_submitter_allowed(struct idxd_idpt_entry_data *idpte_data)
{
	lockdep_assert_held(&idpte_data->lock);
	return list_empty(&idpte_data->submit_list);
}

static int idxd_add_submitter(struct idxd_device *idxd,
			      struct idxd_idpt_entry_data *idpte_data,
			      struct idxd_submit_node *sn)
{
	u32 offset;
	union idpte idpte;
	int rc;

	lockdep_assert_held(&idpte_data->lock);
	offset = idxd_idpte_offset(idxd, idpte_data->handle);

	if (idpte_data->multi_user) {
		rc = idxd_idpte_set_bit(idpte_data, submitter_pasid(sn));
		if (rc < 0) {
			dev_warn(&idxd->pdev->dev, "Unable to set IDPT bitmap for %d\n",
				 submitter_pasid(sn));
			return rc;
		}
	}

	if (list_empty(&idpte_data->submit_list)) {
		idpte.bits[0] = ioread64(idxd->reg_base + offset);
		idpte.usable = 1;
		if (idpte.type == IDPTE_TYPE_SASS)
			idpte.submit_pasid = submitter_pasid(sn);
		iowrite64(idpte.bits[0], idxd->reg_base + offset);

	{
		int i;
		struct device *dev = &idxd->pdev->dev;

		dev_dbg(dev, "IDPTE from attach\n");
		for (i = 0; i < IDPT_STRIDES; i++)
			dev_dbg(dev, "IDPTE[%#x][%u]: %#llx\n",
				offset - idxd->idpt_offset, i, idpte.bits[i]);
	}

	}

	list_add_tail(&sn->list, &idpte_data->submit_list);
	return 0;
}

static long idxd_idpt_win_attach(struct file *submit_wq, int fd, u16 __user *uhandle)
{
	struct idxd_user_context *ctx = submit_wq->private_data;
	struct idxd_device *idxd = ctx->wq->idxd;
	struct device *dev = &idxd->pdev->dev;
	struct file *idpte_file;
	struct idxd_idpt_entry_data *idpte_data;
	struct iommu_sva *submit_sva;
	struct idxd_submit_node *new_submit;
	u32 khandle;
	int rc;

	idpte_file = idxd_idpte_data_get_file(fd);
	if (IS_ERR(idpte_file))
		return PTR_ERR(idpte_file);

	idpte_data = idpte_file->private_data;
	if (idpte_data->idxd != idxd) {
		rc = -EINVAL;
		goto err_match_dev;
	}

	mutex_lock(&idpte_data->lock);

	if (!idpte_data->handle_valid) {
		rc = -EINVAL;
		goto err_invalid_handle;
	}

	submit_sva = iommu_sva_bind_device(dev, current->mm);
	if (IS_ERR(submit_sva)) {
		rc = PTR_ERR(submit_sva);
		goto err_sva;
	}

	if (idxd_submitter_exist(idpte_data, submit_sva)) {
		rc = -EEXIST;
		goto rel_mutex;
	}

#if 0
	if (!idxd_new_submitter_allowed(idpte_data)) {
		rc = -ENOSPC;
		goto err_no_submit;
	}
#endif

	new_submit = kzalloc(sizeof(struct idxd_submit_node), GFP_KERNEL);
	if (!new_submit) {
		rc = -ENOMEM;
		goto err_submit_alloc;
	}

	new_submit->idpte_data = idpte_data;
	new_submit->mm = current->mm;
	new_submit->submit_id = current->files;
	new_submit->submit_sva = submit_sva;
	new_submit->mmu_notify = false;
	rc = idxd_add_submitter(idxd, idpte_data, new_submit);
	if (rc < 0)
		goto err_add_submitter;

rel_mutex:
	khandle = idpte_data->handle;
	mutex_unlock(&idpte_data->lock);
	fput(idpte_file);

	if (put_user(khandle, uhandle)) {
		rc = -EFAULT;
		goto err_put_user;
	}

	return 0;

err_put_user:
	idxd_idpte_flush_submitter_node(new_submit);
	list_del(&new_submit->list);
err_add_submitter:
	kfree(new_submit);

err_submit_alloc:
err_no_submit:
err_sva:
err_invalid_handle:
	mutex_unlock(&idpte_data->lock);
err_match_dev:
	fput(idpte_file);
	return rc;
}

static long idxd_cdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct idxd_win_param win_param;
	struct idxd_win_attach win_attach;
	int rc = -EOPNOTSUPP;

	switch (cmd) {
	case IDXD_WIN_CREATE:
		if (copy_from_user(&win_param, (void __user *)arg, sizeof(win_param)))
			return -EFAULT;

		return idxd_idpt_win_create(filp, &win_param,
					    &((struct idxd_win_param *)arg)->handle);

	case IDXD_WIN_ATTACH:
		if (copy_from_user(&win_attach, (void __user *)arg, sizeof(win_attach)))
			return -EFAULT;

		return idxd_idpt_win_attach(filp, win_attach.fd,
					    &((struct idxd_win_attach *)arg)->handle);

	default:
		break;
	}

	return rc;
}

static const struct file_operations idxd_cdev_fops = {
	.owner = THIS_MODULE,
	.open = idxd_cdev_open,
	.release = idxd_cdev_release,
	.mmap = idxd_cdev_mmap,
	.poll = idxd_cdev_poll,
	.unlocked_ioctl = idxd_cdev_ioctl,
};

int idxd_cdev_get_major(struct idxd_device *idxd)
{
	return MAJOR(ictx[idxd->data->type].devt);
}

int idxd_wq_add_cdev(struct idxd_wq *wq)
{
	struct idxd_device *idxd = wq->idxd;
	struct idxd_cdev *idxd_cdev;
	struct cdev *cdev;
	struct device *dev;
	struct idxd_cdev_context *cdev_ctx;
	int rc, minor;

	idxd_cdev = kzalloc(sizeof(*idxd_cdev), GFP_KERNEL);
	if (!idxd_cdev)
		return -ENOMEM;

	idxd_cdev->idxd_dev.type = IDXD_DEV_CDEV;
	idxd_cdev->wq = wq;
	cdev = &idxd_cdev->cdev;
	dev = cdev_dev(idxd_cdev);
	cdev_ctx = &ictx[wq->idxd->data->type];
	minor = ida_simple_get(&cdev_ctx->minor_ida, 0, MINORMASK, GFP_KERNEL);
	if (minor < 0) {
		kfree(idxd_cdev);
		return minor;
	}
	idxd_cdev->minor = minor;

	device_initialize(dev);
	dev->parent = wq_confdev(wq);
	dev->bus = &dsa_bus_type;
	dev->type = &idxd_cdev_device_type;
	dev->devt = MKDEV(MAJOR(cdev_ctx->devt), minor);

	rc = dev_set_name(dev, "%s/wq%u.%u", idxd->data->name_prefix, idxd->id, wq->id);
	if (rc < 0)
		goto err;

	wq->idxd_cdev = idxd_cdev;
	cdev_init(cdev, &idxd_cdev_fops);
	rc = cdev_device_add(cdev, dev);
	if (rc) {
		dev_dbg(&wq->idxd->pdev->dev, "cdev_add failed: %d\n", rc);
		goto err;
	}

	return 0;

 err:
	put_device(dev);
	wq->idxd_cdev = NULL;
	return rc;
}

void idxd_wq_del_cdev(struct idxd_wq *wq)
{
	struct idxd_cdev *idxd_cdev;

	idxd_cdev = wq->idxd_cdev;
	ida_destroy(&file_ida);
	wq->idxd_cdev = NULL;
	cdev_device_del(&idxd_cdev->cdev, cdev_dev(idxd_cdev));
	put_device(cdev_dev(idxd_cdev));
}

static int idxd_user_drv_probe(struct idxd_dev *idxd_dev)
{
	struct device *dev = &idxd_dev->conf_dev;
	struct idxd_wq *wq = idxd_dev_to_wq(idxd_dev);
	struct idxd_device *idxd = wq->idxd;
	int rc;

	if (idxd->state != IDXD_DEV_ENABLED)
		return -ENXIO;

	/*
	 * User type WQ is enabled only when SVA is enabled for two reasons:
	 *   - If no IOMMU or IOMMU Passthrough without SVA, userspace
	 *     can directly access physical address through the WQ.
	 *   - The IDXD cdev driver does not provide any ways to pin
	 *     user pages and translate the address from user VA to IOVA or
	 *     PA without IOMMU SVA. Therefore the application has no way
	 *     to instruct the device to perform DMA function. This makes
	 *     the cdev not usable for normal application usage.
	 */
	if (!device_user_pasid_enabled(idxd)) {
		idxd->cmd_status = IDXD_SCMD_WQ_USER_NO_IOMMU;
		dev_dbg(&idxd->pdev->dev,
			"User type WQ cannot be enabled without SVA.\n");

		return -EOPNOTSUPP;
	}

	mutex_lock(&wq->wq_lock);
	if (!idxd_wq_driver_name_match(wq, dev)) {
		idxd->cmd_status = IDXD_SCMD_WQ_NO_DRV_NAME;
		rc = -ENODEV;
		goto err_drv_name;
	}

	wq->wq = create_workqueue(dev_name(wq_confdev(wq)));
	if (!wq->wq) {
		rc = -ENOMEM;
		goto wq_err;
	}

	wq->type = IDXD_WQT_USER;
	rc = drv_enable_wq(wq);
	if (rc < 0)
		goto err;

	rc = idxd_wq_add_cdev(wq);
	if (rc < 0) {
		idxd->cmd_status = IDXD_SCMD_CDEV_ERR;
		goto err_cdev;
	}

	idxd->cmd_status = 0;
	mutex_unlock(&wq->wq_lock);
	return 0;

err_cdev:
	drv_disable_wq(wq);
err:
	destroy_workqueue(wq->wq);
	wq->type = IDXD_WQT_NONE;
wq_err:
err_drv_name:
	mutex_unlock(&wq->wq_lock);
	return rc;
}

static void idxd_user_drv_remove(struct idxd_dev *idxd_dev)
{
	struct idxd_wq *wq = idxd_dev_to_wq(idxd_dev);

	mutex_lock(&wq->wq_lock);
	idxd_wq_del_cdev(wq);
	drv_disable_wq(wq);
	wq->type = IDXD_WQT_NONE;
	destroy_workqueue(wq->wq);
	wq->wq = NULL;
	mutex_unlock(&wq->wq_lock);
}

static enum idxd_dev_type dev_types[] = {
	IDXD_DEV_WQ,
	IDXD_DEV_NONE,
};

struct idxd_device_driver idxd_user_drv = {
	.probe = idxd_user_drv_probe,
	.remove = idxd_user_drv_remove,
	.name = "user",
	.type = dev_types,
};
EXPORT_SYMBOL_GPL(idxd_user_drv);

int idxd_cdev_register(void)
{
	int rc, i;

	for (i = 0; i < IDXD_TYPE_MAX; i++) {
		ida_init(&ictx[i].minor_ida);
		rc = alloc_chrdev_region(&ictx[i].devt, 0, MINORMASK,
					 ictx[i].name);
		if (rc)
			goto err_free_chrdev_region;
	}

	return 0;

err_free_chrdev_region:
	for (i--; i >= 0; i--)
		unregister_chrdev_region(ictx[i].devt, MINORMASK);

	return rc;
}

void idxd_cdev_remove(void)
{
	int i;

	for (i = 0; i < IDXD_TYPE_MAX; i++) {
		unregister_chrdev_region(ictx[i].devt, MINORMASK);
		ida_destroy(&ictx[i].minor_ida);
	}
}

/**
 * idxd_copy_cr - copy completion record to user address space found by wq and
 *		  PASID
 * @wq:		work queue
 * @pasid:	PASID
 * @addr:	user fault address to write
 * @cr:		completion record
 * @len:	number of bytes to copy
 *
 * This is called by a work that handles completion record fault.
 *
 * Return: number of bytes copied.
 */
int idxd_copy_cr(struct idxd_wq *wq, ioasid_t pasid, unsigned long addr,
		 void *cr, int len)
{
	struct device *dev = &wq->idxd->pdev->dev;
	int left = len, status_size = 1;
	struct idxd_user_context *ctx;
	struct mm_struct *mm;

	mutex_lock(&wq->uc_lock);

	ctx = xa_load(&wq->upasid_xa, pasid);
	if (!ctx) {
		dev_warn(dev, "No user context\n");
		goto out;
	}

	mm = ctx->mm;
	/*
	 * The completion record fault handling work is running in kernel
	 * thread context. It temporarily switches to the mm to copy cr
	 * to addr in the mm.
	 */
	kthread_use_mm(mm);
	left = copy_to_user((void __user *)addr + status_size, cr + status_size,
			    len - status_size);
	/*
	 * Copy status only after the rest of completion record is copied
	 * successfully so that the user gets the complete completion record
	 * when a non-zero status is polled.
	 */
	if (!left) {
		u8 status;

		/*
		 * Ensure that the completion record's status field is written
		 * after the rest of the completion record has been written.
		 * This ensures that the user receives the correct completion
		 * record information once polling for a non-zero status.
		 */
		wmb();
		status = *(u8 *)cr;
		if (put_user(status, (u8 __user *)addr))
			left += status_size;
	} else {
		left += status_size;
	}
	kthread_unuse_mm(mm);

out:
	mutex_unlock(&wq->uc_lock);

	return len - left;
}
