// SPDX-License-Identifier: GPL-2.0
#include <linux/anon_inodes.h>
#include <linux/kvm_host.h>

struct tdx_mig_mbmd_data {
	__u16 size;
	__u16 mig_version;
	__u16 migs_index;
	__u8  mb_type;
	__u8  rsvd0;
	__u32 mb_counter;
	__u32 mig_epoch;
	__u64 iv_counter;
	__u8  type_specific_info[];
} __packed;

struct tdx_mig_mbmd {
	struct tdx_mig_mbmd_data *data;
	uint64_t addr_and_size;
};

/*
 * The buffer list specifies a list of 4KB pages to be used by TDH_EXPORT_MEM
 * and TDH_IMPORT_MEM to export and import guest memory pages. Each entry
 * is 64-bit and points to a physical address of a 4KB page used as buffer. The
 * list itself is a 4KB page, so it can hold up to 512 entries.
 */
union tdx_mig_buf_list_entry {
	uint64_t val;
	struct {
		uint64_t rsvd0		: 12;
		uint64_t pfn		: 40;
		uint64_t rsvd1		: 11;
		uint64_t invalid	: 1;
	};
};

struct tdx_mig_buf_list {
	union tdx_mig_buf_list_entry *entries;
	hpa_t hpa;
};

struct tdx_mig_stream {
	uint16_t idx;
	unsigned long migsc_pa;
	uint32_t buf_list_pages;
	struct tdx_mig_mbmd mbmd;
	/* List of buffers to export/import the TD private memory data */
	struct tdx_mig_buf_list mem_buf_list;
};

struct tdx_mig_state {
	/* Migration (forward) stream to migrate the TD states */
	struct tdx_mig_stream stream;
	/*
	 * Backward stream not used in the version. But required by the TDX
	 * architecture to be created.
	 */
	struct tdx_mig_stream backward_stream;
};

struct tdx_mig_capabilities {
	uint32_t max_migs;
	uint32_t nonmem_state_pages;
};

static struct tdx_mig_capabilities tdx_mig_caps;

static int tdx_mig_capabilities_setup(void)
{
	struct tdx_module_output out;
	uint32_t immutable_state_pages, td_state_pages, vp_state_pages;
	uint64_t err;

	err = tdh_sys_rd(TDX_MD_FID_MAX_MIGS, &out);
	if (err)
		return -EIO;
	tdx_mig_caps.max_migs = out.r8;

	err = tdh_sys_rd(TDX_MD_FID_IMMUTABLE_STATE_PAGES, &out);
	if (err)
		return -EIO;
	immutable_state_pages = out.r8;

	err = tdh_sys_rd(TDX_MD_FID_TD_STATE_PAGES, &out);
	if (err)
		return -EIO;
	td_state_pages = out.r8;

	err = tdh_sys_rd(TDX_MD_FID_VP_STATE_PAGES, &out);
	if (err)
		return -EIO;
	vp_state_pages = out.r8;

	/*
	 * The minimal number of pages required. It hould be large enough to
	 * store all the non-memory states.
	 */
	tdx_mig_caps.nonmem_state_pages = max3(immutable_state_pages,
					       td_state_pages, vp_state_pages);

	return 0;
}

static void tdx_mig_stream_get_tdx_mig_attr(struct tdx_mig_stream *stream,
					    struct kvm_dev_tdx_mig_attr *attr)
{
	attr->version = KVM_DEV_TDX_MIG_ATTR_VERSION;
	attr->max_migs = tdx_mig_caps.max_migs;
	attr->buf_list_pages = stream->buf_list_pages;
}

static int tdx_mig_stream_get_attr(struct kvm_device *dev,
				   struct kvm_device_attr *attr)
{
	struct tdx_mig_stream *stream = dev->private;
	u64 __user *uaddr = (u64 __user *)(long)attr->addr;

	switch (attr->group) {
	case KVM_DEV_TDX_MIG_ATTR: {
		struct kvm_dev_tdx_mig_attr tdx_mig_attr;

		if (attr->attr != sizeof(struct kvm_dev_tdx_mig_attr)) {
			pr_err("Incompatible kvm_dev_get_tdx_mig_attr\n");
			return -EINVAL;
		}

		tdx_mig_stream_get_tdx_mig_attr(stream, &tdx_mig_attr);
		if (copy_to_user(uaddr, &tdx_mig_attr, sizeof(tdx_mig_attr)))
			return -EFAULT;
		break;
	}
	default:
		return -EINVAL;
	}

	return 0;
}

static int tdx_mig_stream_set_tdx_mig_attr(struct tdx_mig_stream *stream,
					   struct kvm_dev_tdx_mig_attr *attr)
{
	uint32_t req_pages = attr->buf_list_pages;
	uint32_t min_pages = tdx_mig_caps.nonmem_state_pages;

	if (req_pages > TDX_MIG_BUF_LIST_PAGES_MAX) {
		stream->buf_list_pages = TDX_MIG_BUF_LIST_PAGES_MAX;
		pr_warn("Cut the buf_list_npages to the max supported num\n");
	} else if (req_pages < min_pages) {
		stream->buf_list_pages = min_pages;
	} else {
		stream->buf_list_pages = req_pages;
	}

	return 0;
}

static int tdx_mig_stream_mbmd_setup(struct tdx_mig_mbmd *mbmd)
{
	struct page *page;
	unsigned long mbmd_size = PAGE_SIZE;
	int order = get_order(mbmd_size);

	page = alloc_pages(GFP_KERNEL_ACCOUNT | __GFP_ZERO, order);
	if (!page)
		return -ENOMEM;

	mbmd->data = page_address(page);
	/*
	 * MBMD address and size format defined in TDX module ABI spec:
	 * Bits 63:52 - size of the MBMD buffer
	 * Bits 51:0  - host physical page frame number of the MBMD buffer
	 */
	mbmd->addr_and_size = page_to_phys(page) | (mbmd_size - 1) << 52;

	return 0;
}

static void tdx_mig_stream_buf_list_cleanup(struct tdx_mig_buf_list *buf_list)
{
	int i;
	kvm_pfn_t pfn;
	struct page *page;

	if (!buf_list->entries)
		return;

	for (i = 0; i < 512; i++) {
		pfn = buf_list->entries[i].pfn;
		if (!pfn)
			break;
		page = pfn_to_page(pfn);
		__free_page(page);
	}
	free_page((unsigned long)buf_list->entries);
}

static int tdx_mig_stream_buf_list_alloc(struct tdx_mig_buf_list *buf_list)
{
	struct page *page;

	/*
	 * Allocate the buf list page, which has 512 entries pointing to up to
	 * 512 pages used as buffers to export/import migration data.
	 */
	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!page)
		return -ENOMEM;

	buf_list->entries = page_address(page);
	buf_list->hpa = page_to_phys(page);

	return 0;
}

static int tdx_mig_stream_buf_list_setup(struct tdx_mig_buf_list *buf_list,
					 uint32_t npages)
{
	int i;
	struct page *page;

	if (!npages) {
		pr_err("Userspace should set_attr on the device first\n");
		return -EINVAL;
	}

	if (tdx_mig_stream_buf_list_alloc(buf_list))
		return -ENOMEM;

	for (i = 0; i < npages; i++) {
		page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
		if (!page) {
			tdx_mig_stream_buf_list_cleanup(buf_list);
			return -ENOMEM;
		}
		buf_list->entries[i].pfn = page_to_pfn(page);
	}

	/* Mark unused entries as invalid */
	for (i = npages; i < 512; i++)
		buf_list->entries[i].invalid = true;

	return 0;
}

static int tdx_mig_stream_setup(struct tdx_mig_stream *stream)
{
	int ret;

	ret = tdx_mig_stream_mbmd_setup(&stream->mbmd);
	if (ret)
		goto err_mbmd;

	ret = tdx_mig_stream_buf_list_setup(&stream->mem_buf_list,
					    stream->buf_list_pages);
	if (ret)
		goto err_mem_buf_list;

	return 0;

err_mem_buf_list:
	free_page((unsigned long)stream->mbmd.data);
err_mbmd:
	pr_err("%s failed\n", __func__);
	return ret;
}

static int tdx_mig_stream_set_attr(struct kvm_device *dev,
				   struct kvm_device_attr *attr)
{
	struct tdx_mig_stream *stream = dev->private;
	u64 __user *uaddr = (u64 __user *)(long)attr->addr;
	int ret;

	switch (attr->group) {
	case KVM_DEV_TDX_MIG_ATTR: {
		struct kvm_dev_tdx_mig_attr tdx_mig_attr;

		if (copy_from_user(&tdx_mig_attr, uaddr, sizeof(tdx_mig_attr)))
			return -EFAULT;

		if (tdx_mig_attr.version != KVM_DEV_TDX_MIG_ATTR_VERSION)
			return -EINVAL;

		ret = tdx_mig_stream_set_tdx_mig_attr(stream, &tdx_mig_attr);
		if (ret)
			break;

		ret = tdx_mig_stream_setup(stream);
		break;
	}
	default:
		return -EINVAL;
	}

	return ret;
}

static int tdx_mig_stream_mmap(struct kvm_device *dev,
				   struct vm_area_struct *vma)
{
	return -ENXIO;
}

static long tdx_mig_stream_ioctl(struct kvm_device *dev, unsigned int ioctl,
				 unsigned long arg)
{
	return -ENXIO;
}

static int tdx_mig_do_stream_create(struct kvm_tdx *kvm_tdx,
				    struct tdx_mig_stream *stream)
{
	struct tdx_module_output out;
	unsigned long migsc_va, migsc_pa;
	uint64_t err;

	migsc_va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!migsc_va)
		return -ENOMEM;
	migsc_pa = __pa(migsc_va);

	err = tdh_mig_stream_create(kvm_tdx->tdr_pa, migsc_pa);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MIG_STREAM_CREATE, err, &out);
		free_page(migsc_va);
		return -EIO;
	}
	stream->migsc_pa = migsc_pa;

	return 0;
}

static int tdx_mig_state_create(struct kvm_tdx *kvm_tdx)
{
	struct tdx_mig_state *mig_state;

	/*
	 * Current version supports only one migration stream. The mig_state
	 * has been allocated when the stream is created.
	 */
	if (kvm_tdx->mig_state) {
		pr_warn("only 1 migration stream supported currently\n");
		return -EEXIST;
	}

	mig_state = kzalloc(sizeof(struct tdx_mig_state), GFP_KERNEL_ACCOUNT);
	if (!mig_state)
		return -ENOMEM;

	if (tdx_mig_do_stream_create(kvm_tdx, &mig_state->backward_stream)) {
		kfree(mig_state);
		return -EIO;
	}
	kvm_tdx->mig_state = mig_state;
	return 0;
}

static void tdx_mig_state_destroy(struct kvm_tdx *kvm_tdx)
{
	struct tdx_mig_state *mig_state =
		(struct tdx_mig_state *)kvm_tdx->mig_state;

	if (!mig_state)
		return;

	tdx_reclaim_td_page(mig_state->stream.migsc_pa);
	tdx_reclaim_td_page(mig_state->backward_stream.migsc_pa);
	kfree(mig_state);
	kvm_tdx->mig_state = NULL;
}

static int tdx_mig_stream_create(struct kvm_device *dev, u32 type)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(dev->kvm);
	struct tdx_mig_state *mig_state;
	struct tdx_mig_stream *stream;
	int ret;

	/*
	 * At least two migration streams (forward stream + backward stream)
	 * are required to be created.
	 */
	if (unlikely(tdx_mig_caps.max_migs < 2))
		return -ENOENT;

	ret = tdx_mig_state_create(kvm_tdx);
	if (ret)
		return ret;

	mig_state = (struct tdx_mig_state *)kvm_tdx->mig_state;
	stream = &mig_state->stream;
	ret = tdx_mig_do_stream_create(kvm_tdx, stream);
	if (ret)
		return ret;

	dev->private = stream;

	return 0;
}

static void tdx_mig_stream_release(struct kvm_device *dev)
{
	struct tdx_mig_stream *stream = dev->private;

	free_page((unsigned long)stream->mbmd.data);
	tdx_mig_stream_buf_list_cleanup(&stream->mem_buf_list);
}

static struct kvm_device_ops kvm_tdx_mig_stream_ops = {
	.name = "kvm-tdx-mig",
	.get_attr = tdx_mig_stream_get_attr,
	.set_attr = tdx_mig_stream_set_attr,
	.mmap = tdx_mig_stream_mmap,
	.ioctl = tdx_mig_stream_ioctl,
	.create = tdx_mig_stream_create,
	.release = tdx_mig_stream_release,
};

static int kvm_tdx_mig_stream_ops_init(void)
{
	return kvm_register_device_ops(&kvm_tdx_mig_stream_ops,
				       KVM_DEV_TYPE_TDX_MIG_STREAM);
}

static void kvm_tdx_mig_stream_ops_exit(void)
{
	kvm_unregister_device_ops(KVM_DEV_TYPE_TDX_MIG_STREAM);
}
