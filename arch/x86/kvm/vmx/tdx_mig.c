// SPDX-License-Identifier: GPL-2.0
#include <linux/anon_inodes.h>
#include <linux/kvm_host.h>

/*
 * Version for the KVM side TDX Migration implementation. Increased it when
 * the KVM side update requires an update to userspace implementation.
 */
#define TDX_MIG_KVM_VERSION 0x0

#define TDX_MIG_FID_MAX_MIGS		0xa000000100000010
#define TDX_MIG_FID_IMMUTABLE_NPAGES	0xa000000000000020
#define TDX_MIG_FID_TD_NPAGES		0xa000000000000021
#define TDX_MIG_FID_VP_NPAGES		0xa000000000000022

/* Worst case buffer size needed for holding an integer. */
#define ITOA_MAX_LEN 12

#define TDX_MIG_NULL_PA ~(0ULL)

#define MBMD_PAGE_SEPT_ENTRY_STATE_MASK 0x300

#define TDX_MIG_EPOCH_START_TOKEN 0xffffffff

#define TDX_MIG_STREAM_CONFIG_RESUME (1UL << 63)
#define TDX_MIG_STREAM_CONFIG_IN_ORDER_DONE (1UL << 63)

/* 4KB buffer can hold 512 entries at most */
#define TDX_MIG_BUF_LIST_NPAGES_MAX	512

#define TDX_MIG_MBMD_ALLOC_ORDER	0
#define TDX_MIG_GPA_LIST_ALLOC_ORDER	0

#define TDX_MIG_GPA_LIST_SIZE (PAGE_SIZE * (1 << TDX_MIG_GPA_LIST_ALLOC_ORDER))
#define TDX_MIG_MBMD_SIZE (PAGE_SIZE * (1 << TDX_MIG_MBMD_ALLOC_ORDER))
#define TDX_MIG_MAC_LIST_SIZE	(PAGE_SIZE * 2)

struct tdx_mig_mbmd_hdr {
	__u16 size;
	__u16 mig_version;
	__u16 migs_index;
	__u8  mb_type;
	__u8  rsvd0;
	__u32 mb_counter;
	__u32 mig_epoch;
	__u64 iv_counter;
	__u8  type_specific_info[];
} __attribute__((packed));

struct tdx_mig_mbmd {
	struct tdx_mig_mbmd_hdr *buf;
	uint64_t config;
};

/*
 * Non-memory states migration - page list:
 * Specifies a list of 4KB pages to be used by the non-memory states export
 * and import, i.e. TDH_EXPORT_STATE_* and TDH_IMPORT_STATE_*. Each entry
 * is 64-bit and specifies the physical adress of a 4KB buffer. The list
 * itself is a 4KB page, so it can hold up to 512 entries.
 */
union tdx_mig_page_list_info {
	uint64_t val;
	struct {
		uint64_t rsvd0		: 12;
		uint64_t pfn		: 40;
		uint64_t rsvd1		: 3;
		uint64_t last_entry	: 9;
	};
};

struct tdx_mig_page_list {
	hpa_t *entries;
	union tdx_mig_page_list_info info;
};

/*
 * Memory migration - GPA list:
 * Specifies a list of GPAs to be used by TDH_EXPORT_MEM, TDH_IMPORT_MEM,
 * TDH_EXPORT_BLOCKW, and TDH_EXPORT_RESTORE. Each entry is 64-bit containing
 * the guest physical address bits and the related info (e.g. rwx bits). The
 * itself is 4KB, so it can hold up to 512 entries.
 */
union tdx_mig_gpa_list_info {
	uint64_t val;
	struct {
		uint64_t rsvd0		: 3;
		uint64_t first_entry	: 9;
		uint64_t pfn		: 40;
		uint64_t rsvd1		: 3;
		uint64_t last_entry	: 9;
	};
};

union tdx_mig_gpa_list_entry {
	uint64_t val;
	struct{
		uint64_t r		: 1;   // Bit 0, same as SEPT
		uint64_t w		: 1;   // Bit 1, same as SEPT
		uint64_t xs		: 1;   // Bit 2, same as SEPT
		#define GPA_LIST_OP_EXPORT	1
		#define GPA_LIST_OP_REEXPORT	3
		uint64_t operation	: 2;   // Bits 4:3
		uint64_t reserved0	: 2;   // Bits 6:5
		uint64_t mig_type 	: 3;   // Bits 9:7
		uint64_t xu       	: 1;   // Bit 10, same as SEPT
		uint64_t pending  	: 1;   // Bit 11
		uint64_t gfn      	: 40;  // Bits 51:12
		uint64_t status   	: 5;   // Bits 56:52
		uint64_t reserved1	: 3;   // Bit 59:57
		uint64_t sss      	: 1;   // Bit 60, same as SEPT
		uint64_t reserved2	: 3;   // Bits 63:61
	};
};

struct tdx_mig_gpa_list {
	union tdx_mig_gpa_list_entry *entries;
	union tdx_mig_gpa_list_info info;
};

/* Operation type used by blockw, ex/import.mem and export.restore */
enum gpa_list_operation_type {
	OP_TYPE_NOP_NOP_NOP = 0,
	OP_TYPE_BLOCKW_MIGRATE_RESTORE,
	OP_TYPE_NOP_CANCEL_NOP,
	OP_TYPE_BLOCKW_REMIGRATE_RESTORE,

	OP_TYPE_MAX,
};

enum gpa_list_mig_type {
	MIG_TYPE_PAGE_4K = 0,

	MIG_TYPE_MAX,
};

/*
 * Memory migration - buffer list:
 * Specifies a list of 4KB pages to be used by TDH_EXPORT_MEM and
 * TDH_IMPORT_MEM to export and import guest memory pages. Each entry
 * is 64-bit and specifies the physical adress of a 4KB buffer. The
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

/*
 * Memory migration - MAC list:
 * Specifies a list of MACs over 4KB migrated pages and their GPA entries
 * to be used by TDH_EXPORT_MEM and TDH_IMPORT_MEM. Each entry is 128-bit
 * containing a single AES-GMAC-256 of a migrated page. The list itself is
 * a 4KB page, so it can hold upto 256 entries. To support the export and
 * import of 512 pages, two such MAC list is needed to be passed to the TDX
 * module.
 */
struct tdx_mig_mac_list {
	void *entries;
	hpa_t hpa;
};

struct tdx_mig_stream {
	uint16_t idx;
	uint32_t mig_buf_list_npages;
	struct tdx_td_page migsc;
	struct tdx_mig_mbmd mbmd;
	struct tdx_mig_gpa_list gpa_list;
	struct tdx_mig_mac_list mac_list[2];
	/* List of buffers storing the memory data */
	struct tdx_mig_buf_list mig_buf_list;
	/* List of TD buffers (i.e TD pages) to recive the memory data */
	struct tdx_mig_buf_list td_buf_list;
	/* List of buffers storing the non-memory state data */
	struct tdx_mig_page_list page_list;
};

union tdx_mig_ept_config {
	uint64_t val;
	struct {
		uint64_t level	: 3;
		uint64_t rsvd1	: 9;
		uint64_t gfn	: 40;
		uint64_t rsvd2	: 12;
	};
};

#define TDX_MIG_STREAM_MAX	64

#define GPA_LIST_ENTRIES_MAX	(PAGE_SIZE / sizeof(gfn_t))

struct tdx_mig_state {
	atomic_t mig_stream_next_idx;
	uint32_t vcpu_export_next_idx;
	uint32_t max_migs;
	struct tdx_mig_gpa_list blockw_gpa_list;
	struct tdx_mig_stream streams[TDX_MIG_STREAM_MAX];
	struct tdx_mig_stream backward_stream;
};

static inline uint16_t tdx_mig_get_stream_num(struct kvm_tdx *kvm_tdx)
{
	struct tdx_mig_state *mig_state =
			(struct tdx_mig_state *)kvm_tdx->mig_state;

	return (uint16_t)atomic_read(&mig_state->mig_stream_next_idx);
}

static int tdx_mig_export_state_immutable(struct kvm_tdx *kvm_tdx,
					  struct tdx_mig_stream *stream,
					  uint64_t __user *data)
{
	struct tdx_module_output out;
	uint16_t stream_num = tdx_mig_get_stream_num(kvm_tdx);
	uint64_t i, err, stream_config = stream_num << 16;
	struct tdx_mig_page_list *page_list = &stream->page_list;
	struct tdx_mig_buf_list *mig_buf_list = &stream->mig_buf_list;

	/* Re-use the buffers filled in the buffer list */
	for (i = 0; i < stream->mig_buf_list_npages; i++)
		page_list->entries[i] = PFN_PHYS(mig_buf_list->entries[i].pfn);
	page_list->info.last_entry = stream->mig_buf_list_npages - 1;

	do {
		err = tdh_export_state_immutable(kvm_tdx->tdr.pa,
						 stream->mbmd.config,
						 page_list->info.val,
						 stream_config,
						 &out);
		if (err == TDX_INTERRUPTED_RESUMABLE)
			stream_config |= TDX_MIG_STREAM_CONFIG_RESUME;
	} while (err == TDX_INTERRUPTED_RESUMABLE);

	if (err == TDX_SUCCESS) {
		stream->idx = stream->mbmd.buf->migs_index;
		/* Tell userspace the num of exported 4KB pages*/
		if (copy_to_user(data, &out.rdx, sizeof(uint64_t)))
			return -EFAULT;
	} else {
		pr_err("%s: failed, err=%llx\n", __func__, err);
		return -EIO;
	}

	return 0;
}

static int tdx_mig_import_state_immutable(struct kvm_tdx *kvm_tdx,
					  struct tdx_mig_stream *stream,
					  uint64_t __user *data)
{
	struct tdx_module_output out;
	uint64_t i, err, npages, stream_config = 0;
	struct tdx_mig_page_list *page_list = &stream->page_list;
	struct tdx_mig_buf_list *mig_buf_list = &stream->mig_buf_list;

	if (copy_from_user(&npages, (void __user *)data, sizeof(uint64_t)))
		return -EFAULT;

	/* Re-use the buffers filled in the buffer list */
	for (i = 0; i < stream->mig_buf_list_npages; i++)
		page_list->entries[i] = PFN_PHYS(mig_buf_list->entries[i].pfn);
	page_list->info.last_entry = npages - 1;

	do {
		err = tdh_import_state_immutable(kvm_tdx->tdr.pa,
						 stream->mbmd.config,
						 stream->page_list.info.val,
						 stream_config,
						 &out);
		if (err == TDX_INTERRUPTED_RESUMABLE) {
			stream_config |= TDX_MIG_STREAM_CONFIG_RESUME;
		}
	} while (err == TDX_INTERRUPTED_RESUMABLE);

	if (err == TDX_SUCCESS) {
		stream->idx = stream->mbmd.buf->migs_index;
	} else {
		pr_err("%s: failed, err=%llx \n", __func__, err);
		return -EIO;
	}

	tdx_init_sept(&kvm_tdx->kvm);

	return 0;
}

static void tdx_mig_buf_list_set_valid(struct tdx_mig_buf_list *mig_buf_list,
				       uint64_t num)
{
	int i;

	for (i = 0; i < num; i++) {
		mig_buf_list->entries[i].invalid = false;
	}
	for (i = num; i < TDX_MIG_BUF_LIST_NPAGES_MAX; i++) {
		if (!mig_buf_list->entries[i].invalid)
			mig_buf_list->entries[i].invalid = true;
		else
			break;
	}
}

static int64_t tdx_mig_stream_export_mem(struct kvm_tdx *kvm_tdx,
					 struct tdx_mig_stream *stream,
					 uint64_t __user *data)
{
	struct tdx_module_output out;
	uint64_t npages, err, stream_config = stream->idx;
	/* Userspace is expected to fill the gpa_list.buf[i] fields */
	struct tdx_mig_gpa_list *gpa_list = &stream->gpa_list;
	struct tdx_mig_buf_list *mig_buf_list = &stream->mig_buf_list;

	if (copy_from_user(&npages, (void __user *)data, sizeof(uint64_t)))
		return -EFAULT;

	if (npages > stream->mig_buf_list_npages)
		return -EINVAL;

	/*
	 * The gpa list page is shared to userspace to fill GPAs directly.
	 * Only need to update the gpa_list info fields here.
	 */
	gpa_list->info.first_entry = 0;
	gpa_list->info.last_entry = npages - 1;
	tdx_mig_buf_list_set_valid(&stream->mig_buf_list, npages);

	do {
		err = tdh_export_mem(kvm_tdx->tdr.pa,
				     stream->mbmd.config,
				     gpa_list->info.val,
				     mig_buf_list->hpa,
				     stream->mac_list[0].hpa,
				     stream->mac_list[1].hpa,
				     stream_config,
				     &out);
		if (err == TDX_INTERRUPTED_RESUMABLE) {
			stream_config |= TDX_MIG_STREAM_CONFIG_RESUME;
			gpa_list->info.val = out.rcx;
		}
	} while (err == TDX_INTERRUPTED_RESUMABLE);

	/*
	 * It is possible that TDX module returns a general success,
	 * with some pages failed to be exported. For example, a page
	 * was write enabled before this export mem seamcall. The failed
	 * page is expected to be marked dirty and re-exported later in
	 * the next round. So no special handling here and just ignore
	 * such error.
	 * The number of failed pages is put in the operand id field, so
	 * we skip that part to indicate a general success of the call.
	 * Userspace should check the gpa list for each entry's status to
	 * decide if it is needed to save that page.
	 */
	if ((err & TDX_SEAMCALL_STATUS_MASK) == TDX_SUCCESS) {
		/*FIXME: need to calculate from gpa list? */
		out.rdx = out.rdx - 2; // workaround
		if (copy_to_user(data, &out.rdx, sizeof(uint64_t)))
			return -EFAULT;
		return 0;
	} else {
		pr_err("%s: err=%llx, gfn=%llx\n",
			__func__, err, (uint64_t)gpa_list->entries[0].gfn);
		return -EIO;
	}

	return 0;
}

static int tdx_mig_stream_buf_list_alloc(struct tdx_mig_buf_list *buf_list)
{
	struct page *page;

	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!page) {
		return -ENOMEM;
	}
	buf_list->entries = page_address(page);
	buf_list->hpa = page_to_phys(page);

	return 0;
}

static int tdx_mig_streamd_buf_list_add(struct kvm *kvm,
					uint64_t npages,
					struct tdx_mig_gpa_list *gpa_list,
					struct tdx_mig_buf_list *td_buf_list)
{
	int i;
	gfn_t gfn;
	union tdx_mig_buf_list_entry *entries;

	if (unlikely(!td_buf_list->entries) &&
	    tdx_mig_stream_buf_list_alloc(td_buf_list))
		return -ENOMEM;
	entries = td_buf_list->entries;
	/* TODO: Loop via gpa_list */

	/*
	 * Entries in priavte_page_list are all valid (zero-ed) by default.
	 * No need to set unfilled entries to invalid, because SEAM won't read
	 * it when reaches the end of gpa list (i.e. npages).
	 */
	for (i = 0; i < npages; i++) {
		gfn = (gfn_t)gpa_list->entries[i].gfn;
		entries[i].pfn = gfn_to_pfn(kvm, gfn);
		get_page(pfn_to_page(entries[i].pfn));
		entries[i].invalid = false;
	}
	if (i < TDX_MIG_BUF_LIST_NPAGES_MAX)
		entries[i].invalid = true;

	return 0;
}

static int tdx_mig_stream_import_mem(struct kvm_tdx *kvm_tdx,
				     struct tdx_mig_stream *stream,
				     uint64_t __user *data)
{
	uint64_t td_buf_list_config, mig_buf_list_config, npages, err;
	struct tdx_module_output out;
	uint64_t stream_config = stream->idx;
	struct tdx_mig_gpa_list *gpa_list = &stream->gpa_list;
	union tdx_mig_gpa_list_entry *entry = &gpa_list->entries[0];
	struct tdx_mig_buf_list *mig_buf_list = &stream->mig_buf_list;
	struct tdx_mig_buf_list *td_buf_list = &stream->td_buf_list;
	int ret;

	if (copy_from_user(&npages, (void __user *)data, sizeof(uint64_t)))
		return -EFAULT;

	ret = tdx_mig_streamd_buf_list_add(&kvm_tdx->kvm, npages,
					   gpa_list, td_buf_list);
	if (ret)
		return ret;

	if (entry->operation == GPA_LIST_OP_EXPORT) {
		/*
		 * For in-place import, the memory data has been put into the
		 * pages to be used as TD pages (e.g. QEMU pages).
		 */
		mig_buf_list_config = td_buf_list->hpa;
		td_buf_list_config = TDX_MIG_NULL_PA;
	} else {
		mig_buf_list_config = mig_buf_list->hpa;
		td_buf_list_config = td_buf_list->hpa;
	}

	do {
		err = tdh_import_mem(kvm_tdx->tdr.pa,
				     stream->mbmd.config,
				     stream->gpa_list.info.val,
				     mig_buf_list_config,
				     stream->mac_list[0].hpa,
				     stream->mac_list[1].hpa,
				     td_buf_list_config,
				     stream_config,
				     &out);
		if (err == TDX_INTERRUPTED_RESUMABLE) {
			stream_config |= TDX_MIG_STREAM_CONFIG_RESUME;
			gpa_list->info.val = out.rcx;
		}
	} while (err == TDX_INTERRUPTED_RESUMABLE);

	if (err != TDX_SUCCESS) {
		pr_err("%s failed, err=%llx\n", __func__, err);
		return -EIO;
	}

	return 0;
}

static bool tdx_mig_stream_in_mig_buf_list(uint32_t i)
{
	if (i >= TDX_MIG_STREAM_BUF_LIST_MAP_OFFSET &&
	    i < TDX_MIG_STREAM_BUF_LIST_MAP_OFFSET + TDX_MIG_BUF_LIST_NPAGES_MAX)
		return true;

	return false;
}

static vm_fault_t tdx_mig_stream_fault(struct vm_fault *vmf)
{
	struct kvm_device *dev = vmf->vma->vm_file->private_data;
	struct tdx_mig_stream *stream = dev->private;
	struct page *page;
	kvm_pfn_t pfn;
	uint32_t i;

	/* See linear_page_index for pgoff */
	if (vmf->pgoff == TDX_MIG_STREAM_MBMD_MAP_OFFSET) {
		page = virt_to_page(stream->mbmd.buf);
	} else if (vmf->pgoff == TDX_MIG_STREAM_GPA_LIST_MAP_OFFSET) {
		page = virt_to_page(stream->gpa_list.entries);
	} else if (vmf->pgoff == TDX_MIG_STREAM_MAC_LIST_MAP_OFFSET ||
		   vmf->pgoff == TDX_MIG_STREAM_MAC_LIST_MAP_OFFSET + 1) {
		i = vmf->pgoff - TDX_MIG_STREAM_MAC_LIST_MAP_OFFSET;
		if (stream->mac_list[i].entries) {
			page = virt_to_page(stream->mac_list[i].entries);
		} else {
			pr_err("%s: err, mac list page %d not allocated\n",
				__func__, i);
			return VM_FAULT_SIGBUS;
		}
	} else if (tdx_mig_stream_in_mig_buf_list(vmf->pgoff)) {
		i = vmf->pgoff - TDX_MIG_STREAM_BUF_LIST_MAP_OFFSET;
		pfn = stream->mig_buf_list.entries[i].pfn;
		page = pfn_to_page(pfn);
	} else {
		pr_err("%s called: VM_FAULT_SIGBUS\n", __func__);
		return VM_FAULT_SIGBUS;
	}

	get_page(page);
	vmf->page = page;
	return 0;
}

static const struct vm_operations_struct tdx_mig_stream_ops = {
	.fault = tdx_mig_stream_fault,
};

static int tdx_mig_stream_mmap(struct kvm_device *dev,
				   struct vm_area_struct *vma)
{
	vma->vm_ops = &tdx_mig_stream_ops;

	return 0;
}

static void
tdx_mig_stream_buf_list_cleanup(struct tdx_mig_buf_list *mig_buf_list, int num)
{
	int i;
	kvm_pfn_t pfn;
	struct page *page;

	for (i = 0; i < num; i++) {
		pfn = mig_buf_list->entries[i].pfn;
		page = pfn_to_page(pfn);
		__free_page(page);
	}
	free_page((unsigned long)mig_buf_list->entries);
}

static int tdx_mig_stream_buf_list_setup(struct tdx_mig_buf_list *mig_buf_list,
					 uint32_t npages)
{
	int i;
	struct page *page;

	if (!npages) {
		pr_err("%s: userspace should set_attr first\n", __func__);
		return -EINVAL;
	}

	if (tdx_mig_stream_buf_list_alloc(mig_buf_list))
		return -ENOMEM;

	for (i = 0; i < npages; i++) {
		page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
		if (!page) {
			tdx_mig_stream_buf_list_cleanup(mig_buf_list, i);
			return -ENOMEM;
		}
		mig_buf_list->entries[i].pfn = page_to_pfn(page);
	}

	/* Mark unused entries as invalid */
	for (i = npages; i < TDX_MIG_BUF_LIST_NPAGES_MAX; i++)
		mig_buf_list->entries[i].invalid = true;

	return 0;
}

/*
 * Reuse the allocated pages from mem_mig_buf_list load non-memory
 * states, so it needs to be set up after tdx_mig_stream_buf_list_setup.
 */
static int tdx_mig_stream_gpa_list_setup(struct tdx_mig_gpa_list *gpa_list)
{
	struct page *page;

	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!page) {
		return -ENOMEM;
	}
	gpa_list->info.pfn = page_to_pfn(page);
	gpa_list->entries = page_address(page);

	return 0;
}

static int tdx_mig_stream_mbmd_setup(struct tdx_mig_mbmd *mbmd)
{
	struct page *page;

	page = alloc_pages(GFP_KERNEL_ACCOUNT | __GFP_ZERO,
			   TDX_MIG_MBMD_ALLOC_ORDER);
	if (!page)
		return -ENOMEM;

	mbmd->buf = page_address(page);
	mbmd->config = page_to_phys(page) | (TDX_MIG_MBMD_SIZE - 1) << 52;

	return 0;
}

static int tdx_mig_stream_mac_list_setup(struct tdx_mig_mac_list *mac_list)
{
	struct page *page;

	page = alloc_pages(GFP_KERNEL_ACCOUNT | __GFP_ZERO, 0);
	if (!page)
		return -ENOMEM;

	mac_list->entries = page_address(page);
	mac_list->hpa = page_to_phys(page);

	return 0;
}

static int
tdx_mig_stream_page_list_setup(struct tdx_mig_page_list *page_list)
{
	struct page *page;

	page = alloc_pages(GFP_KERNEL_ACCOUNT | __GFP_ZERO, 0);
	if (!page)
		return -ENOMEM;

	page_list->entries = page_address(page);
	page_list->info.pfn = page_to_pfn(page);

	return 0;
}

/*
 * Allocate migration buffer list, mbmd, gpa buffer list, and mac buffer list,
 * and they will be shared to userspace for direct access.
 */
static int tdx_mig_stream_setup(struct tdx_mig_stream *stream)
{
	int ret;

	ret = tdx_mig_stream_mbmd_setup(&stream->mbmd);
	if (ret)
		goto err_mbmd;

	ret = tdx_mig_stream_page_list_setup(&stream->page_list);
	if (ret)
		goto err_page_list;

	ret = tdx_mig_stream_buf_list_setup(&stream->mig_buf_list,
					    stream->mig_buf_list_npages);
	if (ret)
		goto err_mig_buf_list;

	ret = tdx_mig_stream_gpa_list_setup(&stream->gpa_list);
	if (ret)
		goto err_gpa_list;

	ret = tdx_mig_stream_mac_list_setup(&stream->mac_list[0]);
	if (ret)
		goto err_mac_list0;
	/*
	 * The 2nd mac list is needed only when the buf list uses more than
	 * 256 entries
	 */
	if (stream->mig_buf_list_npages > 256) {
		ret = tdx_mig_stream_mac_list_setup(&stream->mac_list[1]);
		if (ret)
			goto err_mac_list1;
	}

	return 0;

err_mac_list1:
	free_page((unsigned long)stream->mac_list[0].entries);
err_mac_list0:
	free_page((unsigned long)stream->gpa_list.entries);
err_gpa_list:
	free_page((unsigned long)stream->mig_buf_list.entries);
err_mig_buf_list:
	free_page((unsigned long)stream->page_list.entries);
err_page_list:
	free_page((unsigned long)stream->mbmd.buf);
err_mbmd:
	pr_err("%s called: failed, ret=%d\n", __func__, ret);
	return ret;
}

static int tdx_mig_export_pause(struct kvm_tdx *kvm_tdx)
{
	uint64_t err;

	err = tdh_export_pasue(kvm_tdx->tdr.pa);
	pr_err("%s: paued, err=%llx\n", __func__, err);
	if (err != TDX_SUCCESS) {
		pr_err("%s: failed, err=%llx\n", __func__, err);
		return -EIO;
	}

	return 0;
}

static int tdx_mig_export_track(struct kvm_tdx *kvm_tdx,
				struct tdx_mig_stream *stream,
				uint64_t __user *data)
{

	uint64_t err, stream_config = 0;

	if (copy_from_user(&stream_config, (void __user *)data,
			   sizeof(uint64_t)))
		return -EFAULT;

	/*
	 * IN_ORDER_DONE is set by userspace to generate a start token. Other
	 * bits must be 0.
	 */
	stream_config &= TDX_MIG_STREAM_CONFIG_IN_ORDER_DONE;
	err = tdh_export_track(kvm_tdx->tdr.pa,
			       stream->mbmd.config, stream_config);
	if (err != TDX_SUCCESS) {
		pr_err("%s: failed, err=%llx\n", __func__, err);
		return -EIO;
	}

	return 0;
}

static inline bool
tdx_mig_epoch_is_start_token(struct tdx_mig_mbmd_hdr *mbmd_hdr)
{
	return mbmd_hdr->mig_epoch == TDX_MIG_EPOCH_START_TOKEN;
}

static int tdx_mig_import_track(struct kvm_tdx *kvm_tdx,
				struct tdx_mig_stream *stream)
{
	uint64_t err, stream_config = 0;

	err = tdh_import_track(kvm_tdx->tdr.pa,
				stream->mbmd.config,
				stream_config);
	if (err != TDX_SUCCESS) {
		pr_err("%s: failed, err=%llx\n", __func__, err);
		return -EIO;
	}

	if (tdx_mig_epoch_is_start_token(stream->mbmd.buf)) {
		err = tdh_import_end(kvm_tdx->tdr.pa);
		pr_err("%s: tdh_import_end, err=%llx\n",
			__func__, err);
		if (err != TDX_SUCCESS) {
			pr_err("%s: importend failed, err=%llx\n",
				__func__, err);
			return -EIO;
		}
	}

	return 0;
}

static int tdx_mig_import_end(struct kvm_tdx *kvm_tdx,
			      struct tdx_mig_stream *stream)
{
	uint64_t err = 0;

	err = tdh_import_end(kvm_tdx->tdr.pa);
	if (err != TDX_SUCCESS) {
		pr_err("%s: failed, err=%llx\n", __func__, err);
		return -EIO;
	}
	kvm_tdx->finalized = true;

	return 0;
}

static int tdx_mig_export_state_td(struct kvm_tdx *kvm_tdx,
				   struct tdx_mig_stream *stream,
				   uint64_t __user *data)
{
	struct tdx_module_output out;
	uint64_t err, stream_config = 0;

	do {
		err = tdh_export_state_td(kvm_tdx->tdr.pa,
					  stream->mbmd.config,
					  stream->page_list.info.val,
					  stream_config,
					  &out);
		if (err == TDX_INTERRUPTED_RESUMABLE)
			stream_config |= TDX_MIG_STREAM_CONFIG_RESUME;
	} while (err == TDX_INTERRUPTED_RESUMABLE);

	if (err == TDX_SUCCESS) {
		pr_err("%s: err=%llx, out.rdx=%lld \n", __func__, err, out.rdx);
		if (copy_to_user(data, &out.rdx, sizeof(uint64_t)))
			return -EFAULT;
	} else {
		pr_err("%s: failed, err=%llx \n", __func__, err);
		return -EIO;
	}

	return 0;
}

static int tdx_mig_import_state_td(struct kvm_tdx *kvm_tdx,
				   struct tdx_mig_stream *stream,
				   uint64_t __user *data)
{
	struct tdx_module_output out;
	uint64_t err, npages, stream_config = 0;
	struct tdx_mig_page_list *page_list = &stream->page_list;

	if (copy_from_user(&npages, (void __user *)data, sizeof(uint64_t)))
		return -EFAULT;

	page_list->info.last_entry = npages - 1;
	pr_err("%s: npages=%lld \n", __func__, npages);
	do {
		err = tdh_import_state_td(kvm_tdx->tdr.pa,
					  stream->mbmd.config,
					  page_list->info.val,
					  stream_config,
					  &out);
		if (err == TDX_INTERRUPTED_RESUMABLE)
			stream_config |= TDX_MIG_STREAM_CONFIG_RESUME;
	} while (err == TDX_INTERRUPTED_RESUMABLE);

	if (err != TDX_SUCCESS) {
		pr_err("%s: failed, err=%llx \n", __func__, err);
		return -EIO;
	}

	return 0;
}

static int tdx_mig_export_state_vp(struct kvm_tdx *kvm_tdx,
				   struct tdx_mig_stream *stream,
				   uint64_t __user *data)
{
	struct tdx_module_output out;
	struct kvm *kvm = &kvm_tdx->kvm;
	uint64_t err, stream_config = stream->idx;
	struct kvm_vcpu *vcpu;
	struct vcpu_tdx *vcpu_tdx;
	struct tdx_mig_state *mig_state =
			(struct tdx_mig_state *)kvm_tdx->mig_state;
	int cpu;


	if (mig_state->vcpu_export_next_idx >=
	    atomic_read(&kvm->online_vcpus)) {
		pr_err("%s: vcpu_export_next_idx %d >= online_vcpus %d\n",
			__func__, mig_state->vcpu_export_next_idx,
			atomic_read(&kvm->online_vcpus));
		return -EINVAL;
	}

	vcpu = kvm_get_vcpu(kvm, mig_state->vcpu_export_next_idx);
	vcpu_tdx = to_tdx(vcpu);
	tdx_flush_vp_on_cpu(vcpu);
	cpu = get_cpu();

	do {
		err = tdh_export_state_vp(vcpu_tdx->tdvpr.pa,
					  stream->mbmd.config,
					  stream->page_list.info.val,
					  stream_config,
					  &out);
		if (err == TDX_INTERRUPTED_RESUMABLE)
			stream_config |= TDX_MIG_STREAM_CONFIG_RESUME;
	} while (err == TDX_INTERRUPTED_RESUMABLE);

	if (err == TDX_SUCCESS) {
		mig_state->vcpu_export_next_idx++;
		if (copy_to_user(data, &out.rdx, sizeof(uint64_t)))
			return -EFAULT;
	} else {
		pr_err("%s: failed, err=%llx \n", __func__, err);
		return -EIO;
	}
	tdx_add_vcpu_association(vcpu_tdx, cpu);
	vcpu->cpu = cpu;
	put_cpu();

	return 0;
}

static uint16_t tdx_mig_mbmd_get_vcpu_idx(struct tdx_mig_mbmd_hdr *mbmd)
{
	return *(uint16_t *)mbmd->type_specific_info;
}

static int tdx_mig_import_state_vp(struct kvm_tdx *kvm_tdx,
				   struct tdx_mig_stream *stream,
				   uint64_t __user *data)
{
	struct tdx_module_output out;
	struct vcpu_tdx *vcpu_tdx;
	struct kvm_vcpu *vcpu;
	int cpu, vcpu_idx;
	uint64_t err, npages, stream_config = 0;
	struct tdx_mig_page_list *page_list = &stream->page_list;

	if (copy_from_user(&npages, (void __user *)data, sizeof(uint64_t)))
		return -EFAULT;

	vcpu_idx = tdx_mig_mbmd_get_vcpu_idx(stream->mbmd.buf);
        vcpu = kvm_get_vcpu(&kvm_tdx->kvm, vcpu_idx);
	vcpu_tdx = to_tdx(vcpu);

	page_list->info.last_entry = npages - 1;

	/*TODO: Move to the bottom */
	tdx_td_post_init(kvm_tdx);
	tdx_vcpu_reset(vcpu, false);

	tdx_flush_vp_on_cpu(vcpu);
	cpu = get_cpu();
	do {
		err = tdh_import_state_vp(vcpu_tdx->tdvpr.pa,
					  stream->mbmd.config,
					  page_list->info.val,
					  stream_config,
					  &out);
		if (err == TDX_INTERRUPTED_RESUMABLE)
			stream_config |= TDX_MIG_STREAM_CONFIG_RESUME;
	} while (err == TDX_INTERRUPTED_RESUMABLE);

	if (err != TDX_SUCCESS) {
		pr_err("%s: failed, err=%llx \n", __func__, err);
		put_cpu();
		return -EIO;
	}

	tdx_vcpu_posted_intr_setup(vcpu_tdx);
	tdx_add_vcpu_association(vcpu_tdx, cpu);
	vcpu->cpu = cpu;
	put_cpu();

	return 0;
}

static void tdx_mig_gpa_list_setup(struct tdx_mig_gpa_list *gpa_list,
				   gfn_t *gfns,
				   uint32_t num,
				   uint32_t entry_start,
				   enum gpa_list_operation_type op_type,
				   enum gpa_list_mig_type mig_type)
{
	uint32_t i;

	for (i = entry_start; i < num; i++) {
		gpa_list->entries[i].val = 0;
		gpa_list->entries[i].gfn = gfns[i];
		gpa_list->entries[i].operation = op_type;
		gpa_list->entries[i].mig_type = mig_type;
	}
}

static int tdx_sept_write_disable_spte(struct kvm *kvm, gfn_t *gfns,
				       uint32_t num, int level)
{
	uint64_t err;
	struct tdx_module_output out;
	uint32_t start, blockw_num = 0;
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_mig_state *mig_state =
		(struct tdx_mig_state *)kvm_tdx->mig_state;
	struct tdx_mig_gpa_list *gpa_list = &mig_state->blockw_gpa_list;

	if (level != 1) {
		pr_err("%s: level=%d, num=%d\n", __func__, level, num);
		return -ENOTSUPP;
	}

	if (num > 1)
		pr_err("%s: num=%d, gfns[0]=%llx\n", __func__, num, gfns[0]);
	for (start = 0; start < num; start += blockw_num) {
		if (num > GPA_LIST_ENTRIES_MAX)
			blockw_num = GPA_LIST_ENTRIES_MAX;
		else
			blockw_num = num;

		tdx_mig_gpa_list_setup(gpa_list,
				       gfns + start,
				       blockw_num,
				       0,
				       OP_TYPE_BLOCKW_REMIGRATE_RESTORE,
				       MIG_TYPE_PAGE_4K);

		do {
			err = tdh_export_blockw(kvm_tdx->tdr.pa,
						gpa_list->info.val, &out);
			if (err == TDX_INTERRUPTED_RESUMABLE)
				gpa_list->info.val = out.rcx;
		} while (err == TDX_INTERRUPTED_RESUMABLE);

		if (err != TDX_SUCCESS) {
			pr_err("%s failed, err=%llx, gfn=%lx\n",
				__func__, err, (long)gpa_list->entries[0].gfn);
			return -EIO;
		}
	}

	WRITE_ONCE(kvm_tdx->has_range_blocked, true);

	return 0;
}

static int tdx_sept_write_enable_spte(struct kvm *kvm, gfn_t gfn, int level)
{
	int64_t err;
	struct tdx_module_output out;
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	union tdx_mig_ept_config ept_config = {
		/*
		 * TDX treats level 0 as the leaf level, while Linux treats
		 * level 1 (PG_LEVEL_4K) as the level.
		 */
		.level = pg_level_to_tdx_sept_level(level),
		.rsvd1 = 0,
		.gfn = gfn,
		.rsvd2 = 0,
	};

	tdx_track(kvm_tdx);

	err = tdh_export_unblockw(kvm_tdx->tdr.pa, ept_config.val, &out);
	if (err != TDX_SUCCESS) {
		return -EIO;
	}

	return 0;
}

static int tdx_mig_export_restore_pages(struct kvm_tdx *kvm_tdx,
					struct tdx_mig_stream *stream,
					gfn_t gfn_start,
					uint64_t num)
{
	uint64_t i, err;
	gfn_t gfn;
	struct tdx_module_output out;
	struct tdx_mig_gpa_list *gpa_list = &stream->gpa_list;

	for (i = 0; i < num; i++) {
		gfn = gfn_start + i;
		tdx_mig_gpa_list_setup(gpa_list,
				       &gfn, 1, i,
				       OP_TYPE_BLOCKW_MIGRATE_RESTORE,
				       MIG_TYPE_PAGE_4K);
	}

	do {
		err = tdh_export_restore(kvm_tdx->tdr.pa,
					 gpa_list->info.val, &out);
		if (err == TDX_INTERRUPTED_RESUMABLE)
			gpa_list->info.val = out.rcx;
	} while (err == TDX_INTERRUPTED_RESUMABLE);

	if ((err & TDX_SEAMCALL_STATUS_MASK) != TDX_SUCCESS) {
		pr_err("%s failed, err=%llx, gfn=%lx\n",
			__func__, err, (long)gpa_list->entries[0].gfn);
		return -EIO;
	}

	return 0;
}

static int tdx_mig_export_abort(struct kvm_tdx *kvm_tdx,
				struct tdx_mig_stream *stream,
				uint64_t __user *data)
{
	gfn_t i, gfn_end;
	uint64_t remaining, err;

	if (copy_from_user(&gfn_end, (void __user *)data, sizeof(uint64_t)))
		return -EFAULT;

	err = tdh_export_abort(kvm_tdx->tdr.pa, 0, 0);
	if (err != TDX_SUCCESS) {
		pr_err("%s: tdh_export_abort failed, err=%llx\n", __func__, err);
	}

	for (i = 0; i < gfn_end; i++) {
		/*
		 * Some pages may have already been unblocked and the seamcall
		 * may return an error to indicate that. No need to handle such
		 * errors, just ignore them.
		 */
		tdx_sept_write_enable_spte(&kvm_tdx->kvm, i, PG_LEVEL_4K);
		if (i && !(i % GPA_LIST_ENTRIES_MAX)) {
			tdx_mig_export_restore_pages(kvm_tdx, stream,
				i - GPA_LIST_ENTRIES_MAX, GPA_LIST_ENTRIES_MAX);
		}
	}
	remaining = gfn_end % GPA_LIST_ENTRIES_MAX;
	if (remaining) {
		tdx_mig_export_restore_pages(kvm_tdx, stream,
					gfn_end - remaining, remaining);
	}

	return 0;
}

static long tdx_mig_stream_ioctl(struct kvm_device *dev, unsigned int ioctl,
				 unsigned long arg)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(dev->kvm);
	struct tdx_mig_stream *stream = dev->private;
	void __user *argp = (void __user *)arg;
	struct kvm_tdx_cmd tdx_cmd;
	int r;

	if (copy_from_user(&tdx_cmd, argp, sizeof(struct kvm_tdx_cmd)))
		return -EFAULT;

	switch (tdx_cmd.id) {
	case KVM_TDX_MIG_EXPORT_STATE_IMMUTABLE:
		r = tdx_mig_export_state_immutable(kvm_tdx, stream,
					(uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_IMPORT_STATE_IMMUTABLE:
		r = tdx_mig_import_state_immutable(kvm_tdx, stream,
					(uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_EXPORT_MEM:
		r = tdx_mig_stream_export_mem(kvm_tdx, stream,
					(uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_IMPORT_MEM:
		r = tdx_mig_stream_import_mem(kvm_tdx, stream,
					(uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_EXPORT_PAUSE:
		r = tdx_mig_export_pause(kvm_tdx);
		break;
	case KVM_TDX_MIG_EXPORT_STATE_TD:
		r = tdx_mig_export_state_td(kvm_tdx, stream,
					(uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_IMPORT_STATE_TD:
		r = tdx_mig_import_state_td(kvm_tdx, stream,
					(uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_EXPORT_STATE_VP:
		r = tdx_mig_export_state_vp(kvm_tdx, stream,
					(uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_IMPORT_STATE_VP:
		r = tdx_mig_import_state_vp(kvm_tdx, stream,
					(uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_EXPORT_TRACK:
		r = tdx_mig_export_track(kvm_tdx, stream,
					(uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_IMPORT_TRACK:
		r = tdx_mig_import_track(kvm_tdx, stream);
		break;
	case KVM_TDX_MIG_IMPORT_END:
		/*FIXME: Not needed? to remove */
		r = tdx_mig_import_end(kvm_tdx, stream);
		break;
	case KVM_TDX_MIG_EXPORT_ABORT:
		r = tdx_mig_export_abort(kvm_tdx, stream,
					 (uint64_t __user *)tdx_cmd.data);
		break;
	default:
		r = -EINVAL;
	}

	return r;
}

static int tdx_mig_do_stream_create(struct kvm_tdx *kvm_tdx,
				    struct tdx_mig_stream *stream)
{
	int ret;
	uint64_t err;
	struct tdx_td_page *migsc = &stream->migsc;

	ret = tdx_alloc_td_page(migsc);
	if (ret)
		return ret;

	err = tdh_stream_create(kvm_tdx->tdr.pa, migsc->pa);
	if (err != TDX_SUCCESS) {
		pr_err("%s: failed, err=%llx\n", __func__, err);
		tdx_reclaim_td_page(migsc);
		return -EIO;
	}
	tdx_mark_td_page_added(migsc);

	return 0;
}

static void tdx_mig_state_cleanup(struct kvm_tdx *kvm_tdx)
{
	int i;
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;
	struct tdx_mig_stream *stream = &mig_state->backward_stream;

	if (!mig_state)
		return;

	/* Sanity check: all the streams should have been released */
	if (atomic_read(&mig_state->mig_stream_next_idx)) {
		pr_err("%s: not all streams released: %d\n",
			__func__, atomic_read(&mig_state->mig_stream_next_idx));
		return;
	}

	tdx_reclaim_td_page(&stream->migsc);
	for (i = 0; i < TDX_MIG_STREAM_MAX; i++) {
		stream = &mig_state->streams[i];
		if (!stream->mig_buf_list_npages)
			continue;
		tdx_reclaim_td_page(&stream->migsc);
		memset(stream, 0, sizeof(struct tdx_mig_stream));
	}
	if (mig_state->blockw_gpa_list.entries)
		free_page((unsigned long)mig_state->blockw_gpa_list.entries);
	kfree(mig_state);
	kvm_tdx->mig_state = NULL;
}

static inline bool kvm_tdx_is_migration_src(struct kvm_tdx *kvm_tdx)
{
	/*FIXME: use servtd type as index */
//	return kvm_tdx->mig_slots[0].is_src;
	return true;
}

static struct tdx_mig_state *tdx_mig_state_create(struct kvm_tdx *kvm_tdx)
{
	struct tdx_mig_state *mig_state;
	struct tdx_module_output out;
	uint64_t err;

	err = tdh_sys_rd(TDX_MIG_FID_MAX_MIGS, &out);
	if (err) {
		pr_err("%s: failed to get max_migs err=%llx\n", __func__, err);
		return NULL;
	}

	mig_state = kzalloc(sizeof(struct tdx_mig_state), GFP_KERNEL_ACCOUNT);
	if (!mig_state) {
		pr_err("%s: fail to alloc tdx_mig_state\n", __func__);
		return NULL;
	}
	mig_state->max_migs = out.r8;

	if (kvm_tdx_is_migration_src(kvm_tdx))
		tdx_mig_stream_gpa_list_setup(&mig_state->blockw_gpa_list);

	atomic_set(&mig_state->mig_stream_next_idx, 0);
	mig_state->vcpu_export_next_idx = 0;

	if (tdx_mig_do_stream_create(kvm_tdx, &mig_state->backward_stream)) {
		if (mig_state->blockw_gpa_list.entries)
			kfree(mig_state->blockw_gpa_list.entries);
		kfree(mig_state);
		return NULL;
	}

	return mig_state;
}

static int tdx_mig_stream_create(struct kvm_device *dev, u32 type)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(dev->kvm);
	struct tdx_mig_state *mig_state;
	struct tdx_mig_stream *stream;
	unsigned int idx;
	int err;

	if (!kvm_tdx->mig_state)
		kvm_tdx->mig_state = tdx_mig_state_create(kvm_tdx);

	mig_state = (struct tdx_mig_state *)kvm_tdx->mig_state;
	if (!mig_state)
		return -ENOENT;

	idx = atomic_inc_return(&mig_state->mig_stream_next_idx) - 1;

	if (idx >= mig_state->max_migs)
		return -ENOENT;

	stream = &mig_state->streams[idx];
	err = tdx_mig_do_stream_create(kvm_tdx, stream);
	if (err)
		return err;

	dev->private = stream;

	return 0;
}

static void tdx_mig_stream_release(struct kvm_device *dev)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(dev->kvm);
	struct tdx_mig_stream *stream = dev->private;
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;

	free_page((unsigned long)stream->mbmd.buf);
	free_page((unsigned long)stream->gpa_list.entries);
	free_page((unsigned long)stream->mac_list[0].entries);
	/*
	 * The 2nd mac list page is allocted conditionally (when the batch
	 * size is larger than 256).
	 */
	if (stream->mac_list[1].entries)
		free_page((unsigned long)stream->mac_list[1].entries);

	tdx_mig_stream_buf_list_cleanup(&stream->mig_buf_list,
					stream->mig_buf_list_npages);
	free_page((unsigned long)stream->page_list.entries);
	atomic_dec(&mig_state->mig_stream_next_idx);
}

static int tdx_mig_stream_get_mig_info(struct tdx_mig_stream *stream,
				       struct kvm_dev_tdx_mig_info *info)
{
	uint64_t err;
	struct tdx_module_output out;

	err = tdh_sys_rd(TDX_MIG_FID_MAX_MIGS, &out);
	if (err) {
		pr_err("%s: failed to get max_migs, err=%llx\n",
			__func__, err);
		return -EIO;
	}
	info->max_migs = out.r8;

	info->kvm_version = TDX_MIG_KVM_VERSION;
	info->mbmd_size = TDX_MIG_MBMD_SIZE;
	info->buf_list_size = stream->mig_buf_list_npages * PAGE_SIZE;
	info->mac_list_size =
		stream->mac_list[1].entries ? PAGE_SIZE * 2 : PAGE_SIZE;
	info->gpa_list_size = TDX_MIG_GPA_LIST_SIZE;

	return 0;
}

static int tdx_mig_stream_get_attr(struct kvm_device *dev,
				   struct kvm_device_attr *attr)
{
	struct tdx_mig_stream *stream = dev->private;
	u64 __user *uaddr = (u64 __user *)(long)attr->addr;

	switch (attr->group) {
	case KVM_DEV_TDX_MIG_INFO: {
		struct kvm_dev_tdx_mig_info info;

		if (attr->attr != sizeof(struct kvm_dev_tdx_mig_info)) {
			pr_err("%s: uncompatible kvm_dev_tdx_mig_info\n",
				__func__);
			return -EINVAL;
		}

		tdx_mig_stream_get_mig_info(stream, &info);
		if (copy_to_user(uaddr, &info, sizeof(info)))
			return -EFAULT;
		break;
	}
	default:
		return -EINVAL;
	}

	return 0;
}

static int tdx_mig_stream_set_tdx_mig_info(struct tdx_mig_stream *stream,
					   struct kvm_dev_tdx_mig_info *info)
{
	uint64_t err;
	uint32_t npages_min, npages_req,
		 immutable_npages, td_npages, vp_npages;
	struct tdx_module_output out;

	err = tdh_sys_rd(TDX_MIG_FID_IMMUTABLE_NPAGES, &out);
	if (err) {
		pr_err("%s: failed to get immutable_npages, err=%llx\n",
			__func__, err);
		return -EIO;
	}
	immutable_npages = out.r8;

	err = tdh_sys_rd(TDX_MIG_FID_TD_NPAGES, &out);
	if (err) {
		pr_err("%s: failed to get td_npages, err=%llx\n",
			__func__, err);
		return -EIO;
	}
	td_npages = out.r8;

	err = tdh_sys_rd(TDX_MIG_FID_VP_NPAGES, &out);
	if (err) {
		pr_err("%s: failed to get td_npages, err=%llx\n",
			__func__, err);
		return -EIO;
	}
	vp_npages = out.r8;
	/*
	 * The minimal number of pages required.
	 * Should be large enough to store all the non-memory states.
	 */
	npages_min = max3(immutable_npages, td_npages, vp_npages);

	if (npages_min > TDX_MIG_BUF_LIST_NPAGES_MAX) {
		pr_err("%s: unlikely bug occured\n", __func__);
		return -EIO;
	}

	/*
	 * Check the number of pages to batch requested from userspace
	 * Userspace should get the actual batch number via get_attr after
	 * set_attr is called.
	 */
	npages_req = info->buf_list_size >> PAGE_SHIFT;
	if (npages_req < npages_min)
		stream->mig_buf_list_npages = npages_min;
	else if (npages_req > TDX_MIG_BUF_LIST_NPAGES_MAX)
		stream->mig_buf_list_npages = TDX_MIG_BUF_LIST_NPAGES_MAX;
	else
		stream->mig_buf_list_npages = npages_req;

	return 0;
}

static int tdx_mig_stream_set_attr(struct kvm_device *dev,
				   struct kvm_device_attr *attr)
{
	struct tdx_mig_stream *stream = dev->private;
	u64 __user *uaddr = (u64 __user *)(long)attr->addr;
	int ret;

	switch (attr->group) {
	case KVM_DEV_TDX_MIG_INFO: {
		struct kvm_dev_tdx_mig_info info;

		if (copy_from_user(&info, uaddr, sizeof(info)))
			return -EFAULT;

		/* Requested buf size to map should be page aligned */
		if (info.buf_list_size % PAGE_SIZE)
			return -EINVAL;

		ret = tdx_mig_stream_set_tdx_mig_info(stream, &info);
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

static struct kvm_device_ops kvm_tdx_mig_stream_ops = {
	.name = "kvm-tdx-mig",
	.create = tdx_mig_stream_create,
	.release = tdx_mig_stream_release,
	.ioctl = tdx_mig_stream_ioctl,
	.mmap = tdx_mig_stream_mmap,
	.get_attr = tdx_mig_stream_get_attr,
	.set_attr = tdx_mig_stream_set_attr,
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
