// SPDX-License-Identifier: GPL-2.0
#include <linux/acpi.h>
#include <linux/intel-iommu.h>
#include <linux/kvm_host.h>
#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/spinlock.h>

#include <asm/pci_ide.h>

#define IOMMU_ID_INVALID		(U64_MAX)
#define USED_STREAM_IDS_BM_SIZE		(MAX_IDE_STREAM_ID + 1)

static struct acpi_table_header *keyp_tbl;

unsigned int num_key_config;
static struct key_config **key_config; /* a list of key_config pointers */

struct used_id_bitmap {
	DECLARE_BITMAP(ids, USED_STREAM_IDS_BM_SIZE);
	spinlock_t lock;
};

struct ide_km_request {
	int stream_id;
	int slot_id;

	enum pci_ide_object_id object_id;
	enum pci_ide_stream_key_set_sel key_set;
	enum pci_ide_sub_stream_direction direction;
	enum pci_ide_stream_sub_stream sub_stream;

	/* DOE buffer for exchanging data with device */
	unsigned long request_va;
	unsigned long response_va;
};

struct key_config {
	unsigned int id;

	/*
	 * Now use IOMMU_ID_INVALID(same as U64_MAX) to define iommu_id is not set,
	 * refactor it if U64_MAX has meaning for iommu_id in the future.
	 */
	u64 iommu_id;
	u64 addr;

	u16 num_stream_supported;
	u16 num_tx_key_slots;
	u16 num_rx_key_slots;

	struct used_id_bitmap used_id;

	bool tee_capable;
	unsigned int num_rp;
	spinlock_t rp_cfg_lock;
	unsigned long *rp_cfg_bitmap;
	u32 rp_sbdf[];
};

#define pci_sbdf(seg, bus, devfn)	\
	((((u32)(seg) & 0xffff) << 16) | (((bus) & 0xff) << 8) | ((devfn) & 0xff))

struct intel_ide {
	struct key_config *kconfig;
	int kconfig_idx;

	struct used_id_bitmap used_id;
};

struct intel_ide_key_set {
	int slot_id[PCI_IDE_SUB_STREAM_DIRECTION_NUM][PCI_IDE_SUB_STREAM_NUM];
};

struct intel_ide_stream {
	int key_id;

	struct intel_ide_key_set k_set[PCI_IDE_KEY_SET_NUM];

	/* for ide streams in tee mode */
	struct tdx_td_page exinfo;
};

struct doe_va_t {
	unsigned long doe_request_va;
	unsigned long doe_response_va;
};

static void keyp_table_print_keycu_entry(struct acpi_keyp_kcu *entry)
{
	pr_info("KEYP kcu entry: type:0x%x, length:0x%x, prot_type:0x%x, version:0x%x, rp_count:0x%x, flags:0x%x, addr:0x%llx\n",
		entry->type,
		entry->length,
		entry->prot_type,
		entry->version,
		entry->rp_count,
		entry->flags,
		entry->kcb_addr);
}

static void key_config_info_destroy(void)
{
	int i;

	for (i = 0; i < num_key_config; i++)
		kfree(key_config[i]);

	num_key_config = 0;
	kfree(key_config);
}

static int key_config_unit_check_and_count(void *start, void *end)
{
	struct acpi_keyp_kcu *iter;
	unsigned int count = 0;
	void *next;

	for (iter = start; (void *)iter < end; iter = next) {
		next = (void *)iter + iter->length;

		if (next > end) {
			/* Avoid passing table end */
			pr_warn(FW_BUG "Record passes table end\n");
			return -EINVAL;
		}

		if (iter->length !=
		    sizeof(*iter) + sizeof(struct acpi_keyp_kcu_rp) * iter->rp_count) {
			/* Stop on the bad entry */
			pr_warn(FW_BUG "Invalid entry length or root port count\n");
			break;
		}

		/* Some confusing in SPEC, so CXL CACHE/MEM type is skipped */
		if (iter->prot_type != ACPI_KEYP_KCU_PROT_TYPE_PCIE_CXLIO)
			continue;

		count++;
	}

	return count ? : -EINVAL;
}

static void key_config_info_init(struct key_config *kc)
{
	spin_lock_init(&kc->used_id.lock);
	spin_lock_init(&kc->rp_cfg_lock);
	kc->iommu_id = IOMMU_ID_INVALID;
}

static int key_config_get_capabilities(struct key_config *kc)
{
	u32 cap;
	void *addr;

	addr = ioremap(kc->addr, sizeof(cap));
	if (!addr)
		return -EINVAL;
	cap = readl(addr);
	iounmap(addr);

	kc->num_stream_supported = FIELD_GET(KCB_CAP_NUM_STREAM_SUPPORTED, cap) + 1;
	kc->num_tx_key_slots = FIELD_GET(KCB_CAP_NUM_TX_KEY_SLOTS, cap) + 1;
	kc->num_rx_key_slots = FIELD_GET(KCB_CAP_NUM_RX_KEY_SLOTS, cap) + 1;

	return 0;
}

static struct key_config *key_config_unit_parse(struct acpi_keyp_kcu *kcu)
{
	struct acpi_keyp_kcu_rp *rp;
	struct key_config *kc;
	int ret;
	int i;

	kc = kzalloc(sizeof(*kc) + sizeof(u32) * kcu->rp_count, GFP_KERNEL);
	if (!kc)
		return ERR_PTR(-ENOMEM);

	key_config_info_init(kc);

	kc->addr = kcu->kcb_addr;
	kc->tee_capable = kcu->flags & ACPI_KEYP_KCU_FLAG_TEE_IO_CAP;
	kc->num_rp = kcu->rp_count;
	ret = key_config_get_capabilities(kc);
	if (ret) {
		kfree(kc);
		return ERR_PTR(ret);
	}

	rp = (void *)(kcu + 1);
	for (i = 0; i < kcu->rp_count; i++)
		kc->rp_sbdf[i] = pci_sbdf(rp[i].segment, rp[i].bus, rp[i].devfn);

	kc->rp_cfg_bitmap = kcalloc(BITS_TO_LONGS(kc->num_rp),
				    sizeof(*kc->rp_cfg_bitmap), GFP_KERNEL);
	if (!kc->rp_cfg_bitmap) {
		kfree(kc);
		return ERR_PTR(-ENOMEM);
	}

	return kc;
}

static int key_config_tbl_parse(struct acpi_table_keyp *keyp)
{
	struct acpi_keyp_kcu *iter;
	void *start, *end, *next;
	struct key_config *kc;
	int ret, i;

	start = (void *)(keyp + 1);
	end = start + keyp->header.length - sizeof(*keyp);

	ret = key_config_unit_check_and_count(start, end);
	if (ret <= 0)
		return ret ? : -ENOENT;

	num_key_config = ret;

	/* alloc the pointer array */
	key_config = kcalloc(num_key_config, sizeof(*key_config), GFP_KERNEL);
	if (!key_config)
		return -ENOMEM;

	for (i = 0, iter = start; (void *)iter < end; iter = next) {
		next = (void *)iter + iter->length;

		keyp_table_print_keycu_entry(iter);

		/* Some confusing in SPEC, so CXL CACHE/MEM type is skipped */
		if (iter->prot_type != ACPI_KEYP_KCU_PROT_TYPE_PCIE_CXLIO)
			continue;

		kc = key_config_unit_parse(iter);
		if (IS_ERR(kc)) {
			ret = PTR_ERR(kc);
			goto err;
		}

		key_config[i++] = kc;
	}

	return 0;

err:
	key_config_info_destroy();
	return ret;
}

static int key_config_tbl_detect(void)
{
	acpi_status status = AE_OK;

	if (keyp_tbl)
		return 0;

	status = acpi_get_table(ACPI_SIG_KEYP, 0, &keyp_tbl);

	if (ACPI_SUCCESS(status) && !keyp_tbl) {
		pr_warn("Unable to map KEYP\n");
		status = AE_NOT_FOUND;
	}

	return ACPI_SUCCESS(status) ? 0 : -ENOENT;
}

static int key_config_tbl_init(void)
{
	struct acpi_table_keyp *keyp;
	int ret;

	if (num_key_config)
		return 0;

	/*
	 * initialize KEY_CONFIG data structure per KEYP table
	 * and associate it with root port.
	 */
	ret = key_config_tbl_detect();
	if (!ret)
		return ret;

	keyp = (struct acpi_table_keyp *)keyp_tbl;
	return key_config_tbl_parse(keyp);
}

static __init int intel_pci_ide_key_config_init(void)
{
	return key_config_tbl_init();
}
subsys_initcall(intel_pci_ide_key_config_init);

static __exit void intel_pci_ide_key_config_exit(void)
{
	key_config_info_destroy();
}
module_exit(intel_pci_ide_key_config_exit);

static int key_config_config_rp(struct key_config *kc, int kc_idx)
{
	int i;

	spin_lock(&kc->rp_cfg_lock);

	if (bitmap_empty(kc->rp_cfg_bitmap, kc->num_rp)) {
		for (i = 0; i < kc->num_rp; i++) {
			tdh_iommu_setreg(kc->iommu_id, DMAR_CONFIG_RP_REG,
					(u64)(kc->rp_sbdf[i] & 0xffff));
		}
	}

	bitmap_set(kc->rp_cfg_bitmap, kc_idx, 1);

	spin_unlock(&kc->rp_cfg_lock);

	return 0;
}

static void key_config_clear_rp(struct key_config *kc, int kc_idx)
{
	int i;

	spin_lock(&kc->rp_cfg_lock);

	bitmap_clear(kc->rp_cfg_bitmap, kc_idx, 1);

	if (bitmap_empty(kc->rp_cfg_bitmap, kc->num_rp)) {
		for (i = 0; i < kc->num_rp; i++) {
			tdh_iommu_setreg(kc->iommu_id, DMAR_CLEAR_RP_REG,
					(u64)(kc->rp_sbdf[i] & 0xffff));
		}
	}

	spin_unlock(&kc->rp_cfg_lock);
}

static struct key_config *root_port_to_key_config(struct pci_dev *dev, int *kc_idx)
{
	struct key_config *kc;
	int i, j;

	if (!key_config)
		return NULL;

	for (i = 0; i < num_key_config; i++) {
		kc = key_config[i];
		for (j = 0; j < kc->num_rp; j++) {
			if (kc->rp_sbdf[j] ==
			    pci_sbdf(pci_domain_nr(dev->bus), dev->bus->number, dev->devfn)) {
				if (kc_idx)
					*kc_idx = j;

				return kc;
			}
		}
	}

	return NULL;
}

static int key_config_key_id_alloc(struct key_config *kconfig, struct pci_ide_stream *stm)
{
	if (stm->stream_id >= kconfig->num_stream_supported)
		return -EBUSY;

	return stm->stream_id;
}

static void key_config_key_id_free(struct key_config *kconfig, int key_id)
{
	return;
}

static int key_config_slot_id_alloc(struct key_config *kconfig, struct intel_ide_stream *istm)
{
	struct intel_ide_key_set *k_set;
	int k_set_index, sub_stream, slot_id;
	int key_id = istm->key_id;

	for (k_set_index = 0; k_set_index < PCI_IDE_KEY_SET_NUM; k_set_index++) {
		k_set = &istm->k_set[k_set_index];
		for (sub_stream = 0; sub_stream < PCI_IDE_SUB_STREAM_NUM; sub_stream++) {
			slot_id = key_id * PCI_IDE_SUB_STREAM_NUM * PCI_IDE_KEY_SET_NUM +
				  k_set_index * PCI_IDE_SUB_STREAM_NUM + sub_stream;
			if (slot_id >= kconfig->num_rx_key_slots ||
			    slot_id >= kconfig->num_tx_key_slots)
				return -EBUSY;

			k_set->slot_id[PCI_IDE_SUB_STREAM_DIRECTION_RX][sub_stream] = slot_id;
			k_set->slot_id[PCI_IDE_SUB_STREAM_DIRECTION_TX][sub_stream] = slot_id;
		}
	}

	return 0;
}

static void key_config_slot_id_free(struct key_config *kconfig, struct intel_ide_stream *istm)
{
	return;
}

static int ide_key_config_init(struct pci_ide_stream *stm)
{
	struct intel_ide *ide = pci_ide_get_private(stm->rp_dev);
	struct intel_ide_stream *istm;
	int ret;

	istm = kzalloc(sizeof(*istm), GFP_KERNEL);
	if (!istm)
		return -ENOMEM;

	ret = tdx_alloc_td_page(&istm->exinfo);
	if (ret) {
		pr_warn("%s(): Cannot allocate a exinfo for stream ID %d\n",
			__func__, stm->stream_id);
		goto err_istm_free;
	}

	ret = key_config_key_id_alloc(ide->kconfig, stm);
	if (ret < 0)
		goto err_td_page_free;
	istm->key_id = ret;

	ret = key_config_slot_id_alloc(ide->kconfig, istm);
	if (ret)
		goto err_key_id_free;

	pci_ide_stream_set_private(stm, istm);
	return 0;

err_key_id_free:
	key_config_key_id_free(ide->kconfig, istm->key_id);
err_td_page_free:
	tdx_reclaim_td_page(&istm->exinfo);
err_istm_free:
	kfree(istm);
	return ret;
}

static void ide_key_config_cleanup(struct pci_ide_stream *stm)
{
	struct intel_ide_stream *istm = pci_ide_stream_get_private(stm);
	struct intel_ide *ide = pci_ide_get_private(stm->rp_dev);

	pci_ide_stream_set_private(stm, NULL);

	tdx_reclaim_td_page(&istm->exinfo);
	key_config_key_id_free(ide->kconfig, istm->key_id);
	key_config_slot_id_free(ide->kconfig, istm);

	kfree(istm);
}

int pci_arch_ide_dev_init(struct pci_dev *dev)
{
	struct intel_ide *ide;

	dev_info(&dev->dev, "%s --->\n", __func__);

	if (!num_key_config)
		return -ENOENT;

	ide = kzalloc(sizeof(*ide), GFP_KERNEL);
	if (!ide)
		return -ENOMEM;

	spin_lock_init(&ide->used_id.lock);
	ide->kconfig = root_port_to_key_config(dev, &ide->kconfig_idx);
	pci_ide_set_private(dev, ide);

	return 0;
}

void pci_arch_ide_dev_release(struct pci_dev *dev)
{
	struct intel_ide *ide;
	int weight;

	ide = pci_ide_get_private(dev);
	if (ide) {
		pci_ide_set_private(dev, NULL);
		weight = bitmap_weight(ide->used_id.ids, USED_STREAM_IDS_BM_SIZE);
		if (unlikely(weight))
			dev_warn(&dev->dev,
				 "Some stream IDs didn`t be freed(used: %d)\n",
				 weight);
		kfree(ide);
	}
}

static int find_first_available_stream_id(struct used_id_bitmap *bm1, struct used_id_bitmap *bm2)
{
	DECLARE_BITMAP(or_res, USED_STREAM_IDS_BM_SIZE);
	int id;

	bitmap_or(or_res, bm1->ids, bm2->ids, USED_STREAM_IDS_BM_SIZE);

	/* Find first free stream ID */
	id = find_first_zero_bit(or_res, USED_STREAM_IDS_BM_SIZE);
	if (id > MAX_IDE_STREAM_ID)
		return -EBUSY;

	return id;
}

static inline void used_id_bitmaps_lock(struct used_id_bitmap *bm1, struct used_id_bitmap *bm2)
{
	spin_lock(&bm1->lock);
	spin_lock(&bm2->lock);
}

static inline void used_id_bitmaps_unlock(struct used_id_bitmap *bm1, struct used_id_bitmap *bm2)
{
	spin_unlock(&bm2->lock);
	spin_unlock(&bm1->lock);
}

static struct used_id_bitmap *get_used_stream_id_bitmap(struct pci_dev *dev)
{
	struct intel_ide *ide = pci_ide_get_private(dev);

	if (ide) {
		if (pci_pcie_type(dev) == PCI_EXP_TYPE_ROOT_PORT &&
		    dev->tee_mode)
			return &ide->kconfig->used_id;
		else
			return &ide->used_id;
	} else {
		return ERR_PTR(-EINVAL);
	}
}

static inline bool check_stream_id_used(struct used_id_bitmap *bm, int stream_id)
{
	return !!test_bit(stream_id, bm->ids);
}

static inline void mark_stream_id_used(struct used_id_bitmap *bm, int stream_id)
{
	bitmap_set(bm->ids, stream_id, 1);
}

static inline void clear_stream_id_used(struct used_id_bitmap *bm, int stream_id)
{
	bitmap_clear(bm->ids, stream_id, 1);
}

static int stream_id_alloc(struct used_id_bitmap *bm1, struct used_id_bitmap *bm2)
{
	int stream_id;

	used_id_bitmaps_lock(bm1, bm2);

	stream_id = find_first_available_stream_id(bm1, bm2);
	if (!stream_id_is_valid(stream_id))
		goto unlock;

	mark_stream_id_used(bm1, stream_id);
	mark_stream_id_used(bm2, stream_id);

unlock:
	used_id_bitmaps_unlock(bm1, bm2);

	return stream_id;
}

static void stream_id_free(struct used_id_bitmap *bm, int stream_id)
{
	spin_lock(&bm->lock);
	if (check_stream_id_used(bm, stream_id))
		clear_stream_id_used(bm, stream_id);
	else
		pr_warn("%s: Stream ID %d is not used!\n", __func__, stream_id);
	spin_unlock(&bm->lock);
}

int pci_arch_ide_stream_id_alloc(struct pci_dev *dev1, struct pci_dev *dev2)
{
	struct used_id_bitmap *used_id_bm1, *used_id_bm2;

	if (pcie_find_root_port(dev1) != pcie_find_root_port(dev2)) {
		pr_warn("%s(): %s and %s are not under same Root Port\n",
			__func__, dev_name(&dev1->dev), dev_name(&dev2->dev));
		return -EINVAL;
	}

	/*
	 * Need to lock Used stream ID bitmap carefully,
	 * if not, there would be deadlock.
	 * So defination of the order of taking lock is that taking the device`s lock
	 * which is with lower BDF firstly.
	 * And used_id_bm1 always points to the used_id_bitmap with higher priority.
	 * used_id_bm2 always points to the used_id_bitmap with lower priority.
	 */
	if (pci_dev_id(dev1) < pci_dev_id(dev2)) {
		used_id_bm1 = get_used_stream_id_bitmap(dev1);
		used_id_bm2 = get_used_stream_id_bitmap(dev2);
	} else {
		used_id_bm1 = get_used_stream_id_bitmap(dev2);
		used_id_bm2 = get_used_stream_id_bitmap(dev1);
	}

	if (IS_ERR_OR_NULL(used_id_bm1) || IS_ERR_OR_NULL(used_id_bm2)) {
		pr_warn("%s(): One of Used Stream ID Bitmap is NULL.(%s %s)\n",
			__func__, dev_name(&dev1->dev), dev_name(&dev2->dev));
		return -EINVAL;
	}
	return stream_id_alloc(used_id_bm1, used_id_bm2);
}

void pci_arch_ide_stream_id_free(struct pci_dev *dev1, struct pci_dev *dev2, int stream_id)
{
	struct used_id_bitmap *used_id_bm1, *used_id_bm2;

	if (pcie_find_root_port(dev1) != pcie_find_root_port(dev2)) {
		pr_warn("%s(): %s and %s are not under same Root Port\n",
			__func__, dev_name(&dev1->dev), dev_name(&dev2->dev));
		return;
	}

	/*
	 * Don`t need to sort devices like pci_arch_ide_stream_id_alloc()
	 * We can release stream id one by one.
	 */
	used_id_bm1 = get_used_stream_id_bitmap(dev1);
	used_id_bm2 = get_used_stream_id_bitmap(dev2);

	if (IS_ERR_OR_NULL(used_id_bm1) || IS_ERR_OR_NULL(used_id_bm2)) {
		pr_warn("%s(): One of Used Stream ID Bitmap is NULL.(%s %s)\n",
			__func__, dev_name(&dev1->dev), dev_name(&dev2->dev));
		return;
	}

	/*
	 * No need to hold both used_id_bitmap lock simultaneously,
	 * just release stream IDs one by one
	 */
	stream_id_free(used_id_bm1, stream_id);
	stream_id_free(used_id_bm2, stream_id);
}

static int get_iommu_id(struct pci_dev *pdev, u64 *iommu_id)
{
	struct iommu_hw_info info;
	int ret;

	if (!iommu_id)
		return -EINVAL;

	ret = iommu_get_hw_info(&pdev->dev, &info);
	if (ret) {
		dev_err(&pdev->dev, "Failed to get IOMMU ID\n");
		return ret;
	}

	*iommu_id = info.data.vtd.id;

	return 0;
}

int pci_arch_ide_dev_tee_enter(struct pci_dev *dev)
{
	struct intel_ide *ide;
	u64 iommu_id;
	int ret;

	if (pci_pcie_type(dev) != PCI_EXP_TYPE_ROOT_PORT)
		return 0;

	ide = pci_ide_get_private(dev);

	if (ide->kconfig->iommu_id == IOMMU_ID_INVALID) {
		ret = get_iommu_id(dev, &iommu_id);
		if (ret)
			return ret;

		ide->kconfig->iommu_id = iommu_id;
	}

	/* Hand over root port to SEAM module by IOMMU_SETREG SEAMCALL*/
	key_config_config_rp(ide->kconfig, ide->kconfig_idx);

	return 0;
}

int pci_arch_ide_dev_tee_exit(struct pci_dev *dev)
{
	struct intel_ide *ide;

	if (pci_pcie_type(dev) != PCI_EXP_TYPE_ROOT_PORT)
		return 0;

	ide = pci_ide_get_private(dev);

	/* Hand over root port back from SEAM by IOMMU_SETREG SEAMCALL */
	key_config_clear_rp(ide->kconfig, ide->kconfig_idx);

	return 0;
}

static int ide_set_target_device(struct pci_dev *dev, struct pci_ide_stream *stm)
{
	int pos = dev->ide_pos;
	int addr_assoc_pos;
	u32 reg;
	u32 i;

	dev_info(&dev->dev, "configure IDE Extend Capability\n");

	pos += PCI_IDE_CTRL + 4 + dev->ide_lnk_num * PCI_IDE_LNK_REG_BLOCK_SIZE;
	for (i = dev->ide_lnk_num; i < stm->ide_id; i++) {
		pci_read_config_dword(dev, pos, &reg);
		pos += PCI_IDE_ADDR_ASSOC_REG_BLOCK_OFFSET;
		pos += PCI_IDE_ADDR_ASSOC_REG_BLOCK_SIZE *
		       FIELD_GET(PCI_IDE_SEL_CAP_NUM_ASSOC_BLK, reg);
	}

	reg = FIELD_PREP(PCI_IDE_RID_ASSOC1_LIMIT, 0xFFFF);
	pci_write_config_dword(dev, pos + PCI_IDE_RID_ASSOC1, reg);
	dev_info(&dev->dev, "RID1 %x\n", reg);

	reg = FIELD_PREP(PCI_IDE_RID_ASSOC2_VALID, 1) |
	      FIELD_PREP(PCI_IDE_RID_ASSOC2_BASE, 0x0);
	pci_write_config_dword(dev, pos + PCI_IDE_RID_ASSOC2, reg);
	dev_info(&dev->dev, "RID2 %x\n", reg);

	addr_assoc_pos = pos + PCI_IDE_RID_ASSOC2 + 4;
	reg = FIELD_PREP(PCI_IDE_ADDR_ASSOC1_VALID, 1) |
	      FIELD_PREP(PCI_IDE_ADDR_ASSOC1_MEM_LIMIT_LOWER, 0xFFF) |
	      FIELD_PREP(PCI_IDE_ADDR_ASSOC1_MEM_BASE_LOWER, 0x0);
	pci_write_config_dword(dev, addr_assoc_pos + PCI_IDE_ADDR_ASSOC1, reg);
	dev_info(&dev->dev, "ADR_ASS1 %x\n", reg);

	reg = FIELD_PREP(PCI_IDE_ADDR_ASSOC2_MEM_LIMIT_UPPER, 0xFFFFFFFF);
	pci_write_config_dword(dev, addr_assoc_pos + PCI_IDE_ADDR_ASSOC2, reg);
	dev_info(&dev->dev, "ADR_ASS2 %x\n", reg);

	reg = FIELD_PREP(PCI_IDE_ADDR_ASSOC3_MEM_BASE_UPPER, 0x0);
	pci_write_config_dword(dev, addr_assoc_pos + PCI_IDE_ADDR_ASSOC3, reg);
	dev_info(&dev->dev, "ADR_ASS3 %x\n", reg);

	reg = FIELD_PREP(PCI_IDE_SEL_CTRL_STREAM_ID, stm->stream_id) |
	      FIELD_PREP(PCI_IDE_SEL_CTRL_ALGO, stm->algo) |
	      FIELD_PREP(PCI_IDE_SEL_CTRL_ENABLE, 1);
	pci_write_config_dword(dev, pos + PCI_IDE_SEL_CTRL, reg);
	dev_info(&dev->dev, "CTRL %x\n", reg);

	return 0;
}

static void ide_clear_target_device(struct pci_dev *dev, struct pci_ide_stream *stm)
{
	int pos = dev->ide_pos;
	u32 reg;
	u32 i;

	pos += PCI_IDE_CTRL + 4 + dev->ide_lnk_num * PCI_IDE_LNK_REG_BLOCK_SIZE;
	for (i = dev->ide_lnk_num; i < stm->ide_id; i++) {
		pci_read_config_dword(dev, pos, &reg);
		pos += PCI_IDE_ADDR_ASSOC_REG_BLOCK_OFFSET;
		pos += PCI_IDE_ADDR_ASSOC_REG_BLOCK_SIZE *
		       FIELD_GET(PCI_IDE_SEL_CAP_NUM_ASSOC_BLK, reg);
	}

	reg = FIELD_PREP(PCI_IDE_SEL_CTRL_ENABLE, 0);
	pci_write_config_dword(dev, pos + PCI_IDE_SEL_CTRL, reg);
}

static int get_mem_range(struct pci_dev *pdev, resource_size_t *start, resource_size_t *end)
{
	resource_size_t s = ULLONG_MAX, e = 0;
	int i, bar;

	for (i = 0; i < PCI_STD_NUM_BARS; i++) {
		bar = i + PCI_STD_RESOURCES;

		if (!(pci_resource_flags(pdev, bar) & IORESOURCE_MEM))
			continue;

		if (!pci_resource_len(pdev, bar))
			continue;

		s = min_t(resource_size_t, s, pci_resource_start(pdev, bar));
		e = max_t(resource_size_t, e, pci_resource_end(pdev, bar));
	}

	*start = s;
	*end = e;

	return 0;
}

static int tdx_ide_stream_create(struct pci_dev *pdev, struct pci_ide_stream *stm)
{
	struct intel_ide_stream *istm = pci_ide_stream_get_private(stm);
	struct stream_create_param param = { 0 };
	resource_size_t start, end;
	u64 iommu_id;
	u64 ret;

	param.stream_exinfo = istm->exinfo;
	if (get_iommu_id(pdev, &iommu_id))
		return -EINVAL;

	param.ide_stream_cfg = FIELD_PREP(STREAM_CFG_IDE_ID, stm->rp_ide_id) |
			       FIELD_PREP(STREAM_CFG_RP_DF_NUM, stm->rp_dev->devfn) |
			       FIELD_PREP(STREAM_CFG_KEY_ID, istm->key_id) |
			       FIELD_PREP(STREAM_CFG_TYPE, stm->type);

	if (stm->type == PCI_IDE_STREAM_TYPE_SEL) {
		param.ide_stream_ctrl = FIELD_PREP(PCI_IDE_SEL_CTRL_ENABLE, 1) |
					FIELD_PREP(PCI_IDE_SEL_CTRL_ALGO, stm->algo) |
					FIELD_PREP(PCI_IDE_SEL_CTRL_STREAM_ID, stm->stream_id);

		param.rid_assoc1 = FIELD_PREP(PCI_IDE_RID_ASSOC1_LIMIT, pci_dev_id(pdev) + 1);
		param.rid_assoc2 = FIELD_PREP(PCI_IDE_RID_ASSOC2_VALID, 1) |
				   FIELD_PREP(PCI_IDE_RID_ASSOC2_BASE, pci_dev_id(pdev));

		get_mem_range(pdev, &start, &end);
		//end = round_up(end, 0x100000);

		param.addr_assoc1 = FIELD_PREP(PCI_IDE_ADDR_ASSOC1_VALID, 1) |
				    FIELD_PREP(PCI_IDE_ADDR_ASSOC1_MEM_BASE_LOWER,
					       PCI_IDE_GET_LOWER_ADDR_FIELD(start)) |
				    FIELD_PREP(PCI_IDE_ADDR_ASSOC1_MEM_LIMIT_LOWER,
					       PCI_IDE_GET_LOWER_ADDR_FIELD(end));
		param.addr_assoc2 = FIELD_PREP(PCI_IDE_ADDR_ASSOC2_MEM_LIMIT_UPPER,
					       PCI_IDE_GET_UPPER_ADDR_FIELD(end));
		param.addr_assoc3 = FIELD_PREP(PCI_IDE_ADDR_ASSOC3_MEM_BASE_UPPER,
					       PCI_IDE_GET_UPPER_ADDR_FIELD(start));
	}
	ret = tdh_ide_stream_create(iommu_id, spdm_session_idx,
				    param.ide_stream_cfg,
				    param.ide_stream_ctrl,
				    param.rid_assoc1,
				    param.rid_assoc2,
				    param.addr_assoc1,
				    param.addr_assoc2,
				    param.addr_assoc3,
				    param.stream_exinfo.pa);
	if (ret)
		return -EINVAL;

	return 0;
}

static int tdx_ide_stream_block(struct pci_ide_stream *stm)
{
	u64 iommu_id;
	u64 ret;

	pr_info("%s \n", __func__);
	if (get_iommu_id(stm->dev, &iommu_id))
		return -EINVAL;

	ret = tdh_ide_stream_block(iommu_id, stm->stream_id);
	if (ret) {
		pr_err("%s(): failed, ret=0x%llx\n", __func__, ret);
		return -EINVAL;
	}

	return 0;
}

static int tdx_ide_stream_delete(struct pci_ide_stream *stm)
{
	u64 iommu_id;
	u64 ret;

	pr_info("%s \n", __func__);
	if (get_iommu_id(stm->dev, &iommu_id))
		return -EINVAL;

	ret = tdh_ide_stream_delete(iommu_id, stm->stream_id);
	if (ret) {
		pr_err("%s(): failed, ret=0x%llx\n", __func__, ret);
		return -EINVAL;
	}

	return 0;
}

static void ide_stream_stop(struct pci_dev *pdev, struct pci_ide_stream *stm);
static int __ide_stream_release(struct pci_ide_stream *stm)
{
	int ret;

	ret = tdx_ide_stream_block(stm);
	if (ret)
		return ret;

	ret = tdx_ide_stream_delete(stm);
	if (ret)
		return ret;

	return 0;
}

static int ide_stream_release(struct pci_ide_stream *stm)
{
	ide_stream_stop(stm->dev, stm);

	return __ide_stream_release(stm);
}

static int tdx_ide_stream_idekmreq(struct pci_dev *pdev, struct ide_km_request *req)
{
	unsigned int slot_id = 0;
	u8 idekm_param = 0;
	u64 iommu_id;
	u64 ret;

	idekm_param = FIELD_PREP(IDE_KM_PARAM_KSET, req->key_set) |
		      FIELD_PREP(IDE_KM_PARAM_DIR, req->direction) |
		      FIELD_PREP(IDE_KM_PARAM_SUB_STREAM, req->sub_stream);

	if (get_iommu_id(pdev, &iommu_id))
		return -EINVAL;

	if (req->object_id == PCI_IDE_OBJECT_ID_KEY_PROG)
		slot_id = req->slot_id;

	ret = tdh_ide_stream_idekmreq(iommu_id, req->stream_id, req->object_id,
				      idekm_param, slot_id,
				      __pa(req->request_va));
	if (ret)
		return -EINVAL;

	return 0;
}

static void ide_km_request_dump(struct ide_km_request *req)
{
	pr_warn("%s(): ide_km_request dump: stream %d, slot %d, object %d, key_set %d, dir %d, sub_stream %d\n",
		__func__, req->stream_id, req->slot_id, req->object_id, req->key_set,
		req->direction, req->sub_stream);
}

static int check_idekm_ack(struct ide_km_request *req, struct pci_ide_km_ack *ack)
{
	if (ack->protocol_id != PCI_DOE_IDE_PROTOCOL_ID ||
	    ack->stream_id != req->stream_id ||
	    ack->key_set_index != req->key_set ||
	    ack->direction != req->direction ||
	    ack->sub_stream != req->sub_stream) {
		ide_km_request_dump(req);
		pr_warn("%s(): Common ack data error: protocol 0x%x, stream %d, key_set %d, dir %d, sub_stream %d\n",
			__func__, ack->protocol_id, ack->stream_id, ack->key_set_index,
			ack->direction, ack->sub_stream);
		return -EINVAL;
	}

	switch (req->object_id) {
	case PCI_IDE_OBJECT_ID_KEY_PROG:
		if (ack->object_id != PCI_IDE_OBJECT_ID_KP_ACK ||
		    ack->status != PCI_IDE_KEY_PROG_SUCCESS) {
			ide_km_request_dump(req);
			pr_warn("%s(): kp_ack error: object %d, status 0x%x\n",
				__func__, ack->object_id, ack->status);
			return -EINVAL;
		}
		break;
	case PCI_IDE_OBJECT_ID_K_SET_GO:
	case PCI_IDE_OBJECT_ID_K_SET_STOP:
		if (ack->object_id != PCI_IDE_OBJECT_ID_K_GOSTOP_ACK) {
			ide_km_request_dump(req);
			pr_warn("%s(): kp_gostop_ack error: object %d\n", __func__, ack->object_id);
			return -EINVAL;
		}
		break;
	default:
		pr_warn("%s(): Didn`t implement.\n", __func__);
		return -EINVAL;
	}

	return 0;
}

static int tdx_ide_stream_idekmrsp(struct pci_dev *pdev, struct ide_km_request *req)
{
	struct pci_ide_km_ack ack;
	u64 iommu_id;
	u64 ret;

	if (get_iommu_id(pdev, &iommu_id))
		return -EINVAL;

	ret = tdh_ide_stream_idekmrsp(iommu_id, req->stream_id,
				      __pa(req->response_va), (u64 *)&ack);
	if (ret)
		return -EINVAL;

	return check_idekm_ack(req, &ack);
}

static const char *ide_km_obj_to_string(enum pci_ide_object_id object_id)
{
	switch (object_id) {
	case PCI_IDE_OBJECT_ID_KEY_PROG:
		return "PCI_IDE_KM_OBJECT_ID_KEY_PROG";
	case PCI_IDE_OBJECT_ID_K_SET_GO:
		return "PCI_IDE_OBJECT_ID_K_SET_GO";
	case PCI_IDE_OBJECT_ID_K_SET_STOP:
		return "PCI_IDE_OBJECT_ID_K_SET_STOP";
	default:
		return "unknown";
	}
}

static int ide_stream_req_resp(struct pci_dev *pdev, struct pci_doe_mb *doe_mb,
			       struct ide_km_request *req)
{
	int ret;

	dev_info(&pdev->dev, "%s: obj %d - %s\n", __func__, req->object_id,
		 ide_km_obj_to_string(req->object_id));

	ret = tdx_ide_stream_idekmreq(pdev, req);
	if (ret)
		return ret;

	ret = pci_doe_msg_exchange_sync(doe_mb, (void *)req->request_va,
					(void *)req->response_va, PAGE_SIZE);
	if (ret)
		return ret;

	return tdx_ide_stream_idekmrsp(pdev, req);
}

static int doe_buffer_alloc(struct ide_km_request *req)
{
	req->request_va = get_zeroed_page(GFP_KERNEL);
	if (!req->request_va)
		return -ENOMEM;

	req->response_va = get_zeroed_page(GFP_KERNEL);
	if (!req->response_va) {
		free_page(req->request_va);
		return -ENOMEM;
	}

	return 0;
}

static void doe_buffer_free(struct ide_km_request *req)
{
	free_page(req->request_va);
	free_page(req->response_va);
}

static int ide_km_msg_exchange(struct pci_dev *pdev, struct pci_doe_mb *doe_mb,
			       struct intel_ide_stream *istm,
			       struct ide_km_request *req)
{
	int direction, sub_stream;
	int k_set_index = req->key_set;
	int ret;

	for (direction = 0; direction < PCI_IDE_SUB_STREAM_DIRECTION_NUM; direction++) {
		req->direction = direction;

		for (sub_stream = 0; sub_stream < PCI_IDE_SUB_STREAM_NUM; sub_stream++) {
			req->sub_stream = sub_stream;
			req->slot_id = istm->k_set[k_set_index].slot_id[direction][sub_stream];

			ret = ide_stream_req_resp(pdev, doe_mb, req);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int ide_stream_setup(struct pci_dev *pdev, struct pci_ide_stream *stm)
{
	struct intel_ide_stream *istm = pci_ide_stream_get_private(stm);
	struct ide_km_request req = {
		.stream_id = stm->stream_id,
		.key_set = PCI_IDE_KEY_SET_0,
	};
	int ret;

	ret = tdx_ide_stream_create(pdev, stm);
	if (ret)
		return ret;

	ret = doe_buffer_alloc(&req);
	if (ret)
		goto exit_stream_release;

	req.object_id = PCI_IDE_OBJECT_ID_KEY_PROG;
	ret = ide_km_msg_exchange(pdev, stm->doe_mb, istm, &req);
	if (ret)
		goto exit_key_set_stop;

	req.object_id = PCI_IDE_OBJECT_ID_K_SET_GO;
	ret = ide_km_msg_exchange(pdev, stm->doe_mb, istm, &req);
	if (ret)
		goto exit_key_set_stop;

	goto exit;

exit_key_set_stop:
	req.object_id = PCI_IDE_OBJECT_ID_K_SET_STOP;
	ide_km_msg_exchange(pdev, stm->doe_mb, istm, &req);
exit_stream_release:
	__ide_stream_release(stm);
exit:
	doe_buffer_free(&req);

	return ret;
}

static void ide_stream_stop(struct pci_dev *pdev, struct pci_ide_stream *stm)
{
	struct intel_ide_stream *istm = pci_ide_stream_get_private(stm);
	struct ide_km_request req = {
		.stream_id = stm->stream_id,
		.key_set = PCI_IDE_KEY_SET_0,
	};
	int ret;

	ret = doe_buffer_alloc(&req);
	if (ret)
		return;

	req.object_id = PCI_IDE_OBJECT_ID_K_SET_STOP;
	ide_km_msg_exchange(pdev, stm->doe_mb, istm, &req);
	doe_buffer_free(&req);
}

int pci_arch_ide_stream_setup(struct pci_ide_stream *stm)
{
	int ret;

	if (stm->flags & PCI_IDE_FLAG_TEE) {
		ret = ide_key_config_init(stm);
		if (ret)
			return ret;

		ret = ide_set_target_device(stm->dev, stm);
		if (ret)
			goto err_clear_key_config;

		ret = ide_stream_setup(stm->dev, stm);
		if (ret)
			goto err_clear_target_dev;
	}

	return 0;

err_clear_target_dev:
	ide_clear_target_device(stm->dev, stm);

err_clear_key_config:
	ide_key_config_cleanup(stm);
	return ret;
}

void pci_arch_ide_stream_remove(struct pci_ide_stream *stm)
{
	if (ide_stream_release(stm)) {
		WARN(true, "%s(): Cannot release stream ID %d of %s-%s\n",
		     __func__, stm->stream_id, dev_name(&stm->rp_dev->dev),
		     dev_name(&stm->dev->dev));
		/* Skip ide_key_config_cleanup() when releasing stream failed */
		return;
	}

	ide_clear_target_device(stm->dev, stm);
	ide_key_config_cleanup(stm);
}
