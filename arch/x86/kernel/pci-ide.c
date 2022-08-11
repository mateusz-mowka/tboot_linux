// SPDX-License-Identifier: GPL-2.0
#include <linux/acpi.h>
#include <linux/intel-iommu.h>
#include <linux/kvm_host.h>
#include <linux/pci.h>
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
