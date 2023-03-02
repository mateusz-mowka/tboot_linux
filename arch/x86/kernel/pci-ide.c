// SPDX-License-Identifier: GPL-2.0
#include <linux/acpi.h>
#include <linux/intel-iommu.h>
#include <linux/kvm_host.h>
#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/spinlock.h>
#include <linux/rpb.h>

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

	/* for simple spdm implementation WA */
	struct tdx_td_page spdm_wa;
	int spdm_wa_idx;
};

struct doe_va_t {
	unsigned long doe_request_va;
	unsigned long doe_response_va;
};

/* functions and structures for fake IDE KM ACK */
#include <linux/rpb.h>

DEFINE_XARRAY(rpb_ti_mgrs_xa);
EXPORT_SYMBOL(rpb_ti_mgrs_xa);
/*
 * ide_fake_resp_message == IDE_RPB_FAKE_RESP_MODE:
 * fake response message for RPB test card
 * and return to TDX module. Will do nothing for non RPB
 * device.
 *
 * ide_fake_resp_message == IDE_DSA_VERIFY_FAKE_RESP_MODE:
 * verify fake resp message mode, this mode only
 * checks the data between fake response message and the
 * real response message from DSA device.
 *
 * ide_fake_resp_message == IDE_DSA_USING_FAKE_RESP_MODE:
 * request message will send to dsa device over DOE, but
 * IDE driver will generate corresponding fake response
 * message for TDX module.(don't use the response message
 * from DSA)
 */
#define IDE_RPB_FAKE_RESP_MODE		1
#define IDE_VERIFY_FAKE_RESP_MODE	2
#define IDE_DSA_USING_FAKE_RESP_MODE	3
static int ide_fake_resp_message = IDE_RPB_FAKE_RESP_MODE;
module_param(ide_fake_resp_message, int, 0644);

#pragma pack(push, 1)
struct doe_header {
	u16 vendor_id;
	u8 type;
	u8 reserved;
	u32 length;
};

struct secure_spdm_header {
	u32 session_id;
	u16 length;
	u16 app_length;
};

struct vendor_def_header {
	u8 spdm_ver;
	u8 spdm_code;
	u8 param1;
	u8 param2;
	u16 standard_id;
	u8 len;
	u16 vendor_id;
	u16 payload_len;
};

struct ide_km_object {
	u8 protocol_id;
	u8 object_id;
	u16 reserved1;
	u8 stream_id;
	u8 reserved2;
	u8 key_set_index:1;
	u8 direction:1;
	u8 reserved3:2;
	u8 sub_stream:4;
	u8 portindex;
};
#pragma pack(pop)

#define KEY_SIZE 32
static void get_idekm_key(struct ide_km_request *req, u32 *key_buf)
{
	void *pos = (void *)req->request_va;
	u32 *key;
	int i;

	pos += sizeof(struct doe_header) +
	       sizeof(struct secure_spdm_header) +
	       sizeof(struct vendor_def_header) +
	       sizeof(struct ide_km_object);

	key = (u32 *)pos;
	for (i = 0; i < 8; i++)
		key_buf[7 - i] = key[i];
}

static void get_idekm_iv_key(struct ide_km_request *req, u32 *key_buf)
{
	void *pos = (void *)req->request_va;
	u32 *iv_key;

	pos += sizeof(struct doe_header) +
	       sizeof(struct secure_spdm_header) +
	       sizeof(struct vendor_def_header) +
	       sizeof(struct ide_km_object) +
	       KEY_SIZE;

	iv_key = (u32 *)pos;
	key_buf[1] = iv_key[0];
	key_buf[0] = iv_key[1];
}

#define MAC_SIZE	16
static void generate_idekm_ack_msg(struct pci_dev *pdev,
				   struct ide_km_request *req,
				   bool success)
{
	struct vendor_def_header *vendor_h;
	struct secure_spdm_header *spdm_h;
	struct pci_ide_km_ack *idekm_ack_h;
	struct doe_header *doe_h;

	doe_h = (void *)req->response_va;
	spdm_h = (struct secure_spdm_header *)(doe_h + 1);
	vendor_h = (struct vendor_def_header *)(spdm_h + 1);
	idekm_ack_h = (struct pci_ide_km_ack *)(vendor_h + 1);

	/* Fake DOE header */
	doe_h->vendor_id = 0x1;
	doe_h->type = 0x2;
	/* doe_h->length must be 0xd */
	doe_h->length = round_up(sizeof(*doe_h) + sizeof(*spdm_h) +
				 sizeof(*vendor_h) + sizeof(*idekm_ack_h) +
				 MAC_SIZE, 4) / 4;

	/* Fake secure spdm message header */
	spdm_h->session_id = 0;
	/* spdm_h->length must be 0x25 */
	spdm_h->length = sizeof(spdm_h->app_length) +
			 sizeof(*vendor_h) +
			 sizeof(*idekm_ack_h) +
			 MAC_SIZE;
	/* spdm_h->app_length must be 0x13 */
	spdm_h->app_length = sizeof(*vendor_h) + sizeof(*idekm_ack_h);

	/* Fake vendor define response header */
	vendor_h->spdm_ver = 0x1;
	vendor_h->spdm_code = 0x7E;
	vendor_h->standard_id = 0x3;
	vendor_h->len = 2;
	vendor_h->vendor_id = 0x1;
	vendor_h->payload_len = sizeof(*idekm_ack_h);

	/* Fake IDE KM KP_ACK message */
	idekm_ack_h->protocol_id = 0x0;
	if (req->object_id == PCI_IDE_OBJECT_ID_KEY_PROG) {
		idekm_ack_h->object_id = PCI_IDE_OBJECT_ID_KP_ACK;
		if (success)
			idekm_ack_h->status = 0;
		else
			idekm_ack_h->status = 0x4;	/* Unspecified Failure */
	} else
		idekm_ack_h->object_id = PCI_IDE_OBJECT_ID_K_GOSTOP_ACK;
	idekm_ack_h->stream_id = req->stream_id;
	idekm_ack_h->key_set_index = req->key_set;
	idekm_ack_h->direction = req->direction;
	idekm_ack_h->sub_stream = req->sub_stream;
	idekm_ack_h->portindex = 0;

	/*
	 * at the end of the message, there are a MAC and a Padding,
	 * but we don't have SPDM, so just skip them. spdm header length
	 * already includes the length of them.
	 */
}

static int rpb_ide_key_set_go(struct rpb_ti_mgr *ti_mgr,
			      u32 sub_stream, u8 direction)
{
	if (ti_mgr->key_set_go[sub_stream][direction] == false) {
		ti_mgr->key_set_go[sub_stream][direction] = true;
		ti_mgr->kset_go_cnt++;
		if (ti_mgr->kset_go_cnt == PCI_IDE_SUB_STREAM_DIRECTION_NUM *
					    PCI_IDE_SUB_STREAM_NUM)
			return rpb_enable_sel_stream(ti_mgr->ide);
	}

	return 0;
}

static void rpb_ide_key_set_stop(struct rpb_ti_mgr *ti_mgr,
				u32 sub_stream, u8 direction)
{
	if (ti_mgr->key_set_go[sub_stream][direction] == true) {
		ti_mgr->key_set_go[sub_stream][direction] = false;
		ti_mgr->kset_go_cnt--;
		if (ti_mgr->kset_go_cnt == 0)
			rpb_disable_sel_stream(ti_mgr->ide);
	}
}

static void dump_doe_message(struct pci_dev *pdev, u32 *resp)
{
	int i;
	int len = ((struct doe_header *)resp)->length;

	for (i = 0; i < len; i++)
		dev_info(&pdev->dev, "  DW %d: 0x%08x\n", i, resp[i]);
}

static int req_fake_resp_message(struct pci_dev *pdev, struct ide_km_request *req)
{
	struct rpb_ti_mgr *ti_mgr;
	u32 iv_key[2];
	u32 key[8];
	int ret = 0;

	dev_info(&pdev->dev, "DOE request message:\n");
	dump_doe_message(pdev, (u32 *)req->request_va);

	switch (req->object_id) {
	case PCI_IDE_OBJECT_ID_KEY_PROG:
		get_idekm_key(req, key);
		get_idekm_iv_key(req, iv_key);
		if (is_rpb_device(pdev)) {
			ti_mgr = xa_load(&rpb_ti_mgrs_xa, pci_dev_id(pdev));
			WARN_ON(!ti_mgr);
			if (!ti_mgr) {
				ret = -EFAULT;
				break;
			}
			ret = rpb_ide_key_prog(ti_mgr->ide, req->sub_stream,
					       req->direction, key, iv_key);
		}
		generate_idekm_ack_msg(pdev, req, !ret);
		break;
	case PCI_IDE_OBJECT_ID_K_SET_GO:
		if (is_rpb_device(pdev)) {
			ti_mgr = xa_load(&rpb_ti_mgrs_xa, pci_dev_id(pdev));
			WARN_ON(!ti_mgr);
			if (!ti_mgr) {
				ret = -EFAULT;
				break;
			}
			ret = rpb_ide_key_set_go(ti_mgr, req->sub_stream,
						 req->direction);
		}
		generate_idekm_ack_msg(pdev, req, !ret);
		break;
	case PCI_IDE_OBJECT_ID_K_SET_STOP:
		if (is_rpb_device(pdev)) {
			ti_mgr = xa_load(&rpb_ti_mgrs_xa, pci_dev_id(pdev));
			WARN_ON(!ti_mgr);
			if (!ti_mgr) {
				ret = -EFAULT;
				break;
			}
			rpb_ide_key_set_stop(ti_mgr, req->sub_stream,
					     req->direction);
		}
		generate_idekm_ack_msg(pdev, req, true);
		break;
	default:
		dev_err(&pdev->dev, "%s: Not support IDE KM object %d\n",
			__func__, req->object_id);
		return -EINVAL;
	}

	dev_info(&pdev->dev, "Fake response message:\n");
	dump_doe_message(pdev, (u32 *)req->response_va);
	return 0;
}

static void __ide_verify_fake_resp_message(struct pci_dev *pdev,
					   void *orig_response,
					   void *fake_response)
{
	void *orig_p = orig_response;
	void *fake_p = fake_response;

	dev_info(&pdev->dev, "%s: Start to verify fake response message\n",
		 __func__);
	if (memcmp(orig_p, fake_p, sizeof(struct doe_header))) {
		dev_err(&pdev->dev, "%s: DOE headers don't match\n",
			__func__);
		goto exit;
	}

	orig_p = ((struct doe_header *)orig_p) + 1;
	fake_p = ((struct doe_header *)fake_p) + 1;

	if (memcmp(orig_p, fake_p, sizeof(struct secure_spdm_header))) {
		dev_err(&pdev->dev, "%s: Secure SPDM headers don't match\n",
			__func__);
		goto exit;
	}

	orig_p = ((struct secure_spdm_header *)orig_p) + 1;
	fake_p = ((struct secure_spdm_header *)fake_p) + 1;

	if (memcmp(orig_p, fake_p, sizeof(struct vendor_def_header))) {
		dev_err(&pdev->dev, "%s: Vendor Define headers don't match\n",
			__func__);
		goto exit;
	}

	orig_p = ((struct vendor_def_header *)orig_p) + 1;
	fake_p = ((struct vendor_def_header *)fake_p) + 1;

	if (memcmp(orig_p, fake_p, sizeof(struct pci_ide_km_ack))) {
		dev_err(&pdev->dev, "%s: IDE KM ackes don't match\n",
			__func__);
		goto exit;
	}

	dev_info(&pdev->dev, "%s: Fake response message matches real message(Skip MAC)\n",
		 __func__);
exit:
	dev_info(&pdev->dev, "orig resp message:\n");
	dump_doe_message(pdev, orig_response);
	dev_info(&pdev->dev, "fake resp message:\n");
	dump_doe_message(pdev, fake_response);
}

static void ide_verify_fake_resp_message(struct pci_dev *pdev,
					 struct ide_km_request *orig_req)
{
	struct ide_km_request fake_req = *orig_req;

	fake_req.response_va = get_zeroed_page(GFP_KERNEL);
	if (!fake_req.response_va) {
		dev_info(&pdev->dev, "%s: Cannot allocate page to fake request\n",
			 __func__);
		return;
	}

	switch (fake_req.object_id) {
	case PCI_IDE_OBJECT_ID_KEY_PROG:
	case PCI_IDE_OBJECT_ID_K_SET_GO:
	case PCI_IDE_OBJECT_ID_K_SET_STOP:
		generate_idekm_ack_msg(pdev, &fake_req, true);
		break;
	default:
		dev_err(&pdev->dev, "%s: Not support IDE KM object %d\n",
			__func__, fake_req.object_id);
		goto exit;
	}

	__ide_verify_fake_resp_message(pdev,
				       (void *)orig_req->response_va,
				       (void *)fake_req.response_va);
exit:
	free_page(fake_req.response_va);
}

static int rpb_ti_mgr_create(struct pci_dev *pdev, int ide_id, u8 stream_id)
{
	struct rpb_ti_mgr *ti_mgr;
	int ret;

	ti_mgr = kzalloc(sizeof(*ti_mgr), GFP_KERNEL);
	if (!ti_mgr)
		return -ENOMEM;

	ti_mgr->ide = rpb_ide_init(pdev, ide_id, stream_id);
	if (IS_ERR(ti_mgr->ide)) {
		dev_err(&pdev->dev, "%s: Failed to initialize RPB IDE\n",
			__func__);
		ret = PTR_ERR(ti_mgr->ide);
		goto exit_free_mgr;
	}
	ret = xa_insert(&rpb_ti_mgrs_xa, pci_dev_id(pdev),
			ti_mgr, GFP_KERNEL);
	if (ret)
		goto exit_release_ide;

	return 0;

exit_release_ide:
	rpb_ide_release(ti_mgr->ide);
exit_free_mgr:
	kfree(ti_mgr);
	return ret;
}

static void rpb_ti_mgr_release(struct pci_dev *pdev)
{
	struct rpb_ti_mgr *ti_mgr;

	ti_mgr = xa_erase(&rpb_ti_mgrs_xa, pci_dev_id(pdev));
	if (ti_mgr) {
		rpb_ide_release(ti_mgr->ide);
		kfree(ti_mgr);
	}
}
/* end of fake IDE KM ACK related functions and structures */

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
	if (ret)
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

static void ide_target_device_stream_ctrl(struct pci_dev *dev,
					  int ide_id,
					  bool enable)
{
	int pos = dev->ide_pos;
	u32 reg;
	u32 i;

	pos += PCI_IDE_CTRL + 4 + dev->ide_lnk_num * PCI_IDE_LNK_REG_BLOCK_SIZE;
	for (i = dev->ide_lnk_num; i < ide_id; i++) {
		pci_read_config_dword(dev, pos, &reg);
		pos += PCI_IDE_ADDR_ASSOC_REG_BLOCK_OFFSET;
		pos += PCI_IDE_ADDR_ASSOC_REG_BLOCK_SIZE *
		       FIELD_GET(PCI_IDE_SEL_CAP_NUM_ASSOC_BLK, reg);
	}

	pci_read_config_dword(dev, pos + PCI_IDE_SEL_CTRL, &reg);
	if (enable)
		reg |= FIELD_PREP(PCI_IDE_SEL_CTRL_ENABLE, 1);
	else
		reg &= ~PCI_IDE_SEL_CTRL_ENABLE;
	pci_write_config_dword(dev, pos + PCI_IDE_SEL_CTRL, reg);
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
	      FIELD_PREP(PCI_IDE_SEL_CTRL_ALGO, stm->algo);
	pci_write_config_dword(dev, pos + PCI_IDE_SEL_CTRL, reg);
	dev_info(&dev->dev, "CTRL %x\n", reg);

	return 0;
}

static int get_mem_range(struct pci_dev *pdev, resource_size_t *start, resource_size_t *end)
{
	resource_size_t s = ULLONG_MAX, e = 0;
	int i, bar;

	for (i = 0; i < PCI_STD_NUM_BARS; i++) {
		bar = i + PCI_STD_RESOURCES;
		/*
		 * WA for RPB device
		 * TDX-IO requires address type of BARx must be 64 bits,
		 * but only BAR0 is 64 bits in RPB device, so just using
		 * BAR0 address as target address range of Selective IDE
		 * stream on RP side.
		 */
		if (is_rpb_device(pdev) && i > 0)
			break;

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

static DEFINE_IDA(spdm_wa_ida);
static int spdm_wa_create(struct pci_dev *pdev, struct intel_ide_stream *istm,
			  u8 *session_idx)
{
	u64 iommu_id;
	u64 tdx_ret;
	int ret;

	pr_info("%s\n", __func__);
	if (get_iommu_id(pdev, &iommu_id))
		return -EINVAL;

	ret = tdx_alloc_td_page(&istm->spdm_wa);
	if (ret) {
		pr_err("%s(): Cannot allocate spdm_wa page\n", __func__);
		return ret;
	}

	ret = ida_alloc(&spdm_wa_ida, GFP_KERNEL);
	if (ret < 0) {
		pr_err("%s(): Cannot allocate spdm_wa ida\n", __func__);
		goto reclaim_page;
	}
	istm->spdm_wa_idx = ret;

	tdx_ret = tdh_spdm_create(iommu_id, istm->spdm_wa_idx, istm->spdm_wa.pa);
	if (tdx_ret) {
		pr_err("%s(): ret=0x%llx, iommu_id=0x%llx, session_idx=0x%x, pa=0x%llx\n",
		       __func__, tdx_ret, iommu_id, istm->spdm_wa_idx, istm->spdm_wa.pa);
		ret = -EFAULT;
		goto ida_free;
	}

	*session_idx = (u8)istm->spdm_wa_idx;

	return 0;

ida_free:
	ida_free(&spdm_wa_ida, istm->spdm_wa_idx);
reclaim_page:
	tdx_reclaim_td_page(&istm->spdm_wa);
	return ret;
}

static void spdm_wa_destory(struct pci_dev *pdev, struct intel_ide_stream *istm)
{
	u64 spdm_info_pa;
	u64 iommu_id;
	u64 tdx_ret;

	pr_info("%s\n", __func__);
	if (get_iommu_id(pdev, &iommu_id)) {
		pr_warn("%s(): get iommu id failed\n", __func__);
		goto out;
	}

	tdx_ret = tdh_spdm_delete(iommu_id, istm->spdm_wa_idx, &spdm_info_pa);
	if (tdx_ret) {
		pr_err("%s(): ret=0x%llx, iommu_id=0x%llx, session_idx=0x%x\n",
		       __func__, tdx_ret, iommu_id, istm->spdm_wa_idx);
		goto out;
	}

	if (spdm_info_pa != istm->spdm_wa.pa) {
		pr_warn("%s(): spdm delete err, returned spdm_pa = 0x%llx, spdm pa = 0x%llx\n",
			__func__, spdm_info_pa, istm->spdm_wa.pa);
		goto out;
	}

out:
	ida_free(&spdm_wa_ida, istm->spdm_wa_idx);
	tdx_reclaim_td_page(&istm->spdm_wa);
}

static int tdx_ide_stream_create(struct pci_dev *pdev, struct pci_ide_stream *stm)
{
	struct intel_ide_stream *istm = pci_ide_stream_get_private(stm);
	struct stream_create_param param = { 0 };
	resource_size_t start, end;
	u8 spdm_session_idx;
	u64 iommu_id;
	u64 ret;

	param.stream_exinfo = istm->exinfo;
	if (get_iommu_id(pdev, &iommu_id))
		return -EINVAL;

	/* for spdm workaround */
	ret = spdm_wa_create(pdev, istm, &spdm_session_idx);
	if (ret)
		return ret;

	param.ide_stream_cfg = FIELD_PREP(STREAM_CFG_IDE_ID, stm->rp_ide_id) |
			       FIELD_PREP(STREAM_CFG_RP_DF_NUM, stm->rp_dev->devfn) |
			       FIELD_PREP(STREAM_CFG_KEY_ID, istm->key_id) |
			       FIELD_PREP(STREAM_CFG_TYPE, stm->type);

	if (stm->type == PCI_IDE_STREAM_TYPE_SEL) {
		param.ide_stream_ctrl = FIELD_PREP(PCI_IDE_SEL_CTRL_ALGO, stm->algo) |
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
	if (ret) {
		spdm_wa_destory(pdev, istm);
		return -EINVAL;
	}

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

	if (is_rpb_device(stm->dev))
		rpb_ti_mgr_release(stm->dev);

	spdm_wa_destory(stm->dev, pci_ide_stream_get_private(stm));

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

	if (ide_fake_resp_message == IDE_RPB_FAKE_RESP_MODE &&
	    is_rpb_device(pdev))
		ret = req_fake_resp_message(pdev, req);
	else
		ret = pci_doe_msg_exchange_sync(doe_mb, (void *)req->request_va,
						(void *)req->response_va, PAGE_SIZE);
	if (ret)
		return ret;

	if (pdev->vendor == 0x8086 && pdev->device == 0x0b25) {
		if (ide_fake_resp_message == IDE_DSA_USING_FAKE_RESP_MODE) {
			memset((void *)req->response_va, 0x0, PAGE_SIZE);
			ret = req_fake_resp_message(pdev, req);
		} else if (ide_fake_resp_message == IDE_VERIFY_FAKE_RESP_MODE) {
			ide_verify_fake_resp_message(pdev, req);
		}
	}

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

	if (is_rpb_device(pdev)) {
		ret = rpb_ti_mgr_create(pdev, stm->ide_id, stm->stream_id);
		if (ret)
			goto exit_stream_release;
	}

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

		if (!is_vtc_device(stm->dev)) {
			ret = ide_set_target_device(stm->dev, stm);
			if (ret)
				goto err_clear_key_config;
		}

		ret = ide_stream_setup(stm->dev, stm);
		if (ret)
			goto err_clear_key_config;
		ide_target_device_stream_ctrl(stm->dev, stm->ide_id, true);
	}

	return 0;

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

	ide_target_device_stream_ctrl(stm->dev, stm->ide_id, false);
	ide_key_config_cleanup(stm);
}
