// SPDX-License-Identifier: GPL-2.0
#include <linux/bitfield.h>
#include <uapi/linux/pci_regs.h>
#include <linux/pci_ids.h>
#include <linux/vdsm.h>

#include "vdsm_internal.h"
#include "vdsm_ioctl.h"

static int device_read_ide_ext(struct pci_dev *pdev,
			       ide_km_query_ctx_t *query_ctx)
{
	int ret;
	int pos;
	int ide_reg_count;
	uint32_t val32;
	bool link_ide_stm_spt;
	uint8_t link_ide_tcs_num;
	bool sel_ide_stm_spt;
	uint8_t sel_ide_stm_num;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_IDE);
	if (pos == 0) {
		return -ENODEV;
	}

	// IDE Capability Register
	pci_read_config_dword(pdev, pos + PCI_IDE_CAP, &val32);
	query_ctx->ide_reg_buffer[ide_reg_count++] = val32;
	link_ide_stm_spt = FIELD_GET(PCI_IDE_CAP_LNK, val32);
	link_ide_tcs_num = FIELD_GET(PCI_IDE_CAP_LNK_NUM, val32);
	sel_ide_stm_spt = FIELD_GET(PCI_IDE_CAP_SEL, val32);
	sel_ide_stm_num = FIELD_GET(PCI_IDE_CAP_SEL_NUM, val32);

	// IDE Control Register
	pci_read_config_dword(pdev, pos + PCI_IDE_CTRL, &val32);
	query_ctx->ide_reg_buffer[ide_reg_count++] = val32;

	// Link IDE Register Block(repeated 0~8 times)
	for (int i = 0; i < link_ide_tcs_num; i++) {
		pci_read_config_dword(pdev, pos + PCI_IDE_LNK_CTRL, &val32);
		query_ctx->ide_reg_buffer[ide_reg_count++] = val32;
		pci_read_config_dword(pdev, pos + PCI_IDE_LNK_STATUS, &val32);
		query_ctx->ide_reg_buffer[ide_reg_count++] = val32;
	}

	// Selective IDE Register Block(repeated 0~255 times)
	for (int i = 0; i < sel_ide_stm_num; i++) {
		pci_read_config_dword(pdev, pos + PCI_IDE_SEL_CAP, &val32);
		query_ctx->ide_reg_buffer[ide_reg_count++] = val32;
		pci_read_config_dword(pdev, pos + PCI_IDE_SEL_CTRL, &val32);
		query_ctx->ide_reg_buffer[ide_reg_count++] = val32;
		pci_read_config_dword(pdev, pos + PCI_IDE_SEL_STATUS, &val32);
		query_ctx->ide_reg_buffer[ide_reg_count++] = val32;
		pci_read_config_dword(pdev, pos + PCI_IDE_RID_ASSOC1, &val32);
		query_ctx->ide_reg_buffer[ide_reg_count++] = val32;
		pci_read_config_dword(pdev, pos + PCI_IDE_RID_ASSOC2, &val32);
		query_ctx->ide_reg_buffer[ide_reg_count++] = val32;
		pci_read_config_dword(pdev, pos + PCI_IDE_ADDR_ASSOC1, &val32);
		query_ctx->ide_reg_buffer[ide_reg_count++] = val32;
		pci_read_config_dword(pdev, pos + PCI_IDE_ADDR_ASSOC2, &val32);
		query_ctx->ide_reg_buffer[ide_reg_count++] = val32;
		pci_read_config_dword(pdev, pos + PCI_IDE_ADDR_ASSOC3, &val32);
		query_ctx->ide_reg_buffer[ide_reg_count++] = val32;
	}
	query_ctx->ide_reg_buffer_count = ide_reg_count;
	return ret;
}

static void dev_mmio_array_move_back(pci_tdisp_mmio_range_t *dev_mmio, int idx,
				     int step)
{
	memmove(&dev_mmio[idx + step], &dev_mmio[idx],
		sizeof(*dev_mmio) * (DEVIF_RP_MMIO_NUM - (idx + step)));
}

static void insert_to_dev_mmio_array(pci_tdisp_mmio_range_t *dst,
				     pci_tdisp_mmio_range_t *src)
{
	uint64_t start;
	uint32_t pages;
	int i;

	for (i = 0; i < DEVIF_RP_MMIO_NUM; i++) {
		if (!dst[i].number_of_pages)
			break;
		if (dst[i].range_id != src->range_id)
			continue;

		start = dst[i].first_page;
		pages = dst[i].number_of_pages;
		if (start == src->first_page) {
			if (dst[i].number_of_pages == src->number_of_pages) {
				dst[i] = *src;
			} else {
				dev_mmio_array_move_back(dst, i, 1);
				dst[i + 1].first_page =
					GET_DEV_MMIO_END(src) + 1;
				dst[i + 1].number_of_pages =
					dst[i + 1].number_of_pages -
					src->number_of_pages;
				dst[i] = *src;
			}
			return;
		} else if (GET_DEV_MMIO_END(&dst[i]) == GET_DEV_MMIO_END(src)) {
			dev_mmio_array_move_back(dst, i, 1);
			dst[i + 1] = *src;
			dst[i].number_of_pages =
				dst[i].number_of_pages - src->number_of_pages;
			return;
		} else if (start < src->first_page &&
			   GET_DEV_MMIO_END(&dst[i]) > GET_DEV_MMIO_END(src)) {
			dev_mmio_array_move_back(dst, i, 2);
			dst[i].number_of_pages =
				(src->first_page - start + 1) / PAGE_SIZE;
			dst[i + 1] = *src;
			dst[i + 2].first_page = GET_DEV_MMIO_END(src) + 1;
			dst[i + 2].number_of_pages =
				dst[i + 2].number_of_pages -
				dst[i + 1].number_of_pages -
				dst[i].number_of_pages;
			return;
		}
	}
}

static int generate_msix_table_mmio_range(struct pci_dev *pdev,
					  pci_tdisp_mmio_range_t *range)
{
	uint32_t val;
	uint32_t len;
	int ret;

	if (!pdev->msix_cap) {
		range->number_of_pages = 0;
		return 0;
	}

	ret = pci_read_config_dword(pdev, pdev->msix_cap + PCI_MSIX_TABLE,
				    &val);
	if (ret) {
		dev_err(&pdev->dev, "%s: Failed to read PCI_MSIX_TABLE\n",
			__func__);
		return ret;
	}
	range->range_id = FIELD_GET(PCI_MSIX_TABLE_BIR, val);
	range->first_page = (val & PCI_MSIX_TABLE_OFFSET) +
			    pci_resource_start(pdev, range->range_id);

	ret = pci_read_config_word(pdev, pdev->msix_cap + PCI_MSIX_FLAGS,
				   (u16 *)&val);
	if (ret) {
		dev_err(&pdev->dev, "%s: Failed to read PCI_MSIX_FLAGS\n",
			__func__);
		return ret;
	}
	len = MSIX_TABLE_SIZE(val) * PCI_MSIX_ENTRY_SIZE;
	range->range_attributes = DEVIF_RP_MMIO_ATTR_MSIX;
	if (len % PAGE_SIZE)
		dev_warn(&pdev->dev, "%s: MSI-X Table size is %d\n", __func__,
			 len);
	range->number_of_pages = round_up(len, PAGE_SIZE) / PAGE_SIZE;

	return 0;
}

static int generate_msix_pba_mmio_range(struct pci_dev *pdev,
					pci_tdisp_mmio_range_t *range)
{
	uint32_t val;
	uint32_t len;
	int ret;

	if (!pdev->msix_cap) {
		range->number_of_pages = 0;
		return 0;
	}

	ret = pci_read_config_dword(pdev, pdev->msix_cap + PCI_MSIX_PBA, &val);
	if (ret) {
		dev_err(&pdev->dev, "%s: Failed to read PCI_MSIX_PBA\n",
			__func__);
		return ret;
	}
	range->range_id = FIELD_GET(PCI_MSIX_PBA_BIR, val);
	range->first_page = (val & PCI_MSIX_PBA_OFFSET) +
			    pci_resource_start(pdev, range->range_id);

	ret = pci_read_config_word(pdev, pdev->msix_cap + PCI_MSIX_FLAGS,
				   (u16 *)&val);
	if (ret) {
		dev_err(&pdev->dev, "%s: Failed to read PCI_MSIX_FLAGS\n",
			__func__);
		return ret;
	}
	range->range_attributes = DEVIF_RP_MMIO_ATTR_PBA;
	len = round_up(MSIX_TABLE_SIZE(val), 64) / 64 * 8;
	if (len % PAGE_SIZE)
		dev_warn(&pdev->dev, "%s: MSI-X PBA size is %d\n", __func__,
			 len);
	range->number_of_pages = round_up(len, PAGE_SIZE) / PAGE_SIZE;

	return 0;
}

static void dump_dev_mmio_range(pci_tdisp_mmio_range_t *dev_mmio)
{
	int i;

	for (i = 0; i < DEVIF_RP_MMIO_NUM; i++) {
		pr_info("%s: %d offset=0x%llx, pages=0x%x, attrs=0x%x, bar=%d\n",
			__func__, i, dev_mmio[i].first_page, dev_mmio[i].number_of_pages,
			dev_mmio[i].range_id, dev_mmio[i].range_attributes);
	}
}

static int generate_dev_mmio_range(struct pci_dev *pdev,
				   pci_tdisp_mmio_range_t *dev_mmio)
{
	pci_tdisp_mmio_range_t msix_tbl = { 0 };
	pci_tdisp_mmio_range_t msix_pba = { 0 };
	unsigned long flags;
	int ret;
	int pos;
	int i;

	/* the last two mmio_ranges are used to store MSIX-TABLE and MSIX-PBA */
	ret = generate_msix_table_mmio_range(pdev, &msix_tbl);
	if (ret)
		return ret;
	ret = generate_msix_pba_mmio_range(pdev, &msix_pba);
	if (ret)
		return ret;

	/* Parse BARs */
	for (pos = 0, i = 0; i < PCI_STD_NUM_BARS; i++) {
		flags = pci_resource_flags(pdev, i);
		if (!pci_resource_len(pdev, i) ||
		    flags & IORESOURCE_UNSET ||
		    flags & IORESOURCE_IO)
			continue;

		/* It is a WA for RPB device, we don't publish BAR4 to TD */
		if ((pdev->vendor == PCI_VENDOR_ID_INTEL &&
		     pdev->device == PCIE_DEVICE_ID_CAMBRIA) &&
		    i == 4)
			continue;

		if (pci_resource_len(pdev, i) % PAGE_SIZE)
			dev_warn(&pdev->dev,
				 "%s: BAR %d size is not PAGE_SIZE aligned\n",
				 __func__, i);
		dev_mmio[pos].first_page = pci_resource_start(pdev, i);
		dev_mmio[pos].number_of_pages =
			round_up(pci_resource_len(pdev, i), PAGE_SIZE) /
			PAGE_SIZE;
		dev_mmio[pos].range_id = i;
		dev_mmio[pos].range_attributes = (i << 16);
		pos++;
	}
	dump_dev_mmio_range(dev_mmio);

	if (msix_tbl.number_of_pages) {
		insert_to_dev_mmio_array(dev_mmio, &msix_tbl);
		dump_dev_mmio_range(dev_mmio);
	}

	if (msix_pba.number_of_pages) {
		insert_to_dev_mmio_array(dev_mmio, &msix_pba);
		dump_dev_mmio_range(dev_mmio);
	}

	return 0;
}

static int
tdisp_device_intf_report_msg(struct pci_dev *pdev, tdisp_interface_report_ctx_t *intf_report_ctx)
{
	pci_tdisp_mmio_range_t dev_mmio[DEVIF_RP_MMIO_NUM] = { 0 };
	pci_tdisp_device_interface_report_struct_t *report;
	pci_tdisp_mmio_range_t *range;
	uint32_t *dev_specific_info_len;
	uint32_t val32;
	uint16_t val16;
	int pos;
	int ret;
	int i;

	ret = generate_dev_mmio_range(pdev, dev_mmio);
	if (ret)
		return ret;

	report = (pci_tdisp_device_interface_report_struct_t *)(intf_report_ctx->interface_report);
	report->interface_info =
		VDSM_TDISP_INTERFACE_INFO_NO_UPDATE_AFTER_LOCK |
		VDSM_TDISP_INTERFACE_INFO_DMA_WITHOUT_PASID;
	report->lnr_control = 0;
	if (pdev->msix_cap) {
		ret = pci_read_config_word(
			pdev, pdev->msix_cap + PCI_MSIX_FLAGS, &val16);
		if (ret)
			return ret;
		report->msi_x_message_control = val16;
	}
	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_TPH);
	if (pos) {
		pci_read_config_dword(pdev, pos + PCI_TPH_CTRL, &val32);
		report->tph_control = val32;
	}

	intf_report_ctx->interface_report_size += sizeof(*report);

	range = (pci_tdisp_mmio_range_t *)(report + 1);
	for (i = 0; i < DEVIF_RP_MMIO_NUM; i++) {
		if (!dev_mmio[i].number_of_pages)
			continue;
		range->first_page = dev_mmio[i].first_page + intf_report_ctx->mmio_reporting_offset;
		range->number_of_pages = dev_mmio[i].number_of_pages;
		range->range_attributes = dev_mmio[i].range_attributes;
		range->range_id = dev_mmio[i].range_id;
		report->mmio_range_count++;
		intf_report_ctx->interface_report_size += sizeof(*range);
		range++;
	}
	dev_specific_info_len = (uint32_t *)range;
	*dev_specific_info_len = 0;
	intf_report_ctx->interface_report_size += sizeof(*dev_specific_info_len);

	return ret;
}

static int
adisp_device_intf_report_msg(struct pci_dev *pdev, adisp_interface_report_ctx_t *intf_report_ctx)
{
	pci_adisp_mmio_range_t dev_mmio[DEVIF_RP_MMIO_NUM] = { 0 };
	pci_adisp_device_interface_report_struct_t *report;
	pci_tdisp_mmio_range_t *range;
	uint32_t *dev_specific_info_len;
	uint32_t val32;
	uint16_t val16;
	int pos;
	int ret;
	int i;

	ret = generate_dev_mmio_range(pdev, (pci_tdisp_mmio_range_t *)dev_mmio);
	if (ret)
		return ret;

	report = (pci_adisp_device_interface_report_struct_t *)(intf_report_ctx->interface_report);
	report->intf_info = 0;
	report->lnr_ctrl = 0;
	report->virt_dev_id = 0;
	if (pdev->msix_cap) {
		ret = pci_read_config_word(
			pdev, pdev->msix_cap + PCI_MSIX_FLAGS, &val16);
		if (ret)
			return ret;
		report->msix_msg_ctrl = val16;
	}
	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_TPH);
	if (pos) {
		pci_read_config_dword(pdev, pos + PCI_TPH_CTRL, &val32);
		report->tph_ctrl = val32;
	}
	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_PASID);
	if (pos) {
		ret = pci_read_config_word(pdev, pos + PCI_PASID_CTRL, &val16);
		report->pasid_ctrl = val16;
	}

	intf_report_ctx->interface_report_size += sizeof(*report);

	range = (pci_tdisp_mmio_range_t *)(report + 1);
	for (i = 0; i < DEVIF_RP_MMIO_NUM; i++) {
		if (!dev_mmio[i].number_of_pages)
			continue;
		range->first_page = dev_mmio[i].first_page + intf_report_ctx->mmio_reporting_offset;
		range->number_of_pages = dev_mmio[i].number_of_pages;
		range->range_attributes = dev_mmio[i].range_attributes;
		range->range_id = dev_mmio[i].range_id;
		report->mmio_range_cnt++;
		intf_report_ctx->interface_report_size += sizeof(*range);
		range++;
	}
	dev_specific_info_len = (uint32_t *)range;
	*dev_specific_info_len = 0;
	intf_report_ctx->interface_report_size += sizeof(*dev_specific_info_len);

	return ret;
}

int vdsm_bind_eventfd(struct vdsm_kernel_stub *vdks, void *arg)
{
	int evfd;
	int ret;
	struct eventfd_ctx *ctx;

	ret = copy_from_user((void *)&evfd, arg, sizeof(int));
	if (ret) {
		pr_info("%s: failed to copy from user\n", __func__);
		return -EFAULT;
	}

	if (evfd < 0)
		return -ENODEV;

	ctx = eventfd_ctx_fdget(evfd);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	vdks->vdmb.evfd_ctx = ctx;

	return 0;
}

spdm_request_t *generate_request_to_user(struct vdsm_kernel_stub *vdks)
{
	u8 *payload;
	spdm_request_t *req;
	struct pci_doe_task *task;
	struct device *dev = &vdks->pdev->dev;

	task = vdks->vdmb.task;
	req = devm_kzalloc(dev, task->request_pl_sz + PCI_DOE_HEADER_SIZE, GFP_KERNEL);
	if (req == NULL)
		return ERR_PTR(-ENOMEM);

	req->doe_h.vendor_id = task->prot.vid;
	req->doe_h.type = task->prot.type;
	req->doe_h.reserved = 0;
	req->doe_h.length = (task->request_pl_sz + PCI_DOE_HEADER_SIZE) / sizeof(u32);

	payload = (u8 *)req + PCI_DOE_HEADER_SIZE;
	memcpy(payload, task->request_pl, task->request_pl_sz);

	return req;
}

void receive_response_from_user(struct vdsm_kernel_stub *vdks, spdm_response_t *resp)
{
	u8 *payload;
	struct pci_doe_task *task;
	uint32_t min_len;

	task = vdks->vdmb.task;
	payload = (u8 *)resp + PCI_DOE_HEADER_SIZE;
	min_len = min((size_t)resp->doe_h.length - 2,
		      task->response_pl_sz / sizeof(u32)) * sizeof(u32);
	memcpy(task->response_pl, payload, min_len);
	task->rv = min_len;
}

/* IDE KM */

int ide_km_init(struct vdsm_kernel_stub *vdks, void *context)
{
	ide_km_init_ctx_t init_ctx;
	struct vdsm_driver_backend *vdsm_be;
	struct ide_stream_info *stm_info;
	struct device *dev = &vdks->pdev->dev;
	int ret;

	ret = copy_from_user((void *)&init_ctx, context, sizeof(ide_km_init_ctx_t));
	if (ret) {
		pr_err("%s: failed to copy from user\n", __func__);
		return ret;
	}

	stm_info = devm_kzalloc(dev, sizeof(struct ide_stream_info), GFP_KERNEL);
	if (stm_info == NULL) {
		pr_err("%s: cannot allocate memory\n", __func__);
		return -ENOMEM;
	}

	stm_info->stream_id = init_ctx.stream_id;
	vdsm_be = vdks->be;

	/*
	 * Store the device specific data structure for later use.
	 * For example, for RPB driver it's struct rpb_ide and it
	 * will be used later in ide_km_* functions.
	 */
	stm_info->private_data = vdsm_be->ide_be->init(vdks->pdev, stm_info->stream_id);
	if (IS_ERR(stm_info->private_data)) {
		dev_err(&vdks->pdev->dev, "%s: Failed to initialize RPB IDE\n", __func__);
		ret = PTR_ERR(stm_info->private_data);
		kfree(stm_info);
		return ret;
	}

	ret = xa_insert(&vdks->ide_stream_info_xa, stm_info->stream_id, stm_info, GFP_KERNEL);
	if (ret) {
		pr_err("%s: insert ide_stream_info with stream_id %u as index failed\n",
		       __func__, stm_info->stream_id);
		return -EFAULT;
	}

	return ret;
}

int ide_km_query(struct vdsm_kernel_stub *vdks, void *context)
{
	ide_km_query_ctx_t query_ctx;
	int ret;

	ret = copy_from_user((void *)&query_ctx, context, sizeof(ide_km_query_ctx_t));
	if (ret) {
		pr_err("%s: failed to copy from user\n", __func__);
		return ret;
	}

	// TODO: read extended capabilities from PCI configuration
	ret = device_read_ide_ext(vdks->pdev, &query_ctx);

	ret = copy_to_user(context, (void *)&query_ctx, sizeof(ide_km_query_ctx_t));
	if (ret) {
		pr_err("%s: failed to copy to user\n", __func__);
		return ret;
	}

	return ret;
}

int ide_km_key_prog(struct vdsm_kernel_stub *vdks, void *context)
{
	ide_km_key_prog_ctx_t key_prog_ctx;
	struct vdsm_driver_backend *vdsm_be;
	struct ide_stream_info *stm_info;
	uint32_t key[8];
	uint32_t iv[2];
	int i;
	int ret;

	ret = copy_from_user((void *)&key_prog_ctx, context,
			     sizeof(ide_km_key_prog_ctx_t));
	if (ret) {
		pr_err("%s: failed to copy from user\n", __func__);
		return ret;
	}

	stm_info = xa_load(&vdks->ide_stream_info_xa, key_prog_ctx.stream_id);
	if (stm_info == NULL) {
		pr_err("%s: failed to load ide_stream_info with index %d\n",
		       __func__, key_prog_ctx.stream_id);
		return -EFAULT;
	}

	vdsm_be = vdks->be;

	/* The key sequence needs to be reversed. */
	for (i = 0; i < 8; i++) {
		key[7 - i] = key_prog_ctx.key_buffer.key[i];
	}
	iv[0] = key_prog_ctx.key_buffer.iv[1];
	iv[1] = key_prog_ctx.key_buffer.iv[0];

	ret = vdsm_be->ide_be->key_prog(
		stm_info->private_data, SUB_STREAM(key_prog_ctx),
		DIRECTION(key_prog_ctx), key, iv);

	return ret;
}

int ide_km_key_set_go(struct vdsm_kernel_stub *vdks, void *context)
{
	ide_km_key_set_go_ctx_t key_set_go_ctx;
	struct vdsm_driver_backend *vdsm_be;
	struct ide_stream_info *stm_info;
	int ret;

	ret = copy_from_user((void *)&key_set_go_ctx, context,
		       sizeof(ide_km_key_set_go_ctx_t));
	if (ret) {
		pr_err("%s: failed to copy from user\n", __func__);
		return ret;
	}

	stm_info = xa_load(&vdks->ide_stream_info_xa, key_set_go_ctx.stream_id);
	if (stm_info == NULL) {
		pr_err("%s: failed to load ide_stream_info with index %d\n",
		       __func__, key_set_go_ctx.stream_id);
		return -EFAULT;
	}

	if (key_set_go_ctx.key_set_go[SUB_STREAM(key_set_go_ctx)][DIRECTION(key_set_go_ctx)] ==
	    false) {
		key_set_go_ctx.key_set_go[SUB_STREAM(key_set_go_ctx)][DIRECTION(key_set_go_ctx)] = true;
		key_set_go_ctx.key_set_go_cnt++;
		if (key_set_go_ctx.key_set_go_cnt ==
		    PCI_IDE_SUB_STREAM_DIRECTION_NUM * PCI_IDE_SUB_STREAM_NUM) {
			vdsm_be = vdks->be;
			ret = vdsm_be->ide_be->key_set_go(stm_info->private_data);
		}
	}

	ret = copy_to_user(context, (void *)&key_set_go_ctx,
		       sizeof(ide_km_key_set_go_ctx_t));
	if (ret) {
		pr_err("%s: failed to copy to user\n", __func__);
		return ret;
	}

	return ret;
}

int ide_km_key_set_stop(struct vdsm_kernel_stub *vdks, void *context)
{
	ide_km_key_set_stop_ctx_t key_set_stop_ctx;
	struct vdsm_driver_backend *vdsm_be;
	struct ide_stream_info *stm_info;
	int ret;

	ret = copy_from_user((void *)&key_set_stop_ctx, context,
		       sizeof(ide_km_key_set_stop_ctx_t));
	if (ret) {
		pr_err("%s: failed to copy from user\n", __func__);
		return ret;
	}

	stm_info = xa_load(&vdks->ide_stream_info_xa, key_set_stop_ctx.stream_id);
	if (stm_info == NULL) {
		pr_err("%s: failed to load ide_stream_info with index %d\n",
		       __func__, key_set_stop_ctx.stream_id);
		return -EFAULT;
	}

	if (key_set_stop_ctx.key_set_go[SUB_STREAM(key_set_stop_ctx)]
				       [DIRECTION(key_set_stop_ctx)] == true) {
		key_set_stop_ctx.key_set_go[SUB_STREAM(key_set_stop_ctx)][DIRECTION(key_set_stop_ctx)] = false;
		key_set_stop_ctx.key_set_go_cnt--;
		if (key_set_stop_ctx.key_set_go_cnt == 0) {
			vdsm_be = vdks->be;
			ret = vdsm_be->ide_be->key_set_stop(stm_info->private_data);
		}
	}

	ret = copy_to_user(context, (void *)&key_set_stop_ctx,
		       sizeof(ide_km_key_set_stop_ctx_t));
	if (ret) {
		pr_err("%s: failed to copy to user\n", __func__);
		return ret;
	}

	return ret;
}

int ide_km_deinit(struct vdsm_kernel_stub *vdks, void *context)
{
	ide_km_deinit_ctx_t deinit_ctx;
	struct vdsm_driver_backend *vdsm_be;
	struct ide_stream_info *stm_info;
	struct device *dev = &vdks->pdev->dev;
	int ret;

	ret = copy_from_user((void *)&deinit_ctx, context, sizeof(ide_km_deinit_ctx_t));
	if (ret) {
		pr_err("%s: failed to copy from user\n", __func__);
		return ret;
	}

	stm_info = devm_kzalloc(dev, sizeof(struct ide_stream_info), GFP_KERNEL);
	if (stm_info == NULL) {
		pr_err("%s: cannot allocate memory\n", __func__);
		return -ENOMEM;
	}

	stm_info = xa_load(&vdks->ide_stream_info_xa, deinit_ctx.stream_id);
	vdsm_be = vdks->be;
	vdsm_be->ide_be->deinit(stm_info->private_data);

	return ret;
}

/* TDISP */

int tdisp_get_version(struct vdsm_kernel_stub *vdks, void *context)
{
	struct vdsm_driver_backend *vdsm_be;

	vdsm_be = vdks->be;
	if (vdsm_be == NULL ||
	    vdsm_be->tdisp_be == NULL ||
	    vdsm_be->tdisp_be->get_version == NULL) {
		pr_warn("%s: TDISP_GET_VERSION not supported by the device\n", __func__);
		return -ENODEV;
	}

	/* TODO: implement tdisp_get_version */

	return 0;
}

int tdisp_get_capabilities(struct vdsm_kernel_stub *vdks, void *context)
{
	struct vdsm_driver_backend *vdsm_be;

	vdsm_be = vdks->be;
	if (vdsm_be == NULL ||
	    vdsm_be->tdisp_be == NULL ||
	    vdsm_be->tdisp_be->get_capabilities == NULL) {
		pr_warn("%s: TDISP_GET_CAPABILITIES not supported by the device\n", __func__);
		return -ENODEV;
	}

	/* TODO: implement tdisp_get_capabilities */

	return 0;
}

int tdisp_lock_interface(struct vdsm_kernel_stub *vdks, void *context)
{
	struct vdsm_driver_backend *vdsm_be;

	vdsm_be = vdks->be;
	if (vdsm_be == NULL ||
	    vdsm_be->tdisp_be == NULL ||
	    vdsm_be->tdisp_be->lock_interface == NULL) {
		pr_warn("%s: TDISP_LOCK_INTERFACE not supported by the device\n", __func__);
		return -ENODEV;
	}

	/* TODO: implement tdisp_lock_interface */

	return 0;
}

int tdisp_get_device_interface_report(struct vdsm_kernel_stub *vdks, void *context)
{
	tdisp_interface_report_ctx_t *report_ctx;
	struct device *dev = &vdks->pdev->dev;
	int ret;

	report_ctx = devm_kzalloc(dev, sizeof(tdisp_interface_report_ctx_t), GFP_KERNEL);
	if (report_ctx == NULL) {
		pr_err("%s: cannot allocate memory\n", __func__);
		return -ENOMEM;
	}

	ret = copy_from_user((void *)report_ctx, context, sizeof(tdisp_interface_report_ctx_t));
	if (ret) {
		pr_err("%s: failed to copy from user\n", __func__);
		return ret;
	}

	ret = tdisp_device_intf_report_msg(vdks->pdev, report_ctx);
	if (ret) {
		pr_err("%s: failed to get interface report\n", __func__);
		return ret;
	}

	ret = copy_to_user(context, (void *)report_ctx, sizeof(tdisp_interface_report_ctx_t));
	if (ret) {
		pr_err("%s: failed to copy to user\n", __func__);
		return ret;
	}

	return ret;
}

int tdisp_get_device_interface_state(struct vdsm_kernel_stub *vdks, void *context)
{
	struct vdsm_driver_backend *vdsm_be;

	vdsm_be = vdks->be;
	if (vdsm_be == NULL ||
	    vdsm_be->tdisp_be == NULL ||
	    vdsm_be->tdisp_be->get_device_interface_state == NULL) {
		pr_warn("%s: TDISP_GET_DEVICE_INTERFACE_STATE not supported by the device\n", __func__);
		return -ENODEV;
	}

	/* TODO: implement tdisp_get_device_interface_state */

	return 0;
}

int tdisp_start_interface(struct vdsm_kernel_stub *vdks, void *context)
{
	tdisp_start_ctx_t start_ctx;
	struct vdsm_driver_backend *vdsm_be;
	struct ide_stream_info *stm_info;
	int ret;

	ret = copy_from_user((void *)&start_ctx, context, sizeof(tdisp_start_ctx_t));
	if (ret) {
		pr_err("%s: failed to copy from user\n", __func__);
		return ret;
	}

	/* FIXME: how to get stream_id as xarray index in TDISP */
	stm_info = xa_load(&vdks->ide_stream_info_xa, start_ctx.stream_id);
	if (stm_info == NULL) {
		pr_err("%s: failed to load ide_stream_info with index %d\n", __func__, 0);
		return -EFAULT;
	}

	vdsm_be = vdks->be;
	if (vdsm_be == NULL ||
	    vdsm_be->tdisp_be == NULL ||
	    vdsm_be->tdisp_be->start_interface == NULL) {
		pr_warn("%s: TDISP_START_INTERFACE not supported by the device\n", __func__);
		return -ENODEV;
	}

	ret = vdsm_be->tdisp_be->start_interface(stm_info->private_data);
	if (ret)
		pr_err("%s: failed to start interface\n", __func__);

	return ret;
}

int tdisp_stop_interface(struct vdsm_kernel_stub *vdks, void *context)
{
	tdisp_stop_ctx_t stop_ctx;
	struct vdsm_driver_backend *vdsm_be;
	struct ide_stream_info *stm_info;
	int ret;

	ret = copy_from_user((void *)&stop_ctx, context, sizeof(tdisp_stop_ctx_t));
	if (ret) {
		pr_err("%s: failed to copy from user\n", __func__);
		return ret;
	}

	/* FIXME: how to get stream_id as xarray index in TDISP */
	stm_info = xa_load(&vdks->ide_stream_info_xa, stop_ctx.stream_id);
	if (stm_info == NULL) {
		pr_err("%s: failed to load ide_stream_info with index %d\n", __func__, 0);
		return -EFAULT;
	}

	vdsm_be = vdks->be;
	if (vdsm_be == NULL ||
	    vdsm_be->tdisp_be == NULL ||
	    vdsm_be->tdisp_be->stop_interface == NULL) {
		pr_warn("%s: TDISP_STOP_INTERFACE not supported by the device\n", __func__);
		return -ENODEV;
	}

	ret = vdsm_be->tdisp_be->stop_interface(stm_info->private_data);
	if (ret)
		pr_err("%s: failed to stop interface\n", __func__);

	return ret;
}

/* ADISP */

int adisp_get_version(struct vdsm_kernel_stub *vdks, void *context)
{
	struct vdsm_driver_backend *vdsm_be;

	vdsm_be = vdks->be;
	if (vdsm_be == NULL ||
	    vdsm_be->adisp_be == NULL ||
	    vdsm_be->adisp_be->get_version == NULL) {
		pr_warn("%s: ADISP_GET_VERSION not supported by the device\n", __func__);
		return -ENODEV;
	}

	/* TODO: implement adisp_get_version */

	return 0;
}

int adisp_get_capabilities(struct vdsm_kernel_stub *vdks, void *context)
{
	struct vdsm_driver_backend *vdsm_be;

	vdsm_be = vdks->be;
	if (vdsm_be == NULL ||
	    vdsm_be->adisp_be == NULL ||
	    vdsm_be->adisp_be->get_capabilities == NULL) {
		pr_warn("%s: ADISP_GET_CAPABILITIES not supported by the device\n", __func__);
		return -ENODEV;
	}

	/* TODO: implement adisp_get_capabilities */

	return 0;
}

int adisp_lock_interface(struct vdsm_kernel_stub *vdks, void *context)
{
	struct vdsm_driver_backend *vdsm_be;

	vdsm_be = vdks->be;
	if (vdsm_be == NULL ||
	    vdsm_be->adisp_be == NULL ||
	    vdsm_be->adisp_be->lock_interface == NULL) {
		pr_warn("%s: ADISP_LOCK_INTERFACE not supported by the device\n", __func__);
		return -ENODEV;
	}

	/* TODO: implement adisp_lock_interface */

	return 0;
}

int adisp_get_device_interface_report(struct vdsm_kernel_stub *vdks, void *context)
{
	adisp_interface_report_ctx_t *report_ctx;
	struct device *dev = &vdks->pdev->dev;
	int ret;

	report_ctx = devm_kzalloc(dev, sizeof(adisp_interface_report_ctx_t), GFP_KERNEL);
	if (report_ctx == NULL) {
		pr_err("%s: cannot allocate memory\n", __func__);
		return -ENOMEM;
	}

	ret = copy_from_user((void *)report_ctx, context, sizeof(adisp_interface_report_ctx_t));
	if (ret) {
		pr_err("%s: failed to copy from user\n", __func__);
		return ret;
	}

	ret = adisp_device_intf_report_msg(vdks->pdev, report_ctx);
	if (ret) {
		pr_err("%s: failed to get interface report\n", __func__);
		return ret;
	}

	ret = copy_to_user(context, (void *)report_ctx, sizeof(adisp_interface_report_ctx_t));
	if (ret) {
		pr_err("%s: failed to copy to user\n", __func__);
		return ret;
	}

	return ret;
}

int adisp_get_device_interface_state(struct vdsm_kernel_stub *vdks, void *context)
{
	struct vdsm_driver_backend *vdsm_be;

	vdsm_be = vdks->be;
	if (vdsm_be == NULL ||
	    vdsm_be->adisp_be == NULL ||
	    vdsm_be->adisp_be->get_device_interface_state == NULL) {
		pr_warn("%s: ADISP_GET_DEVICE_INTERFACE_STATE not supported by the device\n", __func__);
		return -ENODEV;
	}

	/* TODO: implement adisp_get_device_interface_state */

	return 0;
}

int adisp_start_interface_mmio(struct vdsm_kernel_stub *vdks, void *context)
{
	adisp_start_mmio_ctx_t start_mmio_ctx;
	struct vdsm_driver_backend *vdsm_be;
	struct ide_stream_info *stm_info;
	int ret;

	ret = copy_from_user((void *)&start_mmio_ctx, context, sizeof(adisp_start_mmio_ctx_t));
	if (ret) {
		pr_err("%s: failed to copy from user\n", __func__);
		return ret;
	}

	/* FIXME: how to get stream_id as xarray index in TDISP */
	stm_info = xa_load(&vdks->ide_stream_info_xa, start_mmio_ctx.stream_id);
	if (stm_info == NULL) {
		pr_err("%s: failed to load ide_stream_info with index %d\n", __func__, 0);
		return -EFAULT;
	}

	vdsm_be = vdks->be;
	if (vdsm_be == NULL ||
	    vdsm_be->adisp_be == NULL ||
	    vdsm_be->adisp_be->start_interface_mmio == NULL) {
		pr_warn("%s: ADISP_START_INTERFACE_MMIO not supported by the device\n", __func__);
		return -ENODEV;
	}

	ret = vdsm_be->adisp_be->start_interface_mmio(stm_info->private_data);
	if (ret)
		pr_err("%s: failed to start interface mmio\n", __func__);

	return ret;
}

int adisp_start_interface_dma(struct vdsm_kernel_stub *vdks, void *context)
{
	adisp_start_dma_ctx_t start_dma_ctx;
	struct vdsm_driver_backend *vdsm_be;
	struct ide_stream_info *stm_info;
	int ret;

	ret = copy_from_user((void *)&start_dma_ctx, context, sizeof(adisp_start_dma_ctx_t));
	if (ret) {
		pr_err("%s: failed to copy from user\n", __func__);
		return ret;
	}

	/* FIXME: how to get stream_id as xarray index in TDISP */
	stm_info = xa_load(&vdks->ide_stream_info_xa, start_dma_ctx.stream_id);
	if (stm_info == NULL) {
		pr_err("%s: failed to load ide_stream_info with index %d\n", __func__, 0);
		return -EFAULT;
	}

	vdsm_be = vdks->be;
	if (vdsm_be == NULL ||
	    vdsm_be->adisp_be == NULL ||
	    vdsm_be->adisp_be->start_interface_dma == NULL) {
		pr_warn("%s: ADISP_START_INTERFACE_DMA not supported by the device\n", __func__);
		return -ENODEV;
	}

	ret = vdsm_be->adisp_be->start_interface_dma(stm_info->private_data);
	if (ret)
		pr_err("%s: failed to start interface dma\n", __func__);

	return ret;
}

int adisp_stop_interface(struct vdsm_kernel_stub *vdks, void *context)
{
	adisp_stop_ctx_t stop_ctx;
	struct vdsm_driver_backend *vdsm_be;
	struct ide_stream_info *stm_info;
	int ret;

	ret = copy_from_user((void *)&stop_ctx, context, sizeof(adisp_stop_ctx_t));
	if (ret) {
		pr_err("%s: failed to copy from user\n", __func__);
		return ret;
	}

	/* FIXME: how to get stream_id as xarray index in TDISP */
	stm_info = xa_load(&vdks->ide_stream_info_xa, stop_ctx.stream_id);
	if (stm_info == NULL) {
		pr_err("%s: failed to load ide_stream_info with index %d\n", __func__, 0);
		return -EFAULT;
	}

	vdsm_be = vdks->be;
	if (vdsm_be == NULL ||
	    vdsm_be->adisp_be == NULL ||
	    vdsm_be->adisp_be->stop_interface == NULL) {
		pr_warn("%s: ADISP_STOP_INTERFACE not supported by the device\n", __func__);
		return -ENODEV;
	}

	ret = vdsm_be->adisp_be->stop_interface(stm_info->private_data);
	if (ret)
		pr_err("%s: failed to stop interface\n", __func__);

	return ret;
}
