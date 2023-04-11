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
