// SPDX-License-Identifier: GPL-2.0
#include <linux/vdsm.h>

#include "vdsm_internal.h"
#include "vdsm_ioctl.h"

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
