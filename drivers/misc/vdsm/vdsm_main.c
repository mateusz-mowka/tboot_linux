// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/device/class.h>
#include <linux/vdsm.h>
#include <linux/delay.h>

#include "vdsm_internal.h"
#include "vdsm_ioctl.h"

bool enable_vdsm = 1;
module_param(enable_vdsm, bool, 0600);

bool enable_dummy_requester = 0;
#if defined(CONFIG_VDSM_DUMMY_REQUESTER) || defined(CONFIG_VDSM_DUMMY_REQUESTER_MODULE)
module_param(enable_dummy_requester, bool, 0600);
#endif

extern struct xarray vdsm_driver_backend_xa;

static const struct file_operations vdsm_fops;

/* Global char dev variables */
static uint32_t vdsm_minor[VDSM_MAX_MINORS];
static uint32_t vdsm_major;
static struct class *vdsm_class;

/* Internal helper functions */
static int create_vdsm_device(struct cdev *cdev);
static void create_doe_mb_placeholder(struct pci_doe_mb *doe_mb,
				      struct pci_dev *pdev);
static inline struct vdsm_driver_backend *load_backend(struct pci_dev *pdev);
static int signal_eventfd_to_user(struct vdsm_kernel_stub *vdks);

inline void *vdsm_alloc(struct pci_dev *pdev, size_t size)
{
	struct device *dev = &pdev->dev;

	if (enable_dummy_requester) {
		return kzalloc(size, GFP_KERNEL);
	}

	return devm_kzalloc(dev, size, GFP_KERNEL);
}

/* Exported to DOE driver */
struct pci_doe_mb *vdsm_doe_create_mb(struct pci_dev *pdev)
{
	struct vdsm_kernel_stub *vdks;
	int ret;

	vdks = vdsm_alloc(pdev, sizeof(struct vdsm_kernel_stub));
	if (!vdks) {
		ret = -ENOMEM;
		goto exit_err;
	}

	vdks->be = load_backend(pdev);
	vdks->pdev = pdev;
	ret = create_vdsm_device(&vdks->cdev);
	if (ret) {
		goto exit_free_vdks;
	}

	create_doe_mb_placeholder(&vdks->vdmb.mb, pdev);

	xa_init(&vdks->ide_stream_info_xa);

	return &vdks->vdmb.mb;

exit_free_vdks:
	kfree(vdks);
exit_err:
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(vdsm_doe_create_mb);

/* Exported to DOE driver */
int vdsm_doe_submit_task(struct pci_doe_mb *doe_mb, struct pci_doe_task *task,
			 struct pci_dev *pdev)
{
	struct vdsm_kernel_stub *vdks;

	vdks = container_of(doe_mb, struct vdsm_kernel_stub, vdmb.mb);
	vdks->vdmb.task = task;

	return signal_eventfd_to_user(vdks);
}
EXPORT_SYMBOL_GPL(vdsm_doe_submit_task);

bool is_registered_to_vdsm(struct pci_dev *pdev)
{
	struct vdsm_driver_backend *vdbe;

	vdbe = load_backend(pdev);
	if (!vdbe)
		return false;

	return true;
}
EXPORT_SYMBOL_GPL(is_registered_to_vdsm);

static uint32_t vdsm_get_free_minor(void)
{
	uint32_t minor;
	for (minor = 0; minor < VDSM_MAX_MINORS; minor++) {
		if (vdsm_minor[minor] == 0)
			break;
	}

	return minor;
}

static int create_vdsm_device(struct cdev *cdev)
{
	uint32_t minor;
	dev_t dev_num;
	int ret;

	minor = vdsm_get_free_minor();
	if (minor == VDSM_MAX_MINORS) {
		pr_err("No minor left under vdks_class\n");
		ret = -ENODEV;
		goto exit_err;
	}

	vdsm_minor[minor] = 1;
	dev_num = MKDEV(vdsm_major, minor);
	cdev_init(cdev, &vdsm_fops);
	ret = cdev_add(cdev, dev_num, 1);
	if (ret) {
		pr_err("No minor left under vdks_class\n");
		goto exit_err;
	}

	if (IS_ERR(device_create(vdsm_class, NULL, dev_num, NULL,
				 "vdsm_kernel_stub_%d", minor))) {
		ret = -ENODEV;
		goto exit_del_cdev;
	}

	return 0;

exit_del_cdev:
	cdev_del(cdev);
exit_err:
	return ret;
}

static inline void create_doe_mb_placeholder(struct pci_doe_mb *doe_mb,
					     struct pci_dev *pdev)
{
	/* vDSM DOE mailbox won't touch work_queue field. */
	doe_mb->pdev = pdev;
	doe_mb->cap_offset= 0;
	xa_init(&doe_mb->prots);
}

static inline struct vdsm_driver_backend *load_backend(struct pci_dev *pdev)
{
	unsigned long be_idx;

	be_idx = UNIQUE_BE_IDX(pdev->vendor, pdev->device);

	return xa_load(&vdsm_driver_backend_xa, be_idx);
}

static int signal_eventfd_to_user(struct vdsm_kernel_stub *vdks)
{
	bool is_evfd_bound = true;

	if (vdks->vdmb.evfd_ctx == NULL) {
		pr_info("%s: vdks->vdmb.evfd_ctx NULL, retrying...\n", __func__);
		is_evfd_bound = false;
	        /* Wait until user successfully bind eventfd via ioctl. */
		for (int max_retry = 5; max_retry > 0; max_retry--) {
			msleep(10);
			if (vdks->vdmb.evfd_ctx)
				is_evfd_bound = true;
		}
	}

	if (is_evfd_bound) {
		eventfd_signal(vdks->vdmb.evfd_ctx, 1);
	} else {
		pr_err("%s: failed to signal eventfd to user\n", __func__);
		return -EFAULT;
	}

	return 0;
}

static int vdsm_open(struct inode *inode, struct file *file)
{
	struct cdev *cdev = inode->i_cdev;

	file->private_data = cdev;
	return 0;
}

static int vdsm_close(struct inode *inode, struct file *file)
{
	/* TODO */
	return 0;
}

static long vdsm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct cdev *cdev = file->private_data;
	struct vdsm_kernel_stub *vdks;
	int ret;

	vdks = container_of(cdev, struct vdsm_kernel_stub, cdev);

	if (vdks == NULL) {
		pr_err("%s xa_load vdks failed\n", __func__);
		return -EFAULT;
	}
	switch (cmd) {
	case VDSM_BIND_EVFD:
		ret = vdsm_bind_eventfd(vdks, (void *)arg);
		if (ret)
			pr_err("vdsm_bind_eventfd failed\n");
		break;
	case VDSM_RECV_REQUEST: {
		spdm_request_t *req;
		req = generate_request_to_user(vdks);
		if (IS_ERR(req)) {
			pr_err("Failed to get request\n");
			ret = -ENOMEM;
			break;
		}

		ret = copy_to_user((void *)arg, req,
				   vdks->vdmb.task->request_pl_sz +
				   PCI_DOE_HEADER_SIZE);
		if (ret)
			pr_err("vdsm: copy spdm_request_t to user failed\n");
		break;
	}
	case VDSM_SEND_RESPONSE: {
		/* alloc max response_pl_sz because we don't know doe_h.length yet */
		spdm_response_t *resp =
			vdsm_alloc(vdks->pdev, vdks->vdmb.task->response_pl_sz +
				   PCI_DOE_HEADER_SIZE);
		if (resp == NULL) {
			pr_err("Failed to alloc space for response\n");
			ret = -ENOMEM;
			break;
		}
		ret = copy_from_user(resp, (void *)arg,
				     vdks->vdmb.task->response_pl_sz +
				     PCI_DOE_HEADER_SIZE);
		if (ret)
			pr_err("vdsm: copy spdm_response_t from user failed\n");

		receive_response_from_user(vdks, resp);
		/* send completion signal so driver will start to read response */
		vdks->vdmb.task->complete(vdks->vdmb.task);
		break;
	}
	case VDSM_IDE_KM_INIT:
		pr_info("vdsm: VDSM_IDE_KM_INIT\n");
		ret = ide_km_init(vdks, (void *)arg);
		break;
	case VDSM_IDE_KM_QUERY:
		pr_info("vdsm: VDSM_IDE_KM_QUERY\n");
		ret = ide_km_query(vdks, (void *)arg);
		break;
	case VDSM_IDE_KM_KEY_PROG:
		pr_info("vdsm: VDSM_IDE_KM_KEY_PROG\n");
		ret = ide_km_key_prog(vdks, (void *)arg);
		break;
	case VDSM_IDE_KM_KEY_SET_GO:
		pr_info("vdsm: VDSM_IDE_KM_KEY_SET_GO\n");
		ret = ide_km_key_set_go(vdks, (void *)arg);
		break;
	case VDSM_IDE_KM_KEY_SET_STOP:
		pr_info("vdsm: VDSM_IDE_KM_KEY_SET_STOP\n");
		ret = ide_km_key_set_stop(vdks, (void *)arg);
		break;
	case VDSM_IDE_KM_DEINIT:
		pr_info("vdsm: VDSM_IDE_KM_DEINIT\n");
		ret = ide_km_deinit(vdks, (void *)arg);
		break;
	case VDSM_TDISP_GET_VERSION:
		pr_info("vdsm: VDSM_TDISP_GET_VERSION\n");
		ret = tdisp_get_version(vdks, (void *)arg);
		break;
	case VDSM_TDISP_GET_CAPABILITIES:
		pr_info("vdsm: VDSM_TDISP_GET_CAPABILITIES\n");
		ret = tdisp_get_capabilities(vdks, (void *)arg);
		break;
	case VDSM_TDISP_LOCK_INTERFACE:
		pr_info("vdsm: VDSM_TDISP_LOCK_INTERFACE\n");
		ret = tdisp_lock_interface(vdks, (void *)arg);
		break;
	case VDSM_TDISP_GET_DEVICE_INTERFACE_REPORT:
		pr_info("vdsm: VDSM_TDISP_GET_DEVICE_INTERFACE_REPORT\n");
		ret = tdisp_get_device_interface_report(vdks, (void *)arg);
		break;
	case VDSM_TDISP_GET_DEVICE_INTERFACE_STATE:
		pr_info("vdsm: VDSM_TDISP_GET_DEVICE_INTERFACE_STATE\n");
		ret = tdisp_get_device_interface_state(vdks, (void *)arg);
		break;
	case VDSM_TDISP_START_INTERFACE:
		pr_info("vdsm: VDSM_TDISP_START_INTERFACE\n");
		ret = tdisp_start_interface(vdks, (void *)arg);
		break;
	case VDSM_TDISP_STOP_INTERFACE:
		pr_info("vdsm: VDSM_TDISP_STOP_INTERFACE\n");
		ret = tdisp_stop_interface(vdks, (void *)arg);
		break;
	case VDSM_ADISP_GET_VERSION:
		pr_info("vdsm: VDSM_ADISP_GET_VERSION\n");
		ret = adisp_get_version(vdks, (void *)arg);
		break;
	case VDSM_ADISP_GET_CAPABILITIES:
		pr_info("vdsm: VDSM_ADISP_GET_CAPABILITIES\n");
		ret = adisp_get_capabilities(vdks, (void *)arg);
		break;
	case VDSM_ADISP_LOCK_INTERFACE:
		pr_info("vdsm: VDSM_ADISP_LOCK_INTERFACE\n");
		ret = adisp_lock_interface(vdks, (void *)arg);
		break;
	case VDSM_ADISP_GET_DEVICE_INTERFACE_REPORT:
		pr_info("vdsm: VDSM_ADISP_GET_DEVICE_INTERFACE_REPORT\n");
		ret = adisp_get_device_interface_report(vdks, (void *)arg);
		break;
	case VDSM_ADISP_GET_DEVICE_INTERFACE_STATE:
		pr_info("vdsm: VDSM_ADISP_GET_DEVICE_INTERFACE_STATE\n");
		ret = adisp_get_device_interface_state(vdks, (void *)arg);
		break;
	case VDSM_ADISP_START_INTERFACE_MMIO:
		pr_info("vdsm: VDSM_ADISP_START_MMIO\n");
		ret = adisp_start_interface_mmio(vdks, (void *)arg);
		break;
	case VDSM_ADISP_START_INTERFACE_DMA:
		pr_info("vdsm: VDSM_ADISP_START_DMA\n");
		ret = adisp_start_interface_dma(vdks, (void *)arg);
		break;
	case VDSM_ADISP_STOP_INTERFACE:
		pr_info("vdsm: VDSM_ADISP_STOP\n");
		ret = adisp_stop_interface(vdks, (void *)arg);
		break;
	default:
		pr_err("vdsm: unknown ioctl 0x%x\n", cmd);
		ret = -EINVAL;
	}

	return ret;
}

static const struct file_operations vdsm_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = vdsm_ioctl,
	.open = vdsm_open,
	.release = vdsm_close,
};

static int __init vdsm_init(void)
{
	int ret;
	dev_t dev_num;

	/* Create vDSM char dev class */
	vdsm_class = class_create(THIS_MODULE, "vdks_class");
	if (IS_ERR(vdsm_class))
		return PTR_ERR(vdsm_class);

	ret = alloc_chrdev_region(&dev_num, 0, VDSM_MAX_MINORS,
				  "vdsm_kernel_stub");
	if (ret < 0) {
		class_destroy(vdsm_class);
		pr_info("vdsm: %s failed\n", __func__);
		return ret;
	}

	vdsm_major = MAJOR(dev_num);

	return 0;
}

static void __exit vdsm_exit(void)
{
	/* TODO: free all other data */
	unregister_chrdev_region(MKDEV(vdsm_major, 0), VDSM_MAX_MINORS);
	class_destroy(vdsm_class);
}

subsys_initcall(vdsm_init);
module_exit(vdsm_exit);

MODULE_DESCRIPTION("Virtual Device Security Manager");
MODULE_AUTHOR("Intel FLEX");
MODULE_LICENSE("GPL v2");
