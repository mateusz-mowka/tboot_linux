// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022-2023 Intel Corporation */

#include "dummy_requester.h"

struct pci_dev glb_dummy_pdev = {
	.vendor = PCI_VENDOR_ID_INTEL,
	.device = 0xdead,
};

struct pci_doe_mb *glb_doe_mb[MAX_DEVICES];

u8 glb_req[MAX_DEVICES][LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE];
u8 glb_resp[MAX_DEVICES][LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE];

struct eventfd_ctx *glb_evfd_ctx[MAX_DEVICES];

dev_t device_number;
struct class *vdks_class;
static struct cdev my_cdev[MAX_DEVICES];

static int vdsm_dummy_device_open(struct inode *inode, struct file *file)
{
	struct cdev *cdev = inode->i_cdev;
	int minor = MINOR(cdev->dev);

	pr_info("%s\n", __func__);
	file->private_data = cdev;

	/* Call pcim_doe_create_mb directly to bypass VFIO/TDISP/IDE. */
	glb_doe_mb[minor] = pcim_doe_create_mb(&glb_dummy_pdev, 1);
	if (glb_doe_mb[minor] == NULL) {
		pr_err("%s: failed to create vdsm mailbox\n", __func__);
		return -EFAULT;
	}

	return 0;
}

static int vdsm_dummy_device_release(struct inode *inode, struct file *file)
{
	pr_info("%s\n", __func__);
	return 0;
}

ssize_t vdsm_dummy_device_read(struct file *file, char __user *user_buffer,
		      size_t count, loff_t *offset)
{
	pr_info("%s\n", __func__);
	return 0;
}

ssize_t vdsm_dummy_device_write(struct file *file, const char __user *user_buffer,
		       size_t count, loff_t *offset)
{
	pr_info("%s\n", __func__);
	return count;
}

static long vdsm_dummy_device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	int evfd;
	int len;
	struct cdev *cdev = file->private_data;
	int minor = MINOR(cdev->dev);
	spdm_response_t *resp;

	switch (cmd) {
	case VDSM_BIND_EVFD:
		ret = copy_from_user((void *)&evfd, (void *)arg, sizeof(int));
		if (ret) {
			pr_err("%s: copy eventfd from user failed\n", __func__);
			break;
		}
		glb_evfd_ctx[minor] = eventfd_ctx_fdget(evfd);
		if (IS_ERR(glb_evfd_ctx[minor])) {
			ret = PTR_ERR(glb_evfd_ctx[minor]);
			pr_err("%s: failed to bind eventfd\n", __func__);
		}
		break;
	case VDSM_SEND_REQUEST:
		ret = copy_from_user(glb_req[minor], (void *)arg,
				     LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE);
		if (ret) {
			pr_err("%s: copy spdm_request_t from user failed\n", __func__);
			ret = -EFAULT;
			break;
		}

		ret = pci_doe_msg_exchange_sync(glb_doe_mb[minor],
						(u32 *)glb_req[minor],
						(u32 *)glb_resp[minor],
						LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE);
		if (ret) {
			pr_err("%s: vdsm_doe_submit_task failed\n", __func__);
			break;
		}
		/* Send signal to requester when response is ready. */
		eventfd_signal(glb_evfd_ctx[minor], 1);

		break;
	case VDSM_RECV_RESPONSE:
		resp = (spdm_response_t *)glb_resp[minor];
		len = resp->doe_h.length * sizeof(uint32_t);

		ret = copy_to_user((void *)arg, resp, len);
		if (ret) {
			pr_err("%s: copy spdm_response_t to user failed\n", __func__);
			ret = -EFAULT;
			break;
		}

		break;
	default:
		pr_err("ioctl cmd not recognized");
	}

	return 0;
}

struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = vdsm_dummy_device_open,
	.release = vdsm_dummy_device_release,
	.read = vdsm_dummy_device_read,
	.write = vdsm_dummy_device_write,
	.unlocked_ioctl = vdsm_dummy_device_ioctl,
};

static inline void *dummy_init(struct pci_dev *pdev, uint8_t stream_id)
{
	int *init_var;

	init_var = kzalloc(sizeof(int), GFP_KERNEL);
	if (init_var == NULL) {
		pr_err("%s: failed to alloc memory for private data\n", __func__);
	}

	*init_var = stream_id + 8086;
	pr_info("dummy backend: %s\n", __func__);

	return (void *)init_var;
}

static inline int dummy_key_prog(void *private_data, u32 sub_stream,
				 u8 direction, u32 *key, u32 *iv_key)
{
	int *var;

	var = private_data;

	pr_info("dummy backend: %s - private_data = %d\n", __func__, *var);

	return 0;
}

static inline int dummy_key_set_go(void *private_data)
{
	int *var;

	var = private_data;

	pr_info("dummy backend: %s - private_data = %d\n", __func__, *var);

	return 0;
}

static inline int dummy_key_set_stop(void *private_data)
{
	int *var;

	var = private_data;

	pr_info("dummy backend: %s - private_data = %d\n", __func__, *var);

	return 0;
}

static inline void dummy_deinit(void *private_data)
{
	int *var;

	var = private_data;

	pr_info("dummy backend: %s - private_data = %d\n", __func__, *var);
}

static inline int dummy_start(void *private_data)
{
	int *var;

	var = private_data;

	pr_info("dummy backend: %s - private_data = %d\n", __func__, *var);

	return 0;
}

static inline int dummy_stop(void *private_data)
{
	int *var;

	var = private_data;

	pr_info("dummy backend: %s - private_data = %d\n", __func__, *var);

	return 0;
}

static inline int dummy_adisp_interface_report(struct pci_dev *pdev)
{
	pr_info("dummy backend: %s\n", __func__);

	return 0;
}

static inline int dummy_adisp_start_mmio(void *private_data)
{
	int *var;

	var = private_data;

	pr_info("dummy backend: %s - private_data = %d\n", __func__, *var);

	return 0;
}

static inline int dummy_adisp_start_dma(void *private_data)
{
	int *var;

	var = private_data;

	pr_info("dummy backend: %s - private_data = %d\n", __func__, *var);

	return 0;
}

static inline int dummy_adisp_stop(void *private_data)
{
	int *var;

	var = private_data;

	pr_info("dummy backend: %s - private_data = %d\n", __func__, *var);

	return 0;
}

static const struct pci_device_id dummy_id_table[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, 0xdead),},
	{ 0, }
};

static struct vdsm_prot_ide_km_backend dummy_ide_be = {
	.init = dummy_init,
	.key_prog = dummy_key_prog,
	.key_set_go = dummy_key_set_go,
	.key_set_stop = dummy_key_set_stop,
	.deinit = dummy_deinit,
};

static struct vdsm_prot_tdisp_backend dummy_tdisp_be = {
	.start_interface = dummy_start,
	.stop_interface = dummy_stop,
};

static struct vdsm_prot_adisp_backend dummy_adisp_be = {
	.get_device_interface_report = dummy_adisp_interface_report,
	.start_interface_mmio = dummy_adisp_start_mmio,
	.start_interface_dma = dummy_adisp_start_dma,
	.stop_interface = dummy_adisp_stop,
};

static struct vdsm_driver_backend vdsm_be = {
	.dev_ids = dummy_id_table,
	.ide_be = &dummy_ide_be,
	.tdisp_be = &dummy_tdisp_be,
	.adisp_be = &dummy_adisp_be,
};

static int vdsm_dummy_device_init(void)
{
	int ret;
	int i = 0;

	pr_info("Entering %s\n", __func__);

	ret = alloc_chrdev_region(&device_number, 0, MAX_DEVICES, "embedded");
	if (!ret) {
		int major = MAJOR(device_number);
		dev_t my_device;
		vdks_class = class_create(THIS_MODULE, "vdks_requester_class");
		for (i = 0; i < MAX_DEVICES; i++) {
			my_device = MKDEV(major, i);
			cdev_init(&my_cdev[i], &fops);
			ret = cdev_add(&my_cdev[i], my_device, 1);
			if (ret) {
				pr_info("%s: Failed in adding cdev to subsystem "
				        "ret:%d\n", __func__, ret);
			}
			else {
				device_create(vdks_class, NULL, my_device, NULL, "vdsm_requester_%d", i);
			}
		}
	} else {
		pr_err("%s: Failed in allocating device number "
		       "Error:%d\n", __func__, ret);
		return ret;
	}

	ret = vdsm_register_driver_backend(&vdsm_be);
	if (ret) {
		pr_err("vdsm_register_driver_backend failed\n");
	}

	return ret;
}

static void vdsm_dummy_device_exit(void)
{
	int i = 0;
	int major = MAJOR(device_number);
	dev_t my_device;
	for (i = 0; i < MAX_DEVICES; i++) {
		my_device = MKDEV(major, i);
		cdev_del(&my_cdev[i]);
		device_destroy(vdks_class, my_device);
	}
	class_destroy(vdks_class);
	unregister_chrdev_region(device_number, MAX_DEVICES);

	vdsm_unregister_driver_backend(&vdsm_be);
	pr_info("Exiting %s\n", __func__);
}

module_init(vdsm_dummy_device_init);
module_exit(vdsm_dummy_device_exit);
MODULE_LICENSE("GPL");
