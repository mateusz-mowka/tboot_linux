// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Software Defined Silicon driver
 *
 * Copyright (c) 2022, Intel Corporation.
 * All Rights Reserved.
 *
 * Author: "David E. Box" <david.e.box@linux.intel.com>
 */

#include <linux/auxiliary_bus.h>
#include <linux/bits.h>
#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/intel_vsec.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/spdm.h>
#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "sdsi.h"
#include "sdsi_genl.h"

#define ACCESS_TYPE_BARID		2
#define ACCESS_TYPE_LOCAL		3

#define SDSI_MIN_SIZE_DWORDS		276
#define SDSI_SIZE_MAILBOX		1024
#define SDSI_SIZE_REGS			80
#define SDSI_SIZE_CMD			sizeof(u64)
#define SDSI_SIZE_MAILBOX		1024

/*
 * Write messages are currently up to the size of the mailbox
 * while read messages are up to 4 times the size of the
 * mailbox, sent in packets
 */
#define SDSI_SIZE_WRITE_MSG		SDSI_SIZE_MAILBOX
#define SDSI_SIZE_READ_MSG		(SDSI_SIZE_MAILBOX * 4)

#define SDSI_ENABLED_FEATURES_OFFSET	16
#define SDSI_FEATURE_SDSI		BIT(3)
#define SDSI_FEATURE_ATTESTATION	BIT(12)
#define SDSI_FEATURE_METERING		BIT(26)

#define SDSI_MBOX_CMD_SUCCESS		0x40
#define SDSI_MBOX_CMD_TIMEOUT		0x80

#define MBOX_TIMEOUT_US			2000
#define MBOX_TIMEOUT_ACQUIRE_US		1000
#define MBOX_POLLING_PERIOD_US		100
#define MBOX_ACQUIRE_NUM_RETRIES	5
#define MBOX_ACQUIRE_RETRY_DELAY_MS	500
#define MBOX_MAX_PACKETS		4

#define MBOX_OWNER_NONE			0x00
#define MBOX_OWNER_INBAND		0x01

#define CTRL_RUN_BUSY			BIT(0)
#define CTRL_READ_WRITE			BIT(1)
#define CTRL_SOM			BIT(2)
#define CTRL_EOM			BIT(3)
#define CTRL_OWNER			GENMASK(5, 4)
#define CTRL_COMPLETE			BIT(6)
#define CTRL_READY			BIT(7)
#define CTRL_STATUS			GENMASK(15, 8)
#define CTRL_PACKET_SIZE		GENMASK(31, 16)
#define CTRL_MSG_SIZE			GENMASK(63, 48)

#define DISC_TABLE_SIZE			12
#define DT_ACCESS_TYPE			GENMASK(3, 0)
#define DT_SIZE				GENMASK(27, 12)
#define DT_TBIR				GENMASK(2, 0)
#define DT_OFFSET(v)			((v) & GENMASK(31, 3))

#define SDSI_GUID_V1			0x006DD191
#define SDSI_GUID_V2			0xF210D9EF

static int timeout_us = MBOX_TIMEOUT_US;
module_param(timeout_us, int, 0644);

static LIST_HEAD(sdsi_list);
static DEFINE_MUTEX(sdsi_list_lock);

enum sdsi_command {
	SDSI_CMD_PROVISION_AKC		= 0x0004,
	SDSI_CMD_PROVISION_CAP		= 0x0008,
	SDSI_CMD_READ_STATE		= 0x0010,
	SDSI_CMD_READ_METER		= 0x0014,
	SDSI_CMD_ATTESTATION		= 0x1012,
};

struct sdsi_mbox_info {
	u64	*payload;
	void	*buffer;
	int	size;
	int	packet_size;
};

struct disc_table {
	u32	access_info;
	u32	guid;
	u32	offset;
};

/* SDSi mailbox operations must be performed using 64bit mov instructions */
static __always_inline void
sdsi_memcpy64_toio(u64 __iomem *to, const u64 *from, size_t count_bytes)
{
	size_t count = count_bytes / sizeof(*to);
	int i;

	for (i = 0; i < count; i++)
		writeq(from[i], &to[i]);
}

static __always_inline void
sdsi_memcpy64_fromio(u64 *to, const u64 __iomem *from, size_t count_bytes)
{
	size_t count = count_bytes / sizeof(*to);
	int i;

	for (i = 0; i < count; i++)
		to[i] = readq(&from[i]);
}

static void print_control(u64 control)
{
	pr_debug("\n"
		"SDSi CONTROL REGISTER:\n"
		"RUN_BUSY:      %lu\n"
		"READ_WRITE:    %lu\n"
		"SOM:           %lu\n"
		"EOM:           %lu\n"
		"OWNER:         0x%lx\n"
		"COMPLETE:      %lu\n"
		"READY:         %lu\n"
		"STATUS:        0x%lx\n"
		"PACKET_SIZE:   %lu\n"
		"MSG_SIZE:      %lu\n"
		"\n",
		FIELD_GET(CTRL_RUN_BUSY, control),
		FIELD_GET(CTRL_READ_WRITE, control),
		FIELD_GET(CTRL_SOM, control),
		FIELD_GET(CTRL_EOM, control),
		FIELD_GET(CTRL_OWNER, control),
		FIELD_GET(CTRL_COMPLETE, control),
		FIELD_GET(CTRL_READY, control),
		FIELD_GET(CTRL_STATUS, control),
		FIELD_GET(CTRL_PACKET_SIZE, control),
		FIELD_GET(CTRL_MSG_SIZE, control));
}

static inline void sdsi_complete_transaction(struct sdsi_priv *priv)
{
	u64 control = FIELD_PREP(CTRL_COMPLETE, 1);

	lockdep_assert_held(&priv->mb_lock);

	dev_dbg(priv->dev, "%s: Setting complete bit\n", __func__);
	writeq(control, priv->control_addr);
}

static int sdsi_status_to_errno(u32 status)
{
	switch (status) {
	case SDSI_MBOX_CMD_SUCCESS:
		return 0;
	case 0:
		pr_warn("%s: Warning. Status is 0x0. Expected 0x40\n", __func__);
		return 0;
	case SDSI_MBOX_CMD_TIMEOUT:
		return -ETIMEDOUT;
	default:
		return -EIO;
	}
}

static int sdsi_mbox_poll(struct sdsi_priv *priv, struct sdsi_mbox_info *info,
			  size_t *data_size)
{
	struct device *dev = priv->dev;
	u32 total, loop, eom, status, message_size;
	u64 control;
	int ret;

	lockdep_assert_held(&priv->mb_lock);

	dev_dbg(priv->dev, "%s\n", __func__);

	/* Format and send the read command */
	control = FIELD_PREP(CTRL_EOM, 1) |
		  FIELD_PREP(CTRL_SOM, 1) |
		  FIELD_PREP(CTRL_RUN_BUSY, 1) |
		  FIELD_PREP(CTRL_PACKET_SIZE, info->size);
	writeq(control, priv->control_addr);

	/* For reads, data sizes that are larger than the mailbox size are read in packets. */
	total = 0;
	loop = 0;
	do {
		u32 packet_size;

		/* Poll on ready bit */
		dev_dbg(priv->dev, "%s: Packet %d\n", __func__, loop);
		dev_dbg(priv->dev, "%s: Polling ready bit\n", __func__);
		ret = readq_poll_timeout(priv->control_addr, control,
					 control & CTRL_READY,
					 MBOX_POLLING_PERIOD_US,
					 timeout_us);
		if (ret) {
			dev_dbg(priv->dev, "%s: Polling ready bit timed out, error %d\n", __func__, ret);
			break;
		}

		eom = FIELD_GET(CTRL_EOM, control);
		status = FIELD_GET(CTRL_STATUS, control);
		packet_size = FIELD_GET(CTRL_PACKET_SIZE, control);
		message_size = FIELD_GET(CTRL_MSG_SIZE, control);
		print_control(control);

		ret = sdsi_status_to_errno(status);
		if (ret)
			break;

		if (!packet_size) {
			sdsi_complete_transaction(priv);
			break;
		}

		/* Only the last packet can be less than the mailbox size. */
		if (!eom && packet_size != SDSI_SIZE_MAILBOX) {
			dev_err(priv->dev, "Invalid packet size\n");
			ret = -EPROTO;
			break;
		}

		if (packet_size > SDSI_SIZE_MAILBOX) {
			dev_err(priv->dev, "Packet size too large\n");
			ret = -EPROTO;
			break;
		}

		/*
		 * Only store data when the caller has created a buffer for it.
		 * Otherwise it's assumed the caller did not want the data or
		 * the command returned some unexpectedly. Either way, skip it
		 * and keeping looping until all packets have been sent.
		 */
		if (packet_size && info->buffer) {
			void *buf = info->buffer + (SDSI_SIZE_MAILBOX * loop);

			dev_dbg(priv->dev, "%s: Copying packet %d to buffer\n", __func__, loop);
			sdsi_memcpy64_fromio(buf, priv->mbox_addr,
					     round_up(packet_size, SDSI_SIZE_CMD));
			total += packet_size;
		}

		sdsi_complete_transaction(priv);
	} while (!eom && ++loop < MBOX_MAX_PACKETS);

	if (ret) {
		sdsi_complete_transaction(priv);
		return ret;
	}

	if (!eom) {
		dev_err(dev, "Exceeded max number of packets\n");
		return -EPROTO;
	}

	/* Message size check is only valid for multi-packet transfers */
	if (loop && total != message_size)
		dev_warn(dev, "Read count %u differs from expected count %u\n",
			 total, message_size);

	if (data_size)
		*data_size = total;

	return ret;
}

static int sdsi_mbox_cmd_read(struct sdsi_priv *priv, struct sdsi_mbox_info *info,
			      size_t *data_size)
{
	u64 control;

	lockdep_assert_held(&priv->mb_lock);

	dev_dbg(priv->dev, "%s\n", __func__);

	/* Format and send the read command */
	control = FIELD_PREP(CTRL_EOM, 1) |
		  FIELD_PREP(CTRL_SOM, 1) |
		  FIELD_PREP(CTRL_RUN_BUSY, 1) |
		  FIELD_PREP(CTRL_PACKET_SIZE, info->packet_size);

	writeq(control, priv->control_addr);

	return sdsi_mbox_poll(priv, info, data_size);
}

static int sdsi_mbox_cmd_write(struct sdsi_priv *priv, struct sdsi_mbox_info *info,
			       size_t *data_size)
{
	u64 control;

	lockdep_assert_held(&priv->mb_lock);

	dev_dbg(priv->dev, "%s\n", __func__);

	/* Write rest of the payload */
	sdsi_memcpy64_toio(priv->mbox_addr + SDSI_SIZE_CMD, info->payload + 1,
			   info->size - SDSI_SIZE_CMD);
	/* Format and send the write command */
	control = FIELD_PREP(CTRL_EOM, 1) |
		  FIELD_PREP(CTRL_SOM, 1) |
		  FIELD_PREP(CTRL_RUN_BUSY, 1) |
		  FIELD_PREP(CTRL_READ_WRITE, 1) |
		  FIELD_PREP(CTRL_PACKET_SIZE, info->packet_size) |
		  FIELD_PREP(CTRL_MSG_SIZE, info->packet_size);

	writeq(control, priv->control_addr);

	return sdsi_mbox_poll(priv, info, data_size);
}

static int sdsi_mbox_acquire(struct sdsi_priv *priv, struct sdsi_mbox_info *info)
{
	u64 control;
	u32 owner;
	int ret, retries = 0;

	lockdep_assert_held(&priv->mb_lock);

	dev_dbg(priv->dev, "%s\n", __func__);

	/* Check mailbox is available */
	control = readq(priv->control_addr);
	print_control(control);
	owner = FIELD_GET(CTRL_OWNER, control);
	if (owner != MBOX_OWNER_NONE) {
		dev_dbg(priv->dev, "%s: Cannot acquire mailbox: Owner is 0x%x\n",
		       __func__, owner);
		return -EBUSY;
	}

	/*
	 * If there has been no recent transaction and no one owns the mailbox,
	 * we should acquire it in under 1ms. However, if we've accessed it
	 * recently it may take up to 2.1 seconds to acquire it again.
	 */
	do {
		/* Write first qword of payload */
		dev_dbg(priv->dev, "%s: Writing first Qword 0x%llx\n", __func__, info->payload[0]);
		writeq(info->payload[0], priv->mbox_addr);

		/* Check for ownership */
		ret = readq_poll_timeout(priv->control_addr, control,
			FIELD_GET(CTRL_OWNER, control) == MBOX_OWNER_INBAND,
			MBOX_POLLING_PERIOD_US, MBOX_TIMEOUT_ACQUIRE_US);

		if (FIELD_GET(CTRL_OWNER, control) == MBOX_OWNER_NONE &&
		    retries++ < MBOX_ACQUIRE_NUM_RETRIES) {
			dev_dbg(priv->dev, "%s: Did not acquire, delaying for 0.5s\n", __func__);
			msleep(MBOX_ACQUIRE_RETRY_DELAY_MS);
			continue;
		}

		/* Either we got it or someone else did. */
		break;
	} while (true);

	if (!ret)
		dev_dbg(priv->dev, "%s: Mailbox acquired\n", __func__);
	else
		dev_dbg(priv->dev, "%s: Did not acquire mailbox, error %d\n", __func__, ret);

	return ret;
}

static int sdsi_mbox_write(struct sdsi_priv *priv, struct sdsi_mbox_info *info,
			   size_t *data_size)
{
	int ret;

	lockdep_assert_held(&priv->mb_lock);

	dev_dbg(priv->dev, "%s\n", __func__);

	ret = sdsi_mbox_acquire(priv, info);
	if (ret)
		return ret;

	return sdsi_mbox_cmd_write(priv, info, data_size);
}

static int sdsi_mbox_read(struct sdsi_priv *priv, struct sdsi_mbox_info *info,
			  size_t *data_size)
{
	int ret;

	lockdep_assert_held(&priv->mb_lock);

	dev_dbg(priv->dev, "%s\n", __func__);

	ret = sdsi_mbox_acquire(priv, info);
	if (ret)
		return ret;

	return sdsi_mbox_cmd_read(priv, info, data_size);
}

static ssize_t sdsi_provision(struct sdsi_priv *priv, char *buf, size_t count,
			      enum sdsi_command command)
{
	struct sdsi_mbox_info info = {};
	int ret;

	if (count > (SDSI_SIZE_WRITE_MSG - SDSI_SIZE_CMD))
		return -EOVERFLOW;

	/* Qword aligned message + command qword */
	info.size = round_up(count, SDSI_SIZE_CMD) + SDSI_SIZE_CMD;

	info.payload = kzalloc(info.size, GFP_KERNEL);
	if (!info.payload)
		return -ENOMEM;

	/* Copy message to payload buffer */
	memcpy(info.payload, buf, count);

	/* Command is last qword of payload buffer */
	info.payload[(info.size - SDSI_SIZE_CMD) / SDSI_SIZE_CMD] = command;

	info.packet_size = info.size;

	ret = mutex_lock_interruptible(&priv->mb_lock);
	if (ret)
		goto free_payload;

	pm_runtime_get_sync(&priv->ivdev->pcidev->dev);
	ret = sdsi_mbox_write(priv, &info, NULL);
	pm_runtime_mark_last_busy(&priv->ivdev->pcidev->dev);
	pm_runtime_put_autosuspend(&priv->ivdev->pcidev->dev);

	mutex_unlock(&priv->mb_lock);

free_payload:
	kfree(info.payload);

	if (ret)
		return ret;

	return count;
}

static ssize_t provision_akc_write(struct file *filp, struct kobject *kobj,
				   struct bin_attribute *attr, char *buf,
				   loff_t off, size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct sdsi_priv *priv = dev_get_drvdata(dev);
	int ret;

	dev_dbg(priv->dev, "****** Start %s ******\n", __func__);

	dev_dbg(priv->dev, "loff:	%lld\n"
		"count:	%ld\n",
		off, count);
	if (off)
		return -ESPIPE;

	ret = sdsi_provision(priv, buf, count, SDSI_CMD_PROVISION_AKC);

	dev_dbg(priv->dev, "****** End %s ******\n"
		"\n", __func__);

	return ret;
}
static BIN_ATTR_WO(provision_akc, SDSI_SIZE_WRITE_MSG);

static ssize_t provision_cap_write(struct file *filp, struct kobject *kobj,
				   struct bin_attribute *attr, char *buf,
				   loff_t off, size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct sdsi_priv *priv = dev_get_drvdata(dev);
	int ret;

	dev_dbg(priv->dev, "****** Start %s ******\n", __func__);

	dev_dbg(priv->dev, "loff:	%lld\n"
		"count:	%ld\n",
		off, count);
	if (off)
		return -ESPIPE;

	ret = sdsi_provision(priv, buf, count, SDSI_CMD_PROVISION_CAP);

	dev_dbg(priv->dev, "****** End %s ******\n"
		"\n", __func__);

	return ret;
}
static BIN_ATTR_WO(provision_cap, SDSI_SIZE_WRITE_MSG);

static ssize_t
certificate_read(u64 command, struct sdsi_priv *priv, char *buf, loff_t off,
		 size_t count)
{
	struct sdsi_mbox_info info = {};
	size_t size;
	int ret;

	if (off)
		return 0;

	/* Buffer for return data */
	info.buffer = kmalloc(SDSI_SIZE_READ_MSG, GFP_KERNEL);
	if (!info.buffer)
		return -ENOMEM;

	info.payload = &command;
	info.size = sizeof(command);
	info.packet_size = info.size;

	ret = mutex_lock_interruptible(&priv->mb_lock);
	if (ret)
		goto free_buffer;

	pm_runtime_get_sync(&priv->ivdev->pcidev->dev);
	ret = sdsi_mbox_read(priv, &info, &size);
	pm_runtime_mark_last_busy(&priv->ivdev->pcidev->dev);
	pm_runtime_put_autosuspend(&priv->ivdev->pcidev->dev);

	mutex_unlock(&priv->mb_lock);
	if (ret < 0)
		goto free_buffer;

	if (size > count)
		size = count;

	memcpy(buf, info.buffer, size);

free_buffer:
	kfree(info.buffer);

	if (ret)
		return ret;

	return size;
}

static ssize_t
state_certificate_read(struct file *filp, struct kobject *kobj,
		       struct bin_attribute *attr, char *buf, loff_t off,
		       size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct sdsi_priv *priv = dev_get_drvdata(dev);
	int ret;

	dev_dbg(priv->dev, "****** Start %s ******\n", __func__);

	dev_dbg(priv->dev, "loff:	%lld\n"
		"count:	%ld\n",
		off, count);
	ret = certificate_read(SDSI_CMD_READ_STATE, priv, buf, off, count);

	dev_dbg(priv->dev, "****** End %s ******\n"
		"\n", __func__);

	return ret;
}
static BIN_ATTR(state_certificate, 0400, state_certificate_read, NULL, SDSI_SIZE_READ_MSG);

static ssize_t
meter_certificate_read(struct file *filp, struct kobject *kobj,
		       struct bin_attribute *attr, char *buf, loff_t off,
		       size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct sdsi_priv *priv = dev_get_drvdata(dev);
	int ret;

	dev_dbg(priv->dev, "****** Start %s ******\n", __func__);

	dev_dbg(priv->dev, "loff:	%lld\n"
		"count:	%ld\n",
		off, count);
	ret = certificate_read(SDSI_CMD_READ_METER, priv, buf, off, count);

	dev_dbg(priv->dev, "****** End %s ******\n"
		"\n", __func__);

	return ret;
}
static BIN_ATTR(meter_certificate, 0400, meter_certificate_read, NULL, SDSI_SIZE_READ_MSG);

static ssize_t registers_read(struct file *filp, struct kobject *kobj,
			      struct bin_attribute *attr, char *buf, loff_t off,
			      size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct sdsi_priv *priv = dev_get_drvdata(dev);
	void __iomem *addr = priv->regs_addr;
	int size =  priv->registers_size;

	/*
	 * The check below is performed by the sysfs caller based on the static
	 * file size. But this may be greater than the actual size which is based
	 * on the GUID. So check here again based on actual size before reading.
	 */
	if (off >= size)
		return 0;

	if (off + count > size)
		count = size - off;

	pm_runtime_get_sync(&priv->ivdev->pcidev->dev);
	memcpy_fromio(buf, addr + off, count);
	pm_runtime_mark_last_busy(&priv->ivdev->pcidev->dev);
	pm_runtime_put_autosuspend(&priv->ivdev->pcidev->dev);

	return count;
}
static BIN_ATTR(registers, 0400, registers_read, NULL, SDSI_SIZE_REGS);

static struct bin_attribute *sdsi_bin_attrs[] = {
	&bin_attr_registers,
	&bin_attr_state_certificate,
	&bin_attr_meter_certificate,
	&bin_attr_provision_akc,
	&bin_attr_provision_cap,
	NULL
};

static umode_t
sdsi_battr_is_visible(struct kobject *kobj, struct bin_attribute *attr, int n)
{
	struct device *dev = kobj_to_dev(kobj);
	struct sdsi_priv *priv = dev_get_drvdata(dev);

	/* Registers file is always readable if the device is present */
	if (attr == &bin_attr_registers)
		return attr->attr.mode;

	/* All other attributes not visible if BIOS has not enabled SDSI */
	if (!(priv->features & SDSI_FEATURE_SDSI))
		return 0;

	if (attr == &bin_attr_state_certificate ||
	    attr == &bin_attr_provision_akc ||
	    attr == &bin_attr_provision_cap)
		return attr->attr.mode;

	if (attr == &bin_attr_meter_certificate &&
	    !!(priv->features & SDSI_FEATURE_METERING))
		return attr->attr.mode;

	return 0;
}

static ssize_t guid_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct sdsi_priv *priv = dev_get_drvdata(dev);

	return sysfs_emit(buf, "0x%x\n", priv->guid);
}
static DEVICE_ATTR_RO(guid);

static struct attribute *sdsi_attrs[] = {
	&dev_attr_guid.attr,
	NULL
};

static const struct attribute_group sdsi_group = {
	.attrs = sdsi_attrs,
	.bin_attrs = sdsi_bin_attrs,
	.is_bin_visible = sdsi_battr_is_visible,
};
__ATTRIBUTE_GROUPS(sdsi);

// Attestation
static int sdsi_spdm_exchange(void *private, struct spdm_exchange *spdm_ex)
{
	struct sdsi_priv *priv = private;
	struct sdsi_mbox_info info = {};
	size_t size;
	int ret;

	/*
	 * For the attestation command, the total write size is the sum of:
	 *     Size of the SPDM payload, padded for qword alignment
	 *     8 bytes for the mailbox command
	 *     8 bytes for the actual (non-padded) size of the SPDM payload
	 */

	/*
	 * The driver does not handle request sizes that are larger than the
	 * the mailbox write size. This must also account for the extra 8 byte
	 * ATTESTATION command and 8 byte non-padded packet size.
	 */
	if (spdm_ex->request_pl_sz > (SDSI_SIZE_WRITE_MSG - (SDSI_SIZE_CMD * 2)))
		return -EOVERFLOW;

	/* Qword aligned message + command qword */
	info.size = round_up(spdm_ex->request_pl_sz, SDSI_SIZE_CMD) +
		    SDSI_SIZE_CMD * 2;

	info.payload = kzalloc(info.size, GFP_KERNEL);
	if (!info.payload)
		return -ENOMEM;

	/* Buffer for return data */
	info.buffer = kmalloc(SDSI_SIZE_READ_MSG, GFP_KERNEL);
	if (!info.buffer)
		return -ENOMEM;

	/* Copy SPDM message to payload buffer */
	memcpy(info.payload, spdm_ex->request_pl, spdm_ex->request_pl_sz);

	/* The non-padded SPDM payload size is the 2nd-to-last qword */
	info.payload[((info.size - SDSI_SIZE_CMD) / SDSI_SIZE_CMD) - 1] =
		spdm_ex->request_pl_sz;

	/* Attestation mailbox command is the last qword of payload buffer */
	info.payload[(info.size - SDSI_SIZE_CMD) / SDSI_SIZE_CMD] =
		SDSI_CMD_ATTESTATION;

	/* For actual packet size we need to subtract the SPDM payload size field */
	info.packet_size = info.size;

	ret = mutex_lock_interruptible(&priv->mb_lock);
	if (ret)
		goto free_payload;
	ret = sdsi_mbox_write(priv, &info, &size);
	mutex_unlock(&priv->mb_lock);
	if (ret < 0)
		goto free_payload;

	if (size < spdm_ex->response_pl_sz)
		dev_warn(priv->dev, "Attestion warning: Expected response size %ld, got %ld\n",
			spdm_ex->response_pl_sz, size);

	if (size > spdm_ex->response_pl_sz)
		dev_warn(priv->dev, "Expected response size %ld, got %ld. Ignoring excess\n",
			 spdm_ex->response_pl_sz, size);

	memcpy(spdm_ex->response_pl, info.buffer, spdm_ex->response_pl_sz);

free_payload:
	kfree(info.payload);
	kfree(info.buffer);

	if (ret)
		return ret;

	return size;
}

static int sdsi_init_spdm_state(struct sdsi_priv *priv) {

	struct spdm_state *s;

	if (!(priv->features & SDSI_FEATURE_ATTESTATION)) {
		dev_dbg(priv->dev, "%s: Attestation not supported\n", __func__);
		return 0;
	}

	s = devm_kzalloc(priv->dev, sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	s->dev = priv->dev;
	s->transport_priv = priv;
	s->transport_ex = sdsi_spdm_exchange;

	spdm_init(s);
	priv->spdm_state = s;

	return 0;
}

static int sdsi_get_layout(struct sdsi_priv *priv, struct disc_table *table)
{
	switch (table->guid) {
	case SDSI_GUID_V1:
		priv->control_size = 8;
		priv->registers_size = 72;
		break;
	case SDSI_GUID_V2:
		priv->control_size = 16;
		priv->registers_size = 80;
		break;
	default:
		dev_err(priv->dev, "Unrecognized GUID 0x%x\n", table->guid);
		return -EINVAL;
	}
	return 0;
}

static int
sdsi_map_mbox_registers(struct sdsi_priv *priv, struct pci_dev *parent,
			struct disc_table *disc_table, struct resource *disc_res)
{
	u32 access_type = FIELD_GET(DT_ACCESS_TYPE, disc_table->access_info);
	u32 size = FIELD_GET(DT_SIZE, disc_table->access_info);
	u32 tbir = FIELD_GET(DT_TBIR, disc_table->offset);
	u32 offset = DT_OFFSET(disc_table->offset);
	struct resource res = {};

	/* Starting location of SDSi MMIO region based on access type */
	switch (access_type) {
	case ACCESS_TYPE_LOCAL:
		if (tbir) {
			dev_err(priv->dev, "Unsupported BAR index %u for access type %u\n",
				tbir, access_type);
			return -EINVAL;
		}

		/*
		 * For access_type LOCAL, the base address is as follows:
		 * base address = end of discovery region + base offset + 1
		 */
		res.start = disc_res->end + offset + 1;
		break;

	case ACCESS_TYPE_BARID:
		res.start = pci_resource_start(parent, tbir) + offset;
		break;

	default:
		dev_err(priv->dev, "Unrecognized access_type %u\n", access_type);
		return -EINVAL;
	}

	res.end = res.start + size * sizeof(u32) - 1;
	res.flags = IORESOURCE_MEM;

	dev_info(priv->dev, "\n"
		"DISCOVERY TABLE:\n"
		"Access Type:   %s\n"
		"Size:          %d\n"
		"Tbir:          %d\n"
		"Offset:        0x%x\n"
		"Resource:      %pR\n"
		"\n",
		access_type == ACCESS_TYPE_LOCAL ? "LOCAL" : "BARID",
		size, tbir, offset, &res);

	priv->control_addr = devm_ioremap_resource(priv->dev, &res);
	if (IS_ERR(priv->control_addr))
		return PTR_ERR(priv->control_addr);

	priv->mbox_addr = priv->control_addr + priv->control_size;
	priv->regs_addr = priv->mbox_addr + SDSI_SIZE_MAILBOX;

	priv->features = readq(priv->regs_addr + SDSI_ENABLED_FEATURES_OFFSET);

	return 0;
}

static int
sdsi_probe(struct auxiliary_device *auxdev, const struct auxiliary_device_id *id)
{
	struct intel_vsec_device *intel_cap_dev = auxdev_to_ivdev(auxdev);
	struct disc_table disc_table;
	struct resource *disc_res;
	void __iomem *disc_addr;
	struct sdsi_priv *priv;
	int ret;

	priv = devm_kzalloc(&auxdev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->dev = &auxdev->dev;
	priv->ivdev = intel_cap_dev;
	mutex_init(&priv->mb_lock);
	auxiliary_set_drvdata(auxdev, priv);

	/* Get the SDSi discovery table */
	disc_res = &intel_cap_dev->resource[0];
	disc_addr = devm_ioremap_resource(&auxdev->dev, disc_res);
	if (IS_ERR(disc_addr))
		return PTR_ERR(disc_addr);

	memcpy_fromio(&disc_table, disc_addr, DISC_TABLE_SIZE);

	priv->guid = disc_table.guid;

	/* Get guid based layout info */
	ret = sdsi_get_layout(priv, &disc_table);
	if (ret)
		return ret;

	/* Map the SDSi mailbox registers */
	ret = sdsi_map_mbox_registers(priv, intel_cap_dev->pcidev, &disc_table,
				      disc_res);
	if (ret)
		return ret;

	/* Used by genl attestation API */
	priv->name = kasprintf(GFP_KERNEL, "intel_vsec.%s.%d", auxdev->name,
			       auxdev->id);
	if (!priv->name)
		return -ENOMEM;

	priv->id = auxdev->id;

	/* Initialize spdm_state for attestation service if supported */
	ret = sdsi_init_spdm_state(priv);
	if (ret) {
		kfree(priv->name);
		return ret;
	}

	mutex_lock(&sdsi_list_lock);
	list_add(&priv->node, &sdsi_list);
	mutex_unlock(&sdsi_list_lock);

	return 0;
}

static void
sdsi_remove(struct auxiliary_device *auxdev)
{
	struct sdsi_priv *priv = auxiliary_get_drvdata(auxdev);

	if (priv->spdm_state) {
		spdm_finish(priv->spdm_state);
		kfree(priv->spdm_state);
	}

	kfree(priv->name);
	list_del(&priv->node);
}

int for_each_sdsi_device(int (*cb)(struct sdsi_priv *, void *),
			 void *data)
{
	struct sdsi_priv *priv;
	int ret = 0;

	mutex_lock(&sdsi_list_lock);
	list_for_each_entry(priv, &sdsi_list, node) {
		ret = cb(priv, data);
		if (ret)
			break;
	}
	mutex_unlock(&sdsi_list_lock);

	return ret;
}

struct sdsi_priv *sdsi_dev_get_by_id(int id)
{
	struct sdsi_priv *priv, *match = NULL;

	mutex_lock(&sdsi_list_lock);
	list_for_each_entry(priv, &sdsi_list, node) {
		if (priv->id == id) {
			match = priv;
			break;
		}
	}
	mutex_unlock(&sdsi_list_lock);

	return match;
}

static const struct auxiliary_device_id sdsi_aux_id_table[] = {
	{ .name = "intel_vsec.sdsi" },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, sdsi_aux_id_table);

static struct auxiliary_driver sdsi_aux_driver = {
	.driver = {
		.dev_groups = sdsi_groups,
	},
	.id_table	= sdsi_aux_id_table,
	.probe		= sdsi_probe,
	.remove		= sdsi_remove,
};

static bool netlink_initialized;

static int __init sdsi_init(void)
{
	int ret;


	ret = auxiliary_driver_register(&sdsi_aux_driver);
	if (ret)
		goto error;

	ret = sdsi_netlink_init();
	if (ret)
		pr_warn("Intel SDSi failed to init netlink\n");
	else
		netlink_initialized = true;

error:
	mutex_destroy(&sdsi_list_lock);
	return ret;
}
module_init(sdsi_init);

static void __exit sdsi_exit(void)
{
	if (netlink_initialized)
		sdsi_netlink_exit();

	auxiliary_driver_unregister(&sdsi_aux_driver);

	mutex_destroy(&sdsi_list_lock);
}
module_exit(sdsi_exit);

MODULE_AUTHOR("David E. Box <david.e.box@linux.intel.com>");
MODULE_DESCRIPTION("Intel Software Defined Silicon driver");
MODULE_LICENSE("GPL");
