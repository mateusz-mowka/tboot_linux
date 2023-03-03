// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Platform Monitoring Technology Watcher driver
 *
 * Copyright (c) 2022, Intel Corporation.
 * All Rights Reserved.
 *
 * Authors: "David E. Box" <david.e.box@linux.intel.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/overflow.h>

#include "class.h"

#define SMPLR_DEV_PREFIX	"sample"

#define TYPE_SAMPLER		1

/* Watcher sampler mods */
#define MODE_OFF		0
#define MODE_PERIODIC		1
#define MODE_ONESHOT		2
#define MODE_SHARED		3

/* Watcher access types */
#define ACCESS_FUTURE		1
#define ACCESS_BARID		2
#define ACCESS_LOCAL		3

/* Common Header */
#define GUID_OFFSET		0x4
#define BASE_OFFSET		0x8
#define GET_ACCESS(v)		((v) & GENMASK(3, 0))
#define GET_TYPE(v)		(((v) & GENMASK(11, 4)) >> 4)
#define GET_SIZE(v)		(((v) & GENMASK(27, 12)) >> 10)

/* Common Config fields */
#define GET_MODE(v)		((v) & 0x3)
#define MODE_MASK		GENMASK(1, 0)
#define GET_REQ(v)		((v) & BIT(31))
#define SET_REQ_BIT(v)		((v) | BIT(31))
#define REQUEST_PENDING		1
#define MAX_PERIOD_US		(396 * USEC_PER_SEC)	/* 3600s + 360s = 1.1 hours */

/* Sampler Config Offsets */
#define SMPLR_BUFFER_SIZE_OFFSET	0x4
#define SMPLR_CONTROL_OFFSET		0xC
#define SMPLR_VECTOR_OFFSET		0x10
#define DATA_BUFFER_SIZE(v)		((v) & GENMASK(9, 0))
#define SAMPLE_SETS(v)			(((v) & GENMASK(14, 10)) >> 10)

/*
 * Sampler data size in bytes.
 * s - the size of the sampler data buffer space
 *     given in the config header (pointer field)
 * n - is the number of select vectors
 *
 * Subtract 8 bytes for the size of the timestamp
 */
#define SMPLR_NUM_SAMPLES(s, n)		(((s) - (n) - 8) / 8)

static const char * const sample_mode[] = {
	[MODE_OFF] = "off",
	[MODE_PERIODIC] = "periodic",
	[MODE_ONESHOT] = "oneshot",
	[MODE_SHARED] = "shared"
};

struct watcher_config {
	unsigned int	select_limit;
	unsigned int	vector_size;
	unsigned long	*vector;
	u32		control;
	u32		period;
	u32		stream_uid;
};

struct pmt_watcher_priv;

struct watcher_entry {
	/* entry must be first member of struct */
	struct intel_pmt_entry	entry;
	struct watcher_config	config;
	u8			type;
	struct resource		*header_res;
	void __iomem		*cfg_base;
	bool			mode_lock;
	s8			ctrl_offset;
	s8			vector_start;
};

#define to_pmt_watcher(e) container_of(e, struct watcher_entry, entry)

struct pmt_watcher_priv {
	int			num_entries;
	struct watcher_entry	entry[];
};

static inline bool pmt_watcher_is_sampler(struct watcher_entry *watcher)
{
	return watcher->type == TYPE_SAMPLER;
}

static inline bool pmt_watcher_select_limited(struct watcher_entry *watcher)
{
	return pmt_watcher_is_sampler(watcher);
}

/*
 * I/O
 */
static bool pmt_watcher_request_pending(struct watcher_entry *watcher)
{
	/*
	 * Read request pending bit into temporary location so we can read the
	 * pending bit without overwriting other settings. If a collection is
	 * still in progress we can't start a new one.
	 */
	u32 control = readl(watcher->cfg_base + watcher->ctrl_offset);

	return GET_REQ(control) == REQUEST_PENDING;
}

static bool pmt_watcher_in_use(struct watcher_entry *watcher)
{
	/*
	 * Read request pending bit into temporary location so we can read the
	 * pending bit without overwriting other settings. If a collection is
	 * still in progress we can't start a new one.
	 */
	u32 control = readl(watcher->cfg_base + watcher->ctrl_offset);

	return GET_MODE(control) != MODE_OFF;
}

static void pmt_watcher_write_ctrl_to_dev(struct watcher_entry *watcher)
{
	/*
	 * Set the request pending bit and write the control register to
	 * start the collection.
	 */
	u32 control = SET_REQ_BIT(watcher->config.control);

	writel(control, watcher->cfg_base + watcher->ctrl_offset);
}

static void pmt_watcher_write_period_to_dev(struct watcher_entry *watcher)
{
	/* The period exists on the DWORD opposite the control register */
	writel(watcher->config.period, watcher->cfg_base + (watcher->ctrl_offset ^ 0x4));
}

static void
pmt_watcher_write_vector_to_dev(struct watcher_entry *watcher)
{
	memcpy_toio(watcher->cfg_base + watcher->vector_start,
		    watcher->config.vector,
		    DIV_ROUND_UP(watcher->config.vector_size, BITS_PER_BYTE));
}

static int
pmt_watcher_write_vector(struct device *dev, struct watcher_entry *watcher,
			 unsigned long *bit_vector)
{
	/*
	 * Sampler vector select is limited by the size of the sampler
	 * result buffer. Determine if we're exceeding the limit.
	 */
	if (pmt_watcher_select_limited(watcher)) {
		int hw = bitmap_weight(bit_vector, watcher->config.vector_size);

		if (hw > watcher->config.select_limit) {
			dev_err(dev, "Too many bits(%d) selected. Maximum is %d\n",
				hw, watcher->config.select_limit);
			return -EINVAL;
		}
	}

	/* Save the vector */
	bitmap_copy(watcher->config.vector, bit_vector, watcher->config.vector_size);

	return 0;
}

/*
 * sysfs
 */
static ssize_t
mode_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct watcher_entry *watcher;
	int i, cnt = 0;

	watcher = dev_get_drvdata(dev);

	for (i = 0; i < ARRAY_SIZE(sample_mode); i++) {
		if (i == GET_MODE(watcher->config.control))
			cnt += sprintf(buf + cnt, "[%s]", sample_mode[i]);
		else
			cnt += sprintf(buf + cnt, "%s", sample_mode[i]);
		if (i < (ARRAY_SIZE(sample_mode) - 1))
			cnt += sprintf(buf + cnt, " ");
	}

	cnt += sprintf(buf + cnt, "\n");

	return cnt;
}

static ssize_t
mode_store(struct device *dev, struct device_attribute *attr,
	   const char *buf, size_t count)
{
	struct watcher_entry *watcher;
	int mode;

	watcher = dev_get_drvdata(dev);

	mode = sysfs_match_string(sample_mode, buf);
	if (mode < 0)
		return mode;

	/*
	 * Allowable transitions:
	 * Current State     Requested State
	 * -------------     ---------------
	 * DISABLED          PERIODIC or ONESHOT
	 * PERIODIC          DISABLED
	 * ONESHOT           DISABLED
	 * SHARED            DISABLED
	 */
	if ((GET_MODE(watcher->config.control) != MODE_OFF) &&
	    (mode != MODE_OFF))
		return -EPERM;

	/* Do not allow user to put device in shared state */
	if (mode == MODE_SHARED)
		return -EPERM;

	/* We cannot change state if there is a request already pending */
	if (pmt_watcher_request_pending(watcher))
		return -EBUSY;

	/*
	 * Transition request is valid. Set mode, mode_lock
	 * and execute request.
	 */
	watcher->config.control &= ~MODE_MASK;
	watcher->config.control |= mode;

	watcher->mode_lock = false;

	if (mode != MODE_OFF) {
		watcher->mode_lock = true;

		/* Write the period and vector registers to the device */
		pmt_watcher_write_period_to_dev(watcher);
		pmt_watcher_write_vector_to_dev(watcher);
	}

	/* Submit requested changes to device */
	pmt_watcher_write_ctrl_to_dev(watcher);

	return strnlen(buf, count);
}
static DEVICE_ATTR_RW(mode);

static ssize_t
period_us_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct watcher_entry *watcher;

	watcher = dev_get_drvdata(dev);

	return sprintf(buf, "%u\n", watcher->config.period);
}

static ssize_t
period_us_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct watcher_entry *watcher;
	u32 period;
	int err;

	watcher = dev_get_drvdata(dev);

	if (watcher->mode_lock)
		return -EPERM;

	err = kstrtouint(buf, 0, &period);
	if (err)
		return err;

	if (period > MAX_PERIOD_US) {
		dev_err(dev, "Maximum period(us) allowed is %ld\n",
			MAX_PERIOD_US);
		return -EINVAL;
	}

	watcher->config.period = period;

	return strnlen(buf, count);
}
static DEVICE_ATTR_RW(period_us);

static ssize_t
enable_list_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct watcher_entry *watcher;
	int err;

	watcher = dev_get_drvdata(dev);

	err = bitmap_print_to_pagebuf(true, buf, watcher->config.vector,
				      watcher->config.vector_size);

	return err ?: strlen(buf);
}

static ssize_t
enable_list_store(struct device *dev, struct device_attribute *attr,
		    const char *buf, size_t count)
{
	struct watcher_entry *watcher;
	unsigned long *temp;
	int err;

	watcher = dev_get_drvdata(dev);

	if (watcher->mode_lock)
		return -EPERM;

	/*
	 * Create a temp buffer to store the incoming selection for
	 * validation before saving.
	 */
	temp = bitmap_zalloc(watcher->config.vector_size, GFP_KERNEL);
	if (!temp)
		return -ENOMEM;

	/*
	 * Convert and store hexadecimal input string values into the
	 * temp buffer.
	 */
	err = bitmap_parselist(buf, temp, watcher->config.vector_size);

	/* Write new vector to watcher entry */
	if (!err)
		err = pmt_watcher_write_vector(dev, watcher, temp);

	kfree(temp);

	return err ?: count;
}
static DEVICE_ATTR_RW(enable_list);

static ssize_t
enable_vector_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct watcher_entry *watcher;
	int err;

	watcher = dev_get_drvdata(dev);

	err = bitmap_print_to_pagebuf(false, buf, watcher->config.vector,
				      watcher->config.vector_size);

	return err ?: strlen(buf);
}

static ssize_t
enable_vector_store(struct device *dev, struct device_attribute *attr,
		    const char *buf, size_t count)
{
	struct watcher_entry *watcher;
	unsigned long *temp;
	int err;

	watcher = dev_get_drvdata(dev);

	if (watcher->mode_lock)
		return -EPERM;

	/*
	 * Create a temp buffer to store the incoming selection for
	 * validation before saving.
	 */
	temp = bitmap_zalloc(watcher->config.vector_size, GFP_KERNEL);
	if (!temp)
		return -ENOMEM;

	/*
	 * Convert and store hexadecimal input string values into the
	 * temp buffer.
	 */
	err = bitmap_parse(buf, count, temp, watcher->config.vector_size);

	/* Write new vector to watcher entry */
	if (!err)
		err = pmt_watcher_write_vector(dev, watcher, temp);

	kfree(temp);

	return err ?: count;
}
static DEVICE_ATTR_RW(enable_vector);

static ssize_t
enable_id_limit_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	struct watcher_entry *watcher;

	watcher = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", watcher->config.vector_size - 1);
}
static DEVICE_ATTR_RO(enable_id_limit);

static ssize_t
select_limit_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct watcher_entry *watcher;

	watcher = dev_get_drvdata(dev);

	/* vector limit only applies to sampler */
	if (!pmt_watcher_select_limited(watcher))
		return sprintf(buf, "%d\n", -1);

	return sprintf(buf, "%u\n", watcher->config.select_limit);
}
static DEVICE_ATTR_RO(select_limit);

static struct attribute *pmt_watcher_attrs[] = {
	&dev_attr_period_us.attr,
	&dev_attr_mode.attr,
	&dev_attr_enable_list.attr,
	&dev_attr_enable_vector.attr,
	&dev_attr_enable_id_limit.attr,
	&dev_attr_select_limit.attr,
	NULL
};

static struct attribute_group pmt_watcher_group = {
	.attrs	= pmt_watcher_attrs,
};

/*
 * initialization
 */
static void
pmt_sample_repopulate_header(struct intel_pmt_entry *entry,
			    struct device *dev)
{
	struct watcher_entry *watcher = to_pmt_watcher(entry);
	size_t vector_sz_in_bytes = entry->size - watcher->vector_start;
	struct intel_pmt_header *header = &entry->header;
	unsigned int sample_limit;
	u32 pointer2;
	u8 sample_sets;
	u8 bir;

	/*
	 * The base offset should always be 8 byte aligned.
	 *
	 * For non-local access types the lower 3 bits of base offset
	 * contains the index of the base address register where the
	 * telemetry can be found.
	 */
	bir = GET_BIR(header->base_offset);

	/*
	 * For sampler only, get the physical address and size of
	 * the result buffer for the mmap as well as the vector
	 * select limit for bounds checking.
	 *
	 * We are assuming "local" BAR to be BAR 0.
	 */
	header->base_offset = readl(watcher->cfg_base) + bir;
	pr_debug("%s: Data Buffer Offset is 0x%x\n", __func__, header->base_offset);

	/* Size is reported in DWORDs so multiply by 4 to get bytes */
	pointer2 = readl(watcher->cfg_base + SMPLR_BUFFER_SIZE_OFFSET);

	header->size = DATA_BUFFER_SIZE(pointer2) * 4;
	sample_sets = SAMPLE_SETS(pointer2);

	pr_debug("%s: Data Buffer Size (DWORDS) is 0x%x\n", __func__, header->size / 4);
	pr_debug("%s: Number Sample Sets is %d\n", __func__, sample_sets);

	/*
	 * SMPLR_NUM_SAMPLES returns bytes divided by 8 to get number
	 * of QWORDS which is the unit of sampling. Select_limit is
	 * the maximum allowable hweight for the select vector
	 */
	sample_limit = SMPLR_NUM_SAMPLES(header->size / sample_sets, vector_sz_in_bytes);
	pr_debug("%s: Sample Limit is %d\n", __func__, sample_limit);

	if (sample_limit < watcher->config.select_limit)
		watcher->config.select_limit = sample_limit;
}

static int
pmt_watcher_create_entry(struct intel_pmt_entry *entry,
			 struct device *dev, struct resource *disc_res)
{
	struct watcher_entry *watcher = to_pmt_watcher(entry);
	struct intel_vsec_device *ivdev = dev_to_ivdev(dev);
	struct intel_pmt_header *header = &entry->header;
	size_t vector_sz_in_bytes;
	struct resource res = {0};
	int ret;

	ret = intel_pmt_populate_entry(entry, ivdev, disc_res);
	if (ret)
		return ret;

	watcher->type = GET_TYPE(readb(entry->disc_table));
	if (!pmt_watcher_is_sampler(watcher))
		return 1;

	/* XXX: W/O for incorrect size of 2nd sampler */
	if (header->guid == 0x1a067000) {
		entry->size = 48;
		pr_debug("%s: Changed header size to %lu\n", __func__, entry->size);
	}

	watcher->ctrl_offset = SMPLR_CONTROL_OFFSET;
	watcher->vector_start = SMPLR_VECTOR_OFFSET;

	/*
	 * Verify we have sufficient space to store the sample IDs or
	 * bit vector needed to select sample IDs.
	 */
	vector_sz_in_bytes = entry->size - watcher->vector_start;
	pr_debug("%s: Vector/Select size in bytes is %ld\n", __func__, vector_sz_in_bytes);
	if (vector_sz_in_bytes < 2 || vector_sz_in_bytes > entry->size)
		return -EINVAL;

	/*
	 * Determine the appropriate size of the vector in bits so that
	 * the bitmap can be allocated.
	 */
	watcher->config.vector_size = vector_sz_in_bytes * BITS_PER_BYTE;
	watcher->config.select_limit = vector_sz_in_bytes / 2;

	res.start = entry->base_addr;
	res.end = res.start + entry->size - 1;
	res.flags = IORESOURCE_MEM;
	pr_debug("%s: Mapping resource %pr\n", __func__, &res);

	watcher->cfg_base = devm_ioremap_resource(dev, &res);
	if (IS_ERR(watcher->cfg_base)) {
		dev_err(dev, "Failed to ioremap watcher control region\n");
		return -EIO;
	}

	/*
	 * Reset the base_addr and size fields as what was previously stored
	 * there has now been mapped as the base for configuration. Instead
	 * we will leave this as 0 for now and repopulate in the case of a
	 * sampler.
	 */

	header->access_type = ACCESS_BARID;
	header->size = 0;

	if (pmt_watcher_is_sampler(watcher))
		pmt_sample_repopulate_header(entry, dev);

	/*
	 * If there is already some request that is stuck in the hardware
	 * then we will need to wait for it to be cleared before we can
	 * bring up the device.
	 */
	if (pmt_watcher_request_pending(watcher))
		return -EBUSY;

	watcher->config.vector = bitmap_zalloc(watcher->config.vector_size, GFP_KERNEL);
	if (!watcher->config.vector)
		return -ENOMEM;

	/*
	 * Set mode to "Disabled" to clean up any state that may still be
	 * floating around in the registers. If it looks like an out-of-band
	 * entity might be using the part set the mode to shared to indicate
	 * that we have not taken full control of the device yet.
	 */
	if (!pmt_watcher_in_use(watcher))
		pmt_watcher_write_ctrl_to_dev(watcher);
	else
		watcher->config.control = MODE_SHARED;

	return 0;
}

static int pmt_watcher_header_decode(struct intel_pmt_entry *entry,
				     struct device *dev,
				     struct resource *disc_res)
{
	void __iomem *disc_table = entry->disc_table;
	struct intel_pmt_header *header = &entry->header;

	header->access_type = GET_ACCESS(readb(disc_table));
	header->guid = readl(disc_table + GUID_OFFSET);
	header->base_offset = readl(disc_table + BASE_OFFSET);

	/* Size is measured in DWORDS, but accessor returns bytes */
	header->size = GET_SIZE(readl(disc_table));

	pr_debug("%s:\tAccess type is %d\n"
		    "\tGUID is        0x%x\n"
		    "\tBase offset is 0x%x\n"
		    "\tSize is        %d\n", __func__, header->access_type,
		    header->guid, header->base_offset, header->size);
	return pmt_watcher_create_entry(entry, dev, disc_res);
}

static DEFINE_XARRAY_ALLOC(watcher_array);
static struct intel_pmt_namespace pmt_watcher_ns = {
	.name = "watcher",
	.xa = &watcher_array,
	.attr_grp = &pmt_watcher_group,
	.pmt_header_decode = pmt_watcher_header_decode,
};

static void pmt_watcher_remove(struct auxiliary_device *auxdev)
{
	struct pmt_watcher_priv *priv = auxiliary_get_drvdata(auxdev);
	int i;

	for (i = 0; i < priv->num_entries; i++)
		intel_pmt_dev_destroy(&priv->entry[i].entry, &pmt_watcher_ns);
}

static int pmt_watcher_probe(struct auxiliary_device *auxdev, const struct auxiliary_device_id *id)
{
	struct intel_vsec_device *intel_vsec_dev = auxdev_to_ivdev(auxdev);
	struct pmt_watcher_priv *priv;
	size_t size;
	int i, ret;

	size = struct_size(priv, entry, intel_vsec_dev->num_resources);
	priv = devm_kzalloc(&auxdev->dev, size, GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	auxiliary_set_drvdata(auxdev, priv);

	pr_debug("%s: Number of res %d\n", __func__, intel_vsec_dev->num_resources);
	for (i = 0; i < intel_vsec_dev->num_resources; i++) {
		struct intel_pmt_entry *entry = &priv->entry[priv->num_entries].entry;

		pr_debug("%s: Creating dev for res %d\n", __func__, i);
		ret = intel_pmt_dev_create(entry, &pmt_watcher_ns, intel_vsec_dev, i);
		if (ret < 0) {
			pr_debug("%s: Failed to create dev, ret %d\n", __func__, ret);
			goto abort_probe;
		} if (ret) {
			pr_debug("%s: Skipping res %d\n", __func__, i);
			continue;
		}

		priv->num_entries++;
	}

	return 0;
abort_probe:
	pmt_watcher_remove(auxdev);
	return ret;
}

static const struct auxiliary_device_id pmt_watcher_id_table[] = {
	{ .name = "intel_vsec.watcher" },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, pmt_watcher_id_table);

static struct auxiliary_driver pmt_watcher_aux_driver = {
	.id_table	= pmt_watcher_id_table,
	.remove		= pmt_watcher_remove,
	.probe		= pmt_watcher_probe,
};

static int __init pmt_watcher_init(void)
{
	return auxiliary_driver_register(&pmt_watcher_aux_driver);
}
module_init(pmt_watcher_init);

static void __exit pmt_watcher_exit(void)
{
	auxiliary_driver_unregister(&pmt_watcher_aux_driver);
	xa_destroy(&watcher_array);
}
module_exit(pmt_watcher_exit);

MODULE_AUTHOR("David E. Box <david.e.box@linux.intel.com>");
MODULE_DESCRIPTION("Intel PMT Watcher driver");
MODULE_LICENSE("GPL");
