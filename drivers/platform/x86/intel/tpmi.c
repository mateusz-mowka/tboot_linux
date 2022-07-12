// SPDX-License-Identifier: GPL-2.0-only
/*
 * intel-tpmi : Driver to enumerate TPMI features and create devices
 *
 * Copyright (c) 2022, Intel Corporation.
 * All Rights Reserved.
 *
 */
#define DEBUG

#include <linux/auxiliary_bus.h>
#include <linux/bitfield.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/intel_tpmi.h>
#include <linux/intel_vsec.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>

/**
 * struct intel_tpmi_pfs - TPMI PM Feature Structure (PFS)
 * @tpmi_id:	This field indicates the nature and format of the TPMI feature
 *		structure.
 * @num_entries: Number of entries. Describes the number of feature interface
 *		 instances that exist in the PFS. This represents the maximum
 *		 number of Power domains.
 * @entry_size:	Describe the entry size for each interface instance in
 *		32-bit words.
 * @cap_offset:	Specify the upper 16 bits of the 26 bits Cap Offset
 *		(i.e. Cap Offset is in KB unit) from the PM_Features base
 *		address to point to the base of the PM VSEC register bank.
 * @attribute:	Specify the attribute of this feature. 0x0=BIOS. 0x1=OS. 0x2-
 *		0x3=Reserved.
 * @resd:	Bits for future additions by hardware.
 *
 * Stores data for one PFS entry.
 */
struct intel_tpmi_pfs {
	u64 tpmi_id :8;
	u64 num_entries :8;
	u64 entry_size :16;
	u64 cap_offset :16;
	u64 attribute :2;
	u64 resd :14;
};

/**
 * struct intel_tpmi_pm_feature - TPMI PM Feature information for a TPMI ID
 * @pfs_header:	Stores pfs header struct bits as exported by hardware
 * @vsec_dev:	Pointer to intel_vsec_device structure for this TPMI device
 * @vsec_offset: Start of memory address in MMIO from VSEC offset in the
 *		 PCI header
 *
 * Stores TPMI instance information for a single TPMI ID. This will be used
 * to get MMIO offset and full information from PFS header.
 */
struct intel_tpmi_pm_feature {
	struct intel_tpmi_pfs pfs_header;
	struct intel_vsec_device *vsec_dev;
	unsigned int vsec_offset;
};

/**
 * struct intel_tpmi_info - Stores TPMI info for all IDs for an instance
 * @tpmi_features:	Pointer to a list of TPMI feature instances
 * @vsec_dev:		Pointer to intel_vsec_device structure for this TPMI device
 * @feature_count:	Number of TPMI of TPMI instances pointed by tpmi_features
 * @pfs_start:		Start of PFS offset for the TPMI instances in this device
 * @plat_info:		Stores platform info which can be used by the client drivers
 * @tpmi_control_mem:	Memory mapped IO for getting control information
 * @dbgfs_dir:		debugfs entry pointer
 *
 * Stores the information for all TPMI devices enumerated from a single PCI device.
 */
struct intel_tpmi_info {
	struct intel_tpmi_pm_feature *tpmi_features;
	struct intel_vsec_device *vsec_dev;
	int feature_count;
	u64 pfs_start;
	struct intel_tpmi_plat_info plat_info;
	void __iomem *tpmi_control_mem;
	struct dentry *dbgfs_dir;
};

/**
 * struct tpmi_info_header - TPMI_INFO ID header
 * @fn:		PCI function number
 * @dev:	PCI device number
 * @bus:	PCI bus number
 * @pkg:	CPU Package id
 * @resd:	Reserved for future use
 * @lock:	locked
 *
 * This structure is used parse TPMI_INFO contents. This is packed to the
 * same format as defined in the specifications.
 */
struct tpmi_info_header {
	u64 fn :3;
	u64 dev :5;
	u64 bus :8;
	u64 pkg :8;
	u64 resd :39;
	u64 lock :1;
};

/*
 * Supported list of TPMI IDs.
 * Since there is no use case for some TPMI features in Linux
 * there are holes in IDs
 */
enum intel_tpmi_id {
	TPMI_ID_RAPL = 0, /* Running Average Power Limit */
	TPMI_ID_PEM = 1, /* Power and Perf excursion Monitor */
	TPMI_ID_UNCORE = 2, /* Uncore Frequency Scaling */
	TPMI_ID_SST = 5, /* Speed Select Technology */
};

#define tpmi_to_dev(info)	(&info->vsec_dev->pcidev->dev)

/* Used during auxbus device creation */
static DEFINE_IDA(intel_vsec_tpmi_ida);

#define TPMI_MAX_INSTANCE	16
static struct intel_tpmi_info *tpmi_instances[TPMI_MAX_INSTANCE];
static int tpmi_instance_count;

static struct intel_tpmi_pm_feature *tpmi_pfs_info(int package_id, int tpmi_id)
{
	int i;

	for (i = 0; i < tpmi_instance_count; ++i) {
		struct intel_tpmi_info *tpmi_info = tpmi_instances[i];
		int j;

		if (!tpmi_info)
			continue;

		if (tpmi_info->plat_info.package_id != package_id)
			continue;

		for (j = 0; j < tpmi_info->feature_count; ++j) {
			struct intel_tpmi_pm_feature *pfs;

			pfs = &tpmi_info->tpmi_features[j];
			if (pfs->pfs_header.tpmi_id == tpmi_id) {
				return pfs;
			}
		}
	}

	return NULL;
}

int tpmi_get_info(int package_id, int tpmi_id, int *num_entries, int *entry_size)
{
	struct intel_tpmi_pm_feature *pfs;

	pfs = tpmi_pfs_info(package_id, tpmi_id);
	if (!pfs)
		return -EINVAL;

	*num_entries = pfs->pfs_header.num_entries;
	*entry_size = 4 * pfs->pfs_header.entry_size;

	return 0;
}
EXPORT_SYMBOL_NS_GPL(tpmi_get_info, INTEL_TPMI);

void __iomem *tpmi_get_mem(int package_id, int tpmi_id, int *size)
{
	struct intel_tpmi_pm_feature *pfs;
	int _size;

	pfs = tpmi_pfs_info(package_id, tpmi_id);
	if (!pfs)
		return NULL;

	_size = pfs->pfs_header.num_entries * pfs->pfs_header.entry_size * 4;
	*size = _size;

	return ioremap(pfs->vsec_offset, _size);
}
EXPORT_SYMBOL_NS_GPL(tpmi_get_mem, INTEL_TPMI);

void tpmi_free_mem(void __iomem *mem)
{
	iounmap(mem);
}
EXPORT_SYMBOL_NS_GPL(tpmi_free_mem, INTEL_TPMI);

int intel_tpmi_readq(struct auxiliary_device *auxdev, const void __iomem *addr, u64 *val)
{
	int ret;

	ret = pm_runtime_resume_and_get(&auxdev->dev);
	if (ret < 0)
		return ret;

	*val = readq(addr);
	pm_runtime_mark_last_busy(&auxdev->dev);
	pm_runtime_put_autosuspend(&auxdev->dev);

	return 0;
}
EXPORT_SYMBOL_NS_GPL(intel_tpmi_readq, INTEL_TPMI);

int intel_tpmi_writeq(struct auxiliary_device *auxdev, u64 value, void __iomem *addr)
{
	int ret;

	ret = pm_runtime_resume_and_get(&auxdev->dev);
	if (ret < 0)
		return ret;

	writeq(value, addr);
	pm_runtime_mark_last_busy(&auxdev->dev);
	pm_runtime_put_autosuspend(&auxdev->dev);

	return 0;
}
EXPORT_SYMBOL_NS_GPL(intel_tpmi_writeq, INTEL_TPMI);

struct intel_tpmi_plat_info *tpmi_get_platform_data(struct auxiliary_device *auxdev)
{
	struct intel_vsec_device *vsec_dev = auxdev_to_ivdev(auxdev);

	return vsec_dev->priv_data;
}
EXPORT_SYMBOL_NS_GPL(tpmi_get_platform_data, INTEL_TPMI);

int tpmi_get_resource_count(struct auxiliary_device *auxdev)
{
	struct intel_vsec_device *vsec_dev = auxdev_to_ivdev(auxdev);

	if (vsec_dev)
		return vsec_dev->num_resources;

	return 0;
}
EXPORT_SYMBOL_NS_GPL(tpmi_get_resource_count, INTEL_TPMI);

struct resource *tpmi_get_resource_at_index(struct auxiliary_device *auxdev, int index)
{
	struct intel_vsec_device *vsec_dev = auxdev_to_ivdev(auxdev);

	if (vsec_dev && index < vsec_dev->num_resources)
		return &vsec_dev->resource[index];

	return NULL;
}
EXPORT_SYMBOL_NS_GPL(tpmi_get_resource_at_index, INTEL_TPMI);

/* TPMI Control Interface */

#define TPMI_CONTROL_ID			0x80
#define TPMI_CONTROL_STATUS_OFFSET	0x00
#define TPMI_COMMAND_OFFSET		0x08
#define TPMI_DATA_OFFSET		0x0C
/*
 * Spec is calling for max 1 seconds to get ownership at the worst,
 * case, So combined with the loop count it will be 1 second max
 */
#define TPMI_CONTROL_TIMEOUT_MS		10
#define TPMI_MAX_OWNER_LOOP_COUNT	100

#define TPMI_RB_TIMEOUT_RESCHD_MS	10
#define TPMI_RB_TIMEOUT_MS		1000
#define TPMI_OWNER_NONE			0
#define TPMI_OWNER_IN_BAND		1

#define TPMI_GENMASK_OWNER	GENMASK_ULL(5, 4)
#define TPMI_GENMASK_STATUS	GENMASK_ULL(15, 8)


#define TPMI_GET_STATE_CMD		0x10
#define TPMI_GET_STATE_CMD_DATA_OFFSET	8
#define TPMI_CMD_DATA_OFFSET		32
#define TPMI_CMD_PKT_LEN_OFFSET		16
#define TPMI_CMD_PKT_LEN		2
#define TPMI_CONTROL_RB_BIT		0
#define TPMI_CONTROL_CPL_BIT		6
#define TPMI_CMD_STATUS_SUCCESS		0x40
#define TPMI_GET_STATUS_BIT_ENABLE	0
#define TPMI_GET_STATUS_BIT_LOCKED	31

/* Mutex to complete get feature status without interruption */
static DEFINE_MUTEX(tpmi_dev_lock);

static int tpmi_wait_for_owner(struct intel_tpmi_info *tpmi_info, u8 owner)
{
	int index, ret = -1;
	u64 control;

	index = 0;
	/* Wait until owner match */
	do {
		control = readq(tpmi_info->tpmi_control_mem + TPMI_CONTROL_STATUS_OFFSET);
		control = FIELD_GET(TPMI_GENMASK_OWNER, control);
		if (control != owner) {
			ret = -EBUSY;
			pr_info("Waiting for mailbox ownership\n");
			msleep(TPMI_CONTROL_TIMEOUT_MS);
			continue;
		}
		ret = 0;
		break;
	} while (index++ < TPMI_MAX_OWNER_LOOP_COUNT);

	return ret;
}

static int _tpmi_get_feature_status(struct intel_tpmi_info *tpmi_info,
				    int feature_id, int *locked, int *disabled)
{
	u64 control, data;
	s64 tm_delta = 0;
	ktime_t tm;
	int ret;

	pr_info("Feature status READ start\n");

	if (!tpmi_info->tpmi_control_mem)
		return -EFAULT;

	mutex_lock(&tpmi_dev_lock);

	ret = tpmi_wait_for_owner(tpmi_info, TPMI_OWNER_NONE);
	if (ret)
		goto err_proc;

	pr_info("Feature status \n");

	/* set command id to 0x10 for TPMI_GET_STATE */
	data = TPMI_GET_STATE_CMD;
	/* 32 bits for DATA offset and +8 for feature_id field */
	data |= ((u64)feature_id << (TPMI_CMD_DATA_OFFSET + TPMI_GET_STATE_CMD_DATA_OFFSET));

	/* Write at command offset for qword access */
	writeq(data, tpmi_info->tpmi_control_mem + TPMI_COMMAND_OFFSET);

	ret = tpmi_wait_for_owner(tpmi_info, TPMI_OWNER_IN_BAND);
	if (ret)
		goto err_proc;

	pr_info("Feature status owner is now inband\n");

	/* Set Run Busy and packet length of 2 dwords */
	writeq(BIT_ULL(TPMI_CONTROL_RB_BIT) | (TPMI_CMD_PKT_LEN << TPMI_CMD_PKT_LEN_OFFSET),
	       tpmi_info->tpmi_control_mem + TPMI_CONTROL_STATUS_OFFSET);

	pr_info("Feature status owner Wait for RB = 0\n");
	/* Poll for rb bit == 0 */
	tm = ktime_get();
	do {
		control = readq(tpmi_info->tpmi_control_mem + TPMI_CONTROL_STATUS_OFFSET);
		if (control & BIT_ULL(TPMI_CONTROL_RB_BIT)) {
			ret = -EBUSY;
			tm_delta = ktime_ms_delta(ktime_get(), tm);
			if (tm_delta > TPMI_RB_TIMEOUT_RESCHD_MS)
				cond_resched();
			continue;
		}
		ret = 0;
		break;
	} while (tm_delta < TPMI_RB_TIMEOUT_MS);

	if (ret)
		goto done_proc;

	pr_info("Feature status owner RB == 0\n");

	control = FIELD_GET(TPMI_GENMASK_STATUS, control);
	if (control != TPMI_CMD_STATUS_SUCCESS) {
		ret = -EBUSY;
		pr_info("Mailbox command failed\n");
		goto done_proc;
	}

	data = readq(tpmi_info->tpmi_control_mem + TPMI_COMMAND_OFFSET);
	data >>= TPMI_CMD_DATA_OFFSET; /* Upper 32 bits are for TPMI_DATA */

	*disabled = 0;
	*locked = 0;

	if (!(data & BIT_ULL(TPMI_GET_STATUS_BIT_ENABLE)))
		*disabled = 1;

	if (data & BIT_ULL(TPMI_GET_STATUS_BIT_LOCKED))
		*locked = 1;

	ret = 0;

done_proc:
	/* SET CPL "completion"bit */
	writeq(BIT_ULL(TPMI_CONTROL_CPL_BIT),  tpmi_info->tpmi_control_mem + TPMI_CONTROL_STATUS_OFFSET);

err_proc:
	mutex_unlock(&tpmi_dev_lock);
	pr_info("Feature status READ End\n");

	return ret;
}

int tpmi_get_feature_status(struct auxiliary_device *auxdev,
			    int feature_id, int *locked, int *disabled)
{
	struct intel_vsec_device *intel_vsec_dev = dev_to_ivdev(auxdev->dev.parent);
	struct intel_tpmi_info *tpmi_info = auxiliary_get_drvdata(&intel_vsec_dev->auxdev);

	return _tpmi_get_feature_status(tpmi_info, feature_id, locked, disabled);
}
EXPORT_SYMBOL_NS_GPL(tpmi_get_feature_status, INTEL_TPMI);

static int tpmi_help_show(struct seq_file *s, void *unused)
{
	seq_puts(s, "TPMI debugfs help\n");
	seq_puts(s, "There will be multiple instances of debugfs folders, one for each package\n");
	seq_puts(s, "E.g. intel_extnd_cap_66.1.auto and intel_extnd_cap_66.2.auto\n");
	seq_puts(s, "\t 1 and 2 are instance number, which can change always\n");
	seq_puts(s, "Attrubutes:\n");
	seq_puts(s, "pfs_dump: Shows all PFS entries. Refer to TPMI spec for details\n");
	seq_puts(s, "Each of the TPMI ID will have its folder for read/write register access\n");
	seq_puts(s, "The name of the folder suffixed with tpmi ID\n");
	seq_puts(s, "Each folder contains two entries\n");
	seq_puts(s, "mem_dump and mem_write\n");
	seq_puts(s, "mem_dump: Show register contents of full PFS for all TPMI instances\n");
	seq_puts(s, "The total size will be pfs->entry_size * pfs->number of entries * 4\n");
	seq_puts(s, "mem_write: Allows to write at any offset. It doesn't check for Read/Write access\n");
	seq_puts(s, "Read/write is at offset multiples of 4\n");
	seq_puts(s, "The format is instance:offset:contents\n");
	seq_puts(s, "The actual value follows the 0x* for hex, 0x for octal or plain decimal without any prefix\n");
	seq_puts(s, "Example: echo 0:0x20:0xff > mem_write\n");
	seq_puts(s, "Example: echo 1:64:64 > mem_write\n");
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(tpmi_help);

static int tpmi_pfs_dbg_show(struct seq_file *s, void *unused)
{
	struct intel_tpmi_info *tpmi_info = s->private;
        struct intel_vsec_device *vsec_dev;
	int i, ret;

	vsec_dev = tpmi_info->vsec_dev;

        pm_runtime_get_sync(&vsec_dev->auxdev.dev);

	seq_printf(s, "tpmi PFS start offset 0x:%llx\n", tpmi_info->pfs_start);
	seq_puts(s, "tpmi_id\t\tnum_entries\tentry_size\t\tcap_offset\tattribute\tfull_base_pointer_for_memmap\tlocked\tdisabled\n");
	for (i = 0; i < tpmi_info->feature_count; ++i) {
		struct intel_tpmi_pm_feature *pfs;
		int locked, disabled;

		pfs = &tpmi_info->tpmi_features[i];
		ret = _tpmi_get_feature_status(tpmi_info, pfs->pfs_header.tpmi_id, &locked, &disabled);
		if (ret) {
			locked = 'U';
			disabled = 'U';
		} else {
			disabled = disabled ? 'Y' : 'N';
			locked = locked ? 'Y' : 'N';
		}
		seq_printf(s, "0x%02x\t\t0x%02x\t\t0x%06x\t\t0x%04x\t\t0x%02x\t\t0x%x\t\t\t%c\t%c\n",
			   pfs->pfs_header.tpmi_id, pfs->pfs_header.num_entries, pfs->pfs_header.entry_size,
			   pfs->pfs_header.cap_offset, pfs->pfs_header.attribute, pfs->vsec_offset, locked, disabled);
	}

	pm_runtime_mark_last_busy(&vsec_dev->auxdev.dev);
	pm_runtime_put_autosuspend(&vsec_dev->auxdev.dev);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(tpmi_pfs_dbg);

static int tpmi_mem_dump_show(struct seq_file *s, void *unused)
{
	struct intel_tpmi_pm_feature *pfs = s->private;
	struct intel_vsec_device *vsec_dev = pfs->vsec_dev;
	size_t row_size = 8 * sizeof(u32);
	int i, count, ret = 0;
	void __iomem *mem;
	u16 size;
	u32 off;

	off = pfs->vsec_offset;

	pm_runtime_get_sync(&vsec_dev->auxdev.dev);

	for (count = 0; count < pfs->pfs_header.num_entries; ++count) {
		size = pfs->pfs_header.entry_size * 4;

		seq_printf(s, "TPMI Instance:%d offset:0x%x\n", count, off);
		mem = ioremap(off, size);
		if (!mem) {
			ret = -ENOMEM;
			goto done_mem_show;
		}
		for (i = 0; i < size; i += row_size) {
			char line[128];
			u32 buffer[16];
			int j, k = 0;

			for (j = 0; j < row_size; j += sizeof(u32)) {
				int index = i + j;
				u8 __iomem *_mem;

				if (index >= size)
					break;

				_mem = (u8 __iomem *)mem + index;
				buffer[k++] = readl(_mem);
			}

			hex_dump_to_buffer(buffer, j, row_size, sizeof(u32), line, sizeof(line),
					   false);
			seq_printf(s, "[%04x] %s\n", i, line);
		}

		iounmap(mem);

		off += size;
	}
done_mem_show:
	pm_runtime_mark_last_busy(&vsec_dev->auxdev.dev);
	pm_runtime_put_autosuspend(&vsec_dev->auxdev.dev);

	return ret;
}
DEFINE_SHOW_ATTRIBUTE(tpmi_mem_dump);

static ssize_t mem_write_write(struct file *file, const char __user *userbuf,
			       size_t len, loff_t *ppos)
{
	struct seq_file *m = file->private_data;
	struct intel_tpmi_pm_feature *pfs = m->private;
	struct intel_vsec_device *vsec_dev = pfs->vsec_dev;
	char buf[32], *tmp, *tmp1, *tmp_val;
	u32 addr, value, punit;
	void __iomem *mem;
	u16 size;

	if (len >= sizeof(buf))
		return -EINVAL;

	if (copy_from_user(buf, userbuf, len))
		return -EFAULT;

	/* Get punit number */
	tmp = strchr(buf, ':');
	if (!tmp)
		return -EINVAL;

	*tmp = '\0';

	if (kstrtouint(buf, 0, &punit))
		return -EINVAL;

	if (punit >= pfs->pfs_header.num_entries)
		return -EINVAL;

	++tmp;

	/* Get offset */
	tmp1 = strchr(tmp, ':');
	if (!tmp1)
		return -EINVAL;

	*tmp1 = '\0';

	if (kstrtouint(tmp, 0, &addr))
		return -EINVAL;

	/* Get Value to write */
	tmp_val = tmp1 + 1;
	tmp = strchr(tmp_val, '\n');
	if (!tmp)
		return -EINVAL;

	*tmp = '\0';

	if (kstrtouint(tmp_val, 0, &value))
		return -EINVAL;

	size = pfs->pfs_header.entry_size * 4;
	pr_debug("instance%d size:%d offset:0x%x addr:0x%x value:0x%x\n", punit, size,
		 addr, pfs->vsec_offset + (punit * size) + addr, value);
	if (addr >= size)
		return -EINVAL;

	mem = ioremap(pfs->vsec_offset + (punit * size), size);
	if (!mem)
		return -ENOMEM;

	pm_runtime_get_sync(&vsec_dev->auxdev.dev);

	writel(value, (u8 __iomem *)mem + addr);

	iounmap(mem);

	pm_runtime_mark_last_busy(&vsec_dev->auxdev.dev);
	pm_runtime_put_autosuspend(&vsec_dev->auxdev.dev);

	return len;
}

static int mem_write_show(struct seq_file *s, void *unused)
{
	return 0;
}

static int mem_write_open(struct inode *inode, struct file *file)
{
	return single_open(file, mem_write_show, inode->i_private);
}

static const struct file_operations mem_write_ops = {
	.open           = mem_write_open,
	.read           = seq_read,
	.write          = mem_write_write,
	.llseek         = seq_lseek,
	.release        = single_release,
};

static void tpmi_dbgfs_register(struct intel_tpmi_info *tpmi_info)
{
	struct dentry *top_dir;
	char name[64];
	int i;

	snprintf(name, sizeof(name), "tpmi-%s", dev_name(tpmi_to_dev(tpmi_info)));
	top_dir = debugfs_create_dir(name, NULL);
	tpmi_info->dbgfs_dir = top_dir;

	debugfs_create_file("pfs_dump", 0444, top_dir, tpmi_info,
			    &tpmi_pfs_dbg_fops);
	debugfs_create_file("help", 0444, top_dir, NULL, &tpmi_help_fops);
	for (i = 0; i < tpmi_info->feature_count; ++i) {
		struct intel_tpmi_pm_feature *pfs;
		struct dentry *dir;
		char name[16];

		pfs = &tpmi_info->tpmi_features[i];
		snprintf(name, sizeof(name), "tpmi-id-%02x", pfs->pfs_header.tpmi_id);
		dir = debugfs_create_dir(name, top_dir);

		debugfs_create_file("mem_dump", 0444, dir, pfs,
				    &tpmi_mem_dump_fops);
		debugfs_create_file("mem_write", 0644, dir, pfs,
				    &mem_write_ops);
	}
}

static void tpmi_dbgfs_unregister(struct intel_tpmi_info *tpmi_info)
{
	debugfs_remove_recursive(tpmi_info->dbgfs_dir);
}

static void tpmi_set_control_base(struct intel_tpmi_info *tpmi_info,
				  struct intel_tpmi_pm_feature *pfs)
{
	void __iomem *mem;
	u16 size;

	size = pfs->pfs_header.num_entries * pfs->pfs_header.entry_size * 4;
	mem = ioremap(pfs->vsec_offset, size);
	if (!mem)
		return;

	/* mem is pointing to TPMI CONTROL base */
	tpmi_info->tpmi_control_mem = mem;
}

/* Read one PFS entry and fill pfs structure */
static int tpmi_update_pfs(struct intel_tpmi_pm_feature *pfs, u64 start,
			   int size)
{
	void __iomem *pfs_mem;
	u64 header;

	pfs_mem = ioremap(start, size);
	if (!pfs_mem)
		return -ENOMEM;

	header = readq(pfs_mem);
	pfs->pfs_header = *(struct intel_tpmi_pfs *) &header;
	iounmap(pfs_mem);

	return 0;
}

static const char *intel_tpmi_name(enum intel_tpmi_id id)
{
	switch (id) {
	case TPMI_ID_RAPL:
		return "rapl";
	case TPMI_ID_PEM:
		return "pem";
	case TPMI_ID_UNCORE:
		return "uncore";
	case TPMI_ID_SST:
		return "sst";
	default:
		return NULL;
	}
}

/* String Length for tpmi-"feature_name(upto 8 bytes)"*/
#define TPMI_FEATURE_NAME_LEN	14

static int tpmi_create_device(struct intel_tpmi_info *tpmi_info,
			      struct intel_tpmi_pm_feature *pfs,
			      u64 pfs_start)
{
	struct intel_vsec_device *vsec_dev = tpmi_info->vsec_dev;
	struct intel_vsec_device *feature_vsec_dev;
	struct resource *res, *tmp;
	char feature_id_name[TPMI_FEATURE_NAME_LEN];
	const char *name;
	int ret, i;

	name = intel_tpmi_name(pfs->pfs_header.tpmi_id);
	if (!name)
		return -EOPNOTSUPP;

	feature_vsec_dev = kzalloc(sizeof(*feature_vsec_dev), GFP_KERNEL);
	if (!feature_vsec_dev)
		return -ENOMEM;

	res = kcalloc(pfs->pfs_header.num_entries, sizeof(*res), GFP_KERNEL);
	if (!res) {
		ret = -ENOMEM;
		goto free_vsec;
	}

	snprintf(feature_id_name, sizeof(feature_id_name), "tpmi-%s", name);

	for (i = 0, tmp = res; i < pfs->pfs_header.num_entries; i++, tmp++) {
		tmp->start = pfs->vsec_offset + (pfs->pfs_header.entry_size * 4) * i;
		tmp->end = tmp->start + (pfs->pfs_header.entry_size * 4) - 1;
		tmp->flags = IORESOURCE_MEM;
		dev_dbg(tpmi_to_dev(tpmi_info), " TPMI id:%x Entry %d, %pr", pfs->pfs_header.tpmi_id,
			i, tmp);
	}

	feature_vsec_dev->pcidev = vsec_dev->pcidev;
	feature_vsec_dev->resource = res;
	feature_vsec_dev->num_resources = pfs->pfs_header.num_entries;
	feature_vsec_dev->priv_data = &tpmi_info->plat_info;
	feature_vsec_dev->priv_data_size = sizeof(tpmi_info->plat_info);
	feature_vsec_dev->ida = &intel_vsec_tpmi_ida;

	/*
	 * intel_vsec_add_aux() is resource managed, no explicit
	 * delete is required on error or on module unload.
	 */
	ret = intel_vsec_add_aux(vsec_dev->pcidev, &vsec_dev->auxdev.dev,
				 feature_vsec_dev, feature_id_name);
	if (ret)
		goto free_res;

	return 0;

free_res:
	kfree(res);
free_vsec:
	kfree(feature_vsec_dev);

	return ret;
}

static int tpmi_create_devices(struct intel_tpmi_info *tpmi_info)
{
	struct intel_vsec_device *vsec_dev = tpmi_info->vsec_dev;
	int ret, i;

	for (i = 0; i < vsec_dev->num_resources; i++) {
		struct intel_tpmi_pm_feature *pfs;

		pfs = &tpmi_info->tpmi_features[i];
		/* Todo: Till tested on HW, just create device anyway even if locked */
		ret = tpmi_create_device(tpmi_info, &tpmi_info->tpmi_features[i],
					 tpmi_info->pfs_start);
		/*
		 * Fail, if the supported features fails to create device,
		 * otherwise, continue
		 */
		if (ret && ret != -EOPNOTSUPP)
			return ret;
	}

	return 0;
}

#define TPMI_INFO_ID 0x81
#define TPMI_INFO_BUS_INFO_OFFSET 0x08

static int tpmi_process_info(struct intel_tpmi_info *tpmi_info,
			     struct intel_tpmi_pm_feature *pfs)
{
	struct tpmi_info_header *header;
	void __iomem *info_mem;
	u64 info;

	info_mem = ioremap(pfs->vsec_offset + TPMI_INFO_BUS_INFO_OFFSET,
			   pfs->pfs_header.entry_size * 4 - TPMI_INFO_BUS_INFO_OFFSET);
	if (!info_mem)
		return -ENOMEM;

	info = readq(info_mem);

	header = (struct tpmi_info_header *)&info;
	dev_dbg(tpmi_to_dev(tpmi_info), "[bus:%d dev:%d fn:%d pkg_id:%d]\n", header->bus, header->dev, header->fn, header->pkg);

	tpmi_info->plat_info.package_id = header->pkg;
	tpmi_info->plat_info.bus_number = header->bus;
	tpmi_info->plat_info.device_number = header->dev;
	tpmi_info->plat_info.function_number = header->fn;

	iounmap(info_mem);

	return 0;
}

static int tpmi_get_resource(struct intel_vsec_device *vsec_dev, int index,
			     u64 *resource_start)
{
	struct resource *res;
	int size;

	res = &vsec_dev->resource[index];
	if (!res)
		return -EINVAL;

	size = resource_size(res);

	*resource_start = res->start;

	return size;
}

#define TPMI_AUTO_SUSPEND_DELAY_MS	2000

static int intel_vsec_tpmi_init(struct auxiliary_device *auxdev)
{
	struct intel_vsec_device *vsec_dev = auxdev_to_ivdev(auxdev);
	struct pci_dev *pci_dev = vsec_dev->pcidev;
	struct intel_tpmi_info *tpmi_info;
	u64 pfs_start = 0;
	int ret, i;

	dev_dbg(&pci_dev->dev, "%s no_resource:%d\n", __func__,
		vsec_dev->num_resources);

	tpmi_info = devm_kzalloc(&auxdev->dev, sizeof(*tpmi_info), GFP_KERNEL);
	if (!tpmi_info)
		return -ENOMEM;

	tpmi_info->vsec_dev = vsec_dev;
	tpmi_info->feature_count = vsec_dev->num_resources;
	tpmi_info->plat_info.bus_number = pci_dev->bus->number;

	tpmi_info->tpmi_features = devm_kcalloc(&auxdev->dev, vsec_dev->num_resources,
						sizeof(*tpmi_info->tpmi_features),
						GFP_KERNEL);
	if (!tpmi_info->tpmi_features)
		return -ENOMEM;

	for (i = 0; i < vsec_dev->num_resources; i++) {
		struct intel_tpmi_pm_feature *pfs;
		u64 res_start;
		int size, ret;

		pfs = &tpmi_info->tpmi_features[i];
		pfs->vsec_dev = vsec_dev;

		size = tpmi_get_resource(vsec_dev, i, &res_start);
		if (size < 0)
			continue;

		ret = tpmi_update_pfs(pfs, res_start, size);
		if (ret)
			continue;

		if (!pfs_start)
			pfs_start = res_start;

		pfs->pfs_header.cap_offset *= 1024;

		pfs->vsec_offset = pfs_start + pfs->pfs_header.cap_offset;

		dev_dbg(&pci_dev->dev, "PFS[tpmi_id=0x%x num_entries=0x%x entry_size=0x%x cap_offset=0x%x pfs->pfs_header.attribute=0x%x\n",
			 pfs->pfs_header.tpmi_id, pfs->pfs_header.num_entries, pfs->pfs_header.entry_size, pfs->pfs_header.cap_offset, pfs->pfs_header.attribute);

		/* Process TPMI_INFO to get BDF to package mapping */
		if (pfs->pfs_header.tpmi_id == TPMI_INFO_ID)
			tpmi_process_info(tpmi_info, pfs);

		if (pfs->pfs_header.tpmi_id == TPMI_CONTROL_ID)
			tpmi_set_control_base(tpmi_info, pfs);
	}

	tpmi_info->pfs_start = pfs_start;

	auxiliary_set_drvdata(auxdev, tpmi_info);

	ret = tpmi_create_devices(tpmi_info);
	if (ret)
		return ret;

	tpmi_dbgfs_register(tpmi_info);

	if (tpmi_info->plat_info.package_id < TPMI_MAX_INSTANCE) {
		tpmi_instances[tpmi_info->plat_info.package_id] = tpmi_info;
		++tpmi_instance_count;
		pr_debug("TPMI NO intances %d\n", tpmi_instance_count);
	}

	pm_runtime_set_active(&auxdev->dev);
	pm_runtime_set_autosuspend_delay(&auxdev->dev, TPMI_AUTO_SUSPEND_DELAY_MS);
	pm_runtime_use_autosuspend(&auxdev->dev);
	pm_runtime_enable(&auxdev->dev);
	pm_runtime_mark_last_busy(&auxdev->dev);

	return 0;
}

static int tpmi_probe(struct auxiliary_device *auxdev,
		      const struct auxiliary_device_id *id)
{
	return intel_vsec_tpmi_init(auxdev);
}

static void tpmi_remove(struct auxiliary_device *auxdev)
{
	struct intel_tpmi_info *tpmi_info = auxiliary_get_drvdata(auxdev);

	pm_runtime_disable(&auxdev->dev);

	if (tpmi_info->tpmi_control_mem)
		iounmap(tpmi_info->tpmi_control_mem);

	tpmi_dbgfs_unregister(auxiliary_get_drvdata(auxdev));
}

static const struct auxiliary_device_id tpmi_id_table[] = {
	{ .name = "intel_vsec.tpmi" },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, tpmi_id_table);

static struct auxiliary_driver tpmi_aux_driver = {
	.id_table	= tpmi_id_table,
	.remove		= tpmi_remove,
	.probe		= tpmi_probe,
};

module_auxiliary_driver(tpmi_aux_driver);

MODULE_DESCRIPTION("Intel TPMI enumeration module");
MODULE_LICENSE("GPL");
