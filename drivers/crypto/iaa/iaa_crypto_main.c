// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Intel Corporation. All rights rsvd. */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/iommu.h>
#include <uapi/linux/idxd.h>
#include <linux/highmem.h>
#include <linux/sched/smt.h>
#include <crypto/internal/acompress.h>

#include "idxd.h"
#include "iaa_crypto.h"
#include "iaa_crypto_stats.h"

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt)			"idxd: " IDXD_SUBDRIVER_NAME ": " fmt

#define IAA_ALG_PRIORITY		300

/* number of iaa instances probed */
static unsigned int nr_iaa;
static unsigned int nr_cpus;
static unsigned int nr_nodes;
static unsigned int nr_cpus_per_node;

/* Number of physical cpus sharing each iaa instance */
static unsigned int cpus_per_iaa;

/* Per-cpu lookup table for balanced wqs */
static struct wq_table_entry __percpu *wq_table;

static struct idxd_wq *wq_table_next_wq(int cpu)
{
	struct wq_table_entry *entry = per_cpu_ptr(wq_table, cpu);

	if (++entry->cur_wq >= entry->n_wqs)
		entry->cur_wq = 0;

	return entry->wqs[entry->cur_wq];
}

static void wq_table_add(int cpu, struct idxd_wq *wq)
{
	struct wq_table_entry *entry = per_cpu_ptr(wq_table, cpu);

	if (WARN_ON(entry->n_wqs == entry->max_wqs))
		return;

	entry->wqs[entry->n_wqs++] = wq;

	pr_debug("%s: added iaa wq %d.%d to idx %d of cpu %d\n", __func__,
		 entry->wqs[entry->n_wqs - 1]->idxd->id,
		 entry->wqs[entry->n_wqs - 1]->id, entry->n_wqs - 1, cpu);
}

static void wq_table_free_entry(int cpu)
{
	struct wq_table_entry *entry = per_cpu_ptr(wq_table, cpu);

	kfree(entry->wqs);
	memset(entry, 0, sizeof(*entry));
}

static void wq_table_clear_entry(int cpu)
{
	struct wq_table_entry *entry = per_cpu_ptr(wq_table, cpu);

	entry->n_wqs = 0;
	entry->cur_wq = 0;
	memset(entry->wqs, 0, entry->max_wqs * sizeof(struct idxd_wq *));
}

static LIST_HEAD(iaa_devices);
static DEFINE_MUTEX(iaa_devices_lock);

/* If enabled, IAA hw crypto algos are registered, unavailable otherwise */
static bool iaa_crypto_enabled;

/* Verify results of IAA compress or not */
static bool iaa_verify_compress = true;

static ssize_t verify_compress_show(struct device_driver *driver, char *buf)
{
	return sprintf(buf, "%d\n", iaa_verify_compress);
}

static ssize_t verify_compress_store(struct device_driver *driver,
				     const char *buf, size_t count)
{
	int ret = -EBUSY;

	mutex_lock(&iaa_devices_lock);

	if (iaa_crypto_enabled)
		goto out;

	ret = kstrtobool(buf, &iaa_verify_compress);
	if (ret)
		goto out;

	ret = count;
out:
	mutex_unlock(&iaa_devices_lock);

	return ret;
}
static DRIVER_ATTR_RW(verify_compress);

/*
 * The iaa crypto driver supports three 'sync' methods determining how
 * compressions and decompressions are performed:
 *
 * - sync:      the compression or decompression completes before
 *              returning.  This is the mode used by the async crypto
 *              interface when the sync mode is set to 'sync' and by
 *              the sync crypto interface regardless of setting.
 *
 * - async:     the compression or decompression is submitted and returns
 *              immediately.  Completion interrupts are not used so
 *              the caller is responsible for polling the descriptor
 *              for completion.  This mode is applicable to only the
 *              async crypto interface and is ignored for anything
 *              else.
 *
 * - async_irq: the compression or decompression is submitted and
 *              returns immediately.  Completion interrupts are
 *              enabled so the caller can wait for the completion and
 *              yield to other threads.  When the compression or
 *              decompression completes, the completion is signaled
 *              and the caller awakened.  This mode is applicable to
 *              only the async crypto interface and is ignored for
 *              anything else.
 *
 * These modes can be set using the iaa_crypto sync_mode driver
 * attribute.
 */

/* Use async mode */
static bool async_mode;
/* Use interrupts */
static bool use_irq;

/**
 * set_iaa_sync_mode - Set IAA sync mode
 * @name: The name of the sync mode
 *
 * Make the IAA sync mode named @name the current sync mode used by
 * compression/decompression.
 */

static int set_iaa_sync_mode(const char *name)
{
	int ret = 0;

	if (sysfs_streq(name, "sync")) {
		async_mode = false;
		use_irq = false;
	} else if (sysfs_streq(name, "async")) {
		async_mode = true;
		use_irq = false;
	} else if (sysfs_streq(name, "async_irq")) {
		async_mode = true;
		use_irq = true;
	} else {
		ret = -EINVAL;
	}

	return ret;
}

static ssize_t sync_mode_show(struct device_driver *driver, char *buf)
{
	int ret = 0;

	if (!async_mode && !use_irq)
		ret = sprintf(buf, "%s\n", "sync");
	else if (async_mode && !use_irq)
		ret = sprintf(buf, "%s\n", "async");
	else if (async_mode && use_irq)
		ret = sprintf(buf, "%s\n", "async_irq");

	return ret;
}

static ssize_t sync_mode_store(struct device_driver *driver,
			       const char *buf, size_t count)
{
	int ret = -EBUSY;

	mutex_lock(&iaa_devices_lock);

	if (iaa_crypto_enabled)
		goto out;

	ret = set_iaa_sync_mode(buf);
	if (ret == 0)
		ret = count;
out:
	mutex_unlock(&iaa_devices_lock);

	return ret;
}
static DRIVER_ATTR_RW(sync_mode);

static struct iaa_compression_mode *iaa_compression_modes[IAA_COMP_MODES_MAX];
static int active_compression_mode;

static bool canned_mode;

static ssize_t compression_mode_show(struct device_driver *driver, char *buf)
{
	int ret = 0;

	if (canned_mode)
		ret = sprintf(buf, "%s\n", "canned");
	else
		ret = sprintf(buf, "%s\n", "fixed");

	return ret;
}

static ssize_t compression_mode_store(struct device_driver *driver,
				      const char *buf, size_t count)
{
	int ret = -EBUSY;
	char *mode_name;

	mutex_lock(&iaa_devices_lock);

	if (iaa_crypto_enabled)
		goto out;

	mode_name = kstrndup(buf, count, GFP_KERNEL);
	if (!mode_name) {
		ret = -ENOMEM;
		goto out;
	}

	ret = set_iaa_compression_mode(strim(mode_name));
	if (ret == 0)
		ret = count;

	kfree(mode_name);
out:
	mutex_unlock(&iaa_devices_lock);

	return ret;
}
static DRIVER_ATTR_RW(compression_mode);

static int find_empty_iaa_compression_mode(void)
{
	int i = -EINVAL;

	for (i = 0; i < IAA_COMP_MODES_MAX; i++) {
		if (iaa_compression_modes[i])
			continue;
		break;
	}

	return i;
}

static struct iaa_compression_mode *find_iaa_compression_mode(const char *name, int *idx)
{
	struct iaa_compression_mode *mode;
	int i;

	for (i = 0; i < IAA_COMP_MODES_MAX; i++) {
		mode = iaa_compression_modes[i];
		if (!mode)
			continue;

		if (!strcmp(mode->name, name)) {
			*idx = i;
			return iaa_compression_modes[i];
		}
	}

	return NULL;
}

static void free_iaa_compression_mode(struct iaa_compression_mode *mode)
{
	kfree(mode->name);
	kfree(mode->ll_table);
	kfree(mode->d_table);
	kfree(mode->header_table);

	kfree(mode);
}

/*
 * IAA Compression modes are defined by an ll_table, a d_table, and an
 * optional header_table.  These tables are typically generated and
 * captured using statistics collected from running actual
 * compress/decompress workloads.
 *
 * A module or other kernel code can add and remove compression modes
 * with a given name using the exported @add_iaa_compression_mode()
 * and @remove_iaa_compression_mode functions.
 *
 * Successfully added compression modes can be selected using the
 * function @set_iaa_compression_mode(), passing in the name of the
 * compression mode.  Henceforth, all compressions and decompressions
 * will use the given compression mode.  Any in-flight decompressions
 * using the old mode will subsequently fail.
 *
 * When a new compression mode is added, the tables are saved in a
 * global compression mode list.  When IAA devices are added, a
 * per-IAA device dma mapping is created for each IAA device, for each
 * compression mode.  These are the tables used to do the actual
 * compression/deccompression and are unmapped if/when the devices are
 * removed.  Currently, compression modes must be added before any
 * device is added, and removed after all devices have been removed.
 */

/**
 * remove_iaa_compression_mode - Remove an IAA compression mode
 * @name: The name the compression mode will be known as
 *
 * Remove the IAA compression mode named @name.
 */
void remove_iaa_compression_mode(const char *name)
{
	struct iaa_compression_mode *mode;
	int idx;

	mutex_lock(&iaa_devices_lock);

	if (!list_empty(&iaa_devices))
		goto out;

	mode = find_iaa_compression_mode(name, &idx);
	if (mode) {
		free_iaa_compression_mode(mode);
		iaa_compression_modes[idx] = NULL;
	}
out:
	mutex_unlock(&iaa_devices_lock);
}
EXPORT_SYMBOL_GPL(remove_iaa_compression_mode);

/**
 * add_iaa_compression_mode - Add an IAA compression mode
 * @name: The name the compression mode will be known as
 * @ll_table: The ll table
 * @ll_table_size: The ll table size in bytes
 * @d_table: The d table
 * @d_table_size: The d table size in bytes
 * @header_table: Optional header table
 * @header_table_size: Optional header table size in bytes
 * @gen_decomp_table_flags: Otional flags used to generate the decomp table
 * @init: Optional callback function to init the compression mode data
 * @free: Optional callback function to free the compression mode data
 *
 * Add a new IAA compression mode named @name.  If successful, @name
 * can subsequently be given to @set_iaa_compression_mode() to make
 * that mode the current mode for iaa compression/decompression.
 *
 * Returns 0 if successful, errcode otherwise.
 */
int add_iaa_compression_mode(const char *name,
			     const u32 *ll_table,
			     int ll_table_size,
			     const u32 *d_table,
			     int d_table_size,
			     const u8 *header_table,
			     int header_table_size,
			     u16 gen_decomp_table_flags,
			     iaa_dev_comp_init_fn_t init,
			     iaa_dev_comp_free_fn_t free)
{
	struct iaa_compression_mode *mode;
	int idx, ret = -ENOMEM;

	mutex_lock(&iaa_devices_lock);

	if (!list_empty(&iaa_devices)) {
		ret = -EBUSY;
		goto out;
	}

	mode = kzalloc(sizeof(*mode), GFP_KERNEL);
	if (!mode)
		goto out;

	mode->name = kstrdup(name, GFP_KERNEL);
	if (!mode->name)
		goto free;

	if (ll_table) {
		mode->ll_table = kzalloc(ll_table_size, GFP_KERNEL);
		if (!mode->ll_table)
			goto free;
		memcpy(mode->ll_table, ll_table, ll_table_size);
		mode->ll_table_size = ll_table_size;
	}

	if (d_table) {
		mode->d_table = kzalloc(d_table_size, GFP_KERNEL);
		if (!mode->d_table)
			goto free;
		memcpy(mode->d_table, d_table, d_table_size);
		mode->d_table_size = d_table_size;
	}

	if (header_table) {
		mode->header_table = kzalloc(header_table_size, GFP_KERNEL);
		if (!mode->header_table)
			goto free;
		memcpy(mode->header_table, header_table, header_table_size);
		mode->header_table_size = header_table_size;
	}

	mode->gen_decomp_table_flags = gen_decomp_table_flags;

	mode->init = init;
	mode->free = free;

	idx = find_empty_iaa_compression_mode();
	if (idx < 0)
		goto free;

	pr_debug("IAA compression mode %s added at idx %d\n",
		 mode->name, idx);

	iaa_compression_modes[idx] = mode;

	ret = 0;
out:
	mutex_unlock(&iaa_devices_lock);

	return ret;
free:
	free_iaa_compression_mode(mode);
	goto out;
}
EXPORT_SYMBOL_GPL(add_iaa_compression_mode);

static void set_iaa_device_compression_mode(struct iaa_device *iaa_device, int idx)
{
	iaa_device->active_compression_mode = iaa_device->compression_modes[idx];
}

static void update_iaa_devices_compression_mode(void)
{
	struct iaa_device *iaa_device;

	list_for_each_entry(iaa_device, &iaa_devices, list)
		set_iaa_device_compression_mode(iaa_device, active_compression_mode);
}

/**
 * set_iaa_compression_mode - Set an IAA compression mode
 * @name: The name of the compression mode
 *
 * Make the IAA compression mode named @name the current compression
 * mode used by compression/decompression.
 */

int set_iaa_compression_mode(const char *name)
{
	struct iaa_compression_mode *mode;
	int ret = -EINVAL;
	int idx;

	mode = find_iaa_compression_mode(name, &idx);
	if (mode) {
		active_compression_mode = idx;
		update_iaa_devices_compression_mode();
		pr_debug("compression mode set to: %s\n", name);
		ret = 0;
	}

	if (ret == 0 && !strcmp(name, "canned"))
		canned_mode = true;

	if (ret == 0 && !strcmp(name, "fixed"))
		canned_mode = false;

	return ret;
}

static void free_device_compression_mode(struct iaa_device *iaa_device,
					 struct iaa_device_compression_mode *device_mode)
{
	size_t size = sizeof(struct aecs_comp_table_record) + IAA_AECS_ALIGN;
	struct device *dev = &iaa_device->idxd->pdev->dev;

	kfree(device_mode->name);

	if (device_mode->aecs_comp_table)
		dma_free_coherent(dev, size, device_mode->aecs_comp_table,
				  device_mode->aecs_comp_table_dma_addr);
	if (device_mode->aecs_decomp_table)
		dma_free_coherent(dev, size, device_mode->aecs_decomp_table,
				  device_mode->aecs_decomp_table_dma_addr);

	kfree(device_mode);
}

#define IDXD_OP_FLAG_AECS_RW_TGLS       0x400000
#define IAX_AECS_DEFAULT_FLAG (IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_CC)
#define IAX_AECS_COMPRESS_FLAG	(IAX_AECS_DEFAULT_FLAG | IDXD_OP_FLAG_RD_SRC2_AECS)
#define IAX_AECS_DECOMPRESS_FLAG (IAX_AECS_DEFAULT_FLAG | IDXD_OP_FLAG_RD_SRC2_AECS)
#define IAX_AECS_GEN_FLAG (IAX_AECS_DEFAULT_FLAG | \
						IDXD_OP_FLAG_WR_SRC2_AECS_COMP | \
						IDXD_OP_FLAG_AECS_RW_TGLS)

static int check_completion(struct device *dev,
			    struct iax_completion_record *comp,
			    bool compress,
			    bool only_once);

static int decompress_header(struct iaa_device_compression_mode *device_mode,
			     struct iaa_compression_mode *mode,
			     struct idxd_wq *wq)
{
	dma_addr_t src_addr, src2_addr;
	struct idxd_desc *idxd_desc;
	struct iax_hw_desc *desc;
	struct device *dev;
	int ret = 0;

	idxd_desc = idxd_alloc_desc(wq, IDXD_OP_BLOCK);
	if (IS_ERR(idxd_desc))
		return PTR_ERR(idxd_desc);

	desc = idxd_desc->iax_hw;

	dev = &wq->idxd->pdev->dev;

	src_addr = dma_map_single(dev, (void *)mode->header_table,
				  mode->header_table_size, DMA_TO_DEVICE);
	dev_dbg(dev, "%s: mode->name %s, src_addr %llx, dev %p, src %p, slen %d\n",
		__func__, mode->name, src_addr,	dev,
		mode->header_table, mode->header_table_size);
	if (unlikely(dma_mapping_error(dev, src_addr))) {
		dev_dbg(dev, "dma_map_single err, exiting\n");
		ret = -ENOMEM;
		return ret;
	}

	desc->flags = IAX_AECS_GEN_FLAG;
	desc->opcode = IAX_OPCODE_DECOMPRESS;

	desc->src1_addr = (u64)src_addr;
	desc->src1_size = mode->header_table_size;

	src2_addr = device_mode->aecs_decomp_table_dma_addr;
	desc->src2_addr = (u64)src2_addr;
	desc->src2_size = 1088;
	dev_dbg(dev, "%s: mode->name %s, src2_addr %llx, dev %p, src2_size %d\n",
		__func__, mode->name, desc->src2_addr, dev, desc->src2_size);
	desc->max_dst_size = 0; // suppressed output

	desc->decompr_flags = mode->gen_decomp_table_flags;

#ifdef SPR_E0
	desc->priv = 1;
#else
	desc->priv = 0;
#endif
	desc->completion_addr = idxd_desc->compl_dma;

	ret = idxd_submit_desc(wq, idxd_desc);
	if (ret) {
		pr_err("%s: submit_desc failed ret=0x%x\n", __func__, ret);
		goto out;
	}

	ret = check_completion(dev, idxd_desc->iax_completion, false, false);
	if (ret)
		dev_dbg(dev, "%s: mode->name %s check_completion failed ret=%d\n",
			__func__, mode->name, ret);
	else
		dev_dbg(dev, "%s: mode->name %s succeeded\n", __func__,
			mode->name);
out:
	dma_unmap_single(dev, src2_addr, 1088, DMA_TO_DEVICE);

	return ret;
}

static int init_device_compression_mode(struct iaa_device *iaa_device,
					struct iaa_compression_mode *mode,
					int idx, struct idxd_wq *wq)
{
	size_t size = sizeof(struct aecs_comp_table_record) + IAA_AECS_ALIGN;
	struct device *dev = &iaa_device->idxd->pdev->dev;
	struct iaa_device_compression_mode *device_mode;
	int ret = -ENOMEM;

	device_mode = kzalloc(sizeof(*device_mode), GFP_KERNEL);
	if (!device_mode)
		return -ENOMEM;

	device_mode->name = kstrdup(mode->name, GFP_KERNEL);
	if (!device_mode->name)
		goto free;

	device_mode->aecs_comp_table = dma_alloc_coherent(dev, size,
							  &device_mode->aecs_comp_table_dma_addr, GFP_KERNEL);
	if (!device_mode->aecs_comp_table)
		goto free;

	device_mode->aecs_decomp_table = dma_alloc_coherent(dev, size,
							    &device_mode->aecs_decomp_table_dma_addr, GFP_KERNEL);
	if (!device_mode->aecs_decomp_table)
		goto free;

	/* Add Huffman table to aecs */
	memset(device_mode->aecs_comp_table, 0, sizeof(*device_mode->aecs_comp_table));
	memcpy(device_mode->aecs_comp_table->ll_sym, mode->ll_table, mode->ll_table_size);
	memcpy(device_mode->aecs_comp_table->d_sym, mode->d_table, mode->d_table_size);

	if (mode->header_table) {
		ret = decompress_header(device_mode, mode, wq);
		if (ret) {
			pr_debug("iaa header decompression failed: ret=%d\n", ret);
			goto free;
		}
	}

	if (mode->init) {
		ret = mode->init(device_mode);
		if (ret)
			goto free;
	}

	/* mode index should match iaa_compression_modes idx */
	iaa_device->compression_modes[idx] = device_mode;

	pr_debug("IAA %s compression mode initialized for iaa device %d\n",
		 mode->name, iaa_device->idxd->id);

	ret = 0;
out:
	return ret;
free:
	pr_debug("IAA %s compression mode initialization failed for iaa device %d\n",
		 mode->name, iaa_device->idxd->id);

	free_device_compression_mode(iaa_device, device_mode);
	goto out;
}

static int init_device_compression_modes(struct iaa_device *iaa_device,
					 struct idxd_wq *wq)
{
	struct iaa_compression_mode *mode;
	int i, ret = 0;

	for (i = 0; i < IAA_COMP_MODES_MAX; i++) {
		mode = iaa_compression_modes[i];
		if (!mode)
			continue;

		ret = init_device_compression_mode(iaa_device, mode, i, wq);
		if (ret)
			break;
	}

	return ret;
}

static void remove_device_compression_modes(struct iaa_device *iaa_device)
{
	struct iaa_device_compression_mode *device_mode;
	int i;

	for (i = 0; i < IAA_COMP_MODES_MAX; i++) {
		device_mode = iaa_device->compression_modes[i];
		if (!device_mode)
			continue;

		free_device_compression_mode(iaa_device, device_mode);
		iaa_device->compression_modes[i] = NULL;
		if (iaa_compression_modes[i]->free)
			iaa_compression_modes[i]->free(device_mode);
	}
}

/*
 * Given a cpu, find the closest IAA instance.  The idea is to try to
 * choose the most appropriate IAA instance for a caller and spread
 * available workqueues around to clients.
 */
static inline int cpu_to_iaa(int cpu)
{
	int node, n_cpus = 0, test_cpu, iaa = 0;
	int nr_iaa_per_node, nr_cores_per_iaa;
	const struct cpumask *node_cpus;

	if (!nr_nodes)
		return 0;

	nr_iaa_per_node = nr_iaa / nr_nodes;
	if (!nr_iaa_per_node)
		return 0;

	nr_cores_per_iaa = nr_cpus_per_node / nr_iaa_per_node;

	for_each_online_node(node) {
		node_cpus = cpumask_of_node(node);
		if (!cpumask_test_cpu(cpu, node_cpus))
			continue;

		for_each_cpu(test_cpu, node_cpus) {
			if ((n_cpus % nr_cpus_per_node) == 0)
				iaa = node * nr_iaa_per_node;

			if (test_cpu == cpu)
				return iaa;

			n_cpus++;

			if ((n_cpus % cpus_per_iaa) == 0)
				iaa++;
		}
	}

	return -1;
}

static struct iaa_device *iaa_device_alloc(void)
{
	struct iaa_device *iaa_device;

	iaa_device = kzalloc(sizeof(*iaa_device), GFP_KERNEL);
	if (!iaa_device)
		return NULL;

	INIT_LIST_HEAD(&iaa_device->wqs);

	return iaa_device;
}

static void iaa_device_free(struct iaa_device *iaa_device)
{
	struct iaa_wq *iaa_wq, *next;

	list_for_each_entry_safe(iaa_wq, next, &iaa_device->wqs, list) {
		list_del(&iaa_wq->list);
		kfree(iaa_wq);
	}

	kfree(iaa_device);
}

static bool iaa_has_wq(struct iaa_device *iaa_device, struct idxd_wq *wq)
{
	struct iaa_wq *iaa_wq;

	list_for_each_entry(iaa_wq, &iaa_device->wqs, list) {
		if (iaa_wq->wq == wq)
			return true;
	}

	return false;
}

static struct iaa_device *add_iaa_device(struct idxd_device *idxd)
{
	struct iaa_device *iaa_device;

	iaa_device = iaa_device_alloc();
	if (!iaa_device)
		return NULL;

	iaa_device->idxd = idxd;

	list_add_tail(&iaa_device->list, &iaa_devices);

	nr_iaa++;

	return iaa_device;
}

static int init_iaa_device(struct iaa_device *iaa_device, struct iaa_wq *iaa_wq)
{
	int ret = 0;

	ret = init_device_compression_modes(iaa_device, iaa_wq->wq);
	if (ret)
		return ret;

	set_iaa_device_compression_mode(iaa_device, active_compression_mode);

	return ret;
}

static void del_iaa_device(struct iaa_device *iaa_device)
{
	remove_device_compression_modes(iaa_device);

	list_del(&iaa_device->list);

	iaa_device_free(iaa_device);

	nr_iaa--;
}

static int add_iaa_wq(struct iaa_device *iaa_device, struct idxd_wq *wq,
		      struct iaa_wq **new_wq)
{
	struct idxd_device *idxd = iaa_device->idxd;
	struct pci_dev *pdev = idxd->pdev;
	struct device *dev = &pdev->dev;
	struct iaa_wq *iaa_wq;

	iaa_wq = kzalloc(sizeof(*iaa_wq), GFP_KERNEL);
	if (!iaa_wq)
		return -ENOMEM;

	iaa_wq->wq = wq;
	iaa_wq->iaa_device = iaa_device;
	wq->private_data = iaa_wq;

	list_add_tail(&iaa_wq->list, &iaa_device->wqs);

	iaa_device->n_wq++;

	if (new_wq)
		*new_wq = iaa_wq;

	dev_dbg(dev, "added wq %d to iaa device %d, n_wq %d\n",
		wq->id, iaa_device->idxd->id, iaa_device->n_wq);

	return 0;
}

static void del_iaa_wq(struct iaa_device *iaa_device, struct idxd_wq *wq)
{
	struct idxd_device *idxd = iaa_device->idxd;
	struct pci_dev *pdev = idxd->pdev;
	struct device *dev = &pdev->dev;
	struct iaa_wq *iaa_wq;

	list_for_each_entry(iaa_wq, &iaa_device->wqs, list) {
		if (iaa_wq->wq == wq) {
			list_del(&iaa_wq->list);
			iaa_device->n_wq--;

			dev_dbg(dev, "removed wq %d from iaa_device %d, n_wq %d, nr_iaa %d\n",
				wq->id, iaa_device->idxd->id,
				iaa_device->n_wq, nr_iaa);

			if (iaa_device->n_wq == 0)
				del_iaa_device(iaa_device);
			break;
		}
	}
}

static void clear_wq_table(void)
{
	int cpu;

	for (cpu = 0; cpu < nr_cpus; cpu++)
		wq_table_clear_entry(cpu);

	pr_debug("cleared wq table\n");
}

static void free_wq_table(void)
{
	int cpu;

	for (cpu = 0; cpu < nr_cpus; cpu++)
		wq_table_free_entry(cpu);

	free_percpu(wq_table);

	pr_debug("freed wq table\n");
}

static int alloc_wq_table(int max_wqs)
{
	struct wq_table_entry *entry;
	int cpu;

	wq_table = alloc_percpu(struct wq_table_entry);
	if (!wq_table)
		return -ENOMEM;

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		entry = per_cpu_ptr(wq_table, cpu);
		entry->wqs = kzalloc(GFP_KERNEL, max_wqs * sizeof(struct wq *));
		if (!entry->wqs) {
			free_wq_table();
			return -ENOMEM;
		}

		entry->max_wqs = max_wqs;
	}

	pr_debug("initialized wq table\n");

	return 0;
}

static int save_iaa_wq(struct idxd_wq *wq)
{
	struct iaa_device *iaa_device, *found = NULL;
	struct idxd_device *idxd;
	struct pci_dev *pdev;
	struct device *dev;
	int ret = 0;

	list_for_each_entry(iaa_device, &iaa_devices, list) {
		if (iaa_device->idxd == wq->idxd) {
			idxd = iaa_device->idxd;
			pdev = idxd->pdev;
			dev = &pdev->dev;
			/*
			 * Check to see that we don't already have this wq.
			 * Shouldn't happen but we don't control probing.
			 */
			if (iaa_has_wq(iaa_device, wq)) {
				dev_dbg(dev, "same wq probed multiple times for iaa_device %p\n",
					iaa_device);
				goto out;
			}

			found = iaa_device;

			ret = add_iaa_wq(iaa_device, wq, NULL);
			if (ret)
				goto out;

			break;
		}
	}

	if (!found) {
		struct iaa_device *new_device;
		struct iaa_wq *new_wq;

		new_device = add_iaa_device(wq->idxd);
		if (!new_device) {
			ret = -ENOMEM;
			goto out;
		}

		ret = add_iaa_wq(new_device, wq, &new_wq);
		if (ret) {
			del_iaa_device(new_device);
			goto out;
		}

		ret = init_iaa_device(new_device, new_wq);
		if (ret) {
			del_iaa_wq(new_device, new_wq->wq);
			del_iaa_device(new_device);
			goto out;
		}
	}

	if (WARN_ON(nr_iaa == 0))
		return -EINVAL;

	idxd_wq_get(wq);

	cpus_per_iaa = (nr_nodes * nr_cpus_per_node) / nr_iaa;
out:
	return 0;
}

static void remove_iaa_wq(struct idxd_wq *wq)
{
	struct iaa_device *iaa_device;

	list_for_each_entry(iaa_device, &iaa_devices, list) {
		if (iaa_has_wq(iaa_device, wq)) {
			del_iaa_wq(iaa_device, wq);
			idxd_wq_put(wq);
			break;
		}
	}

	if (nr_iaa)
		cpus_per_iaa = (nr_nodes * nr_cpus_per_node) / nr_iaa;
	else
		cpus_per_iaa = 0;
}

static int wq_table_add_wqs(int iaa, int cpu)
{
	struct iaa_device *iaa_device, *found_device = NULL;
	int ret = 0, cur_iaa = 0, n_wqs_added = 0;
	struct idxd_device *idxd;
	struct iaa_wq *iaa_wq;
	struct pci_dev *pdev;
	struct device *dev;

	list_for_each_entry(iaa_device, &iaa_devices, list) {
		idxd = iaa_device->idxd;
		pdev = idxd->pdev;
		dev = &pdev->dev;

		if (cur_iaa != iaa) {
			cur_iaa++;
			continue;
		}

		found_device = iaa_device;
		dev_dbg(dev, "getting wq from iaa_device %d, cur_iaa %d\n",
			found_device->idxd->id, cur_iaa);
		break;
	}

	if (!found_device) {
		found_device = list_first_entry_or_null(&iaa_devices,
							struct iaa_device, list);
		if (!found_device) {
			pr_debug("couldn't find any iaa devices with wqs!\n");
			ret = -EINVAL;
			goto out;
		}
		cur_iaa = 0;

		idxd = found_device->idxd;
		pdev = idxd->pdev;
		dev = &pdev->dev;
		dev_dbg(dev, "getting wq from only iaa_device %d, cur_iaa %d\n",
			found_device->idxd->id, cur_iaa);
	}

	list_for_each_entry(iaa_wq, &found_device->wqs, list) {
		wq_table_add(cpu, iaa_wq->wq);
		pr_debug("rebalance: added wq for cpu=%d: iaa wq %d.%d\n",
			 cpu, iaa_wq->wq->idxd->id, iaa_wq->wq->id);
		n_wqs_added++;
	};

	if (!n_wqs_added) {
		pr_debug("couldn't find any iaa wqs!\n");
		ret = -EINVAL;
		goto out;
	}
out:
	return ret;
}

static void rebalance_wq_table(void)
{
	int cpu, iaa;

	if (nr_iaa == 0)
		return;

	clear_wq_table();

	pr_debug("rebalance: nr_nodes=%d, nr_cpus %d, nr_iaa %d, cpus_per_iaa %d\n",
		 nr_nodes, nr_cpus, nr_iaa, cpus_per_iaa);

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		iaa = cpu_to_iaa(cpu);
		pr_debug("rebalance: cpu=%d iaa=%d\n", cpu, iaa);

		if (WARN_ON(iaa == -1)) {
			pr_debug("rebalance (cpu_to_iaa(%d)) failed!\n", cpu);
			return;
		}

		if (WARN_ON(wq_table_add_wqs(iaa, cpu))) {
			pr_debug("could not add any wqs for iaa %d to cpu %d!\n", iaa, cpu);
			return;
		}
	}
}

static inline int check_completion(struct device *dev,
				   struct iax_completion_record *comp,
				   bool compress,
				   bool only_once)
{
	int ret = 0;

	while (!comp->status) {
		if (only_once)
			return -EAGAIN;
		cpu_relax();
	}

	if (comp->status != IAX_COMP_SUCCESS) {
		if (comp->status == IAA_ERROR_WATCHDOG_EXPIRED) {
			ret = -ETIMEDOUT;
			goto out;
		}

		if (comp->status == IAA_ANALYTICS_ERROR &&
		    comp->error_code == IAA_ERROR_COMP_BUF_OVERFLOW && compress) {
			ret = -E2BIG;
			goto out;
		}

		ret = -EINVAL;

		goto out;
	}
out:
	return ret;
}

static int iaa_compress_verify(struct crypto_tfm *tfm, struct acomp_req *req,
			       struct idxd_wq *wq,
			       dma_addr_t src_addr, unsigned int slen,
			       dma_addr_t dst_addr, unsigned int *dlen,
			       u32 compression_crc);

static void iaa_desc_complete(struct idxd_desc *idxd_desc,
			      enum idxd_complete_type comp_type,
			      bool free_desc, void *__ctx,
			      u32 *status)
{
	struct crypto_ctx *ctx = __ctx;
	struct idxd_device *idxd;
	struct iaa_wq *iaa_wq;
	struct pci_dev *pdev;
	struct device *dev;
	int ret, err = 0;

	iaa_wq = idxd_desc->wq->private_data;
	idxd = iaa_wq->iaa_device->idxd;
	pdev = idxd->pdev;
	dev = &pdev->dev;

	ret = check_completion(dev, idxd_desc->iax_completion,
			       ctx->compress, false);
	if (ret) {
		err = -EIO;
	}

	ctx->req->dlen = idxd_desc->iax_completion->output_size;

	/* Update stats */
	if (ctx->compress) {
		update_total_comp_bytes_out(ctx->req->dlen);
		update_wq_comp_bytes(iaa_wq->wq, ctx->req->dlen);
	} else {
		update_total_decomp_bytes_in(ctx->req->dlen);
		update_wq_decomp_bytes(iaa_wq->wq, ctx->req->dlen);
	}

	if (ctx->compress && iaa_verify_compress) {
		u32 compression_crc;

		compression_crc = idxd_desc->iax_completion->crc;
		dma_sync_sg_for_device(dev, ctx->req->dst, 1, DMA_FROM_DEVICE);
		dma_sync_sg_for_device(dev, ctx->req->src, 1, DMA_TO_DEVICE);
		ret = iaa_compress_verify(ctx->tfm, ctx->req, iaa_wq->wq, ctx->src_addr,
					  ctx->req->slen, ctx->dst_addr, &ctx->req->dlen,
					  compression_crc);
		if (ret) {
			err = -EIO;
		}
	}

	if (ctx->req->base.complete)
		acomp_request_complete(ctx->req, err);

	dma_unmap_sg(dev, ctx->req->dst, sg_nents(ctx->req->dst), DMA_FROM_DEVICE);
	dma_unmap_sg(dev, ctx->req->src, sg_nents(ctx->req->src), DMA_TO_DEVICE);

	if (free_desc)
		idxd_free_desc(idxd_desc->wq, idxd_desc);
}

static int iaa_compress(struct crypto_tfm *tfm,	struct acomp_req *req,
			struct idxd_wq *wq,
			dma_addr_t src_addr, unsigned int slen,
			dma_addr_t dst_addr, unsigned int *dlen,
			u32 *compression_crc,
			bool disable_async)
{
	struct idxd_desc *idxd_desc;
	struct iax_hw_desc *desc;
	struct idxd_device *idxd;
	struct iaa_wq *iaa_wq;
	struct pci_dev *pdev;
	struct device *dev;
	int ret = 0;

	iaa_wq = wq->private_data;
	idxd = iaa_wq->iaa_device->idxd;
	pdev = idxd->pdev;
	dev = &pdev->dev;

	idxd_desc = idxd_alloc_desc(wq, IDXD_OP_BLOCK);
	if (IS_ERR(idxd_desc)) {
		dev_dbg(dev, "idxd descriptor allocation failed\n");
		dev_dbg(dev, "iaa compress failed: ret=%ld\n", PTR_ERR(idxd_desc));
		return PTR_ERR(idxd_desc);
	}
	desc = idxd_desc->iax_hw;

	desc->flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR |
		IDXD_OP_FLAG_RD_SRC2_AECS | IDXD_OP_FLAG_CC;
	desc->opcode = IAX_OPCODE_COMPRESS;
	desc->compr_flags = IAA_COMP_FLAGS;
#ifdef SPR_E0
	desc->priv = 1;
#else
	desc->priv = 0;
#endif

	desc->src1_addr = (u64)src_addr;
	desc->src1_size = slen;
	desc->dst_addr = (u64)dst_addr;
	desc->max_dst_size = *dlen;
	desc->src2_addr = iaa_wq->iaa_device->active_compression_mode->aecs_comp_table_dma_addr;
	desc->src2_size = sizeof(struct aecs_comp_table_record);
	desc->completion_addr = idxd_desc->compl_dma;

	if (use_irq) {
		desc->flags |= IDXD_OP_FLAG_RCI;

		idxd_desc->crypto.req = req;
		idxd_desc->crypto.tfm = tfm;
		idxd_desc->crypto.src_addr = src_addr;
		idxd_desc->crypto.dst_addr = dst_addr;
		idxd_desc->crypto.compress = true;
	} else if (req && async_mode && !disable_async)
		req->base.data = idxd_desc;

	ret = idxd_submit_desc(wq, idxd_desc);
	if (ret) {
		goto err;
	}

	/* Update stats */
	update_total_comp_calls();
	update_wq_comp_calls(wq);

	if (req && async_mode && !disable_async) {
		ret = -EINPROGRESS;
		goto out;
	}

	ret = check_completion(dev, idxd_desc->iax_completion, true, false);
	if (ret) {
		goto err;
	}

	*dlen = idxd_desc->iax_completion->output_size;

	*compression_crc = idxd_desc->iax_completion->crc;

	idxd_free_desc(wq, idxd_desc);
out:
	return ret;
err:
	idxd_free_desc(wq, idxd_desc);

	goto out;
}

static int iaa_compress_verify(struct crypto_tfm *tfm, struct acomp_req *req,
			       struct idxd_wq *wq,
			       dma_addr_t src_addr, unsigned int slen,
			       dma_addr_t dst_addr, unsigned int *dlen,
			       u32 compression_crc)
{
	struct idxd_desc *idxd_desc;
	struct iax_hw_desc *desc;
	struct idxd_device *idxd;
	struct iaa_wq *iaa_wq;
	struct pci_dev *pdev;
	dma_addr_t src2_addr;
	struct device *dev;
	int ret = 0;

	iaa_wq = wq->private_data;
	idxd = iaa_wq->iaa_device->idxd;
	pdev = idxd->pdev;
	dev = &pdev->dev;

	idxd_desc = idxd_alloc_desc(wq, IDXD_OP_BLOCK);
	if (IS_ERR(idxd_desc)) {
		dev_dbg(dev, "idxd descriptor allocation failed\n");
		dev_dbg(dev, "iaa compress failed: ret=%ld\n",
			PTR_ERR(idxd_desc));
		return PTR_ERR(idxd_desc);
	}
	desc = idxd_desc->iax_hw;

	/* Verify (optional) - decompress and check crc, suppress dest write */

	desc->flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_CC;
	desc->opcode = IAX_OPCODE_DECOMPRESS;
	desc->decompr_flags = IAA_DECOMP_FLAGS | IAA_DECOMP_SUPPRESS_OUTPUT;
#ifdef SPR_E0
	desc->priv = 1;
#else
	desc->priv = 0;
#endif

	desc->src1_addr = (u64)dst_addr;
	desc->src1_size = *dlen;
	desc->dst_addr = (u64)src_addr;
	desc->max_dst_size = slen;
	desc->completion_addr = idxd_desc->compl_dma;

	if (canned_mode) {
		src2_addr = iaa_wq->iaa_device->active_compression_mode->aecs_decomp_table_dma_addr;
		desc->src2_addr = (u64)src2_addr;
		desc->src2_size = 1088;
		desc->flags |= IDXD_OP_FLAG_RD_SRC2_AECS;
	}

	ret = idxd_submit_desc(wq, idxd_desc);
	if (ret) {
		goto err;
	}

	ret = check_completion(dev, idxd_desc->iax_completion, false, false);
	if (ret) {
		goto err;
	}

	if (compression_crc != idxd_desc->iax_completion->crc) {
		ret = -EINVAL;
		goto err;
	}

	idxd_free_desc(wq, idxd_desc);
out:
	return ret;
err:
	idxd_free_desc(wq, idxd_desc);

	goto out;
}

static int iaa_decompress(struct crypto_tfm *tfm, struct acomp_req *req,
			  struct idxd_wq *wq,
			  dma_addr_t src_addr, unsigned int slen,
			  dma_addr_t dst_addr, unsigned int *dlen,
			  bool disable_async)
{
	struct idxd_desc *idxd_desc;
	struct iax_hw_desc *desc;
	struct idxd_device *idxd;
	struct iaa_wq *iaa_wq;
	struct pci_dev *pdev;
	dma_addr_t src2_addr;
	struct device *dev;
	int ret = 0;

	iaa_wq = wq->private_data;
	idxd = iaa_wq->iaa_device->idxd;
	pdev = idxd->pdev;
	dev = &pdev->dev;

	idxd_desc = idxd_alloc_desc(wq, IDXD_OP_BLOCK);
	if (IS_ERR(idxd_desc)) {
		dev_dbg(dev, "idxd descriptor allocation failed\n");
		dev_dbg(dev, "iaa decompress failed: ret=%ld\n",
			PTR_ERR(idxd_desc));
		return PTR_ERR(idxd_desc);
	}
	desc = idxd_desc->iax_hw;

	desc->flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_CC;
	desc->opcode = IAX_OPCODE_DECOMPRESS;
	desc->max_dst_size = PAGE_SIZE;
	desc->decompr_flags = IAA_DECOMP_FLAGS;
#ifdef SPR_E0
	desc->priv = 1;
#else
	desc->priv = 0;
#endif

	desc->src1_addr = (u64)src_addr;
	desc->dst_addr = (u64)dst_addr;
	desc->max_dst_size = *dlen;
	desc->src1_size = slen;
	desc->completion_addr = idxd_desc->compl_dma;

	if (canned_mode) {
		src2_addr = iaa_wq->iaa_device->active_compression_mode->aecs_decomp_table_dma_addr;
		desc->src2_addr = (u64)src2_addr;
		desc->src2_size = 1088;
		desc->flags |= IDXD_OP_FLAG_RD_SRC2_AECS;
	}

	if (use_irq) {
		desc->flags |= IDXD_OP_FLAG_RCI;

		idxd_desc->crypto.req = req;
		idxd_desc->crypto.compress = false;
	} else if (req && async_mode && !disable_async)
		req->base.data = idxd_desc;

	ret = idxd_submit_desc(wq, idxd_desc);
	if (ret) {
		goto err;
	}

	/* Update stats */
	update_total_decomp_calls();
	update_wq_decomp_calls(wq);

	if (req && async_mode && !disable_async) {
		ret = -EINPROGRESS;
		goto out;
	}

	ret = check_completion(dev, idxd_desc->iax_completion, false, false);
	if (ret) {
		goto err;
	}

	*dlen = idxd_desc->iax_completion->output_size;

	idxd_free_desc(wq, idxd_desc);
out:
	return ret;
err:
	idxd_free_desc(wq, idxd_desc);

	goto out;
}

static int iaa_comp_compress(struct crypto_tfm *tfm,
			     const u8 *src, unsigned int slen,
			     u8 *dst, unsigned int *dlen)
{
	dma_addr_t src_addr, dst_addr;
	u32 compression_crc;
	struct idxd_wq *wq;
	struct device *dev;
	int cpu, ret = 0;

	if (!iaa_crypto_enabled) {
		pr_debug("iaa_crypto disabled, not compressing\n");
		return -ENODEV;
	}

	cpu = get_cpu();
	wq = wq_table_next_wq(cpu);
	put_cpu();
	if (!wq) {
		pr_debug("no wq configured for cpu=%d\n", cpu);
		ret = -ENODEV;
		goto out;
	}
	dev = &wq->idxd->pdev->dev;

	src_addr = dma_map_single(dev, (void *)src, slen, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(dev, src_addr))) {
		dev_dbg(dev, "dma_map_single err, exiting\n");
		ret = -ENOMEM;
		goto out;
	}

	dst_addr = dma_map_single(dev, (void *)dst, *dlen, DMA_FROM_DEVICE);
	if (unlikely(dma_mapping_error(dev, dst_addr))) {
		dev_dbg(dev, "dma_map_single err, exiting\n");
		ret = -ENOMEM;
		goto err_map_dst;
	}

	ret = iaa_compress(tfm, NULL, wq, src_addr, slen, dst_addr,
			   dlen, &compression_crc, true);

	if (iaa_verify_compress) {
		dma_sync_single_for_device(dev, dst_addr, *dlen, DMA_FROM_DEVICE);
		dma_sync_single_for_device(dev, src_addr, slen, DMA_TO_DEVICE);
		ret = iaa_compress_verify(tfm, NULL, wq, src_addr,
					  slen, dst_addr, dlen, compression_crc);
	}

	dma_unmap_single(dev, dst_addr, *dlen, DMA_FROM_DEVICE);
err_map_dst:
	dma_unmap_single(dev, src_addr, slen, DMA_TO_DEVICE);
out:
	return ret;
}

static int iaa_comp_decompress(struct crypto_tfm *tfm,
			       const u8 *src, unsigned int slen,
			       u8 *dst, unsigned int *dlen)
{
	dma_addr_t src_addr, dst_addr;
	struct idxd_wq *wq;
	struct device *dev;
	int cpu, ret = 0;

	if (!iaa_crypto_enabled) {
		pr_debug("iaa_crypto disabled, not decompressing\n");
		return -ENODEV;
	}

	cpu = get_cpu();
	wq = wq_table_next_wq(cpu);
	put_cpu();
	if (!wq) {
		pr_debug("no wq configured for cpu=%d\n", cpu);
		ret = -ENODEV;
		goto out;
	}
	dev = &wq->idxd->pdev->dev;

	src_addr = dma_map_single(dev, (void *)src, slen, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(dev, src_addr))) {
		dev_dbg(dev, "dma_map_single err, exiting\n");
		ret = -ENOMEM;
		goto out;
	}

	dst_addr = dma_map_single(dev, (void *)dst, *dlen, DMA_FROM_DEVICE);
	if (unlikely(dma_mapping_error(dev, dst_addr))) {
		dev_dbg(dev, "dma_map_single err, exiting\n");
		ret = -ENOMEM;
		goto err_map_dst;
	}

	ret = iaa_decompress(tfm, NULL, wq, src_addr, slen, dst_addr, dlen, true);

	dma_unmap_single(dev, dst_addr, *dlen, DMA_FROM_DEVICE);
err_map_dst:
	dma_unmap_single(dev, src_addr, slen, DMA_TO_DEVICE);
out:
	return ret;
}

static struct crypto_alg iaa_comp_deflate = {
	.cra_name		= "deflate",
	.cra_driver_name	= "iaa_crypto",
	.cra_flags		= CRYPTO_ALG_TYPE_COMPRESS,
	.cra_priority		= IAA_ALG_PRIORITY,
	.cra_module		= THIS_MODULE,
	.cra_u			= {
	.compress = {
			.coa_compress	= iaa_comp_compress,
			.coa_decompress	= iaa_comp_decompress
		}
	}
};

static int iaa_comp_acompress(struct acomp_req *req)
{
	struct crypto_tfm *tfm = req->base.tfm;
	dma_addr_t src_addr, dst_addr;
	int nr_sgs, cpu, ret = 0;
	struct iaa_wq *iaa_wq;
	u32 compression_crc;
	struct idxd_wq *wq;
	struct device *dev;

	if (!iaa_crypto_enabled) {
		pr_debug("iaa_crypto disabled, not compressing\n");
		return -ENODEV;
	}

	cpu = get_cpu();
	wq = wq_table_next_wq(cpu);
	put_cpu();
	if (!wq) {
		pr_debug("no wq configured for cpu=%d\n", cpu);
		ret = -ENODEV;
		goto out;
	}
	iaa_wq = wq->private_data;

	dev = &wq->idxd->pdev->dev;

	nr_sgs = dma_map_sg(dev, req->src, sg_nents(req->src), DMA_TO_DEVICE);
	if (nr_sgs <= 0 || nr_sgs > 1) {
		dev_dbg(dev, "couldn't map src sg for iaa device %d,"
			" wq %d: ret=%d\n", iaa_wq->iaa_device->idxd->id,
			iaa_wq->wq->id, ret);
		ret = -EIO;
		goto out;
	}
	src_addr = sg_dma_address(req->src);

	nr_sgs = dma_map_sg(dev, req->dst, sg_nents(req->dst), DMA_FROM_DEVICE);
	if (nr_sgs <= 0 || nr_sgs > 1) {
		dev_dbg(dev, "couldn't map dst sg for iaa device %d,"
			" wq %d: ret=%d\n", iaa_wq->iaa_device->idxd->id,
			iaa_wq->wq->id, ret);
		ret = -EIO;
		goto err_map_dst;
	}
	dst_addr = sg_dma_address(req->dst);

	ret = iaa_compress(tfm, req, wq, src_addr, req->slen, dst_addr,
			   &req->dlen, &compression_crc, false);
	if (ret == -EINPROGRESS)
		goto out;

	if (iaa_verify_compress) {
		dma_sync_sg_for_device(dev, req->dst, 1, DMA_FROM_DEVICE);
		dma_sync_sg_for_device(dev, req->src, 1, DMA_TO_DEVICE);
		ret = iaa_compress_verify(tfm, req, wq, src_addr, req->slen,
					  dst_addr, &req->dlen, compression_crc);
	}

	dma_unmap_sg(dev, req->dst, sg_nents(req->dst), DMA_FROM_DEVICE);
err_map_dst:
	dma_unmap_sg(dev, req->src, sg_nents(req->src), DMA_TO_DEVICE);
out:
	return ret;
}

static int iaa_comp_adecompress(struct acomp_req *req)
{
	struct crypto_tfm *tfm = req->base.tfm;
	dma_addr_t src_addr, dst_addr;
	int nr_sgs, cpu, ret = 0;
	struct iaa_wq *iaa_wq;
	struct device *dev;
	struct idxd_wq *wq;

	if (!iaa_crypto_enabled) {
		pr_debug("iaa_crypto disabled, not decompressing\n");
		return -ENODEV;
	}

	cpu = get_cpu();
	wq = wq_table_next_wq(cpu);
	put_cpu();
	if (!wq) {
		pr_debug("no wq configured for cpu=%d\n", cpu);
		ret = -ENODEV;
		goto out;
	}
	iaa_wq = wq->private_data;

	dev = &wq->idxd->pdev->dev;

	nr_sgs = dma_map_sg(dev, req->src, sg_nents(req->src), DMA_TO_DEVICE);
	if (nr_sgs <= 0 || nr_sgs > 1) {
		dev_dbg(dev, "couldn't map src sg for iaa device %d,"
			" wq %d: ret=%d\n", iaa_wq->iaa_device->idxd->id,
			iaa_wq->wq->id, ret);
		ret = -EIO;
		goto out;
	}
	src_addr = sg_dma_address(req->src);

	nr_sgs = dma_map_sg(dev, req->dst, sg_nents(req->dst), DMA_FROM_DEVICE);
	if (nr_sgs <= 0 || nr_sgs > 1) {
		dev_dbg(dev, "couldn't map dst sg for iaa device %d,"
			" wq %d: ret=%d\n", iaa_wq->iaa_device->idxd->id,
			iaa_wq->wq->id, ret);
		ret = -EIO;
		goto err_map_dst;
	}
	dst_addr = sg_dma_address(req->dst);

	ret = iaa_decompress(tfm, req, wq, src_addr, req->slen,
			     dst_addr, &req->dlen, false);
	if (ret == -EINPROGRESS)
		goto out;

	dma_unmap_sg(dev, req->dst, sg_nents(req->dst), DMA_FROM_DEVICE);
err_map_dst:
	dma_unmap_sg(dev, req->src, sg_nents(req->src), DMA_TO_DEVICE);
out:
	return ret;
}

static int iaa_comp_poll(struct acomp_req *req)
{
	struct idxd_desc *idxd_desc;
	struct idxd_device *idxd;
	struct iaa_wq *iaa_wq;
	struct pci_dev *pdev;
	struct device *dev;
	struct idxd_wq *wq;
	int ret;

	idxd_desc = req->base.data;
	if (!idxd_desc)
		return -EAGAIN;

	wq = idxd_desc->wq;
	iaa_wq = wq->private_data;
	idxd = iaa_wq->iaa_device->idxd;
	pdev = idxd->pdev;
	dev = &pdev->dev;

	ret = check_completion(dev, idxd_desc->iax_completion, true, true);
	if (ret == -EAGAIN)
		return ret;
	if (ret)
		goto out;

	req->dlen = idxd_desc->iax_completion->output_size;

	/* Update stats */
	update_total_comp_bytes_out(req->dlen);
	update_wq_comp_bytes(wq, req->dlen);

	if (iaa_verify_compress && (idxd_desc->iax_hw->opcode == IAX_OPCODE_COMPRESS)) {
		struct crypto_tfm *tfm = req->base.tfm;
		dma_addr_t src_addr, dst_addr;
		u32 compression_crc;

		compression_crc = idxd_desc->iax_completion->crc;

		dma_sync_sg_for_device(dev, req->dst, 1, DMA_FROM_DEVICE);
		dma_sync_sg_for_device(dev, req->src, 1, DMA_TO_DEVICE);

		src_addr = sg_dma_address(req->src);
		dst_addr = sg_dma_address(req->dst);

		ret = iaa_compress_verify(tfm, req, wq, src_addr, req->slen,
					  dst_addr, &req->dlen, compression_crc);
	}
out:
	/* caller doesn't call crypto_wait_req, so no acomp_request_complete() */

	dma_unmap_sg(dev, req->dst, sg_nents(req->dst), DMA_FROM_DEVICE);
	dma_unmap_sg(dev, req->src, sg_nents(req->src), DMA_TO_DEVICE);

	idxd_free_desc(idxd_desc->wq, idxd_desc);

	return ret;
}

static struct acomp_alg iaa_acomp_deflate = {
	.compress		= iaa_comp_acompress,
	.decompress		= iaa_comp_adecompress,
	.poll			= iaa_comp_poll,
	.base			= {
		.cra_name		= "deflate",
		.cra_driver_name	= "iaa_crypto",
		.cra_module		= THIS_MODULE,
		.cra_priority           = IAA_ALG_PRIORITY,
	}
};

static int iaa_register_compression_device(void)
{
	int ret;

	ret = crypto_register_alg(&iaa_comp_deflate);
	if (ret < 0) {
		pr_debug("deflate algorithm registration failed\n");
		return ret;
	}

	if (async_mode && !use_irq)
		iaa_acomp_deflate.poll = iaa_comp_poll;
	else
		iaa_acomp_deflate.poll = NULL;

	ret = crypto_register_acomp(&iaa_acomp_deflate);
	if (ret) {
		pr_err("deflate algorithm acomp registration failed (%d)\n", ret);
		goto err_unregister_alg_deflate;
	}

	return ret;

err_unregister_alg_deflate:
	crypto_unregister_alg(&iaa_comp_deflate);

	return ret;
}

static int iaa_unregister_compression_device(void)
{
	if (refcount_read(&iaa_acomp_deflate.base.cra_refcnt) > 1)
		return -EBUSY;

	crypto_unregister_alg(&iaa_comp_deflate);
	crypto_unregister_acomp(&iaa_acomp_deflate);

	return 0;
}

static int iaa_crypto_probe(struct idxd_dev *idxd_dev)
{
	struct idxd_wq *wq = idxd_dev_to_wq(idxd_dev);
	struct idxd_device *idxd = wq->idxd;
	struct idxd_driver_data *data = idxd->data;
	struct device *dev = &idxd_dev->conf_dev;
	bool first_wq = false;
	int ret = 0;

	if (idxd->state != IDXD_DEV_ENABLED)
		return -ENXIO;

	if (data->type != IDXD_TYPE_IAX)
		return -ENODEV;

	mutex_lock(&wq->wq_lock);

	if (!idxd_wq_driver_name_match(wq, dev)) {
		dev_dbg(dev, "wq %d.%d driver_name match failed: wq driver_name %s, dev driver name %s\n",
			idxd->id, wq->id, wq->driver_name, dev->driver->name);
		idxd->cmd_status = IDXD_SCMD_WQ_NO_DRV_NAME;
		ret = -ENODEV;
		goto err;
	}

	wq->type = IDXD_WQT_KERNEL;

	ret = drv_enable_wq(wq);
	if (ret < 0) {
		dev_dbg(dev, "enable wq %d.%d failed: %d\n",
			idxd->id, wq->id, ret);
		ret = -ENXIO;
		goto err;
	}

	mutex_lock(&iaa_devices_lock);

	if (list_empty(&iaa_devices)) {
		ret = alloc_wq_table(wq->idxd->max_wqs);
		if (ret)
			goto err_alloc;
		first_wq = true;
	}

	ret = save_iaa_wq(wq);
	if (ret)
		goto err_save;

	rebalance_wq_table();

	if (first_wq) {
		ret = iaa_register_compression_device();
		if (ret == 0) {
			iaa_crypto_enabled = true;
		} else {
			dev_dbg(dev, "IAA compression device registration failed\n");
			goto err_register;
		}

		pr_info("iaa_crypto now ENABLED\n");
	}

	mutex_unlock(&iaa_devices_lock);
out:
	mutex_unlock(&wq->wq_lock);

	return ret;

err_register:
	remove_iaa_wq(wq);
err_save:
	if (first_wq)
		free_wq_table();
err_alloc:
	mutex_unlock(&iaa_devices_lock);
	drv_disable_wq(wq);
err:
	wq->type = IDXD_WQT_NONE;

	goto out;
}

static void iaa_crypto_remove(struct idxd_dev *idxd_dev)
{
	struct idxd_wq *wq = idxd_dev_to_wq(idxd_dev);
	struct device *dev = &idxd_dev->conf_dev;

	idxd_wq_quiesce(wq);

	mutex_lock(&wq->wq_lock);
	mutex_lock(&iaa_devices_lock);

	remove_iaa_wq(wq);
	drv_disable_wq(wq);
	rebalance_wq_table();

	if (nr_iaa == 0) {
		iaa_crypto_enabled = false;
		free_wq_table();

		if (iaa_unregister_compression_device())
			dev_dbg(dev, "IAA compression device unregister failed\n");

		pr_info("iaa_crypto now DISABLED\n");
	}

	mutex_unlock(&iaa_devices_lock);
	mutex_unlock(&wq->wq_lock);
}

static enum idxd_dev_type dev_types[] = {
	IDXD_DEV_WQ,
	IDXD_DEV_NONE,
};

static struct idxd_device_driver iaa_crypto_driver = {
	.probe = iaa_crypto_probe,
	.remove = iaa_crypto_remove,
	.name = IDXD_SUBDRIVER_NAME,
	.type = dev_types,
	.desc_complete = iaa_desc_complete,
};

int wq_stats_show(struct seq_file *m, void *v)
{
	struct iaa_device *iaa_device;

	mutex_lock(&iaa_devices_lock);

	global_stats_show(m);

	list_for_each_entry(iaa_device, &iaa_devices, list)
		device_stats_show(m, iaa_device);

	mutex_unlock(&iaa_devices_lock);

	return 0;
}

int iaa_crypto_stats_reset(void *data, u64 value)
{
	struct iaa_device *iaa_device;

	reset_iaa_crypto_stats();

	mutex_lock(&iaa_devices_lock);

	list_for_each_entry(iaa_device, &iaa_devices, list)
		reset_device_stats(iaa_device);

	mutex_unlock(&iaa_devices_lock);

	return 0;
}

static int __init iaa_crypto_init_module(void)
{
	int ret = 0;

	nr_cpus = num_online_cpus();
	nr_nodes = num_online_nodes();
	nr_cpus_per_node = boot_cpu_data.x86_max_cores;

	ret = idxd_driver_register(&iaa_crypto_driver);
	if (ret) {
		pr_debug("IAA wq sub-driver registration failed\n");
		goto out;
	}

	ret = driver_create_file(&iaa_crypto_driver.drv,
				 &driver_attr_sync_mode);
	if (ret) {
		pr_debug("IAA sync mode attr creation failed\n");
		goto err_attr_create;
	}

	ret = driver_create_file(&iaa_crypto_driver.drv,
				 &driver_attr_compression_mode);
	if (ret) {
		pr_debug("IAA compression mode attr creation failed\n");
		goto err_attr_create;
	}

	ret = driver_create_file(&iaa_crypto_driver.drv,
				 &driver_attr_verify_compress);
	if (ret) {
		pr_debug("IAA verify_compress attr creation failed\n");
		goto err_attr_create;
	}

	ret = iaa_aecs_init_canned();
	if (ret < 0) {
		pr_debug("IAA canned compression mode init failed\n");
		goto err_compression_mode;
	}

	ret = iaa_aecs_init_fixed();
	if (ret < 0) {
		iaa_aecs_cleanup_canned();
		pr_debug("IAA fixed compression mode init failed\n");
		goto err_compression_mode;
	}

	if (iaa_crypto_debugfs_init())
		pr_warn("debugfs init failed, stats not available\n");

	pr_debug("initialized\n");
out:
	return ret;

err_compression_mode:
	driver_remove_file(&iaa_crypto_driver.drv,
			   &driver_attr_sync_mode);
	driver_remove_file(&iaa_crypto_driver.drv,
			   &driver_attr_compression_mode);
	driver_remove_file(&iaa_crypto_driver.drv,
			   &driver_attr_verify_compress);
err_attr_create:
	idxd_driver_unregister(&iaa_crypto_driver);

	goto out;
}

static void __exit iaa_crypto_cleanup_module(void)
{
	iaa_crypto_debugfs_cleanup();
	driver_remove_file(&iaa_crypto_driver.drv,
			   &driver_attr_sync_mode);
	driver_remove_file(&iaa_crypto_driver.drv,
			   &driver_attr_compression_mode);
	driver_remove_file(&iaa_crypto_driver.drv,
			   &driver_attr_verify_compress);
	idxd_driver_unregister(&iaa_crypto_driver);
	iaa_aecs_cleanup_canned();
	iaa_aecs_cleanup_fixed();

	pr_debug("cleaned up\n");
}

MODULE_IMPORT_NS(IDXD);
MODULE_LICENSE("GPL");
MODULE_ALIAS_IDXD_DEVICE(0);
MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("IAA Compression Accelerator Crypto Driver");

module_init(iaa_crypto_init_module);
module_exit(iaa_crypto_cleanup_module);
