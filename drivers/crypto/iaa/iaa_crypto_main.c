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

/* Number of physical cpus sharing each iaa instance */
static unsigned int cpus_per_iaa;

/* Per-cpu lookup table for balanced wqs */
static struct idxd_wq * __percpu *wq_table;

/* If enabled, IAA hw crypto is being used, software deflate otherwise */
static bool iaa_crypto_enabled;

/* IAA completion timeout value in tsc units */
static unsigned int iaa_completion_timeout = IAA_COMPLETION_TIMEOUT;

module_param_named(iaa_completion_timeout, iaa_completion_timeout, uint, 0644);
MODULE_PARM_DESC(iaa_completion_timeout, "IAA completion timeout (1000000 cycles default)");

/* Verify results of IAA compress or not */
static bool iaa_verify_compress = 1;

module_param_named(iaa_verify_compress, iaa_verify_compress, bool, 0644);
MODULE_PARM_DESC(iaa_verify_compress,
		 "Verify IAA compression (value = 1) or not (value = 0)");

static struct crypto_comp *deflate_generic_tfm;

static LIST_HEAD(iaa_devices);
static DEFINE_MUTEX(iaa_devices_lock);

static int iaa_wqs_get(struct iaa_device *iaa_device)
{
	struct iaa_wq *iaa_wq;
	int n_wqs = 0;

	list_for_each_entry(iaa_wq, &iaa_device->wqs, list) {
		idxd_wq_get(iaa_wq->wq);
		n_wqs++;
	}

	return n_wqs;
}

static void iaa_wqs_put(struct iaa_device *iaa_device)
{
	struct iaa_wq *iaa_wq;

	list_for_each_entry(iaa_wq, &iaa_device->wqs, list)
		idxd_wq_put(iaa_wq->wq);
}

static int iaa_all_wqs_get(void)
{
	struct iaa_device *iaa_device;
	int n_wqs = 0;
	int ret;

	mutex_lock(&iaa_devices_lock);
	list_for_each_entry(iaa_device, &iaa_devices, list) {
		ret = iaa_wqs_get(iaa_device);
		if (ret < 0) {
			mutex_unlock(&iaa_devices_lock);
			return ret;
		}
		n_wqs += ret;
	}
	mutex_unlock(&iaa_devices_lock);

	return n_wqs;
}

static void iaa_all_wqs_put(void)
{
	struct iaa_device *iaa_device;

	mutex_lock(&iaa_devices_lock);
	list_for_each_entry(iaa_device, &iaa_devices, list)
		iaa_wqs_put(iaa_device);
	mutex_unlock(&iaa_devices_lock);
}

static int iaa_crypto_enable(const char *val, const struct kernel_param *kp)
{
	int ret = 0;

	if (val[0] == '0') {
		iaa_crypto_enabled = false;
		iaa_all_wqs_put();
	} else if (val[0] == '1') {
		ret = iaa_all_wqs_get();
		if (ret == 0) {
			pr_debug("no wqs available, not enabling iaa_crypto\n");
			return ret;
		} else if (ret < 0) {
			pr_debug("iaa_crypto enable failed: ret=%d\n", ret);
			return ret;
		} else {
			iaa_crypto_enabled = true;
			ret = 0;
		}
	} else {
		pr_debug("iaa_crypto failed, bad enable val: ret=%d\n", -EINVAL);
		return -EINVAL;
	}

	pr_info("iaa_crypto now %s\n",
		iaa_crypto_enabled ? "ENABLED" : "DISABLED");

	return ret;
}

static const struct kernel_param_ops enable_ops = {
	.set = iaa_crypto_enable,
	.get = param_get_bool,
};

module_param_cb(iaa_crypto_enable, &enable_ops, &iaa_crypto_enabled, 0644);
MODULE_PARM_DESC(iaa_crypto_enable, "Enable (value = 1) or disable (value = 0) iaa_crypto");

/*
 * Given a cpu, find the closest IAA instance.  The idea is to try to
 * choose the most appropriate IAA instance for a caller and spread
 * available workqueues around to clients.
 */
static inline int cpu_to_iaa(int cpu)
{
	const struct cpumask *node_cpus;
	int node, n_cpus = 0, test_cpu, iaa = 0;
	int nr_iaa_per_node;

	nr_iaa_per_node = nr_iaa / nr_nodes;

	for_each_online_node(node) {
		node_cpus = cpumask_of_node(node);
		if (!cpumask_test_cpu(cpu, node_cpus))
			continue;

		iaa = node * nr_iaa_per_node;

		for_each_cpu(test_cpu, node_cpus) {
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

static void free_iaa_devices(void)
{
	struct iaa_device *iaa_device, *next;

	mutex_lock(&iaa_devices_lock);
	list_for_each_entry_safe(iaa_device, next, &iaa_devices, list) {
		list_del(&iaa_device->list);
		iaa_device_free(iaa_device);
	}
	mutex_unlock(&iaa_devices_lock);
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

	if (iaa_aecs_alloc(iaa_device) < 0)
		return NULL;

	list_add_tail(&iaa_device->list, &iaa_devices);

	nr_iaa++;

	return iaa_device;
}

static void del_iaa_device(struct iaa_device *iaa_device)
{
	iaa_aecs_free(iaa_device);

	list_del(&iaa_device->list);

	iaa_device_free(iaa_device);

	nr_iaa--;
}

static int add_iaa_wq(struct iaa_device *iaa_device, struct idxd_wq *wq)
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

	dev_dbg(dev, "added wq %p to iaa %p, n_wq %d\n",
		wq, iaa_device, iaa_device->n_wq);

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

			dev_dbg(dev, "removed wq %p from iaa_device %p, n_wq %d, nr_iaa %d\n",
				wq, iaa_device, iaa_device->n_wq, nr_iaa);

			if (iaa_device->n_wq == 0) {
				del_iaa_device(iaa_device);
				break;
			}
		}
	}
}

static int save_iaa_wq(struct idxd_wq *wq)
{
	struct iaa_device *iaa_device, *found = NULL;
	struct idxd_device *idxd;
	struct pci_dev *pdev;
	struct device *dev;
	int ret = 0;

	mutex_lock(&iaa_devices_lock);
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

			ret = add_iaa_wq(iaa_device, wq);
			if (ret)
				goto out;

			break;
		}
	}

	if (!found) {
		struct iaa_device *new;

		new = add_iaa_device(wq->idxd);
		if (!new) {
			ret = -ENOMEM;
			goto out;
		}

		ret = add_iaa_wq(new, wq);
		if (ret) {
			del_iaa_device(new);
			goto out;
		}
	}

	if (WARN_ON(nr_iaa == 0))
		return -EINVAL;

	cpus_per_iaa = nr_cpus / nr_iaa;
out:
	mutex_unlock(&iaa_devices_lock);

	return 0;
}

static void clear_wq_table(void)
{
	int cpu;

	for (cpu = 0; cpu < nr_cpus; cpu++)
		*per_cpu_ptr(wq_table, cpu) = NULL;

	pr_debug("cleared wq table\n");
}

static void remove_iaa_wq(struct idxd_wq *wq)
{
	struct iaa_device *iaa_device;

	mutex_lock(&iaa_devices_lock);
	list_for_each_entry(iaa_device, &iaa_devices, list) {
		if (iaa_has_wq(iaa_device, wq)) {
			del_iaa_wq(iaa_device, wq);
			if (nr_iaa == 0)
				clear_wq_table();
			break;
		}
	}
	mutex_unlock(&iaa_devices_lock);

	if (nr_iaa)
		cpus_per_iaa = nr_cpus / nr_iaa;
	else
		cpus_per_iaa = 0;
}

static struct idxd_wq *request_iaa_wq(int iaa)
{
	struct iaa_device *iaa_device, *found_device = NULL;
	struct idxd_wq *bkup_wq = NULL, *found_wq = NULL;
	int cur_iaa = 0, cur_wq = 0, cur_bkup;
	struct idxd_device *idxd;
	struct iaa_wq *iaa_wq;
	struct pci_dev *pdev;
	struct device *dev;

	mutex_lock(&iaa_devices_lock);
	list_for_each_entry(iaa_device, &iaa_devices, list) {
		idxd = iaa_device->idxd;
		pdev = idxd->pdev;
		dev = &pdev->dev;

		if (cur_iaa != iaa) {
			cur_iaa++;
			continue;
		}

		found_device = iaa_device;
		dev_dbg(dev, "getting wq from iaa_device %p (%d)\n",
			found_device, cur_iaa);
		break;
	}

	if (!found_device) {
		found_device = list_first_entry_or_null(&iaa_devices,
							struct iaa_device, list);
		if (!found_device) {
			pr_debug("couldn't find any iaa devices with wqs!\n");
			goto out;
		}
		cur_iaa = 0;

		idxd = found_device->idxd;
		pdev = idxd->pdev;
		dev = &pdev->dev;
		dev_dbg(dev, "getting wq from only iaa_device %p (%d)\n",
			found_device, cur_iaa);
	}

	list_for_each_entry(iaa_wq, &found_device->wqs, list) {
		/* Prefer unused wq but use if we can't find one */
		if (idxd_wq_refcount(iaa_wq->wq) > 0) {
			bkup_wq = iaa_wq->wq;
			cur_bkup = cur_wq;
		} else {
			dev_dbg(dev, "returning unused wq %p (%d) from iaa device %p (%d)\n",
				iaa_wq->wq, cur_wq, found_device, cur_iaa);
			found_wq = iaa_wq->wq;
			goto out;
		}
		cur_wq++;
	}

	if (bkup_wq) {
		dev_dbg(dev, "returning used wq %p (%d) from iaa device %p (%d)\n",
			bkup_wq, cur_bkup, found_device, cur_iaa);
		found_wq = bkup_wq;
		goto out;
	}
out:
	mutex_unlock(&iaa_devices_lock);

	return found_wq;
}

static void rebalance_wq_table(void)
{
	int node, cpu, iaa;
	struct idxd_wq *wq;

	if (nr_iaa == 0)
		return;

	pr_debug("nr_nodes=%d, nr_cpus %d, nr_iaa %d, cpus_per_iaa %d\n",
		 nr_nodes, nr_cpus, nr_iaa, cpus_per_iaa);

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		iaa = cpu_to_iaa(cpu);
		pr_debug("iaa=%d\n", iaa);

		if (WARN_ON(iaa == -1)) {
			pr_debug("rebalance (cpu_to_iaa(%d)) failed!\n", cpu);
			return;
		}

		wq = request_iaa_wq(iaa);
		if (!wq) {
			pr_debug("could not get wq for iaa %d!\n", iaa);
			return;
		}

		*per_cpu_ptr(wq_table, cpu) = wq;
		pr_debug("assigned wq for cpu=%d, node=%d = wq %p\n",
			 cpu, node, wq);
	}
}

static inline int check_completion(struct device *dev,
				   struct iax_completion_record *comp,
				   bool compress)
{
	char *op_str = compress ? "compress" : "decompress";
	int ret = 0;

	while (!comp->status)
		cpu_relax();

	if (comp->status != IAX_COMP_SUCCESS) {
		if (comp->status == IAA_ERROR_WATCHDOG_EXPIRED) {
			ret = -ETIMEDOUT;
			dev_dbg(dev, "%s timed out, size=0x%x\n",
				op_str, comp->output_size);
			update_completion_timeout_errs();
			goto out;
		}

		if (comp->status == IAA_ANALYTICS_ERROR &&
		    comp->error_code == IAA_ERROR_COMP_BUF_OVERFLOW &&
		    compress == true) {
			ret = -E2BIG;
			dev_dbg(dev, "compressed > uncompressed size,"
				" not compressing, size=0x%x\n",
				comp->output_size);
			update_completion_comp_buf_overflow_errs();
			goto out;
		}

		ret = -EINVAL;
		dev_dbg(dev, "iaa %s status=0x%x, error=0x%x, size=0x%x\n",
			op_str, comp->status, comp->error_code, comp->output_size);
		print_hex_dump(KERN_INFO, "cmp-rec: ", DUMP_PREFIX_OFFSET, 8, 1, comp, 64, 0);
		update_completion_einval_errs();

		goto out;
	}
out:
	return ret;
}

static int iaa_compress(struct crypto_tfm *tfm,	struct idxd_wq *wq,
			dma_addr_t src_addr, unsigned int slen,
			dma_addr_t dst_addr, unsigned int *dlen,
			u32 *compression_crc)
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
	desc->priv = 1;

	desc->src1_addr = (u64)src_addr;
	desc->src1_size = slen;
	desc->dst_addr = (u64)dst_addr;
	desc->max_dst_size = *dlen;
	desc->src2_addr = iaa_wq->iaa_device->aecs_table_dma_addr;
	desc->src2_size = sizeof(struct aecs_table_record);
	desc->completion_addr = idxd_desc->compl_dma;

	dev_dbg(dev, "desc->src1_addr %llx, desc->src1_size %d,"
		"desc->dst_addr %llx, desc->max_dst_size %d,"
		"desc->src2_addr %llx, desc->src2_size %d\n",
		desc->src1_addr, desc->src1_size, desc->dst_addr,
		desc->max_dst_size, desc->src2_addr, desc->src2_size);

	ret = idxd_submit_desc(wq, idxd_desc);
	if (ret) {
		dev_dbg(dev, "submit_desc failed ret=%d\n", ret);
		goto err;
	}

	ret = check_completion(dev, idxd_desc->iax_completion, true);
	if (ret) {
		dev_dbg(dev, "check_completion failed ret=%d\n", ret);
		goto err;
	}

	*dlen = idxd_desc->iax_completion->output_size;

	/* Update stats */
	update_total_comp_calls();
	update_total_comp_bytes_out(*dlen);
	update_wq_comp_calls(wq);
	update_wq_comp_bytes(wq, *dlen);

	*compression_crc = idxd_desc->iax_completion->crc;

	idxd_free_desc(wq, idxd_desc);
out:
	return ret;
err:
	idxd_free_desc(wq, idxd_desc);
	dev_dbg(dev, "iaa compress failed: ret=%d\n", ret);

	goto out;
}

static int iaa_compress_verify(struct crypto_tfm *tfm,	struct idxd_wq *wq,
			       dma_addr_t src_addr, unsigned int slen,
			       dma_addr_t dst_addr, unsigned int *dlen,
			       u32 compression_crc)
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
		dev_dbg(dev, "iaa compress failed: ret=%ld\n",
			PTR_ERR(idxd_desc));
		return PTR_ERR(idxd_desc);
	}
	desc = idxd_desc->iax_hw;

	/* Verify (optional) - decompress and check crc, suppress dest write */

	desc->flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_CC;
	desc->opcode = IAX_OPCODE_DECOMPRESS;
	desc->decompr_flags = IAA_DECOMP_FLAGS | IAA_DECOMP_SUPPRESS_OUTPUT;
	desc->priv = 1;

	desc->src1_addr = (u64)dst_addr;
	desc->src1_size = *dlen;
	desc->dst_addr = (u64)src_addr;
	desc->max_dst_size = slen;
	desc->completion_addr = idxd_desc->compl_dma;

	dev_dbg(dev, "(verify) desc->src1_addr %llx, desc->src1_size %d,"
		" desc->dst_addr %llx, desc->max_dst_size %d,"
		" desc->src2_addr %llx, desc->src2_size %d\n",
		desc->src1_addr, desc->src1_size, desc->dst_addr,
		desc->max_dst_size, desc->src2_addr, desc->src2_size);

	ret = idxd_submit_desc(wq, idxd_desc);
	if (ret) {
		dev_dbg(dev, "submit_desc (verify) failed ret=%d\n", ret);
		goto err;
	}

	ret = check_completion(dev, idxd_desc->iax_completion, true);
	if (ret) {
		dev_dbg(dev, "(verify) check_completion failed ret=%d\n", ret);
		goto err;
	}

	if (compression_crc != idxd_desc->iax_completion->crc) {
		ret = -EINVAL;
		dev_dbg(dev, "(verify) iaa comp/decomp crc mismatch:"
			" comp=0x%x, decomp=0x%x\n", compression_crc,
			idxd_desc->iax_completion->crc);
		print_hex_dump(KERN_INFO, "cmp-rec: ", DUMP_PREFIX_OFFSET,
			       8, 1, idxd_desc->iax_completion, 64, 0);
		goto err;
	}

	idxd_free_desc(wq, idxd_desc);
out:
	return ret;
err:
	idxd_free_desc(wq, idxd_desc);
	dev_dbg(dev, "iaa compress failed: ret=%d\n", ret);

	goto out;
}

static int iaa_decompress(struct crypto_tfm *tfm, struct idxd_wq *wq,
			  dma_addr_t src_addr, unsigned int slen,
			  dma_addr_t dst_addr, unsigned int *dlen)
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
		dev_dbg(dev, "iaa decompress failed: ret=%ld\n",
			PTR_ERR(idxd_desc));
		return PTR_ERR(idxd_desc);
	}
	desc = idxd_desc->iax_hw;

	desc->flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_CC;
	desc->opcode = IAX_OPCODE_DECOMPRESS;
	desc->max_dst_size = PAGE_SIZE;
	desc->decompr_flags = IAA_DECOMP_FLAGS;
	desc->priv = 1;

	desc->src1_addr = (u64)src_addr;
	desc->dst_addr = (u64)dst_addr;
	desc->max_dst_size = *dlen;
	desc->src1_size = slen;
	desc->completion_addr = idxd_desc->compl_dma;

	dev_dbg(dev, "desc->src1_addr %llx, desc->src1_size %d,"
		" desc->dst_addr %llx, desc->max_dst_size %d,"
		" desc->src2_addr %llx, desc->src2_size %d\n",
		desc->src1_addr, desc->src1_size, desc->dst_addr,
		desc->max_dst_size, desc->src2_addr, desc->src2_size);

	ret = idxd_submit_desc(wq, idxd_desc);
	if (ret) {
		dev_dbg(dev, "submit_desc failed ret=%d\n", ret);
		goto err;
	}

	ret = check_completion(dev, idxd_desc->iax_completion, true);
	if (ret) {
		dev_dbg(dev, "check_completion failed ret=%d\n", ret);
		goto err;
	}

	*dlen = idxd_desc->iax_completion->output_size;

	idxd_free_desc(wq, idxd_desc);

	/* Update stats */
	update_total_decomp_calls();
	update_total_decomp_bytes_in(slen);
	update_wq_decomp_calls(wq);
	update_wq_decomp_bytes(wq, slen);
out:
	return ret;
err:
	idxd_free_desc(wq, idxd_desc);
	dev_dbg(dev, "iaa decompress failed: ret=%d\n", ret);

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
	u64 start_time_ns;
	int cpu, ret = 0;

	if (!iaa_crypto_enabled) {
		pr_debug("iaa_crypto disabled, using deflate-generic"
			 " compression\n");
		ret = crypto_comp_compress(deflate_generic_tfm,
					   src, slen, dst, dlen);
		return ret;
	}

	cpu = get_cpu();
	wq = *per_cpu_ptr(wq_table, cpu);
	put_cpu();
	if (!wq) {
		pr_debug("no wq configured for cpu=%d\n", cpu);
		ret = -ENODEV;
		goto out;
	}
	dev = &wq->idxd->pdev->dev;

	src_addr = dma_map_single(dev, (void *)src, slen, DMA_TO_DEVICE);
	dev_dbg(dev, "dma_map_single, src_addr %llx, dev %p,"
		" src %p, slen %d\n", src_addr, dev, src, slen);
	if (unlikely(dma_mapping_error(dev, src_addr))) {
		dev_dbg(dev, "dma_map_single err, exiting\n");
		ret = -ENOMEM;
		goto out;
	}

	dst_addr = dma_map_single(dev, (void *)dst, *dlen, DMA_FROM_DEVICE);
	dev_dbg(dev, "dma_map_single, dst_addr %llx, dev %p,"
		" dst %p, *dlen %d\n", dst_addr, dev, dst, *dlen);
	if (unlikely(dma_mapping_error(dev, dst_addr))) {
		dev_dbg(dev, "dma_map_single err, exiting\n");
		ret = -ENOMEM;
		goto err_map_dst;
	}

	dev_dbg(dev, "src %p, src_addr %llx, slen %d, dst %p,"
		" dst_addr %llx, dlen %u\n", src, src_addr,
		slen, dst, dst_addr, *dlen);

	start_time_ns = ktime_get_ns();
	ret = iaa_compress(tfm, wq, src_addr, slen, dst_addr, dlen, &compression_crc);
	update_max_comp_delay_ns(start_time_ns);
	if (iaa_verify_compress) {
		dma_sync_single_for_device(dev, dst_addr, *dlen, DMA_FROM_DEVICE);
		dma_sync_single_for_device(dev, src_addr, slen, DMA_TO_DEVICE);
		ret = iaa_compress_verify(tfm, wq, src_addr, slen, dst_addr, dlen, compression_crc);
	}

	if (ret != 0)
		dev_dbg(dev, "synchronous compress failed ret=%d\n", ret);

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
	u64 start_time_ns;
	int cpu, ret = 0;

	if (!iaa_crypto_enabled) {
		pr_debug("iaa_crypto disabled, using deflate-generic"
			 " decompression\n");
		ret = crypto_comp_decompress(deflate_generic_tfm,
					     src, slen, dst, dlen);
		goto out;
	}

	cpu = get_cpu();
	wq = *per_cpu_ptr(wq_table, cpu);
	put_cpu();
	if (!wq) {
		pr_debug("no wq configured for cpu=%d\n", cpu);
		ret = -ENODEV;
		goto out;
	}
	dev = &wq->idxd->pdev->dev;

	dev_dbg(dev, "using wq for cpu=%d = wq %p\n", cpu, wq);

	src_addr = dma_map_single(dev, (void *)src, slen, DMA_TO_DEVICE);
	dev_dbg(dev, "dma_map_single, src_addr %llx, dev %p,"
		" src %p, slen %d\n", src_addr, dev, src, slen);
	if (unlikely(dma_mapping_error(dev, src_addr))) {
		dev_dbg(dev, "dma_map_single err, exiting\n");
		ret = -ENOMEM;
		goto out;
	}

	dst_addr = dma_map_single(dev, (void *)dst, *dlen, DMA_FROM_DEVICE);
	dev_dbg(dev, "dma_map_single, dst_addr %llx, dev %p,"
		" dst %p, *dlen %d\n", dst_addr, dev, dst, *dlen);
	if (unlikely(dma_mapping_error(dev, dst_addr))) {
		dev_dbg(dev, "dma_map_single err, exiting\n");
		ret = -ENOMEM;
		goto err_map_dst;
	}

	dev_dbg(dev, "src %p, src_addr %llx, slen %d, dst %p,"
		" dst_addr %llx, dlen %u\n", src, src_addr,
		slen, dst, dst_addr, *dlen);

	start_time_ns = ktime_get_ns();
	ret = iaa_decompress(tfm, wq, src_addr, slen, dst_addr, dlen);
	update_max_decomp_delay_ns(start_time_ns);
	if (ret != 0)
		dev_dbg(dev, "synchronous decompress failed ret=%d\n", ret);

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
	u64 start_time_ns;

	if (!iaa_crypto_enabled) {
		void *src, *dst;

		pr_debug("iaa_crypto disabled, using "
			 "deflate-generic compression\n");
		src = kmap_atomic(sg_page(req->src)) + req->src->offset;
		dst = kmap_atomic(sg_page(req->dst)) + req->dst->offset;

		ret = crypto_comp_compress(deflate_generic_tfm,
					   src, req->slen, dst, &req->dlen);
		kunmap_atomic(src);
		kunmap_atomic(dst);

		return ret;
	}

	cpu = get_cpu();
	wq = *per_cpu_ptr(wq_table, cpu);
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
	dev_dbg(dev, "dma_map_sg, src_addr %llx, nr_sgs %d, req->src %p,"
		" req->slen %d, sg_dma_len(sg) %d\n", src_addr, nr_sgs,
		req->src, req->slen, sg_dma_len(req->src));

	nr_sgs = dma_map_sg(dev, req->dst, sg_nents(req->dst), DMA_FROM_DEVICE);
	if (nr_sgs <= 0 || nr_sgs > 1) {
		dev_dbg(dev, "couldn't map dst sg for iaa device %d,"
			" wq %d: ret=%d\n", iaa_wq->iaa_device->idxd->id,
			iaa_wq->wq->id, ret);
		ret = -EIO;
		goto err_map_dst;
	}
	dst_addr = sg_dma_address(req->dst);
	dev_dbg(dev, "dma_map_sg, dst_addr %llx, nr_sgs %d, req->dst %p,"
		" req->dlen %d, sg_dma_len(sg) %d\n", dst_addr, nr_sgs,
		req->dst, req->dlen, sg_dma_len(req->dst));

	start_time_ns = ktime_get_ns();
	ret = iaa_compress(tfm, wq, src_addr, req->slen, dst_addr, &req->dlen, &compression_crc);
	update_max_acomp_delay_ns(start_time_ns);

	if (iaa_verify_compress) {
		dma_sync_sg_for_device(dev, req->dst, 1, DMA_FROM_DEVICE);
		dma_sync_sg_for_device(dev, req->src, 1, DMA_TO_DEVICE);
		ret = iaa_compress_verify(tfm, wq, src_addr, req->slen, dst_addr, &req->dlen, compression_crc);
	}

	if (ret != 0)
		dev_dbg(dev, "asynchronous compress failed ret=%d\n", ret);

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
	u64 start_time_ns;
	void *src, *dst;

	if (!iaa_crypto_enabled) {
		pr_debug("iaa_crypto disabled, using deflate-generic"
			 " decompression\n");
		src = kmap_atomic(sg_page(req->src)) + req->src->offset;
		dst = kmap_atomic(sg_page(req->dst)) + req->dst->offset;

		ret = crypto_comp_decompress(deflate_generic_tfm,
					     src, req->slen, dst, &req->dlen);
		kunmap_atomic(src);
		kunmap_atomic(dst);
		return ret;
	}

	cpu = get_cpu();
	wq = *per_cpu_ptr(wq_table, cpu);
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
	dev_dbg(dev, "dma_map_sg, src_addr %llx, nr_sgs %d, req->src %p,"
		" req->slen %d, sg_dma_len(sg) %d\n", src_addr, nr_sgs,
		req->src, req->slen, sg_dma_len(req->src));

	nr_sgs = dma_map_sg(dev, req->dst, sg_nents(req->dst), DMA_FROM_DEVICE);
	if (nr_sgs <= 0 || nr_sgs > 1) {
		dev_dbg(dev, "couldn't map dst sg for iaa device %d,"
			" wq %d: ret=%d\n", iaa_wq->iaa_device->idxd->id,
			iaa_wq->wq->id, ret);
		ret = -EIO;
		goto err_map_dst;
	}
	dst_addr = sg_dma_address(req->dst);
	dev_dbg(dev, "dma_map_sg, dst_addr %llx, nr_sgs %d, req->dst %p,"
		" req->dlen %d, sg_dma_len(sg) %d\n", dst_addr, nr_sgs,
		req->dst, req->dlen, sg_dma_len(req->dst));

	start_time_ns = ktime_get_ns();
	ret = iaa_decompress(tfm, wq, src_addr, req->slen, dst_addr, &req->dlen);
	update_max_decomp_delay_ns(start_time_ns);
	if (ret != 0)
		dev_dbg(dev, "asynchronous decompress failed ret=%d\n", ret);

	dma_unmap_sg(dev, req->dst, sg_nents(req->dst), DMA_FROM_DEVICE);
err_map_dst:
	dma_unmap_sg(dev, req->src, sg_nents(req->src), DMA_TO_DEVICE);
out:
	return ret;
}

static struct acomp_alg iaa_acomp_deflate = {
	.compress		= iaa_comp_acompress,
	.decompress		= iaa_comp_adecompress,
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

static void iaa_unregister_compression_device(void)
{
	crypto_unregister_alg(&iaa_comp_deflate);
	crypto_unregister_acomp(&iaa_acomp_deflate);
}

static int iaa_crypto_probe(struct idxd_dev *idxd_dev)
{
	struct idxd_wq *wq = idxd_dev_to_wq(idxd_dev);
	struct idxd_device *idxd = wq->idxd;
	struct idxd_driver_data *data = idxd->data;
	struct device *dev = &idxd_dev->conf_dev;
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

	ret = save_iaa_wq(wq);
	if (ret)
		goto err_save;

	rebalance_wq_table();
out:
	mutex_unlock(&wq->wq_lock);

	return ret;

err_save:
	drv_disable_wq(wq);
err:
	wq->type = IDXD_WQT_NONE;

	goto out;
}

static void iaa_crypto_remove(struct idxd_dev *idxd_dev)
{
	struct idxd_wq *wq = idxd_dev_to_wq(idxd_dev);

	idxd_wq_quiesce(wq);

	mutex_lock(&wq->wq_lock);
	remove_iaa_wq(wq);
	drv_disable_wq(wq);
	rebalance_wq_table();
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

	if (crypto_has_comp("deflate-generic", 0, 0))
		deflate_generic_tfm = crypto_alloc_comp("deflate-generic", 0, 0);

	if (IS_ERR_OR_NULL(deflate_generic_tfm)) {
		pr_debug("IAA could not alloc %s tfm: errcode = %ld\n",
			 "deflate-generic", PTR_ERR(deflate_generic_tfm));
		return -ENOMEM;
	}

	wq_table = alloc_percpu(struct idxd_wq *);
	if (!wq_table)
		return -ENOMEM;

	ret = idxd_driver_register(&iaa_crypto_driver);
	if (ret) {
		pr_debug("IAA wq sub-driver registration failed\n");
		goto err_driver_register;
	}

	ret = iaa_register_compression_device();
	if (ret < 0) {
		pr_debug("IAA compression device registration failed\n");
		goto err_crypto_register;
	}

	if (iaa_crypto_debugfs_init())
		pr_warn("debugfs init failed, stats not available\n");

	pr_debug("initialized\n");
out:
	return ret;

err_crypto_register:
	idxd_driver_unregister(&iaa_crypto_driver);
err_driver_register:
	crypto_free_comp(deflate_generic_tfm);
	free_percpu(wq_table);

	goto out;
}

static void __exit iaa_crypto_cleanup_module(void)
{
	iaa_crypto_debugfs_cleanup();
	idxd_driver_unregister(&iaa_crypto_driver);
	iaa_unregister_compression_device();
	free_percpu(wq_table);
	free_iaa_devices();

	crypto_free_comp(deflate_generic_tfm);
	pr_debug("cleaned up\n");
}

MODULE_IMPORT_NS(IDXD);
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_IDXD_DEVICE(0);
MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("IAA Compression Accelerator Crypto Driver");

module_init(iaa_crypto_init_module);
module_exit(iaa_crypto_cleanup_module);
