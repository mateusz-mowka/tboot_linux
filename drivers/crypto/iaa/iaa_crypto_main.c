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

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt)			"idxd: " IDXD_SUBDRIVER_NAME ": " fmt

/* number of iaa instances probed */
static unsigned int nr_iaa;

static unsigned int nr_cpus;
static unsigned int nr_nodes;

/* Number of physical cpus sharing each iaa instance */
static unsigned int cpus_per_iaa;

/* Per-cpu lookup table for balanced wqs */
static struct idxd_wq * __percpu *wq_table;

static LIST_HEAD(iaa_devices);
static DEFINE_MUTEX(iaa_devices_lock);

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

	list_add_tail(&iaa_device->list, &iaa_devices);

	nr_iaa++;

	return iaa_device;
}

static void del_iaa_device(struct iaa_device *iaa_device)
{
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

static int __init iaa_crypto_init_module(void)
{
	int ret = 0;

	nr_cpus = num_online_cpus();
	nr_nodes = num_online_nodes();

	wq_table = alloc_percpu(struct idxd_wq *);
	if (!wq_table)
		return -ENOMEM;

	ret = idxd_driver_register(&iaa_crypto_driver);
	if (ret) {
		pr_debug("IAA wq sub-driver registration failed\n");
		goto err_driver_register;
	}

	pr_debug("initialized\n");
out:
	return ret;

err_driver_register:
	free_percpu(wq_table);

	goto out;
}

static void __exit iaa_crypto_cleanup_module(void)
{
	idxd_driver_unregister(&iaa_crypto_driver);
	free_percpu(wq_table);
	free_iaa_devices();

	pr_debug("cleaned up\n");
}

MODULE_IMPORT_NS(IDXD);
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_IDXD_DEVICE(0);
MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("IAA Compression Accelerator Crypto Driver");

module_init(iaa_crypto_init_module);
module_exit(iaa_crypto_cleanup_module);
