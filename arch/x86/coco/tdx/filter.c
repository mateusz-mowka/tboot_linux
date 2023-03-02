// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Intel Corporation
 */
#define pr_fmt(fmt) "TDX: " fmt

#include <linux/acpi.h>
#include <linux/pci.h>
#include <linux/pci-tdisp.h>
#include <linux/device.h>
#include <linux/cc_platform.h>
#include <linux/export.h>
#include <uapi/linux/virtio_ids.h>
#include <crypto/hash.h>

#include <asm/tdx.h>
#include <asm/cmdline.h>

#define CMDLINE_MAX_NODES		100
#define CMDLINE_MAX_LEN			1000

/*
 * struct authorize_node - Device authorization node
 *
 * @bus: Name of the bus
 * @dev_list: device allow list per bus device type (eg:
 *            struct pci_device_id). If NULL, allow all
 *            devices.
 */
struct authorize_node {
	const char *bus;
	void *dev_list;
};

/*
 * Memory to store data passed via command line options
 * authorize_allow_devs.
 */
static char cmd_authorized_devices[CMDLINE_MAX_LEN];
static struct authorize_node cmd_allowed_nodes[CMDLINE_MAX_NODES];
static struct pci_device_id cmd_pci_ids[CMDLINE_MAX_NODES];
static int cmd_pci_nodes_len;
static int cmd_allowed_nodes_len;
static char acpi_allowed[CMDLINE_MAX_LEN];

/* Set true if authorize_allow_devs is used */
static bool filter_overridden;

#define PCI_DEVICE_DATA2(vend, dev, data) \
	.vendor = vend, .device = dev, \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID, 0, 0, \
	.driver_data = (kernel_ulong_t)(data)

/*
 * Allow list for PCI bus
 *
 * NOTE: Device ID is duplicated here. But for small list
 * of devices, it is easier to maintain the duplicated list
 * here verses exporting the device ID table from the driver
 * and use it.
 */
struct pci_device_id pci_allow_ids[] = {
	{ PCI_DEVICE_DATA2(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO_TRANS_ID_NET, MODE_SHARED) },
	{ PCI_DEVICE_DATA2(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO_TRANS_ID_BLOCK, MODE_SHARED) },
	{ PCI_DEVICE_DATA2(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO_TRANS_ID_CONSOLE, MODE_SHARED) },
	{ PCI_DEVICE_DATA2(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO_TRANS_ID_9P, MODE_SHARED) },
	{ PCI_DEVICE_DATA2(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_NET, MODE_SHARED) },
	{ PCI_DEVICE_DATA2(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_BLOCK, MODE_SHARED) },
	{ PCI_DEVICE_DATA2(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_CONSOLE, MODE_SHARED) },
	{ PCI_DEVICE_DATA2(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_9P, MODE_SHARED) },
	{ PCI_DEVICE_DATA2(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_VSOCK, MODE_SHARED) },
	{ 0, },
};

/* List of ACPI HID allow list */
static char *acpi_allow_hids[] = {
	"LNXPWRBN",
};

static struct authorize_node allow_list[] = {
	/* Allow devices in pci_allow_list in "pci" bus */
	{ "pci", pci_allow_ids },
	/* Allow devices in acpi_allow_hids in "acpi" bus */
	{ "acpi", acpi_allow_hids },
};

static bool dev_is_acpi(struct device *dev)
{
	return !strcmp(dev_bus_name(dev), "acpi");
}

static inline u32 devid(struct pci_dev *pdev)
{
	return PCI_DEVID(pdev->bus->number, pdev->devfn);
}

/* debug only */
static u32 devif_rp_read(void *data, u32 offset)
{
	return *(u32 *)(data + offset);
}

static u32 devif_rp_remain(void *data)
{
	return DEVIF_RP_LEN_REMAIN(devif_rp_read(data, DEVIF_RP_LEN));
}

static u32 devif_rp_len(void *data)
{
	return DEVIF_RP_LEN_PORTION(devif_rp_read(data, DEVIF_RP_LEN));
}

static u64 devif_rp_read_mmio_addr(void *data, u32 index)
{
	return devif_rp_read(data, DEVIF_RP_MMIO_ADDR_LO(index)) |
	 ((u64)devif_rp_read(data, DEVIF_RP_MMIO_ADDR_HI(index)) << 32);
}

static u32 devif_rp_read_mmio_pages(void *data, u32 index)
{
	return devif_rp_read(data, DEVIF_RP_MMIO_PAGES(index));
}

static u32 devif_rp_read_mmio_attr(void *data, u32 index)
{
	return devif_rp_read(data, DEVIF_RP_MMIO_ATTR(index));
}

static void dump_devif_report(struct pci_dev *pdev, void *data)
{
	struct device *dev = &pdev->dev;
	u32 num, attr, v, i;

#if 0
	v = devif_rp_read(data, DEVIF_RP_HDR);

	dev_dbg(dev, "%s: header: version 0x%x type 0x%x\n",
		__func__, DEVIF_RP_HDR_VER(v), DEVIF_RP_HDR_TYPE(v));
#endif

	v = devif_rp_read(data, DEVIF_RP_LEN);

	dev_dbg(dev, "%s: header: portion len 0x%x remaining len 0x%x\n",
		__func__, DEVIF_RP_LEN_PORTION(v), DEVIF_RP_LEN_REMAIN(v));

	num = devif_rp_read(data, DEVIF_RP_MMIO_NUM);

	dev_dbg(dev, "%s: mmio_range_num: 0x%x\n", __func__, num);

	/* for each mmio range */
	for (i = 0; i < num; i++) {
		attr = devif_rp_read_mmio_attr(data, i);

		dev_dbg(dev, "%s: range[%u]: addr 0x%016llx pages 0x%x, attr id %x pba %x msix %x\n",
			__func__, i,
			devif_rp_read_mmio_addr(data, i),
			devif_rp_read_mmio_pages(data, i),
			DEVIF_RP_MMIO_ATTR_ID(attr),
			DEVIF_RP_MMIO_ATTR_PBA(attr),
			DEVIF_RP_MMIO_ATTR_MSIX(attr));
	}
}

#define DEVICE_INFO_DATA_BUF_SZ		(8 * PAGE_SIZE)

static int tdxio_devif_get_device_info(struct pci_dev *pdev,
				       void **info_va, size_t *info_sz)
{
	size_t buf_sz = DEVICE_INFO_DATA_BUF_SZ;
	void *buf_va;
	int ret;

	buf_va = (void *)__get_free_pages(GFP_KERNEL, get_order(buf_sz));
	if (!buf_va)
		return -ENOMEM;

	ret = tdx_get_device_info(pdev->handle, buf_va, buf_sz);
	if (!ret) {
		*info_va = buf_va;
		*info_sz = buf_sz;
		return 0;
	}

	free_pages((unsigned long)buf_va, get_order(buf_sz));
	return ret;
}

static int tdxio_devif_validate(struct pci_dev *pdev, void *info, size_t size)
{
	struct crypto_shash *alg;
	struct shash_desc *sdesc;
	u64 result[6];
	size_t len;
	int rc, i;

	alg = crypto_alloc_shash("sha384", 0, 0);
	if (IS_ERR(alg))
		return PTR_ERR(alg);

	pr_info("%s: sha384 digestsize %u\n", __func__, crypto_shash_digestsize(alg));

	len = sizeof(*sdesc) + crypto_shash_digestsize(alg);
	sdesc = kmalloc(len, GFP_KERNEL);
	if (!sdesc) {
		crypto_free_shash(alg);
		return -ENOMEM;
	}

	sdesc->tfm = alg;
	rc = crypto_shash_digest(sdesc, info, size, (u8 *)result);
	kfree(sdesc);
	if (!rc) {
		for (i = 0; i < 6; i++)
			pr_info("%s: result[%d] %llx\n", __func__, i, result[i]);
	}

	crypto_free_shash(alg);

	/* currently use SHA384 HASH for dev pub key hash */
	return tdx_devif_validate(pdev->handle, result[5], result[4], result[3],
				  result[2], result[1], result[0]);
}

static int tdxio_devif_get_report(struct pci_dev *pdev, void **report, size_t *size)
{
	u64 total, remain, offset;
	void *tmp, *rp;
	int ret;

	/* FIXME: need to use TD_TDISP_BUFF_SIZE, now it's hardcode as 4096 */
	tmp = (void *)__get_free_page(GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	ret = tdx_devif_tdisp(pdev->handle, devid(pdev),
			     TDISP_GET_DEVIF_REPORT, __pa(tmp));
	if (ret)
		goto done;

	remain = devif_rp_remain(tmp);
	if (!remain) {
		*report = tmp;
		*size = devif_rp_len(tmp) + DEVIF_RP_HDR_SIZE;
		dump_devif_report(pdev, tmp);
		return 0;
	}

	/*
	 * as remaining length is not zero, copy devif report in one
	 * buffer for later phasing.
	 */
	total = devif_rp_len(tmp) + remain + DEVIF_RP_HDR_SIZE;
	offset = total - remain;

	rp = (void *)__get_free_pages(GFP_KERNEL, get_order(total));
	if (!rp) {
		ret = -ENOMEM;
		goto done;
	}

	memcpy(rp, tmp, DEVIF_RP_HDR_SIZE + devif_rp_len(tmp));

	while (remain) {
		memset(tmp, 0, PAGE_SIZE);

		ret = tdx_devif_tdisp(pdev->handle, devid(pdev),
				     TDISP_GET_DEVIF_REPORT, __pa(tmp));
		if (ret) {
			free_pages((unsigned long)rp, get_order(total));
			goto done;
		}

		memcpy(rp + offset, tmp + DEVIF_RP_HDR_SIZE, devif_rp_len(tmp));

		offset += devif_rp_len(tmp);
		remain -= devif_rp_len(tmp);
	}

	*report = rp;
	*size = total;
	dump_devif_report(pdev, rp);

done:
	free_page((unsigned long)tmp);
	return ret;
}

static int tdx_guest_dev_attest(struct pci_dev *pdev, unsigned int enum_mode)
{
	struct device *dev = &pdev->dev;
	void *info_va, *rp_va;
	size_t info_sz, rp_sz;
	int ret, result = 0;
	u64 handle;

	/*
	 * Step 0: Check Device Capability
	 *
	 * If valid handle (!= 0), means this pci_dev is a TDISP device
	 * exposed to TDX Guest.
	 */
	ret = tdx_get_devif_handle(devid(pdev), &handle);
	if (ret)
		return 0;

	/* If invalid handle, means this pci_dev is a non-TDISP device */
	if (!handle) {
		if (enum_mode == MODE_SHARED || enum_mode == MODE_UNAUTHORIZED) {
			pdev->untrusted = true;
			return MODE_SHARED;
		}

		return 0;
	}

	/* uses TDI in shared mode is not possible as TDI may be locked already */
	if (enum_mode == MODE_SHARED)
		return 0;

	pdev->handle = handle;

	/*
	 * Step 1: Device Data Collection for TDI
	 *
	 * 1.1 Get DEVICE_INFO_DATA by TDVMCALL from VMM
	 * 1.2 TDG.DEVIF.VALIDATE
	 *   ensure DEVIF is locked and DEVICE_INFO_DATA is trusted
	 * 1.3 Get TDISP DEVIF report
	 */
	ret = tdxio_devif_get_device_info(pdev, &info_va, &info_sz);
	if (ret) {
		dev_err(dev, "Fail to get DEVICE_INFO_DATA %d\n", ret);
		return 0;
	}

	ret = tdxio_devif_validate(pdev, info_va, info_sz);
	if (ret) {
		dev_err(dev, "Fail to validate DEVICE_INFO_DATA %d\n", ret);
		goto free_device_info;
	}

	ret = tdxio_devif_get_report(pdev, &rp_va, &rp_sz);
	if (ret) {
		dev_err(dev, "Fail to get TDISP DEVIF Report %d\n", ret);
		goto free_device_info;
	}

free_device_info:
	free_pages((unsigned long)info_va, get_order(info_sz));

	return result;
}

static int authorized_node_match(struct device *dev,
				  struct authorize_node *node)
{
	const struct pci_device_id *id;
	struct pci_dev *pdev;
	int status;
	int i;

	/* If bus matches "ALL" and dev_list is NULL, return true */
	if (!strcmp(node->bus, "ALL") && !node->dev_list)
		return MODE_SHARED;

	/*
	 * Since next step involves bus specific comparison, make
	 * sure the bus name matches with filter node. If not
	 * return false.
	 */
	if (strcmp(node->bus, dev->bus->name))
		return MODE_UNAUTHORIZED;

	/* If dev_list is NULL, allow all and return true */
	if (!node->dev_list)
		return MODE_SHARED;

	/*
	 * Do bus specific device ID match. Currently only PCI
	 * and ACPI bus is supported.
	 */
	if (dev_is_pci(dev)) {
		pdev = to_pci_dev(dev);
		id = pci_match_id((struct pci_device_id *)node->dev_list, pdev);
		if (id)
			status = tdx_guest_dev_attest(pdev, id->driver_data);
		else
			status = MODE_UNAUTHORIZED;

		pr_info("PCI vendor:%x device:%x %s %s\n", pdev->vendor,
			pdev->device, status ? "allowed" : "blocked",
			status == MODE_SECURE ? "trusted" : "untrusted");

		return status;
	} else if (dev_is_acpi(dev)) {
		for (i = 0; i < ARRAY_SIZE(acpi_allow_hids); i++) {
			if (!strncmp(acpi_allow_hids[i], dev_name(dev),
						strlen(acpi_allow_hids[i])))
				return MODE_SHARED;
		}
	}

	return MODE_UNAUTHORIZED;
}

static void fixup_unauthorized_device(struct device *dev)
{
	/*
	 * Prevent any config space accesses in initcalls.
	 * No locking needed here because it's a fresh device.
	 */
	if (dev_is_pci(dev))
		to_pci_dev(dev)->error_state = pci_channel_io_perm_failure;
}

static struct pci_device_id *parse_pci_id(char *ids)
{
	unsigned int subdevice = PCI_ANY_ID, class = 0, class_mask = 0;
	unsigned int vendor, device, subvendor = PCI_ANY_ID;
	char *p, *id;
	int fields;

	p = ids;
	while ((id = strsep(&p, ","))) {
		if (!strlen(id))
			continue;
		fields = sscanf(id, "%x:%x:%x:%x:%x:%x", &vendor, &device,
				&subvendor, &subdevice, &class, &class_mask);
		if (fields < 2)
			continue;
		cmd_pci_ids[cmd_pci_nodes_len].vendor = vendor;
		cmd_pci_ids[cmd_pci_nodes_len].device = device;
		cmd_pci_ids[cmd_pci_nodes_len].subvendor = subvendor;
		cmd_pci_ids[cmd_pci_nodes_len].subdevice = subdevice;
		cmd_pci_nodes_len++;
	}

	return cmd_pci_ids;
}

static void *parse_device_id(const char *bus, char *ids)
{
	if (!strcmp(ids, "ALL"))
		return NULL;

	if (!strcmp(bus, "pci"))
		return parse_pci_id(ids);
	else
		return ids;
}

static __init void add_authorize_nodes(char *p)
{
	struct authorize_node *n;
	int j = 0;
	char *k;

	while ((k = strsep(&p, ";")) != NULL) {
		if (j >= CMDLINE_MAX_NODES) {
			pr_err("Authorize nodes exceeds MAX allowed\n");
			break;
		}
		n = &cmd_allowed_nodes[j++];
		n->bus = strsep(&k, ":");
		n->dev_list = parse_device_id(n->bus, k);
	}

	if (j)
		cmd_allowed_nodes_len = j;
}

static __init int allowed_cmdline_setup(char *buf)
{
	if (strlen(buf) >= CMDLINE_MAX_LEN)
		pr_warn("Authorized allowed devices list exceed %d chars\n",
			CMDLINE_MAX_LEN);

	strscpy(cmd_authorized_devices, buf, CMDLINE_MAX_LEN);

	add_authorize_nodes(cmd_authorized_devices);

	filter_overridden = true;

	return 0;
}
__setup("authorize_allow_devs=", allowed_cmdline_setup);

int arch_dev_authorized(struct device *dev)
{
	int i, authorized;

	if (!dev->bus)
		return dev->authorized;

	/* Lookup arch allow list */
	for (i = 0;  i < ARRAY_SIZE(allow_list); i++) {
		authorized = authorized_node_match(dev, &allow_list[i]);
		if (authorized)
			return authorized;

	}

	/* Lookup command line allow list */
	for (i = 0; i < cmd_allowed_nodes_len; i++) {
		authorized = authorized_node_match(dev, &cmd_allowed_nodes[i]);
		if (authorized)
			return authorized;
	}

	fixup_unauthorized_device(dev);

	return dev_default_authorization;
}

bool tdx_allowed_port(short int port)
{
	if (tdx_debug_enabled() && !cc_filter_enabled())
		return true;

	switch (port) {
	/* MC146818 RTC */
	case 0x70 ... 0x71:
	/* i8237A DMA controller */
	case 0x80 ... 0x8f:
	/* PCI */
	case 0xcd8 ... 0xcdf:
	case 0xcf8 ... 0xcff:
		return true;
	/* PCIE hotplug device state for Q35 machine type */
	case 0xcc4:
	case 0xcc8:
		return true;
	/* ACPI ports list:
	 * 0600-0603 : ACPI PM1a_EVT_BLK
	 * 0604-0605 : ACPI PM1a_CNT_BLK
	 * 0608-060b : ACPI PM_TMR
	 * 0620-062f : ACPI GPE0_BLK
	 */
	case 0x600 ... 0x62f:
		return true;
	/* serial */
	case 0x2e8 ... 0x2ef:
	case 0x2f8 ... 0x2ff:
	case 0x3e8 ... 0x3ef:
	case 0x3f8 ... 0x3ff:
		return tdx_debug_enabled();
	default:
		return false;
	}
}

void __init tdx_filter_init(void)
{
	char a_allowed[60];
	char *allowed;

	if (!cc_platform_has(CC_ATTR_GUEST_DEVICE_FILTER))
		return;

	if (cmdline_find_option_bool(boot_command_line, "noccfilter"))
		cc_set_filter_status(false);

	if (!cc_filter_enabled()) {
		pr_info("Disabled TDX guest filter support\n");
		add_taint(TAINT_CONF_NO_LOCKDOWN, LOCKDEP_STILL_OK);
		return;
	}

	dev_default_authorization = false;

	if (filter_overridden) {
		add_taint(TAINT_CONF_NO_LOCKDOWN, LOCKDEP_STILL_OK);
		pr_debug("Device filter is overridden\n");
	}

	allowed = "XSDT,FACP,DSDT,FACS,APIC,SVKL,TDEL";
	if (cmdline_find_option(boot_command_line, "tdx_allow_acpi",
				a_allowed, sizeof(a_allowed)) >= 0) {
		add_taint(TAINT_CONF_NO_LOCKDOWN, LOCKDEP_STILL_OK);
		snprintf(acpi_allowed, sizeof(acpi_allowed), "%s,%s", allowed,
			 a_allowed);
		allowed = acpi_allowed;
	}
	acpi_tbl_allow_setup(allowed);

	pr_info("Enabled TDX guest device filter\n");
}
