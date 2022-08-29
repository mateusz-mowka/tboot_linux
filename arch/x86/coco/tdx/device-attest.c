// SPDX-License-Identifier: GPL-2.0
#define DEBUG
#define pr_fmt(fmt) "Device Attestation: " fmt

#include <linux/types.h>
#include <linux/string.h>
#include <linux/minmax.h>
#include <linux/asn1.h>
#include <linux/stddef.h>
#include <linux/printk.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/random.h>
#include "device-attest.h"
#include "device-pre-certs.h"

/* 2-byte tag and 2-byte size */
#define DER_CERT_HDR_SIZE	4
#define DER_CERT_SIZE(hdr)	(((u16)hdr[2] << 8 | (u16)hdr[3]) + DER_CERT_HDR_SIZE)

#define MAX_CHAIN_DEPTH		8
/* Size of device_spdm_certificate->struct_version */
#define SPDM_CERT_VER_SIZE	4
/* Size of device_spdm_certificate->cert0_size */
#define SPDM_CHAIN_HDR_SIZE	2
/* Size of device_spdm_measurement->all_measurement_block_size */
#define SPDM_MEASU_HDR_SIZE	3

/* Max 8 certificate chains */
#define CHAIN_NUM		8
/* Size of chain (header + data) */
#define CHAIN_SIZE(hdr)		(*((u16 *)(hdr)) + SPDM_CHAIN_HDR_SIZE)
/* Current chain header */
#define CHAIN_CURR(hdr)		((u8 *)(hdr))
/* Next chain header */
#define CHAIN_NEXT(hdr)		(CHAIN_CURR(hdr) + CHAIN_SIZE(hdr))

#define	for_each_chain(i, size, tmp, chain, chains)	\
	for (i = 0, tmp = chains;			\
		size = CHAIN_SIZE(tmp),			\
		chain = CHAIN_CURR(tmp), i < CHAIN_NUM;	\
		tmp = CHAIN_NEXT(tmp), i++)

#define MAX_MEASUREMENTS	32

#define for_each_measu(i, size, tmp, m, ms)		\
	for (i = 0, tmp = ms;				\
		m = tmp,				\
		size = m->size, i < MAX_MEASUREMENTS;	\
		tmp = (struct measurement_block *)	\
		((u8 *)&m->dmtf + m->size), i++)	\

static void show_device_mode_measu(struct device_mode_measurement *d)
{
	pr_info("  Operational mode cap : 0x%x\n", d->operational_mode_capabilties);
	pr_info("  Operational mode sts : 0x%x\n", d->operational_mode_state);
	pr_info("  Device mode cap      : 0x%x\n", d->device_mode_capabilties);
	pr_info("  Device mode sts      : 0x%x\n", d->device_mode_state);
}

static void show_measus(struct device_spdm_measurement *spdm_meas)
{
	size_t size, total_size = 0, used_size = 0;
	struct measurement_block *tmp, *m, *ms;
	struct dmtf_measurement *dmtf;
	int i;

	ms = (struct measurement_block *)spdm_meas->all_measurement_block;

	memcpy(&total_size, spdm_meas->all_measurement_block_size,
	       sizeof(spdm_meas->all_measurement_block_size));

	for_each_measu(i, size, tmp, m, ms) {
		size += offsetof(struct measurement_block, dmtf);
		used_size += size;

		if (m->specification != DMTF_MEASU_SPEC) {
			pr_info("Skip non-dmtf measure(index %u)\n", m->index);
			continue;
		}

		dmtf = &m->dmtf;
		pr_info("Measure type 0x%02x index: %u\n", dmtf->value_type, m->index);

		if (DMTF_VALUE_TYPE(dmtf->value_type) == DMTF_VALUE_TYPE_DEV_MODE) {
			show_device_mode_measu(&dmtf->device_mode_measurement);
			continue;
		}

		size = m->dmtf.value_size < 64 ? m->dmtf.value_size : 64;

		print_hex_dump_bytes(" DMTF ", DUMP_PREFIX_OFFSET, dmtf->value, size);

		if (used_size >= total_size)
			break;
	}
}

static int get_cert_size(u8 *cert)
{
	u8 tag = cert[0];

	if (tag != ((ASN1_UNIV << 6) | ASN1_CONS_BIT | ASN1_SEQ)) {
		pr_err("Invalid cert(tag %02x)\n", tag);
		return -EBADMSG;
	}

	if (cert[1] == ASN1_INDEFINITE_LENGTH) {
		pr_warn("Not supported cert with infinite length yet\n");
		return -EBADMSG;
	}

	if (cert[1] != 0x82) {
		pr_err("Invalid cert(no size)\n");
		return -EBADMSG;
	}

	return DER_CERT_SIZE(cert);
}

static u8 *extract_root_cert(u8 *cert_chain, int idx)
{
	size_t chain_size;
	u8 *root_cert;

	chain_size = CHAIN_SIZE(cert_chain);

	if (chain_size <= SPDM_CHAIN_HDR_SIZE) {
		/* pr_debug("Empty SPDM cert chain%d\n", idx); */
		return NULL;
	}

	chain_size -= SPDM_CHAIN_HDR_SIZE;

	if (chain_size < 2) {
		pr_debug("Invalid SPDM cert chain%d(no root cert header)\n", idx);
		return NULL;
	}

	root_cert = cert_chain + SPDM_CHAIN_HDR_SIZE;

	return root_cert;
}

static u8 *extract_dev_cert(u8 *cert_chain, int idx)
{
	size_t chain_size;
	int i, size;
	u8 *cert;

	cert = extract_root_cert(cert_chain, idx);
	if (!cert)
		return NULL;

	if (CHAIN_SIZE(cert_chain) < SPDM_CHAIN_HDR_SIZE)
		return NULL;

	chain_size = CHAIN_SIZE(cert_chain) - SPDM_CHAIN_HDR_SIZE;
	size = get_cert_size(cert);

	for (i = 0; i < MAX_CHAIN_DEPTH; i++) {
		if (size < 0)
			return NULL;

		if (chain_size < size) {
			pr_err("Empty cert%d in chain%d\n", i, idx);
			return NULL;
		}

		if (chain_size == size)
			return cert;

		chain_size -= size;
		cert += size;
		size = get_cert_size(cert);
	}

	pr_err("Exceed max chain depth %d\n", MAX_CHAIN_DEPTH);

	return NULL;
}

static bool match_cert(u8 *cert, struct certs *pre_cert)
{
	if (pre_cert->size != DER_CERT_SIZE(cert))
		return false;

	if (!memcmp(cert, pre_cert->data, pre_cert->size))
		return true;

	return false;
}

static struct certs *find_cert(struct pci_dev *pdev, struct certs **pre_certs)
{
	struct certs *c;

	for (; c = *pre_certs, c; ++pre_certs) {
		if (c->vendor == pdev->vendor && c->device == pdev->device)
			return c;
	}

	return NULL;
}

static bool match_chain(u8 *chain, struct certs *pre_cert_chain)
{
	size_t chain_size;
	u8 *chain_data;

	chain_data = chain + SPDM_CHAIN_HDR_SIZE;
	chain_size = CHAIN_SIZE(chain) - SPDM_CHAIN_HDR_SIZE;

	if (chain_size != pre_cert_chain->size)
		return false;

	if (!memcmp(chain_data, pre_cert_chain->data, pre_cert_chain->size))
		return true;

	return false;
}

static bool match_root_cert(struct pci_dev *pdev, u8 *chains)
{
	struct certs *pre_cert;
	u8 *cert, *chain, *tmp;
	size_t size;
	int i;

	pre_cert = find_cert(pdev, pre_root_certs);
	if (!pre_cert)
		return NULL;

	for_each_chain(i, size, tmp, chain, chains) {
		cert = extract_root_cert(chain, i);
		if (!cert)
			continue;

		size = get_cert_size(cert);

		if (match_cert(cert, pre_cert))
			return true;
	}

	return false;
}

static bool match_dev_cert(struct pci_dev *pdev, u8 *chains)
{
	struct certs *pre_cert;
	u8 *cert, *chain, *tmp;
	size_t size;
	int i;

	pre_cert = find_cert(pdev, pre_dev_certs);
	if (!pre_cert)
		return false;

	for_each_chain(i, size, tmp, chain, chains) {
		cert = extract_dev_cert(chain, i);
		if (!cert)
			continue;

		if (match_cert(cert, pre_cert))
			return true;
	}

	return false;
}

static bool match_cert_chain(struct pci_dev *pdev, u8 *chains)
{
	struct certs *pre_cert;
	u8 *chain, *tmp;
	size_t chain_size;
	int i;

	pre_cert = find_cert(pdev, pre_cert_chains);
	if (!pre_cert)
		return false;

	for_each_chain(i, chain_size, tmp, chain, chains) {
		if (match_chain(chain, pre_cert))
			return true;
	}

	return false;
}

static struct device_spdm_certificate *extract_spdm_certificate(struct device_info_data *data,
								size_t data_size,
								size_t *cert_size)
{
	size_t size, chain_size, chains_size;
	u8 *chain, *chains, *tmp;
	int i;

	/* Each chain starts with a header of chain size */
	chains = (u8 *)(&data->device_spdm_certificate.cert0_size);

	/* Non-chain size */
	size = offsetof(struct device_info_data, device_spdm_certificate) +
	       offsetof(struct device_spdm_certificate, cert0_size) +
	       sizeof(struct device_tdisp_information);

	if (data_size < size + SPDM_CHAIN_HDR_SIZE) {
		pr_err("No any SPDM cert chains\n");
		return NULL;
	}

	data_size -= size;
	chains_size = 0;

	for_each_chain(i, chain_size, tmp, chain, chains) {
		if (data_size < chain_size) {
			pr_err("No SPDM cert chain%d with size %zu\n", i, chain_size);
			return NULL;
		}

		size = chain_size - SPDM_CHAIN_HDR_SIZE;
		if (size)
			pr_info("Extracted SPDM cert chain%d with size %zu\n", i, size);

		data_size -= chain_size;
		chains_size += chain_size;

		/* Last chain break out */
		if (i == CHAIN_NUM - 1)
			break;

		if (data_size < SPDM_CHAIN_HDR_SIZE) {
			pr_err("Invalid SPDM cert chain%d(no header)\n", i + 1);
			return NULL;
		}
	}

	*cert_size = chains_size + offsetof(struct device_spdm_certificate, cert0_size);

	return &data->device_spdm_certificate;
}

static struct device_spdm_measurement *extract_spdm_measurement(struct device_info_data *data,
								size_t data_size,
								struct device_spdm_certificate *cert,
								size_t cert_size,
								size_t *measu_size)
{
	struct device_spdm_measurement *measu;
	size_t size;
	u8 *p;
	int i;

	if (!cert || !cert_size) {
		pr_err("Need to pre-exact the SPDM cert\n");
		return NULL;
	}

	size  = (size_t)((unsigned long)cert - (unsigned long)data);
	size += cert_size;
	measu = (struct device_spdm_measurement *)((u8 *)data + size);

	size += offsetof(struct device_spdm_measurement, all_measurement_block_size);

	if (data_size < size + SPDM_MEASU_HDR_SIZE) {
		pr_err("Invalid SPDM measurement(no header)\n");
		return NULL;
	}

	data_size -= size;
	p = ((u8 *)data) + size;

	for (size = 0, i = 0; i < SPDM_MEASU_HDR_SIZE; i++)
		size |= (u32)p[i] << (i * 8);

	data_size -= SPDM_MEASU_HDR_SIZE;

	if (data_size < size) {
		pr_err("No SPDM measurement with size %zu\n", size);
		return NULL;
	}

	*measu_size = size + offsetof(struct device_spdm_measurement, all_measurement_block);

	return measu;
}

static bool attest_certs(struct pci_dev *pdev, u8 *chains, enum attestation_policy policy)
{
	switch (policy) {
	case MATCH_SKIP:
		return true;

	case MATCH_ROOT_CERT:
		return match_root_cert(pdev, chains);

	case MATCH_DEV_CERT:
		return match_dev_cert(pdev, chains);

	case MATCH_CERT_CHAIN:
		return match_cert_chain(pdev, chains);

	default:
		return false;
	}
}

static bool attest_measurements(struct pci_dev *pdev, u8 *measus)
{
	/* TODO: Add what measurement to be attested. */

	return true;
}

static bool attest_device(struct pci_dev *pdev,
			  struct device_spdm_certificate *cert,
			  struct device_spdm_measurement *meas,
			  enum attestation_policy policy)
{
	u8 *chains, *measus;

	chains = (u8 *)&cert->cert0_size;
	measus = (u8 *)&meas->all_measurement_block_size;

	show_measus(meas);

	return attest_certs(pdev, chains, policy) && attest_measurements(pdev, measus);
}

bool tdx_attest_device(struct pci_dev *pdev, struct device_info_data *data, size_t data_size,
		       enum attestation_policy policy)
{
	struct device_spdm_certificate *cert;
	struct device_spdm_measurement *meas;
	size_t cert_size, meas_size;

	cert = extract_spdm_certificate(data, data_size, &cert_size);
	meas = extract_spdm_measurement(data, data_size, cert, cert_size, &meas_size);

	return attest_device(pdev, cert, meas, policy);
}

#define DEVICE_INFO_DATA_BUF_SIZE	(PAGE_SIZE * 16)
#define SPDM_CERT_BUF_SIZE		(DEVICE_INFO_DATA_BUF_SIZE / 2)
#define SPDM_MEAS_BUF_SIZE		(DEVICE_INFO_DATA_BUF_SIZE / 2)

static struct measurement_block *self_test_gen_meas_blk(u8 index, u8 value_type, size_t *size)
{
	struct device_mode_measurement *dev;
	struct dmtf_measurement *dmtf;
	struct measurement_block *b;

	b = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!b)
		return NULL;

	b->index = index;
	b->specification = DMTF_MEASU_SPEC;

	dmtf = &b->dmtf;
	dmtf->value_type = value_type;

	switch (DMTF_VALUE_TYPE(value_type)) {
	case DMTF_VALUE_TYPE_ROM:
		strcpy(dmtf->value, "DMTF_VALUE_TYPE_ROM");
		dmtf->value_size = strlen("DMTF_VALUE_TYPE_ROM");
		break;

	case DMTF_VALUE_TYPE_FW:
		strcpy(dmtf->value, "DMTF_VALUE_TYPE_FW");
		dmtf->value_size = strlen("DMTF_VALUE_TYPE_FW");
		break;

	case DMTF_VALUE_TYPE_HW_CFG:
		strcpy(dmtf->value, "DMTF_VALUE_TYPE_HW_CFG");
		dmtf->value_size = strlen("DMTF_VALUE_TYPE_HW_CFG");
		break;

	case DMTF_VALUE_TYPE_FW_CFG:
		strcpy(dmtf->value, "DMTF_VALUE_TYPE_FW_CFG");
		dmtf->value_size = strlen("DMTF_VALUE_TYPE_FW_CFG");
		break;

	case DMTF_VALUE_TYPE_MANIFEST:
		strcpy(dmtf->value, "DMTF_VALUE_TYPE_MANIFEST");
		dmtf->value_size = strlen("DMTF_VALUE_TYPE_MANIFEST");
		break;

	case DMTF_VALUE_TYPE_DEV_MODE:
		dev = &dmtf->device_mode_measurement;
		dev->operational_mode_capabilties = DEV_OP_CAP_RP_MASK;
		dev->operational_mode_state = DEV_OP_STS_VALIDATION;
		dev->device_mode_capabilties = DEV_MD_CAP_RP_MASK;
		dev->device_mode_state = DEV_MD_STS_NON_INVASIVE;
		dmtf->value_size = sizeof(*dev);
		break;

	case DMTF_VALUE_TYPE_FW_VER:
		strcpy(dmtf->value, "DMTF_VALUE_TYPE_FW_VER");
		dmtf->value_size = strlen("DMTF_VALUE_TYPE_FW_VER");
		break;

	case DMTF_VALUE_TYPE_FW_SECURITY_VER:
		strcpy(dmtf->value, "DMTF_VALUE_TYPE_FW_SECURITY_VER");
		dmtf->value_size = strlen("DMTF_VALUE_TYPE_FW_SECURITY_VER");
		break;

	default:
		kfree(b);
		return NULL;
	}

	b->size = dmtf->value_size + offsetof(struct dmtf_measurement, value);
	*size = b->size + offsetof(struct measurement_block, dmtf);

	return b;
}

static struct device_spdm_measurement *self_test_gen_spdm_meas(size_t *size)
{
	struct device_spdm_measurement *m;
	struct measurement_block *b;
	int i, idx = 0;
	size_t sz;
	u8 *p, *q;

	m = kzalloc(SPDM_MEAS_BUF_SIZE, GFP_KERNEL);
	if (!m)
		return NULL;

	m->struct_version =  0x10000;
	q = (u8 *)m->all_measurement_block;
	p = q;

	for (i = DMTF_VALUE_TYPE_ROM; i <= DMTF_VALUE_TYPE_FW_SECURITY_VER; i++) {
		b = self_test_gen_meas_blk(idx, DMTF_VALUE_TYPE_RAW | i, &sz);
		if (b) {
			memcpy(p, b, sz);
			kfree(b);
			p += sz;
			idx++;
		}
	}

	sz = (unsigned long)(p) - (unsigned long)(q);
	memcpy(m->all_measurement_block_size, &sz, sizeof(m->all_measurement_block_size));
	*size = (unsigned long)(p) - (unsigned long)(m);

	return m;
}

static struct device_spdm_certificate *self_test_gen_spdm_certgc(size_t *size)
{
	const u8 *slot_a_data, *slot_b_data;
	struct device_spdm_certificate *c;
	size_t slot_a_size, slot_b_size;
	u32 tmp, slot_a, slot_b;
	u8 *p;

	c = kzalloc(SPDM_CERT_BUF_SIZE, GFP_KERNEL);
	if (!c)
		return NULL;

	c->struct_version =  0x10000;

	slot_a = get_random_u32() % CHAIN_NUM;
	slot_b = get_random_u32() % CHAIN_NUM;

	if (slot_a == slot_b)
		slot_b = (slot_b + 1) % CHAIN_NUM;

	if (slot_a > slot_b) {
		tmp = slot_a;
		slot_a = slot_b;
		slot_b = tmp;

		slot_a_data = chain_example.data;
		slot_a_size = chain_example.size;
		slot_b_data = chain_example2.data;
		slot_b_size = chain_example2.size;

		pr_debug("Installing slot%u with example cert chain with size %zu\n", slot_a, slot_a_size);
		pr_debug("Installing slot%u with example2 cert chain with size %zu\n", slot_b, slot_b_size);
	} else {
		slot_a_data = chain_example2.data;
		slot_a_size = chain_example2.size;
		slot_b_data = chain_example.data;
		slot_b_size = chain_example.size;

		pr_debug("Installing slot%u with example2 cert chain with size %zu\n", slot_a, slot_a_size);
		pr_debug("Installing slot%u with example cert chain with size %zu\n", slot_b, slot_b_size);
	}

	/* The start of the 1st chain */
	p = (u8 *)&c->cert0_size;

	/* Set the slot_a cert chain */
	p += slot_a * SPDM_CHAIN_HDR_SIZE;
	*((u16 *)p) = slot_a_size;
	p += SPDM_CHAIN_HDR_SIZE;
	memcpy(p, slot_a_data, slot_a_size);
	p += slot_a_size;

	slot_b = slot_b - slot_a - 1;

	/* Set the slot_b cert chain */
	p += slot_b * SPDM_CHAIN_HDR_SIZE;
	*((u16 *)p) = slot_b_size;
	p += SPDM_CHAIN_HDR_SIZE;
	memcpy(p, slot_b_data, slot_b_size);
	p += slot_b_size;

	/* Skip the reset chain slots */
	p += (CHAIN_NUM - 1 - slot_b) * SPDM_CHAIN_HDR_SIZE;

	*size = (unsigned long)(p) - (unsigned long)(c);

	return c;
}

static struct device_info_data *self_test_gen_device_data_info(size_t data_size)
{
	struct device_spdm_certificate *c;
	struct device_spdm_measurement *m;
	struct device_info_data *d;
	size_t size;
	u8 *p;

	d = kzalloc(data_size, GFP_KERNEL);
	if (!d)
		return NULL;

	d->struct_version =  0x10000;

	p  = (u8 *)&d->device_spdm_certificate;

	c = self_test_gen_spdm_certgc(&size);
	if (c) {
		/* pr_info("Generate SPDM cert %p with size %zu\n", c, size); */
		memcpy(p, c, size);
		p += size;
		kfree(c);
	}

	m = self_test_gen_spdm_meas(&size);
	if (m) {
		/* pr_info("Generate SPDM measuement %p with size %zu\n", m, size); */
		memcpy(p, m, size);
		p += size;
		kfree(m);
	}

	return d;
}

static bool self_test_match_root_cert(struct pci_dev *pdev,
				      struct device_spdm_certificate *spdm_cert)
{
	u8 *chains = (u8 *)&spdm_cert->cert0_size;

	return match_root_cert(pdev, chains);
}

static bool self_test_match_dev_cert(struct pci_dev *pdev,
				     struct device_spdm_certificate *spdm_cert)
{
	u8 *chains = (u8 *)&spdm_cert->cert0_size;

	return match_dev_cert(pdev, chains);
}

static bool self_test_match_cert_chain(struct pci_dev *pdev,
				       struct device_spdm_certificate *spdm_cert)
{
	u8 *chains = (u8 *)&spdm_cert->cert0_size;

	return match_cert_chain(pdev, chains);
}

bool self_test_device_attestation(struct pci_dev *pdev)
{
	size_t spdm_cert_size, data_size;
	struct device_spdm_certificate *spdm_cert = NULL;
	struct device_info_data *data;

	data_size = DEVICE_INFO_DATA_BUF_SIZE;
	data = self_test_gen_device_data_info(data_size);

	spdm_cert = extract_spdm_certificate(data, data_size, &spdm_cert_size);

	if (!spdm_cert) {
		pr_info("Self test for extracting SPDM certificate data - failed\n");
		return false;
	}
	pr_info("Self test for extracting SPDM certificate data - passed\n");

	if (!self_test_match_root_cert(pdev, spdm_cert)) {
		pr_info("Self test for matching root certificate - failed\n");
		return false;
	}
	pr_info("Self test for matching root certificate - passed\n");

	if (!self_test_match_dev_cert(pdev, spdm_cert)) {
		pr_info("Self test for matching device certificate - failed\n");
		return false;
	}
	pr_info("Self test for matching device certificate - passed\n");

	if (!self_test_match_cert_chain(pdev, spdm_cert)) {
		pr_info("Self test for matching certificate chain - failed\n");
		return false;
	}
	pr_info("Self test for matching certificate chain - passed\n");

	return true;
}
