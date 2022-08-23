// SPDX-License-Identifier: GPL-2.0
/*
 * DMTF Security Protocol and Data Model
 *
 * Copyright (C) 2021 Huawei
 *     Jonathan Cameron <Jonathan.Cameron@huawei.com>
 */

#include <linux/asn1_encoder.h>
#include <linux/asn1_ber_bytecode.h>
#include <linux/bitfield.h>
#include <linux/cred.h>
#include <linux/dev_printk.h>
#include <linux/digsig.h>
#include <linux/idr.h>
#include <linux/key.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/spdm.h>

#include <crypto/akcipher.h>
#include <crypto/hash.h>
#include <crypto/public_key.h>
#include <keys/asymmetric-type.h>
#include <keys/user-type.h>
#include <asm/unaligned.h>

/*
 * Todo
 * - Secure channel setup.
 * - Multiple slot support.
 * - Measurement support (over secure channel or within CHALLENGE_AUTH.
 * - Support more core algorithms (not CMA does not require them, but may use
 *   them if present.
 * - Extended algorithm, support.
 */
/*
 * Discussions points
 * 1. Worth adding an SPDM layer around a transport layer?
 * 2. Pad all SPDM request response to DWORD so we don't have to bounce for CMA /DOE.
 * 3. Currently only implement one flow - so ignore whether we have certs cached.
 *    Could implement the alternative flows, but at cost of complexity.
 * 4. Keyring management. How to ensure we can easily check root key against
 *    keys in appropriate keyring, but ensure we can't cross check keys
 *    from different devices.  Current solution of one keyring per SPDM has issues
 *    around cleanup when an error occurs.
 * 5. Several corners of the SPDM specification were not totally clear to me, so
 *    where unsure I verified options against openSPDM.
 * Detailed stuff
 * - SPDM spec doesn't define a header, but all requests and responses have same
 *   first 4 bytes.  Either could define that as a header, or givem the better names
 *   to reflect how param1 and param2 are actually used.
 */

static int spdm_append_buffer_a(struct spdm_state *spdm_state, void *data,
				size_t data_size, bool reset)
{
	u8 *a_new;

	if (reset) {
		kfree(spdm_state->a);
		spdm_state->a = NULL;
		spdm_state->a_length = 0;
	}

	a_new = krealloc(spdm_state->a, spdm_state->a_length + data_size, GFP_KERNEL);
	if (!a_new)
		return -ENOMEM;

	spdm_state->a = a_new;
	memcpy(spdm_state->a + spdm_state->a_length, data, data_size);
	spdm_state->a_length += data_size;

	return 0;
}

#define SPDM_REQ 0x80
#define SPDM_GET_VERSION 0x04

struct spdm_get_version_req {
	u8 version;
	u8 code;
	u8 param1;
	u8 param2;
};

struct spdm_get_version_rsp {
	u8 version;
	u8 code;
	u8 param1;
	u8 param2;

	u8 reserved;
	u8 version_number_entry_count;
	__le16 version_number_entries[];
};

#define SPDM_GET_CAPABILITIES 0x61

/* For this exchange the request and response messages have the same form. */
struct spdm_get_capabilities_reqrsp {
	u8 version;
	u8 code;
	u8 param1;
	u8 param2;

	u8 reserved;
	u8 ctexponent;
	u16 reserved2;

/* CACHE_CAP is only valid for response */
#define SPDM_GET_CAP_FLAG_CACHE_CAP			BIT(0)
#define SPDM_GET_CAP_FLAG_CERT_CAP			BIT(1)
#define SPDM_GET_CAP_FLAG_CHAL_CAP			BIT(2)

/* MEAS_CAP values other than 0 only for response */
#define SPDM_GET_CAP_FLAG_MEAS_CAP_MSK			GENMASK(4, 3)
#define   SPDM_GET_CAP_FLAG_MEAS_CAP_NO			0
#define   SPDM_GET_CAP_FLAG_MEAS_CAP_MEAS		1
#define   SPDM_GET_CAP_FLAG_MEAS_CAP_MEAS_SIG		2

/* MEAS_FRESH_CAP == 0 for request */
#define SPDM_GET_CAP_FLAG_MEAS_FRESH_CAP		BIT(5)
#define SPDM_GET_CAP_FLAG_ENCRYPT_CAP			BIT(6)
#define SPDM_GET_CAP_FLAG_MAC_CAP			BIT(7)
#define SPDM_GET_CAP_FLAG_MUT_AUTH_CAP			BIT(8)
#define SPDM_GET_CAP_FLAG_KEY_EX_CAP			BIT(9)

#define SPDM_GET_CAP_FLAG_PSK_CAP_MSK			GENMASK(11, 10)
#define   SPDM_GET_CAP_FLAG_PSK_CAP_NO_PRESHARE		0
#define   SPDM_GET_CAP_FLAG_PSK_CAP_PRESHARE		1

#define SPDM_GET_CAP_FLAG_ENCAP_CAP			BIT(12)
#define SPDM_GET_CAP_FLAG_HBEAT_CAP			BIT(13)
#define SPDM_GET_CAP_FLAG_KEY_UPD_CAP			BIT(14)
#define SPDM_GET_CAP_FLAG_HANDSHAKE_ITC_CAP		BIT(15)
#define SPDM_GET_CAP_FLAG_PUB_KEY_ID_CAP		BIT(16)
	__le32 flags;
};

#define SPDM_NEGOTIATE_ALGS 0x63

struct spdm_negotiate_algs_req {
	u8 version;
	u8 code;
	u8 param1; /* Numer of algorithm structure tables */
	u8 param2;

	__le16 length; /* <= 128 bytes */
	u8 measurement_specification;  /* Only one bit set, BIT 0 == DMTF */
	u8 reserved;
	__le32 base_asym_algo;

	/* Bit mask, entries form spdm_base_hash_algo */
	__le32 base_hash_algo;

	u8 reserved2[12];
	u8 ext_asm_count;
	u8 ext_hash_count;
	u8 reserved3[2];

	/*
	 * Additional fields at end of this structure
	 * - ExtAsym 4 * ext_asm_count
	 * - ExtHash 4 * ext_hash_count
	 * - ReqAlgStruct size * param1
	 */
};

struct spdm_negotiate_algs_rsp {
	u8 version;
	u8 code;
	u8 param1; /* Numer of algorithm structure tables */
	u8 param2;

	__le16 length; /* <= 128 bytes */
	u8 measurement_specification;  /* Only one bit set, BIT 0 == DMTF */
	u8 reserved;

	/* Exactly one bit must be set if GET_MEASUREMENTS is supported */
	__le32 measurement_hash_algo;
	/* At most one bit set to reflect negotiated alg */
	__le32 base_asym_sel;
	__le32 base_hash_sel;
	u8 reserved2[12];
	u8 ext_asym_sel_count; /* Either 0 or 1 */
	u8 ext_hash_sel_count; /* Either 0 or 1 */
	u8 reserved3[2];

	/*
	 * Additional fields at end of this structure
	 * - ExtAsym 4 * ext_asm_count
	 * - ExtHash 4 * ext_hash_count
	 * - ReqAlgStruct size * param1
	 */
};

#define SPDM_REQ_ALG_STRUCT_TYPE_DHE			0x2
#define   SPDM_DHE_ALGO_FFDHE_2048			BIT(0)
#define   SPDM_DHE_ALGO_FFDHE_3072			BIT(1)
#define   SPDM_DHE_ALGO_FFDHE_4096			BIT(2)
#define   SPDM_DHE_ALGO_SECP_256R1			BIT(3)
#define   SPDM_DHE_ALGO_SECP_384R1			BIT(4)
#define   SPDM_DHE_ALGO_SECP_521R1			BIT(5)

#define SPDM_REQ_ALG_STRUCT_TYPE_AEAD_CIPHER_SUITE	0x3
#define   SPDM_AEAD_ALGO_AES_128_GCM			BIT(0)
#define   SPDM_AEAD_ALGO_AES_256_GCM			BIT(1)
#define   SPDM_AEAD_ALGO_CHACHA20_POLY1305		BIT(2)
#define SPDM_REQ_ALG_STRUCT_TYPE_REQ_BASE_ASYM_ALG	0x4
/* As for base_asym_algo above */

#define SPDM_REQ_ALG_STRUCT_TYPE_KEY_SCHEDULE		0x5
#define   SPDM_KEY_SCHEDULE_SPDM			BIT(0)

struct spdm_req_alg_struct {
	u8 alg_type;
	u8 alg_count; /* 0x2K where K is number of alg_external entries */
	/* This field is sized based on alg_count[7:5] - currently always 2 */
	__le16 alg_supported;
	__le32 alg_external[];
};

#define SPDM_GET_DIGESTS 0x01
struct spdm_digest_req {
	u8 version;
	u8 code;
	u8 param1; /* Reserved */
	u8 param2; /* Reserved */
};

struct spdm_cert_chain {
	__le16 length;
	u8 reserved[2];
	/*
	 * Additional fields:
	 * - Hash of the root
	 * - Certs: ASN.1 Der-encoded X.509 v3 - First cert signed by root or is the root.
	 */
};

struct spdm_digest_rsp {
	u8 version;
	u8 code;
	u8 param1; /* Reserved */
	u8 param2; /* Slot mask */
	/* Hash of spdm_cert_chain for each slot */
	u8 digests[];
};

#define SPDM_GET_CERTIFICATE 0x02
struct spdm_certificate_req {
	u8 version;
	u8 code;
	u8 param1; /* Slot number 0..7 */
	u8 param2; /* Reserved */
	__le16 offset;
	__le16 length; /* Note 0xFFFF and offset 0 is special value meaning whole chain */
};

struct spdm_certificate_rsp {
	u8 version;
	u8 code;
	u8 param1; /* Slot number 0..7 */
	u8 param2; /* Reserved */
	__le16 portion_length;
	__le16 remainder_length;
	u8 cert_chain[]; /* Portion Length Long */
};


#define SPDM_CHALLENGE 0x03
struct spdm_challenge_req {
	u8 version;
	u8 code;
	u8 param1; /* Slot number 0..7 */
	u8 param2; /* Measurement summary hash type */
	u8 nonce[32];
};

struct spdm_challenge_rsp {
	u8 version;
	u8 code;
	u8 param1; /* response attribute field, slot id from challenge, bit 7 is mutual auth */
	u8 param2; /* slot mask */
	/* Hash length cert chain */
	/* Nonce, 32 bytes */
	/* Measurement Summary Hash - if present */
	/* 2 byte opaque length */
	/* opaque data if length non 0 */
	/* Signature */
};

static size_t spdm_challenge_rsp_signature_offset(struct spdm_state *spdm_state,
						 struct spdm_challenge_req *req,
						 struct spdm_challenge_rsp *rsp)
{
	u16 opaque_length = 0;
	size_t offset;

	offset = sizeof(*rsp);		/* Header offset */
	offset += spdm_state->h;	/* CertChain hash */
	offset += 32;			/* Nonce */

	/* Measurement summary hash */
	if (req->param2 &&
	    (spdm_state->responder_caps & SPDM_GET_CAP_FLAG_MAC_CAP))
		offset += spdm_state->h;
	/*
	 * This is almost certainly aligned, but that's not obvious from nearby code
	 * so play safe.
	 */
	//opaque_length = get_unaligned_le16((u8 *)rsp + offset);
	offset += sizeof(__le16); /* XXX: OpaqueLength field size */
	offset += opaque_length; /* The length of OpaqueData */

	return offset;
}

#define SPDM_GET_MEASUREMENTS 0x60
struct spdm_measurements_req {
	u8 version;
	u8 code;
	u8 param1; /* Request attributes */
	u8 param2; /* Measurement operation */
	u8 nonce[32];
};

struct spdm_measurements_rsp {
	u8 version;
	u8 code;
	u8 param1; /* number of measurements */
	u8 param2;
	u8 num_blocks;
	u8 measurement_record_len[3];
	u8 measurement_record[];
};

#define SPDM_ERROR 0x7f
enum spdm_error_code {
	spdm_invalid_request = 0x01,
	spdm_invalid_session = 0x02,
	spdm_busy = 0x03,
	spdm_unexpected_request = 0x04,
	spdm_unspecified = 0x05,
	spdm_decrypt_error = 0x06,
	spdm_unsupported_request = 0x07,
	spdm_request_in_flight = 0x08,
	spdm_invalid_response_code = 0x09,
	spdm_session_limit_exceeded = 0x0a,
	spdm_major_version_missmatch = 0x41,
	spdm_response_not_ready = 0x42,
	spdm_request_resync = 0x43,
	spdm_vendor_defined_error = 0xff,
};

struct spdm_error_rsp {
	u8 version;
	u8 code;
	u8 param1; /* Error code */
	u8 param2; /* Error data */
	u8 extended_error_data[];
};
#define SPDM_ERROR_MIN_SIZE sizeof(struct spdm_error_rsp)

static void spdm_err(struct device *dev, enum spdm_error_code error_code,
		     u8 error_data)
{
	switch (error_code) {
	case spdm_invalid_request:
		dev_err(dev, "Invalid Request\n");
		break;
	case spdm_invalid_session:
		dev_err(dev, "Invalid Session %#x\n", error_data);
		break;
	case spdm_busy:
		dev_err(dev, "Busy\n");
		break;
	case spdm_unexpected_request:
		dev_err(dev, "Unexpected request\n");
		break;
	case spdm_unspecified:
		dev_err(dev, "Unspecified\n");
		break;
	case spdm_decrypt_error:
		dev_err(dev, "Decrypt Error\n");
		break;
	case spdm_unsupported_request:
		dev_err(dev, "Unsupported Request %#x\n", error_data);
		break;
	case spdm_request_in_flight:
		dev_err(dev, "Request in flight\n");
		break;
	case spdm_invalid_response_code:
		dev_err(dev, "Invalid response code\n");
		break;
	case spdm_session_limit_exceeded:
		dev_err(dev, "Session limit exceeded\n");
		break;
	case spdm_major_version_missmatch:
		dev_err(dev, "Major version mismatch\n");
		break;
	case spdm_response_not_ready:
		dev_err(dev, "Response not ready\n");
		break;
	case spdm_request_resync:
		dev_err(dev, "Request resynchronization\n");
		break;
	case spdm_vendor_defined_error:
		dev_err(dev, "Vendor defined error\n");
		break;
	}
}

static int __spdm_exchange(struct spdm_state *spdm_state, struct spdm_exchange *ex, u8 version)
{
	int length;
	int rc;

	if (ex->request_pl_sz < sizeof(*ex->request_pl) ||
	    ex->response_pl_sz < sizeof(*ex->response_pl))
		return -EINVAL;

	ex->request_pl->version = version;
	ex->request_pl->code = SPDM_REQ | ex->code;

	/* Will become an op pointer if we have a second transport */
	rc = spdm_state->transport_ex(spdm_state->transport_priv, ex);
	if (rc < 0)
		return rc;

	length = rc;
	if (length < SPDM_ERROR_MIN_SIZE)
		return -EIO;

	if (ex->response_pl->code == SPDM_ERROR) {
		spdm_err(spdm_state->dev, ex->response_pl->param1,
			 ex->response_pl->param2);
		return -EIO;
	}

	if (ex->response_pl->code != ex->code) {
		dev_err(spdm_state->dev,
			"Invalid SPDM response received - does not match request code\n");
		return -EIO;
	}

	return length;
}

static int spdm1p0_exchange(struct spdm_state *spdm_state, struct spdm_exchange *ex)
{
	return __spdm_exchange(spdm_state, ex, 0x10);
}

/* Don't support 1.1 spec at this time */
# if 0
static int spdm1p1_exchange(struct spdm_state *spdm_state, struct spdm_exchange *ex)
{
	return __spdm_exchange(spdm_state, ex, 0x11);
}
#endif

static int spdm_get_version(struct spdm_state *spdm_state)
{
	struct spdm_get_version_req req = {};
	struct spdm_get_version_rsp *rsp;
	struct spdm_exchange spdm_ex;
	ssize_t rc, rsp_sz, length;
	int numversions = 2;

retry:
	rsp_sz = struct_size(rsp, version_number_entries, numversions);
	rsp = kzalloc(rsp_sz, GFP_KERNEL);

	spdm_ex = (struct spdm_exchange) {
		.request_pl = (struct spdm_header *)&req,
		.request_pl_sz = sizeof(req),
		.response_pl = (struct spdm_header *)rsp,
		.response_pl_sz = rsp_sz,
		.code = SPDM_GET_VERSION,
	};
	rc = spdm1p0_exchange(spdm_state, &spdm_ex);
	if (rc < 0)
		goto err;

	length = rc;

	if (length < struct_size(rsp, version_number_entries, 1)) {
		dev_err(spdm_state->dev, "SPDM must support at least one version\n");
		rc = -EIO;
		goto err;
	}

	/* If we didn't allocate enough space the first time, go around again */
	if (rsp->version_number_entry_count > numversions) {
		numversions = rsp->version_number_entry_count;
		kfree(rsp);
		goto retry;
	}

	/*
	 * Cache the request and response to use later to compute a message digest,
	 * as the algorithm to use is not yet known.
	 *
	 * Response may be padded, so we need to compute the length rather than relying
	 * on the length returned by the transport.
	 */
	length = struct_size(rsp, version_number_entries, rsp->version_number_entry_count);
	rc = spdm_append_buffer_a(spdm_state, &req, sizeof(req), true);
	if (rc)
		goto err;

	rc = spdm_append_buffer_a(spdm_state, rsp, length, false);

err:
	kfree(rsp);

	return rc;
}

static int spdm_negotiate_caps(struct spdm_state *spdm_state, u32 req_caps,
			u32 *rsp_caps)
{
	struct spdm_get_capabilities_reqrsp req = {
		.ctexponent = 2, /* FIXME: Chose sensible value */
		.flags = cpu_to_le32(req_caps),
	};
	struct spdm_get_capabilities_reqrsp rsp;
	struct spdm_exchange spdm_ex = {
		.request_pl = (struct spdm_header *)&req,
		.request_pl_sz = 4, /* XXX: Fixed for v1.0 */
		.response_pl = (struct spdm_header *)&rsp,
		.response_pl_sz = sizeof(rsp),
		.code = SPDM_GET_CAPABILITIES,
	};
	int rc, length;

	rc = spdm1p0_exchange(spdm_state, &spdm_ex);
	if (rc < 0)
		return rc;
	length = rc;

	if (length < sizeof(rsp)) {
		dev_err(spdm_state->dev, "NEGOTIATE_CAPS response short\n");
		return -EIO;
	}
	/* Cache capability as can affect data layout for other messages */
	spdm_state->responder_caps = le32_to_cpu(rsp.flags);

	if (rsp_caps)
		*rsp_caps = spdm_state->responder_caps;

	/* XXX: Set req size to 4 here too for v1.0 */
	rc = spdm_append_buffer_a(spdm_state, &req, 4, false);
	if (rc)
		return rc;

	return spdm_append_buffer_a(spdm_state, &rsp, sizeof(rsp), false);
}

static int spdm_start_digest(struct spdm_state *spdm_state,
			     void *req, size_t req_sz, void *rsp, size_t rsp_sz)
{
	int rc;

	/* Build first part of challenge hash */
	switch (spdm_state->base_hash_alg) {
	case spdm_base_hash_sha_384:
		spdm_state->shash = crypto_alloc_shash("sha384", 0, CRYPTO_ALG_ASYNC);
		break;
	case spdm_base_hash_sha_256:
		spdm_state->shash = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);
		break;
	default:
		/* Given device must support one of the above, lets stick to them for now */
		return -EINVAL;
	}

	if (!spdm_state->shash)
		return -ENOMEM;

	/* Used frequently to compute offsets, so cache H */
	spdm_state->h = crypto_shash_digestsize(spdm_state->shash);

	spdm_state->desc = kzalloc(struct_size(spdm_state->desc, __ctx,
					       crypto_shash_descsize(spdm_state->shash)),
				   GFP_KERNEL);
	if (!spdm_state->desc) {
		rc = -ENOMEM;
		goto err_free_shash;
	}
	spdm_state->desc->tfm = spdm_state->shash;

	rc = crypto_shash_init(spdm_state->desc);
	if (rc)
		goto err_free_desc;

	rc = crypto_shash_update(spdm_state->desc, spdm_state->a,
				 spdm_state->a_length);
	if (rc)
		goto err_free_desc;

	rc = crypto_shash_update(spdm_state->desc, (u8 *)req, req_sz);

	if (rc)
		goto err_free_desc;

	rc = crypto_shash_update(spdm_state->desc, (u8 *)rsp, rsp_sz);
	if (rc)
		goto err_free_desc;

	kfree(spdm_state->a);
	spdm_state->a = NULL;
	spdm_state->a_length = 0;

	return 0;

err_free_desc:
	kfree(spdm_state->desc);
err_free_shash:
	crypto_free_shash(spdm_state->shash);
	return rc;
}

static int spdm_negotiate_algs(struct spdm_state *spdm_state)
{
	struct spdm_negotiate_algs_req *req;
	struct spdm_negotiate_algs_rsp *rsp;
	struct spdm_exchange spdm_ex;

	/* XXX: No extended algorithm support for S3M */
	size_t req_sz = sizeof(*req);
	size_t rsp_sz = sizeof(*rsp);

	size_t length;
	int rc;

	req = kzalloc(req_sz, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	req->param1 = 0;	/* XXX: V1.0 change */
	req->code = SPDM_NEGOTIATE_ALGS | SPDM_REQ;
	req->length = cpu_to_le16(req_sz);
	req->measurement_specification = BIT(0);
	req->base_asym_algo = cpu_to_le32(BIT(spdm_asym_rsassa_3072) |
					  BIT(spdm_asym_ecdsa_ecc_nist_p256) |
					  BIT(spdm_asym_ecdsa_ecc_nist_p384));
	req->base_hash_algo = cpu_to_le32(BIT(spdm_base_hash_sha_256) |
					  BIT(spdm_base_hash_sha_384));

	req->ext_asm_count = 0;
	req->ext_hash_count = 0;

	rsp = kzalloc(rsp_sz, GFP_KERNEL);
	if (!rsp) {
		rc = -ENOMEM;
		goto err_free_req;
	}

	spdm_ex = (struct spdm_exchange) {
		.request_pl = (struct spdm_header *)req,
		.request_pl_sz = req_sz,
		.response_pl = (struct spdm_header *)rsp,
		.response_pl_sz = rsp_sz,
		.code = SPDM_NEGOTIATE_ALGS,
	};

	rc = spdm1p0_exchange(spdm_state, &spdm_ex);
	if (rc < 0)
		goto err_free_rsp;
	length = rc;

	//TODO: Check this cannot return short.
	if (length < rsp_sz) {
		dev_err(spdm_state->dev, "Response too short\n");
		rc = -EIO;
		goto err_free_rsp;
	}

	spdm_state->measurement_hash_alg = __ffs(le32_to_cpu(rsp->measurement_hash_algo));
	spdm_state->base_asym_alg = __ffs(le32_to_cpu(rsp->base_asym_sel));
	spdm_state->base_hash_alg = __ffs(le32_to_cpu(rsp->base_hash_sel));

	switch (spdm_state->base_asym_alg) {
	case spdm_asym_rsassa_3072:
		spdm_state->s = 384;
		break;
	case spdm_asym_ecdsa_ecc_nist_p256:
		spdm_state->s = 64;
		break;
	case spdm_asym_ecdsa_ecc_nist_p384:
		spdm_state->s = 96;
		break;
	default:
		dev_err(spdm_state->dev, "Unknown async base algorithm\n");
		rc = -EINVAL;
		goto err_free_rsp;
	}

	rsp_sz = sizeof(*rsp) + rsp->param1 * sizeof(struct spdm_req_alg_struct);
	rc = spdm_start_digest(spdm_state, req, req_sz, rsp, rsp_sz);

err_free_rsp:
	kfree(rsp);
err_free_req:
	kfree(req);

	return rc;
}

static int spdm_get_digests(struct spdm_state *spdm_state)
{
	struct spdm_digest_req req = {};
	struct spdm_digest_rsp *rsp;
	struct spdm_exchange spdm_ex;
	size_t rsp_sz;
	int rc;

	rsp_sz = struct_size(rsp, digests, spdm_state->h);
	rsp = kzalloc(rsp_sz, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	spdm_ex = (struct spdm_exchange) {
		.request_pl = (struct spdm_header *)&req,
		.request_pl_sz = sizeof(req),
		.response_pl = (struct spdm_header *)rsp,
		.response_pl_sz = rsp_sz,
		.code = SPDM_GET_DIGESTS,
	};

	rc = spdm1p0_exchange(spdm_state, &spdm_ex);
	if (rc < 0)
		return rc;

	rc = crypto_shash_update(spdm_state->desc, (u8 *)&req, sizeof(req));
	if (rc)
		goto err_free_rsp;

	rsp_sz = struct_size(rsp, digests,
			     spdm_state->h);

	rc = crypto_shash_update(spdm_state->desc, (u8 *)rsp, rsp_sz);

err_free_rsp:
	kfree(rsp);

	return rc;
}

/* Used to give a unique name for per device keychains */
static DEFINE_IDA(spdm_ida);

static int spdm_get_certificate(struct spdm_state *spdm_state)
{
	u16 bufsize = 0x8000;
	struct spdm_certificate_req req = {
		.param1 = spdm_state->cert_slot_no,
	};
	struct spdm_certificate_rsp *rsp;
	size_t rsp_sz;
	struct spdm_exchange spdm_ex;
	u16 remainder_length = bufsize;
	u16 offset = 0;
	char *keyring_name;
	int keyring_id;
	u8 *certs = NULL;
	u16 certs_length = 0;
	u16 next_cert;
	u16 last_cert;
	int rc;

	rsp_sz = struct_size(rsp, cert_chain, bufsize);
	rsp = kzalloc(rsp_sz, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	spdm_ex = (struct spdm_exchange) {
		.request_pl = (struct spdm_header *)&req,
		.request_pl_sz = sizeof(req),
		.response_pl = (struct spdm_header *)rsp,
		.response_pl_sz = rsp_sz,
		.code = SPDM_GET_CERTIFICATE,
	};

	while (remainder_length > 0) {
		u8 *newcerts;

		req.length = min(remainder_length, bufsize);
		req.offset = offset;

		rc = spdm1p0_exchange(spdm_state, &spdm_ex);
		if (rc < 0)
			goto err_free_certs;

		/*
		 * Taking the hash of each message was established by looking at
		 * what openSPDM does, rather than it being clear from the SPDM
		 * specification.
		 */
		rc = crypto_shash_update(spdm_state->desc, (u8 *)&req, sizeof(req));
		if (rc)
			goto err_free_certs;

		/* Care needed - each message might not be full length due to padding */
		rc = crypto_shash_update(spdm_state->desc, (u8 *)rsp,
					 sizeof(rsp) + rsp->portion_length);
		if (rc)
			goto err_free_certs;

		certs_length += rsp->portion_length;
		newcerts = krealloc(certs, certs_length, GFP_KERNEL);
		if (!newcerts) {
			rc = -ENOMEM;
			goto err_free_certs;
		}
		certs = newcerts;
		memcpy(certs + offset, rsp->cert_chain, rsp->portion_length);
		offset += rsp->portion_length;
		remainder_length = rsp->remainder_length;
	}

	keyring_id = ida_alloc(&spdm_ida, GFP_KERNEL);
	if (keyring_id < 0) {
		rc = keyring_id;
		goto err_free_certs;

	}

	keyring_name = kasprintf(GFP_KERNEL, "_spdm%02d", keyring_id);
	if (!keyring_name) {
		rc = -ENOMEM;
		goto err_free_ida;
	}

	/*
	 * Create a spdm instance specific keyring to avoid mixing certs,
	 * Not a child of _cma keyring, because the search below should
	 * not find a self signed cert in here.
	 *
	 * Not sure how to release a keyring, so currently if this fails we leak.
	 * That might be fine but an ida could get reused.
	 */
	spdm_state->keyring = keyring_alloc(keyring_name,
					    KUIDT_INIT(0), KGIDT_INIT(0),
					    current_cred(),
					    (KEY_POS_ALL & ~KEY_POS_SETATTR) |
					    KEY_USR_VIEW | KEY_USR_READ,
					    KEY_ALLOC_NOT_IN_QUOTA |
					    KEY_ALLOC_SET_KEEP,
					    NULL, NULL);
	kfree(keyring_name);
	if (IS_ERR(spdm_state->keyring)) {
		dev_err(spdm_state->dev,
			"Failed to allocate per spdm keyring\n");
		rc = PTR_ERR(spdm_state->keyring);
		goto err_free_ida;
	}

	next_cert = sizeof(struct spdm_cert_chain) + spdm_state->h;

	/*
	 * Store the certificate chain on the per SPDM instance keyring.
	 * Allow for up to 3 bytes padding as transport sends multiples of 4 bytes.
	 */
	while (next_cert < offset) {
		struct key *key;
		key_ref_t key2;

		key2 = key_create_or_update(make_key_ref(spdm_state->keyring, 1),
					    "asymmetric", NULL,
					    certs + next_cert, offset - next_cert,
					    (KEY_POS_ALL & ~KEY_POS_SETATTR) |
					    KEY_USR_VIEW | KEY_USR_READ,
					    KEY_ALLOC_NOT_IN_QUOTA);

		if (IS_ERR(key2)) {
			/* FIXME: Any additional cleanup to do here? */
			rc = PTR_ERR(key2);
			goto err_put_keyring;
		}

		if (!spdm_state->leaf_key) {
			/* First key in chain, so check against keys on _cma keyring */
			struct public_key_signature *sig =
				key_ref_to_ptr(key2)->payload.data[asym_auth];

			key = spdm_state->rootkey;

			rc = verify_signature(key, sig);
			if (rc) {
				dev_err(spdm_state->dev,
					"Unable to check SPDM cert against root keyring, %d\n", rc);
				key_ref_put(key2);
				goto err_put_keyring;
			}

			spdm_state->leaf_key = key_ref_to_ptr(key2);
		} else {
			/* Not the first key in chain, so check it against previous one */
			struct public_key_signature *sig =
				key_ref_to_ptr(key2)->payload.data[asym_auth];

			rc = verify_signature(spdm_state->leaf_key, sig);
			if (rc) {
				dev_err(spdm_state->dev,
					"Unable to verify SPDM cert against previous cert in chain\n");
				key_ref_put(key2);
				goto err_put_keyring;
			}
			key_put(spdm_state->leaf_key);
			spdm_state->leaf_key = key_ref_to_ptr(key2);
		}
		last_cert = next_cert;
		/*
		 * Horrible but need to pull this directly from the ASN1 stream as the cert
		 * chain is a concatentation of multiple cerificates.
		 */
		next_cert += get_unaligned_be16(certs + next_cert + 2) + 4;
	}

	/* Send the entire certificate chain */
	if (spdm_state->certificate_cb) {
		rc = spdm_state->certificate_cb(certs_length, certs,
						spdm_state->cb_data);
		if (rc)
			goto err_put_keyring;
	}

	/*
	 * Done with the keyring for now at this point. We have the leaf_key which is
	 * the last key2.
	 */
	key_put(spdm_state->keyring);
	kfree(certs);
	kfree(rsp);

	return 0;

err_put_keyring:
	key_put(spdm_state->keyring);
err_free_ida:
	ida_free(&spdm_ida, keyring_id);
err_free_certs:
	kfree(certs);
	kfree(rsp);

	return rc;
}


static int spdm_verify_signature(struct spdm_state *spdm_state, u8 *sig_ptr,
				 u8 *digest, unsigned int digest_size)
{
	const struct asymmetric_key_ids *ids;
	struct public_key_signature sig = {};
	/* Large enough for an ASN1 enocding of supported ECC signatures */
	unsigned char buffer2[128] = {};
	int rc;

	/*
	 * The ecdsa signatures are raw concatentation of the two values.
	 * In order to use verify_signature we need to reformat them into ASN1.
	 */
	switch (spdm_state->base_asym_alg) {
	case spdm_asym_ecdsa_ecc_nist_p256:
	case spdm_asym_ecdsa_ecc_nist_p384:
	{
		unsigned char buffer[128] = {};
		unsigned char *p = buffer;
		unsigned char *p2;

		//TODO: test the ASN1 function rather more extensively.
		/* First pack the two large integer values */
		p = asn1_encode_integer_large_positive(p, buffer + sizeof(buffer),
						       ASN1_INT, sig_ptr,
						       spdm_state->s / 2);
		p = asn1_encode_integer_large_positive(p, buffer + sizeof(buffer),
						       ASN1_INT,
						       sig_ptr + spdm_state->s  / 2,
						       spdm_state->s / 2);

		/* In turn pack those two large integer values into a sequence */
		p2 = asn1_encode_sequence(buffer2, buffer2 + sizeof(buffer2),
					  buffer, p - buffer);

		sig.s = buffer2;
		sig.s_size = p2 - buffer2;
		sig.encoding = "x962";
		break;
	}

	case spdm_asym_rsassa_3072:
		sig.s = sig_ptr;
		sig.s_size = spdm_state->s;
		sig.encoding = "pkcs1";
		break;
	default:
		dev_err(spdm_state->dev,
			"Signature algorithm not yet supported\n");
		return -EINVAL;
	}
	sig.digest = digest;
	sig.digest_size = digest_size;
	ids = asymmetric_key_ids(spdm_state->leaf_key);
	sig.auth_ids[0] = ids->id[0];
	sig.auth_ids[1] = ids->id[1];

	switch (spdm_state->base_hash_alg) {
	case spdm_base_hash_sha_384:
		sig.hash_algo = "sha384";
		break;
	case spdm_base_hash_sha_256:
		sig.hash_algo = "sha256";
		break;
	default:
		return -EINVAL;
	}

	rc = verify_signature(spdm_state->leaf_key, &sig);
	if (rc) {
		dev_err(spdm_state->dev,
			"Failed to verify challenge_auth signature %d\n", rc);
		return rc;
	}

	return 0;
}

static int spdm_challenge(struct spdm_state *spdm_state)
{
	struct spdm_challenge_req req = {
		.param1 = spdm_state->cert_slot_no,
		.param2 = 0, /* no measurement summary hash */
	};
	struct spdm_challenge_rsp *rsp;
	struct spdm_exchange spdm_ex;
	size_t sig_offset, rsp_max_size;
	int length, rc;
	u8 *digest;

	/*
	 * The response length is up to:
	 * 4 byte header
	 * H byte CertChainHash
	 * 32 byte nonce
	 * (H byte Measurement Summary Hash - not currently requested)
	 * 2 byte Opaque Length
	 * <= 1024 bytes Opaque Data
	 * S byte signature
	 */
	rsp_max_size = 4 + spdm_state->h + 32 + 2 + 1024 + spdm_state->s;
	rsp = kzalloc(rsp_max_size, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	get_random_bytes(&req.nonce, sizeof(req.nonce));

	spdm_ex = (struct spdm_exchange) {
		.request_pl = (struct spdm_header *)&req,
		.request_pl_sz = sizeof(req),
		.response_pl = (struct spdm_header *)rsp,
		.response_pl_sz = rsp_max_size,
		.code = SPDM_CHALLENGE,
	};

	rc = spdm1p0_exchange(spdm_state, &spdm_ex);
	if (rc < 0)
		goto err_free_rsp;
	length = rc;

	/* Last step of building the digest */
	rc = crypto_shash_update(spdm_state->desc, (u8 *)&req, sizeof(req));
	if (rc)
		goto err_free_rsp;

	/* The hash is complete + signature received; verify against leaf key */
	sig_offset = spdm_challenge_rsp_signature_offset(spdm_state, &req, rsp);
	if (sig_offset >= length) {
		rc = -EIO;
		goto err_free_rsp;
	}

	rc = crypto_shash_update(spdm_state->desc, (u8 *)rsp, sig_offset);
	if (rc)
		goto err_free_rsp;

	digest = kmalloc(spdm_state->h, GFP_KERNEL);
	if (!digest) {
		rc = -ENOMEM;
		goto err_free_rsp;
	}

	crypto_shash_final(spdm_state->desc, digest);

	rc = spdm_verify_signature(spdm_state, (u8 *)rsp + sig_offset, digest,
				   spdm_state->h);
	if (rc) {
		dev_err(spdm_state->dev, "Failed to verify SPDM challenge auth signature\n");
		goto err_free_digest;
	}

	kfree(spdm_state->desc);
	crypto_free_shash(spdm_state->shash);

	/* Clear to give a simple way to detect out of order */
	spdm_state->desc = NULL;

err_free_digest:
	kfree(digest);

err_free_rsp:
	kfree(rsp);

	return rc;
}

static int spdm_start_mdigest(struct spdm_state *spdm_state )
{
	int rc;

	/* Build first part of measurement hash */
	switch (spdm_state->base_hash_alg) {
	case spdm_base_hash_sha_384:
		spdm_state->m_shash = crypto_alloc_shash("sha384", 0, CRYPTO_ALG_ASYNC);
		break;
	case spdm_base_hash_sha_256:
		spdm_state->m_shash = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);
		break;
	default:
		/* Given device must support one of the above, lets stick to them for now */
		return -EINVAL;
	}

	if (!spdm_state->m_shash)
		return -ENOMEM;

	spdm_state->mdesc = kzalloc(struct_size(spdm_state->mdesc, __ctx,
					        crypto_shash_descsize(spdm_state->m_shash)),
				    GFP_KERNEL);
	if (!spdm_state->mdesc) {
		rc = -ENOMEM;
		goto err_free_m_shash;
	}

	spdm_state->mdesc->tfm = spdm_state->m_shash;

	rc = crypto_shash_init(spdm_state->mdesc);
	if (rc < 0)
		goto err_free_mdesc;

	return 0;

err_free_mdesc:
	kfree(spdm_state->mdesc);
err_free_m_shash:
	crypto_free_shash(spdm_state->m_shash);
	return rc;
}

static int
spdm_get_measurements_update_hash(struct spdm_state *spdm_state, void *msg,
				  size_t msg_size)
{
	u8 measurement_caps = FIELD_GET(SPDM_GET_CAP_FLAG_MEAS_CAP_MSK,
					spdm_state->responder_caps);

	/* Return without error is signature is not supported */
	if (measurement_caps != SPDM_GET_CAP_FLAG_MEAS_CAP_MEAS_SIG)
		return 0;

	return crypto_shash_update(spdm_state->mdesc, msg, msg_size);
}

enum measurement_type {
	MEASUREMENT_COUNT_ONLY,
	MEASUREMENT_REQUEST,
	MEASUREMENT_REQUEST_SIGNED,
};

static int spdm_append_buffer_l(struct spdm_state *spdm_state, void *data,
				size_t data_size)
{
	u8 *l_new;

	l_new = krealloc(spdm_state->l, spdm_state->l_length + data_size, GFP_KERNEL);
	if (!l_new)
		return -ENOMEM;

	spdm_state->l = l_new;
	memcpy(spdm_state->l + spdm_state->l_length, data, data_size);
	spdm_state->l_length += data_size;

	return 0;
}

static int __spdm_get_measurements(struct spdm_state *spdm_state)
{
	struct spdm_measurements_req req = {
		.param1 = spdm_state->measurement_sign ? 1 : 0,
		.param2 = spdm_state->meas_slot_no,
		.nonce = {},
	};
	struct spdm_measurements_rsp *rsp;
	struct spdm_exchange spdm_ex;
	size_t rsp_max_sz = 4096;
	size_t req_max_sz = sizeof(struct spdm_header);
	u8 measurement_caps = FIELD_GET(SPDM_GET_CAP_FLAG_MEAS_CAP_MSK,
					spdm_state->responder_caps);
	enum measurement_type type;
	u8 *digest;
	size_t length;
	int rc;

	if (req.param2 == 0)
		type = MEASUREMENT_COUNT_ONLY;
	else if (req.param1 == 0)
		type = MEASUREMENT_REQUEST;
	else
		type = MEASUREMENT_REQUEST_SIGNED;

	if (measurement_caps == SPDM_GET_CAP_FLAG_MEAS_CAP_NO) {
		dev_err(spdm_state->dev, "SPDM: Responder does not support GET_MEASUREMENTS\n");
		return -ENOTSUPP;
	}

	if (type == MEASUREMENT_REQUEST_SIGNED &&
	    measurement_caps != SPDM_GET_CAP_FLAG_MEAS_CAP_MEAS_SIG) {
		dev_err(spdm_state->dev, "SPDM: Responder does not support GET_MEASUREMENTS signing\n");
		return -ENOTSUPP;
	}

	/*
	 * Allocating just a page for the response. Really, the record length can
         * be large, just over 16MB if all bits are used.
	 */
	rsp = kzalloc(rsp_max_sz, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	/* Create a nonce only if we are signing */
	if (type == MEASUREMENT_REQUEST_SIGNED) {
		get_random_bytes(&req.nonce, sizeof(req.nonce));
		req_max_sz = sizeof(req);
	}

	spdm_ex = (struct spdm_exchange) {
		.request_pl = (struct spdm_header *)&req,
		.request_pl_sz = req_max_sz,
		.response_pl = (struct spdm_header *)rsp,
		.response_pl_sz = rsp_max_sz,
		.code = SPDM_GET_MEASUREMENTS,
	};

	rc = spdm1p0_exchange(spdm_state, &spdm_ex);
	if (rc < 0)
		goto free_rsp;
	length = rc;

	if (length > rsp_max_sz) {
		dev_err(spdm_state->dev, "SPDM: GET_MEASUREMENTS: Need %ld, allocated 4096\n",
			length);
		rc = -EIO;
		goto free_rsp;
	}

	/*
	 * mdesc is reset to NULL if:
	 *     1. Previous GET_MEASUREMENTS signed completed
	 *     2. spdm_authorize is ran
	 *     3. Any error occurs
	 */
	if (!spdm_state->mdesc &&
	    measurement_caps == SPDM_GET_CAP_FLAG_MEAS_CAP_MEAS_SIG) {
		dev_err(spdm_state->dev, "Starting new transcript, mc 0x%x\n",
			measurement_caps);
		rc = spdm_start_mdigest(spdm_state);
		if (rc < 0)
			goto free_rsp;
	}

	/* At this point if we error, we must free the digest and hash */

	/* Hash the request */
	rc = spdm_get_measurements_update_hash(spdm_state, &req, sizeof(req));
	if (rc < 0)
		goto free_hash;

	rc = spdm_append_buffer_l(spdm_state, &req, sizeof(req));
	if (rc < 0)
		goto free_hash;

	if (type != MEASUREMENT_REQUEST_SIGNED) {
		/* Hash the response */
		rc = spdm_get_measurements_update_hash(spdm_state, rsp, length);
		if (rc < 0)
			goto free_l;

		rc = spdm_append_buffer_l(spdm_state, rsp, length);
		if (rc < 0)
			goto free_l;

	} else {
		size_t h = crypto_shash_digestsize(spdm_state->m_shash);
		size_t sig_offset = length - spdm_state->s;
		dev_err(spdm_state->dev, "sig_offset is %ld length %ld s %ld\n", sig_offset, length, spdm_state->s);

		/* Hash the response, without the signature portion */
		rc = spdm_get_measurements_update_hash(spdm_state, rsp, sig_offset);
		if (rc < 0)
			goto free_l;

		digest = kmalloc(h, GFP_KERNEL);
		if (!digest) {
			rc = -ENOMEM;
			goto free_l;
		}

		rc = spdm_append_buffer_l(spdm_state, rsp, sig_offset);
		if (rc < 0)
			goto free_l;

		/* Send back the transcript and signature now */
		rc = spdm_state->meas_transcript_cb(spdm_state->l_length, spdm_state->l,
						    spdm_state->cb_data);
		if (rc)
			dev_warn(spdm_state->dev, "GET_MEASUREMENTS: Transcript callback error\n");

		rc = spdm_state->meas_sig_cb(spdm_state->s, (u8 *)rsp + sig_offset,
					     spdm_state->cb_data);
		if (rc)
			dev_warn(spdm_state->dev, "GET_MEASUREMENTS: Signature callback error\n");

		/* Calculate the final hash and verify the signature */
		rc = crypto_shash_final(spdm_state->mdesc, digest);
		if  (rc) {
			dev_err(spdm_state->dev, "GET_MEASUREMENTS: Could not finalize hash\n");
			kfree(digest);
			goto free_l;
		}

		rc = spdm_verify_signature(spdm_state, (u8 *)rsp + sig_offset,
					   digest, h);
		kfree(digest);

		if (rc) {
			dev_err(spdm_state->dev, "GET_MEASUREMENTS: Failed to verify signature\n");
			goto free_l;
		}

		dev_info(spdm_state->dev, "SPDM: GET_MEASUREMENTS: Succesfully verified signature\n");

		kfree(spdm_state->mdesc);
		crypto_free_shash(spdm_state->m_shash);
		spdm_state->mdesc = NULL;

		kfree(spdm_state->l);
		spdm_state->l = NULL;
		spdm_state->l_length = 0;

	}

	/* Invoke callback to return count or measurement */
	if (req.param2 == 0) /* Request count */
		rc = spdm_state->measurement_cb(rsp->param1, NULL, spdm_state->cb_data);
	else { /* Call user callback to copy buffer */
		u32 len = *(u32 *)rsp->measurement_record_len & 0xFFFFFF;
		rc = spdm_state->measurement_cb(len, rsp->measurement_record, spdm_state->cb_data);
	}

free_rsp:
	kfree(rsp);
	return rc;

free_l:
	kfree(spdm_state->l);
	spdm_state->l = NULL;
	spdm_state->l_length = 0;

free_hash:
	kfree(spdm_state->mdesc);
	crypto_free_shash(spdm_state->m_shash);
	spdm_state->mdesc = NULL;
	kfree(rsp);
	return rc;
}

int spdm_get_measurements(struct spdm_state *spdm_state)
{
	int rc;

	mutex_lock(&spdm_state->lock);
	rc = __spdm_get_measurements(spdm_state);
	mutex_unlock(&spdm_state->lock);

	return rc;
}
EXPORT_SYMBOL_GPL(spdm_get_measurements);

static int __spdm_authenticate(struct spdm_state *spdm_state)
{
	u32 req_caps, rsp_caps;
	int rc;

	rc = spdm_get_version(spdm_state);
	if (rc)
		return rc;

	/* TODO: work out if a subset of these is fine for CMA */
	req_caps = SPDM_GET_CAP_FLAG_CERT_CAP |
		SPDM_GET_CAP_FLAG_CHAL_CAP |
		SPDM_GET_CAP_FLAG_ENCRYPT_CAP |
		SPDM_GET_CAP_FLAG_MAC_CAP |
		SPDM_GET_CAP_FLAG_MUT_AUTH_CAP |
		SPDM_GET_CAP_FLAG_KEY_EX_CAP |
		FIELD_PREP(SPDM_GET_CAP_FLAG_PSK_CAP_MSK, SPDM_GET_CAP_FLAG_PSK_CAP_PRESHARE) |
		SPDM_GET_CAP_FLAG_ENCAP_CAP |
		SPDM_GET_CAP_FLAG_HBEAT_CAP |
		SPDM_GET_CAP_FLAG_KEY_UPD_CAP |
		SPDM_GET_CAP_FLAG_HANDSHAKE_ITC_CAP;

	rc = spdm_negotiate_caps(spdm_state, req_caps, &rsp_caps);
	if (rc)
		return rc;

	rc = spdm_negotiate_algs(spdm_state);
	if (rc)
		return rc;

	/* At this point we know the hash so can start calculating it as we go */
	rc = spdm_get_digests(spdm_state);
	if (rc)
		goto err_free_hash;

	rc = spdm_get_certificate(spdm_state);
	if (rc)
		goto err_free_hash;

	rc = spdm_challenge(spdm_state);
	if (rc)
		goto err_put_leaf_key;

	/*
	 * If we get to here, we have successfully verified the device is one
	 * we are happy with using.
	 */
	dev_info(spdm_state->dev, "SPDM: CHALLENGE: device authentication succesful\n");

	return 0;

err_put_leaf_key:

	/* Challenge failed. We'll need to start over. So put back device key. */
	key_put(spdm_state->leaf_key);

	/* Set to NULL to indicate we need to put it during spdm_finish */
	spdm_state->leaf_key = NULL;

err_free_hash:
	kfree(spdm_state->desc);
	crypto_free_shash(spdm_state->shash);

	return rc;
}

int spdm_authenticate(struct spdm_state *spdm_state)
{
	int rc;

	mutex_lock(&spdm_state->lock);

	/*
	 * We keep the leaf (device) key around after spdm_authenticate
	 * so that it may be used, if needed. But if we are reauthenticating
	 * before calling spdm_finish, we have to put it back so we can obtain
	 * it cleanly again during get_certificates.
	 */
	if (spdm_state->leaf_key) {
		key_put(spdm_state->leaf_key);
		spdm_state->leaf_key = NULL;
	}
	rc = __spdm_authenticate(spdm_state);
	mutex_unlock(&spdm_state->lock);

	return rc;
}
EXPORT_SYMBOL_GPL(spdm_authenticate);

void spdm_init(struct spdm_state *spdm_state)
{
	mutex_init(&spdm_state->lock);

	/*
	 * Ensure it's initialized to an empty and unused state.
	 * There should be no previous key in here when we start.
	 */
	spdm_state->leaf_key = NULL;
	spdm_state->l = NULL;
}
EXPORT_SYMBOL_GPL(spdm_init);

void spdm_finish(struct spdm_state *spdm_state)
{
	/* This is how we clean up the device key */
	if (spdm_state->leaf_key) {
		key_put(spdm_state->leaf_key);

		/*
		 * We really shouldn't be calling spdm_finish again before
		 * doing spdm_start, but just in case.
		 */
		spdm_state->leaf_key = NULL;
	}

	mutex_destroy(&spdm_state->lock);
}
EXPORT_SYMBOL_GPL(spdm_finish);

MODULE_LICENSE("GPL v2");
