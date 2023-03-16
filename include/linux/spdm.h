/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DMTF Security Protocol and Data Model
 *
 * Copyright (C) 2021 Huawei
 *     Jonathan Cameron <Jonathan.Cameron@huawei.com>
 */

#ifndef _SPDM_H_
#define _SPDM_H_

#include <linux/types.h>

enum spdm_base_hash_algo {
	spdm_base_hash_sha_256 = 0,
	spdm_base_hash_sha_384 = 1,
	spdm_base_hash_sha_512 = 2,
	spdm_base_hash_sha3_256 = 3,
	spdm_base_hash_sha3_384 = 4,
	spdm_base_hash_sha3_512 = 5,
};

enum spdm_meas_hash_algo {
	spdm_meas_hash_raw = 0,
	spdm_meas_hash_sha_256 = 1,
	spdm_meas_hash_sha_384 = 2,
	spdm_meas_hash_sha_512 = 3,
	spdm_meas_hash_sha3_256 = 4,
	spdm_meas_hash_sha3_384 = 5,
	spdm_meas_hash_sha3_512 = 6,
};

enum spdm_base_asym_algo {
	spdm_asym_rsassa_2048 = 0,
	spdm_asym_rsapss_2048 = 1,
	spdm_asym_rsassa_3072 = 2,
	spdm_asym_rsapss_3072 = 3,
	spdm_asym_ecdsa_ecc_nist_p256 = 4,
	spdm_asym_rsassa_4096 = 5,
	spdm_asym_rsapss_4096 = 6,
	spdm_asym_ecdsa_ecc_nist_p384 = 7,
	spdm_asym_ecdsa_ecc_nist_p521 = 8
};

struct crypto_shash;
struct shash_desc;
struct key;
struct device;

/*
 * The SPDM specification does not actually define this as the header
 * but all messages have the same first 4 named fields.
 * Note however that the meaning of param1 and param2 is message dependent.
 */
struct spdm_header {
	u8 version;
	u8 code;  /* requestresponsecode */
	u8 param1;
	u8 param2;
};

struct spdm_exchange {
	struct spdm_header *request_pl;
	size_t request_pl_sz;
	struct spdm_header *response_pl;
	size_t response_pl_sz;
	u8 code; /* Overwrites the request code */
};

struct spdm_state {
	enum spdm_meas_hash_algo measurement_hash_alg;
	enum spdm_base_asym_algo base_asym_alg;
	enum spdm_base_hash_algo base_hash_alg;
	u8 cert_slot_no;
	u8 meas_slot_no;
	bool measurement_sign;
	struct key *leaf_key;
	size_t h; /* base hash length - H in specification */
	size_t s; /* base asymmetric signature length - S in specification */
	u32 responder_caps;

	/*
	 * The base hash algorithm is not know until we reach the
	 * NEGOTIATE_ALGORITHMS response.
	 * The CHALLENGE_AUTH response handling requires a digest of all
	 * prior messages in the sequence. As such cache the messages in @a until
	 * they can be used as the first input to the hash function.
	 * Once the hash is known it can be updated as each additional req/rsp
	 * becomes available.
	 */
	void *a;
	size_t a_length;
	void *l;
	size_t l_length;
	struct crypto_shash *shash;
	struct crypto_shash *m_shash;
	struct shash_desc *desc;
	struct shash_desc *mdesc;

	struct key *rootkey; /* Key to check the root*/
	struct mutex lock;
	struct key *keyring; /* used to store certs from device */

	/* Transport specific */
	struct device *dev; /* For error reporting only */
	void *transport_priv;
	int (*transport_ex)(void *priv, struct spdm_exchange *spdm_ex);
	int (*certificate_cb)(size_t count, u8 *certificate, void *arg);
	int (*measurement_cb)(size_t count, u8 *measurements, void *arg);
	int (*meas_transcript_cb)(size_t count, u8 *transcript, void *arg);
	int (*meas_sig_cb)(size_t count, u8 *transcript, void *arg);
	void *cb_data;
};

int spdm_authenticate(struct spdm_state *spdm_state);
int spdm_get_measurements(struct spdm_state *spdm_state);
void spdm_init(struct spdm_state *spdm_state);
void spdm_finish(struct spdm_state *spdm_state);
#endif
