/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Intel Corporation. All rights rsvd. */

#ifndef __IAA_CRYPTO_H__
#define __IAA_CRYPTO_H__

#include <linux/crypto.h>
#include <linux/idxd.h>
#include <uapi/linux/idxd.h>

#define IDXD_SUBDRIVER_NAME		"crypto"

#define IAA_DECOMP_ENABLE		BIT(0)
#define IAA_DECOMP_FLUSH_OUTPUT		BIT(1)
#define IAA_DECOMP_CHECK_FOR_EOB	BIT(2)
#define IAA_DECOMP_STOP_ON_EOB		BIT(3)
#define IAA_DECOMP_SUPPRESS_OUTPUT	BIT(9)

#define IAA_COMP_FLUSH_OUTPUT		BIT(1)
#define IAA_COMP_APPEND_EOB		BIT(2)

#define IAA_COMPLETION_TIMEOUT		1000000

#define IAA_ANALYTICS_ERROR		0x0a
#define IAA_ERROR_COMP_BUF_OVERFLOW	0x19
#define IAA_ERROR_WATCHDOG_EXPIRED	0x24

#define DYNAMIC_HDR			0x2
#define DYNAMIC_HDR_SIZE		3

#define IAA_COMP_FLAGS			(IAA_COMP_FLUSH_OUTPUT | \
					 IAA_COMP_APPEND_EOB)

#define IAA_DECOMP_FLAGS		(IAA_DECOMP_ENABLE |	   \
					 IAA_DECOMP_FLUSH_OUTPUT | \
					 IAA_DECOMP_CHECK_FOR_EOB | \
					 IAA_DECOMP_STOP_ON_EOB)

/* Representation of IAA workqueue */
struct iaa_wq {
	struct list_head	list;
	struct idxd_wq		*wq;

	struct iaa_device	*iaa_device;

	u64			comp_calls;
	u64			comp_bytes;
	u64			decomp_calls;
	u64			decomp_bytes;
};

/* Representation of IAA device with wqs, populated by probe */
struct iaa_device {
	struct list_head		list;
	struct idxd_device		*idxd;

	struct aecs_table_record	*aecs_table;
	dma_addr_t			aecs_table_dma_addr;

	int				n_wq;
	struct list_head		wqs;

	u64				comp_calls;
	u64				comp_bytes;
	u64				decomp_calls;
	u64				decomp_bytes;
};

/*
 * Analytics Engine Configuration and State (AECS) contains parameters and
 * internal state of the analytics engine.
 */
struct aecs_table_record {
	u32 crc;
	u32 xor_checksum;
	u32 reserved0[5];
	u32 num_output_accum_bits;
	u8 output_accum[256];
	u32 ll_sym[286];
	u32 reserved1;
	u32 reserved2;
	u32 d_sym[30];
	u32 reserved_padding[2];
} __packed;

int iaa_aecs_alloc(struct iaa_device *iaa_device);
void iaa_aecs_free(struct iaa_device *iaa_device);

#if defined(CONFIG_CRYPTO_DEV_IAA_CRYPTO_STATS)
void	global_stats_show(struct seq_file *m);
void	device_stats_show(struct seq_file *m, struct iaa_device *iaa_device);
void	reset_iaa_crypto_stats(void);
void	reset_device_stats(struct iaa_device *iaa_device);

#else
static inline void	global_stats_show(struct seq_file *m) {}
static inline void	device_stats_show(struct seq_file *m, struct iaa_device *iaa_device) {}
static inline void	reset_iaa_crypto_stats(void) {}
static inline void	reset_device_stats(struct iaa_device *iaa_device) {}
#endif

#endif
