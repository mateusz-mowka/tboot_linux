// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022-2023 Intel Corporation */

#ifndef __IDE_KM_H__
#define __IDE_KM_H__

#pragma pack(1)

#include <linux/types.h>

#define VDSM_IDE_KM_LINK_IDE_REG_BLOCK_SUPPORTED_COUNT 4
#define VDSM_IDE_KM_SELECTIVE_IDE_REG_BLOCK_SUPPORTED_COUNT 8
#define VDSM_IDE_KM_SELECTIVE_IDE_ADDRESS_ASSOCIATION_REG_BLOCK_SUPPORTED_COUNT 1

/* (2 + 2 * 4 + (3 + 2 + 3 * 1) * 8) = 74 */
#define VDSM_IDE_KM_IDE_REG_BLOCK_SUPPORTED_COUNT                                        \
	(2 + 2 * VDSM_IDE_KM_LINK_IDE_REG_BLOCK_SUPPORTED_COUNT +                        \
	 (3 + 2 +                                                                       \
	  3 * VDSM_IDE_KM_SELECTIVE_IDE_ADDRESS_ASSOCIATION_REG_BLOCK_SUPPORTED_COUNT) * \
		 VDSM_IDE_KM_SELECTIVE_IDE_REG_BLOCK_SUPPORTED_COUNT)

/*
 * 00 = RX | K0
 * 01 = RX | K1
 * 10 = TX | K0
 * 11 = TX | K1
 */

/*
 * vDSM defines these based on user space
 * spdm-emu and some values are different with
 * those defined in common kernel headers.
 */
#define VDSM_IDE_KM_KEY_SET_MASK 0x01
#define VDSM_IDE_KM_KEY_SET_K0 0x00
#define VDSM_IDE_KM_KEY_SET_K1 0x01

#define VDSM_IDE_KM_KEY_DIRECTION_MASK 0x02
#define VDSM_IDE_KM_KEY_DIRECTION_RX 0x00
#define VDSM_IDE_KM_KEY_DIRECTION_TX 0x02

#define VDSM_IDE_KM_KEY_SUB_STREAM_MASK 0xF0
#define VDSM_IDE_KM_KEY_SUB_STREAM_PR 0x00
#define VDSM_IDE_KM_KEY_SUB_STREAM_NPR 0x10
#define VDSM_IDE_KM_KEY_SUB_STREAM_CPL 0x20

typedef struct {
	uint32_t key[8];
	uint32_t iv[2];
} pci_ide_km_aes_256_gcm_key_buffer_t;

/// @brief IDE KM query context, contain base messages and IDE Register Block messages.
/**
 *  ide_reg_buffer[]      Contains Link IDE Register Block(repeated 0 to 8 times)
 *                        and Selective IDE Stream Register Block( repeated 0 to 255 times).
 *  ide_reg_buffer_count  Count of all IDE Register Block.
 **/
typedef struct {
    uint8_t stream_id;
    uint32_t ide_reg_buffer[VDSM_IDE_KM_IDE_REG_BLOCK_SUPPORTED_COUNT];
    uint32_t ide_reg_buffer_count;
} ide_km_query_ctx_t;

typedef struct ide_km_init_ctx {
    uint8_t stream_id;
} ide_km_init_ctx_t;

typedef ide_km_init_ctx_t ide_km_deinit_ctx_t;

typedef struct ide_km_key_prog_ctx {
    uint8_t stream_id;
    uint8_t key_sub_stream;
    pci_ide_km_aes_256_gcm_key_buffer_t key_buffer;
} ide_km_key_prog_ctx_t;

typedef struct ide_km_key_set_go_ctx {
    uint8_t stream_id;
    uint8_t key_sub_stream;
    uint8_t key_set_go_cnt;
    bool key_set_go[PCI_IDE_SUB_STREAM_NUM]
               [PCI_IDE_SUB_STREAM_DIRECTION_NUM];
} ide_km_key_set_go_ctx_t;

typedef ide_km_key_set_go_ctx_t ide_km_key_set_stop_ctx_t;

#pragma pack()

#endif
