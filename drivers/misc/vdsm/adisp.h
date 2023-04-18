// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022-2023 Intel Corporation */

#ifndef ADISP_H
#define ADISP_H

#define PCI_PROTOCOL_ID_ADISP 0x02

#pragma pack(1)

/* ADISP response code */

#define PCI_ADISP_VERSION 0x01
#define PCI_ADISP_CAPABILITIES 0x02
#define PCI_ADISP_LOCK_INTERFACE_RSP 0x03
#define PCI_ADISP_DEVICE_INTERFACE_REPORT 0x04
#define PCI_ADISP_DEVICE_INTERFACE_STATE 0x05
#define PCI_ADISP_START_INTERFACE_MMIO_RSP 0x06
#define PCI_ADISP_START_INTERFACE_DMA_RSP 0x07
#define PCI_ADISP_STOP_INTERFACE_RSP 0x08
#define PCI_ADISP_DRAIN_INTERFACE_RSP 0x09
#define PCI_ADISP_BIND_PASID_RSP 0x0A
#define PCI_ADISP_BIND_P2P_STREAM_RSP 0x0B
#define PCI_ADISP_UNBIND_P2P_STREAM_RSP 0x0C
#define PCI_ADISP_SET_MMIO_ATTRIBUTE_RSP 0x0D
#define PCI_ADISP_ERROR 0x7F

/* ADISP request code */

#define PCI_ADISP_GET_VERSION 0x81
#define PCI_ADISP_GET_CAPABILITIES 0x82
#define PCI_ADISP_LOCK_INTERFACE_REQ 0x83
#define PCI_ADISP_GET_DEVICE_INTERFACE_REPORT 0x84
#define PCI_ADISP_GET_DEVICE_INTERFACE_STATE 0x85
#define PCI_ADISP_START_INTERFACE_MMIO_REQ 0x86
#define PCI_ADISP_START_INTERFACE_DMA_REQ 0x87
#define PCI_ADISP_STOP_INTERFACE_REQ 0x88
#define PCI_ADISP_DRAIN_INTERFACE_REQ 0x89
#define PCI_ADISP_BIND_PASID_REQ 0x8A
#define PCI_ADISP_BIND_P2P_STREAM_REQ 0x8B
#define PCI_ADISP_UNBIND_P2P_STREAM_REQ 0x8C
#define PCI_ADISP_SET_MMIO_ATTRIBUTE_REQ 0x8D

/* ADISP message header */

typedef struct {
	uint8_t version;
	uint8_t message_type;
	uint8_t param1;
	uint8_t param2;
} pci_adisp_header_t;

#define PCI_ADISP_MESSAGE_VERSION_10 0x10
#define PCI_ADISP_MESSAGE_VERSION PCI_ADISP_MESSAGE_VERSION_10


/* ADISP GET_VERSION request */

typedef struct {
	pci_adisp_header_t header;
} pci_adisp_get_version_request_t;

/* ADISP GET_VERSION response */

typedef uint8_t pci_adisp_version_number_t;

typedef struct {
	pci_adisp_header_t header;
	uint8_t version_num_count;
	/*pci_adisp_version_number_t version_num_entry[version_num_count];*/
} pci_adisp_version_response_t;


/* ADISP GET_CAPABILITIES request */

typedef struct {
	uint32_t tsm_caps;
} pci_adisp_requester_capabilities_t;

typedef struct {
	pci_adisp_header_t header;
	pci_adisp_requester_capabilities_t req_caps;
} pci_adisp_get_capabilities_request_t;

/* ADISP GET_CAPABILITIES response */

typedef struct {
	uint32_t dsm_caps;
} pci_adisp_responder_capabilities_t;

typedef struct {
	pci_adisp_header_t header;
	pci_adisp_responder_capabilities_t rsp_caps;
} pci_adisp_capabilities_response_t;


/* ADISP LOCK_INTERFACE_REQUEST request */

typedef struct {
	uint16_t requester_id;
	uint32_t interface_id;
	uint8_t stream_id;
	uint32_t mmio_reporting_offset_lower;
	uint16_t mmio_reporting_offset_upper;
} pci_adisp_lock_interface_param_t;

typedef struct {
	pci_adisp_header_t header;
	pci_adisp_lock_interface_param_t lock_interface_param;
} pci_adisp_lock_interface_request_t;

#define PCI_ADISP_LOCK_INTERFACE_FLAGS_NO_FW_UPDATE 0x1
#define PCI_ADISP_LOCK_INTERFACE_FLAGS_SYSTEM_CACHE_LINE_SIZE 0x2
#define PCI_ADISP_LOCK_INTERFACE_FLAGS_LOCK_MSIX 0x4
#define PCI_ADISP_LOCK_INTERFACE_FLAGS_BIND_P2P 0x8
#define PCI_ADISP_LOCK_INTERFACE_FLAGS_ALL_REQUEST_REDIRECT 0x10

/* ADISP LOCK_INTERFACE_RESPONSE response */

#define PCI_ADISP_START_INTERFACE_NONCE_SIZE 32

typedef struct {
	pci_adisp_header_t header;
	uint8_t mmio_nonce[32];
	uint8_t dma_nonce[32];
} pci_adisp_lock_interface_response_t;


/* ADISP GET_DEVICE_INTERFACE_REPORT request */

typedef struct {
	pci_adisp_header_t header;
	uint16_t requester_id;
	uint32_t interface_id;
	uint16_t offset;
	uint16_t length;
} pci_adisp_get_device_interface_report_request_t;

/* ADISP DEVICE_INTERFACE_REPORT response */

typedef struct {
	pci_adisp_header_t header;
	uint16_t portion_length;
	uint16_t remainder_length;
	/* uint8_t report[portion_length]; */
} pci_adisp_device_interface_report_response_t;

/* ADISP MMIO_RANGE structure */

typedef struct {
	uint64_t first_page;
	uint32_t number_of_pages;
	uint16_t range_attributes;
	uint16_t range_id;
} pci_adisp_mmio_range_t;

/* ADISP MMIO_RANGE Attributes */

#define PCI_ADISP_MMIO_RANGE_ATTRIBUTES_MSIX_TABLE 0x1
#define PCI_ADISP_MMIO_RANGE_ATTRIBUTES_MSIX_PBA 0x2
#define PCI_ADISP_MMIO_RANGE_ATTRIBUTES_IS_NON_TEE_MEM 0x4
#define PCI_ADISP_MMIO_RANGE_ATTRIBUTES_IS_MEM_ATTR_UPDATABLE 0x8

/* ADISP DEVICE_INTERFACE_REPORT structure */

typedef struct {
	uint16_t intf_info;
	uint16_t msix_msg_ctrl;
	uint32_t tph_ctrl;
	uint16_t lnr_ctrl;
	uint16_t pasid_ctrl;
	uint32_t virt_dev_id;
	uint32_t mmio_range_cnt;
} pci_adisp_device_interface_report_struct_t;

#define PCI_ADISP_INTERFACE_INFO_NO_UPDATE_AFTER_LOCK 0x1

/* ADISP GET_DEVICE_INTERFACE_STATE request */

typedef struct {
	pci_adisp_header_t header;
	uint16_t requester_id;
	uint32_t interface_id;
} pci_adisp_get_device_interface_state_request_t;

/* ADISP DEVICE_INTERFACE_STATE response */

typedef struct {
	pci_adisp_header_t header;
} pci_adisp_device_interface_state_response_t;

#define PCI_ADISP_INTERFACE_STATE_CONFIG_UNLOCKED 0
#define PCI_ADISP_INTERFACE_STATE_CONFIG_LOCKED 1
#define PCI_ADISP_INTERFACE_STATE_RUN_MMIO 2
#define PCI_ADISP_INTERFACE_STATE_RUN_DMA_MMIO 3
#define PCI_ADISP_INTERFACE_STATE_ERROR 4


/* ADISP START_MMIO_INTERFACE_REQUEST request */

typedef struct {
	pci_adisp_header_t header;
	uint16_t requester_id;
	uint32_t interface_id;
	uint8_t start_interface_mmio_nonce[32];
} pci_adisp_start_mmio_interface_request_t;

/* ADISP START_MMIO_INTERFACE_RESPONSE response */

typedef struct {
	pci_adisp_header_t header;
} pci_adisp_start_mmio_interface_response_t;


/* ADISP START_DMA_INTERFACE_REQUEST request */

typedef struct {
	pci_adisp_header_t header;
	uint16_t requester_id;
	uint32_t interface_id;
	uint8_t start_interface_dma_nonce[32];
} pci_adisp_start_dma_interface_request_t;

/* ADISP START_DMA_INTERFACE_RESPONSE response */

typedef struct {
	pci_adisp_header_t header;
} pci_adisp_start_dma_interface_response_t;

/* ADISP STOP_INTERFACE_REQUEST request */

typedef struct {
	pci_adisp_header_t header;
	uint16_t requester_id;
	uint32_t interface_id;
} pci_adisp_stop_interface_request_t;

/* ADISP STOP_INTERFACE_RESPONSE response */

typedef struct {
	pci_adisp_header_t header;
} pci_adisp_stop_interface_response_t;


/* ADISP DRAIN_INTERFACE_REQUEST request */

typedef struct {
	pci_adisp_header_t header;
	uint16_t requester_id;
	uint32_t interface_id;
	uint32_t pasid;
} pci_adisp_drain_interface_request_t;

/* ADISP DRAIN_INTERFACE_RESPONSE response */

typedef struct {
	pci_adisp_header_t header;
} pci_adisp_drain_interface_response_t;


/* ADISP BIND_PASID_STREAM_REQUEST request */

typedef struct {
	pci_adisp_header_t header;
	uint16_t requester_id;
	uint32_t interface_id;
	uint32_t pasid;
	uint8_t functional_unit_id;
} pci_adisp_bind_pasid_request_t;

/* ADISP BIND_PASID_STREAM_RESPONSE response */

typedef struct {
	pci_adisp_header_t header;
} pci_adisp_bind_pasid_response_t;

/* ADISP BIND_P2P_STREAM_REQUEST request */

typedef struct {
	pci_adisp_header_t header;
	uint16_t requester_id;
	uint32_t interface_id;
	uint8_t p2p_stream_id;
} pci_adisp_bind_p2p_stream_request_t;

/* ADISP BIND_P2P_STREAM_RESPONSE response */

typedef struct {
	pci_adisp_header_t header;
} pci_adisp_bind_p2p_stream_response_t;


/* ADISP UNBIND_P2P_STREAM_REQUEST request */

typedef struct {
	pci_adisp_header_t header;
	uint16_t requester_id;
	uint32_t interface_id;
	uint8_t p2p_stream_id;
} pci_adisp_unbind_p2p_stream_request_t;

/* ADISP UNBIND_P2P_STREAM_RESPONSE response */

typedef struct {
	pci_adisp_header_t header;
} pci_adisp_unbind_p2p_stream_response_t;


/* ADISP SET_MMIO_ATTRIBUTE_REQUEST request */

typedef struct {
	pci_adisp_header_t header;
	uint16_t requester_id;
	uint32_t interface_id;
	pci_adisp_mmio_range_t mmio_range;
} pci_adisp_set_mmio_attribute_request_t;

/* ADISP SET_MMIO_ATTRIBUTE_RESPONSE response */

typedef struct {
	pci_adisp_header_t header;
} pci_adisp_set_mmio_attribute_response_t;

/* adisp ERROR response */

typedef struct {
	pci_adisp_header_t header;
	uint32_t error_code;
	uint32_t error_data;
	/* uint8_t extended_error_data[]; */
} pci_adisp_error_response_t;

typedef struct {
	uint8_t registry_id;
	uint8_t vendor_id_len;
	/* uint8_t vendor_id[vendor_id_len];
	 * uint8_t vendor_err_data[]; */
} pci_adisp_extended_error_data_t;

#define PCI_ADISP_REGISTRY_ID_PCISIG 0x00
#define PCI_ADISP_REGISTRY_ID_CXL 0x01

/* ADISP error code */

#define PCI_ADISP_ERROR_CODE_INVALID_REQUEST 0x01
#define PCI_ADISP_ERROR_CODE_BUSY 0x03
#define PCI_ADISP_ERROR_CODE_INVALID_INTERFACE_STATE 0x04
#define PCI_ADISP_ERROR_CODE_UNSPECIFIED 0x05
#define PCI_ADISP_ERROR_CODE_UNSUPPORTED_REQUEST 0x07
#define PCI_ADISP_ERROR_CODE_VERSION_MISMATCH 0x41
#define PCI_ADISP_ERROR_CODE_INVALID_INTERFACE 0x101
#define PCI_ADISP_ERROR_CODE_INVALID_NONCE 0x102
#define PCI_ADISP_ERROR_CODE_INSUFFICIENT_ENTROPY 0x103
#define PCI_ADISP_ERROR_CODE_INVALID_FUNCTIONAL_UNIT_ID 0x104
#define PCI_ADISP_ERROR_CODE_INVALID_DEVICE_CONFIGURATION 0x105

#define LIBADISP_MAX_VERSION_COUNT 0x1
#define LIBADISP_INTERFACE_REPORT_MAX_SIZE 0x1000

#define LIBADISP_INTERFACE_REPORT_PORTION_LEN 0x40

typedef struct adisp_interface_report_ctx {
	uint8_t interface_report[LIBADISP_INTERFACE_REPORT_MAX_SIZE];
	uint16_t interface_report_size;
	uint64_t mmio_reporting_offset;
} adisp_interface_report_ctx_t;

typedef struct adisp_start_mmio_ctx {
	uint8_t stream_id;
	uint8_t mmio_nonce[PCI_ADISP_START_INTERFACE_NONCE_SIZE];
} adisp_start_mmio_ctx_t;

typedef struct adisp_start_dma_ctx {
	uint8_t stream_id;
	uint8_t dma_nonce[PCI_ADISP_START_INTERFACE_NONCE_SIZE];
} adisp_start_dma_ctx_t;

typedef struct adisp_stop_ctx {
	uint8_t stream_id;
} adisp_stop_ctx_t;

#pragma pack()

#endif
