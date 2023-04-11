/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TDISP_H__
#define __TDISP_H__

#pragma pack(1)

#include <linux/types.h>
#include <uapi/linux/pci_tdisp.h>

#define VDSM_PROTOCOL_ID_TDISP 0x01

/* TDISP interface ID */

typedef struct {
	uint32_t function_id;
	uint64_t reserved;
} pci_tdisp_interface_id_t;

/* TDISP message header */

typedef struct {
	uint8_t version;
	uint8_t message_type;
	uint8_t reserved[2];
	pci_tdisp_interface_id_t interface_id;
} pci_tdisp_header_t;

#define VDSM_TDISP_MESSAGE_VERSION_10 0x10
#define VDSM_TDISP_MESSAGE_VERSION VDSM_TDISP_MESSAGE_VERSION_10

/* TDISP GET_VERSION request */

typedef struct {
	pci_tdisp_header_t header;
} pci_tdisp_get_version_request_t;

/* TDISP GET_VERSION response */

typedef uint8_t pci_tdisp_version_number_t;

typedef struct {
	pci_tdisp_header_t header;
	uint8_t version_num_count;
	/*pci_tdisp_version_number_t version_num_entry[version_num_count];*/
} pci_tdisp_version_response_t;

/* TDISP GET_CAPABILITIES request */

typedef struct {
	uint32_t tsm_caps;
} pci_tdisp_requester_capabilities_t;

typedef struct {
	pci_tdisp_header_t header;
	pci_tdisp_requester_capabilities_t req_caps;
} pci_tdisp_get_capabilities_request_t;

/* TDISP GET_CAPABILITIES response */

typedef struct {
	uint32_t dsm_caps;
	uint8_t req_msg_supported[16];
	uint16_t lock_interface_flags_supported;
	uint8_t reserved[3];
	uint8_t dev_addr_width;
	uint8_t num_req_this;
	uint8_t num_req_all;
} pci_tdisp_responder_capabilities_t;

typedef struct {
	pci_tdisp_header_t header;
	pci_tdisp_responder_capabilities_t rsp_caps;
} pci_tdisp_capabilities_response_t;

/* TDISP LOCK_INTERFACE_REQUEST request */

typedef struct {
	uint16_t flags;
	uint8_t default_stream_id;
	uint8_t reserved;
	uint64_t mmio_reporting_offset;
	uint64_t bind_p2p_address_mask;
} pci_tdisp_lock_interface_param_t;

typedef struct {
	pci_tdisp_header_t header;
	pci_tdisp_lock_interface_param_t lock_interface_param;
} pci_tdisp_lock_interface_request_t;

#define VDSM_TDISP_LOCK_INTERFACE_FLAGS_NO_FW_UPDATE 0x1
#define VDSM_TDISP_LOCK_INTERFACE_FLAGS_SYSTEM_CACHE_LINE_SIZE 0x2
#define VDSM_TDISP_LOCK_INTERFACE_FLAGS_LOCK_MSIX 0x4
#define VDSM_TDISP_LOCK_INTERFACE_FLAGS_BIND_P2P 0x8
#define VDSM_TDISP_LOCK_INTERFACE_FLAGS_ALL_REQUEST_REDIRECT 0x10

/* TDISP LOCK_INTERFACE_RESPONSE response */

#define VDSM_TDISP_START_INTERFACE_NONCE_SIZE 32

typedef struct {
	pci_tdisp_header_t header;
	uint8_t start_interface_nonce[VDSM_TDISP_START_INTERFACE_NONCE_SIZE];
} pci_tdisp_lock_interface_response_t;

/* TDISP GET_DEVICE_INTERFACE_REPORT request */

typedef struct {
	pci_tdisp_header_t header;
	uint16_t offset;
	uint16_t length;
} pci_tdisp_get_device_interface_report_request_t;

/* TDISP DEVICE_INTERFACE_REPORT response */

typedef struct {
	pci_tdisp_header_t header;
	uint16_t portion_length;
	uint16_t remainder_length;
	/* uint8_t report[portion_length]; */
} pci_tdisp_device_interface_report_response_t;

/* TDISP MMIO_RANGE structure */

typedef struct {
	uint64_t first_page;
	uint32_t number_of_pages;
	uint16_t range_attributes;
	uint16_t range_id;
} pci_tdisp_mmio_range_t;

/* TDISP MMIO_RANGE Attributes */

#define VDSM_TDISP_MMIO_RANGE_ATTRIBUTES_MSIX_TABLE 0x1
#define VDSM_TDISP_MMIO_RANGE_ATTRIBUTES_MSIX_PBA 0x2
#define VDSM_TDISP_MMIO_RANGE_ATTRIBUTES_IS_NON_TEE_MEM 0x4
#define VDSM_TDISP_MMIO_RANGE_ATTRIBUTES_IS_MEM_ATTR_UPDATABLE 0x8

/* TDISP DEVICE_INTERFACE_REPORT structure */

typedef struct {
	uint16_t interface_info;
	uint16_t reserved;
	uint16_t msi_x_message_control;
	uint16_t lnr_control;
	uint32_t tph_control;
	uint32_t mmio_range_count;
} pci_tdisp_device_interface_report_struct_t;

#define VDSM_TDISP_INTERFACE_INFO_NO_UPDATE_AFTER_LOCK 0x1
#define VDSM_TDISP_INTERFACE_INFO_DMA_WITHOUT_PASID 0x2
#define VDSM_TDISP_INTERFACE_INFO_DMA_WITH_PASID 0x4
#define VDSM_TDISP_INTERFACE_INFO_ATS_SUPPORTED 0x8
#define VDSM_TDISP_INTERFACE_INFO_PRS_SUPPORTED 0x10

/* TDISP GET_DEVICE_INTERFACE_STATE request */

typedef struct {
	pci_tdisp_header_t header;
} pci_tdisp_get_device_interface_state_request_t;

/* TDISP DEVICE_INTERFACE_STATE response */

typedef struct {
	pci_tdisp_header_t header;
	uint8_t tdi_state;
} pci_tdisp_device_interface_state_response_t;

#define VDSM_TDISP_INTERFACE_STATE_CONFIG_UNLOCKED 0
#define VDSM_TDISP_INTERFACE_STATE_CONFIG_LOCKED 1
#define VDSM_TDISP_INTERFACE_STATE_RUN 2
#define VDSM_TDISP_INTERFACE_STATE_ERROR 3

/* TDISP START_INTERFACE_REQUEST request */

typedef struct {
	pci_tdisp_header_t header;
	uint8_t start_interface_nonce[VDSM_TDISP_START_INTERFACE_NONCE_SIZE];
} pci_tdisp_start_interface_request_t;

/* TDISP START_INTERFACE_RESPONSE response */

typedef struct {
	pci_tdisp_header_t header;
} pci_tdisp_start_interface_response_t;

/* TDISP STOP_INTERFACE_REQUEST request */

typedef struct {
	pci_tdisp_header_t header;
} pci_tdisp_stop_interface_request_t;

/* TDISP STOP_INTERFACE_RESPONSE response */

typedef struct {
	pci_tdisp_header_t header;
} pci_tdisp_stop_interface_response_t;

/* TDISP BIND_P2P_STREAM_REQUEST request */

typedef struct {
	pci_tdisp_header_t header;
	uint8_t p2p_stream_id;
} pci_tdisp_bind_p2p_stream_request_t;

/* TDISP BIND_P2P_STREAM_RESPONSE response */

typedef struct {
	pci_tdisp_header_t header;
} pci_tdisp_bind_p2p_stream_response_t;

/* TDISP UNBIND_P2P_STREAM_REQUEST request */

typedef struct {
	pci_tdisp_header_t header;
	uint8_t p2p_stream_id;
} pci_tdisp_unbind_p2p_stream_request_t;

/* TDISP UNBIND_P2P_STREAM_RESPONSE response */

typedef struct {
	pci_tdisp_header_t header;
} pci_tdisp_unbind_p2p_stream_response_t;

/* TDISP SET_MMIO_ATTRIBUTE_REQUEST request */

typedef struct {
	pci_tdisp_header_t header;
	pci_tdisp_mmio_range_t mmio_range;
} pci_tdisp_set_mmio_attribute_request_t;

/* TDISP SET_MMIO_ATTRIBUTE_RESPONSE response */

typedef struct {
	pci_tdisp_header_t header;
} pci_tdisp_set_mmio_attribute_response_t;

/* TDISP ERROR response */

typedef struct {
	pci_tdisp_header_t header;
	uint32_t error_code;
	uint32_t error_data;
	/* uint8_t extended_error_data[]; */
} pci_tdisp_error_response_t;

typedef struct {
	uint8_t registry_id;
	uint8_t vendor_id_len;
	/* uint8_t vendor_id[vendor_id_len];
	 * uint8_t vendor_err_data[]; */
} pci_tdisp_extended_error_data_t;

#define VDSM_TDISP_REGISTRY_ID_PCISIG 0x00
#define VDSM_TDISP_REGISTRY_ID_CXL 0x01

/* TDISP error code */

#define VDSM_TDISP_ERROR_CODE_INVALID_REQUEST 0x01
#define VDSM_TDISP_ERROR_CODE_BUSY 0x03
#define VDSM_TDISP_ERROR_CODE_INVALID_INTERFACE_STATE 0x04
#define VDSM_TDISP_ERROR_CODE_UNSPECIFIED 0x05
#define VDSM_TDISP_ERROR_CODE_UNSUPPORTED_REQUEST 0x07
#define VDSM_TDISP_ERROR_CODE_VERSION_MISMATCH 0x41
#define VDSM_TDISP_ERROR_CODE_INVALID_INTERFACE 0x101
#define VDSM_TDISP_ERROR_CODE_INVALID_NONCE 0x102
#define VDSM_TDISP_ERROR_CODE_INSUFFICIENT_ENTROPY 0x103
#define VDSM_TDISP_ERROR_CODE_INVALID_DEVICE_CONFIGURATION 0x104

#define LIBTDISP_MAX_VERSION_COUNT 0x1
#define LIBTDISP_INTERFACE_REPORT_MAX_SIZE 0x1000

#define LIBTDISP_INTERFACE_REPORT_PORTION_LEN 0x40

typedef struct tdisp_interface_report_ctx {
	uint8_t interface_report[LIBTDISP_INTERFACE_REPORT_MAX_SIZE];
	uint16_t interface_report_size;
	uint64_t mmio_reporting_offset;
} tdisp_interface_report_ctx_t;

typedef struct tdisp_start_ctx {
	uint8_t stream_id;
	uint8_t start_interface_nonce[VDSM_TDISP_START_INTERFACE_NONCE_SIZE];
} tdisp_start_ctx_t;

typedef struct tdisp_stop_ctx {
	uint8_t stream_id;
} tdisp_stop_ctx_t;

#pragma pack()

#endif
