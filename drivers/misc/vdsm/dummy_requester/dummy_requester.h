#include <linux/netlink.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/eventfd.h>
#include <linux/pci-doe.h>
#include <linux/vdsm.h>

#define MAX_DEVICES	2

#define VDSM 0xF9
#define BIND_EVFD 0x01
#define SEND_REQUEST 0x02
#define RECV_RESPONSE 0x03

#define VDSM_BIND_EVFD _IOW(VDSM, BIND_EVFD, void *)
#define VDSM_SEND_REQUEST _IOR(VDSM, SEND_REQUEST, void *)
#define VDSM_RECV_RESPONSE _IOW(VDSM, RECV_RESPONSE, void *)

#define LIBSPDM_MAX_MESSAGE_BUFFER_SIZE		0x1200
#define LIBSPDM_DATA_TRANSFER_SIZE		LIBSPDM_MAX_MESSAGE_BUFFER_SIZE
#define LIBSPDM_TRANSPORT_ADDITIONAL_SIZE	64
#define LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE	(LIBSPDM_DATA_TRANSFER_SIZE + \
						 LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)

#define MAX_VENDOR_DEF_PL_SIZE (LIBSPDM_MAX_MESSAGE_BUFFER_SIZE - \
				sizeof(struct vendor_def_header))

#define PCI_PROTOCOL_ID_IDE_KM	0x00
#define PCI_PROTOCOL_ID_TDISP	0x01

#pragma pack(push, 1)
struct doe_header {
	uint16_t vendor_id;
	uint8_t type;
	uint8_t reserved;
	uint32_t length;
};

struct secure_spdm_header {
        uint32_t session_id;
        uint16_t length;
        uint16_t app_length;
};

struct vendor_def_header {
        uint8_t spdm_ver;
        uint8_t spdm_code;
        uint8_t param1;
        uint8_t param2;
        uint16_t standard_id;
        uint8_t len;
        uint16_t vendor_id;
        uint16_t payload_len;
};

struct vendor_def_payload {
	uint8_t protocol_id;
	uint8_t payload[MAX_VENDOR_DEF_PL_SIZE - 1];
};

typedef struct vdsm_spdm_request {
	struct doe_header doe_h;
	struct secure_spdm_header spdm_h;
	struct vendor_def_header vendor_h;
	struct vendor_def_payload vendor_pl;
} spdm_request_t;

typedef spdm_request_t spdm_response_t;

#pragma pack(pop)
