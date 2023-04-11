/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __VDSM_IOCTL_H__
#define __VDSM_IOCTL_H__

#include "ide_km.h"
#include "tdisp.h"
#include "adisp.h"
#include "vdsm_internal.h"

#define VDSM				0xDD

/* Utilities */
#define BIND_EVFD			0x01
#define RECV_REQUEST			0x02
#define SEND_RESPONSE			0x03

/* IDE_KM */
#define IDE_KM_INIT_CMD			0x07
#define IDE_KM_QUERY_CMD		0x08
#define IDE_KM_KEY_PROG_CMD		0x09
#define IDE_KM_KEY_SET_GO_CMD		0x0A
#define IDE_KM_KEY_SET_STOP_CMD		0x0B
#define IDE_KM_DEINIT_CMD		0x0C

/* TDISP */
#define TDISP_GET_VERSION_CMD			0x10
#define TDISP_GET_CAPABILITIES_CMD		0x11
#define TDISP_LOCK_INTERFACE_CMD		0x12
#define TDISP_GET_DEVICE_INTERFACE_REPORT_CMD	0x13
#define TDISP_GET_DEVICE_INTERFACE_STATE_CMD	0x14
#define TDISP_START_INTERFACE_CMD		0x15
#define TDISP_STOP_INTERFACE_CMD		0x16

/* ADISP */
#define ADISP_GET_VERSION_CMD			0x20
#define ADISP_GET_CAPABILITIES_CMD		0x21
#define ADISP_LOCK_INTERFACE_CMD		0x22
#define ADISP_GET_DEVICE_INTERFACE_REPORT_CMD	0x23
#define ADISP_GET_DEVICE_INTERFACE_STATE_CMD	0x24
#define ADISP_START_INTERFACE_MMIO_CMD		0x25
#define ADISP_START_INTERFACE_DMA_CMD		0x26
#define ADISP_STOP_INTERFACE_CMD		0x27

#define VDSM_BIND_EVFD			_IOW(VDSM, BIND_EVFD, void *)
#define VDSM_RECV_REQUEST		_IOR(VDSM, RECV_REQUEST, void *)
#define VDSM_SEND_RESPONSE		_IOW(VDSM, SEND_RESPONSE, void *)

#define VDSM_IDE_KM_INIT		_IOW(VDSM, IDE_KM_INIT_CMD, void *)
#define VDSM_IDE_KM_QUERY		_IOWR(VDSM, IDE_KM_QUERY_CMD, void *)
#define VDSM_IDE_KM_KEY_PROG		_IOW(VDSM, IDE_KM_KEY_PROG_CMD, void *)
#define VDSM_IDE_KM_KEY_SET_GO		_IOWR(VDSM, IDE_KM_KEY_SET_GO_CMD, void *)
#define VDSM_IDE_KM_KEY_SET_STOP	_IOWR(VDSM, IDE_KM_KEY_SET_STOP_CMD, void *)
#define VDSM_IDE_KM_DEINIT		_IOW(VDSM, IDE_KM_DEINIT_CMD, void *)

#define VDSM_TDISP_GET_VERSION			_IOR(VDSM, TDISP_GET_VERSION_CMD, void *)
#define VDSM_TDISP_GET_CAPABILITIES		_IOR(VDSM, TDISP_GET_CAPABILITIES_CMD, void *)
#define VDSM_TDISP_LOCK_INTERFACE		_IOW(VDSM, TDISP_LOCK_INTERFACE_CMD, void *)
#define VDSM_TDISP_GET_DEVICE_INTERFACE_REPORT	_IOWR(VDSM, TDISP_GET_DEVICE_INTERFACE_REPORT_CMD, void *)
#define VDSM_TDISP_GET_DEVICE_INTERFACE_STATE	_IOR(VDSM, TDISP_GET_DEVICE_INTERFACE_STATE_CMD, void *)
#define VDSM_TDISP_START_INTERFACE		_IOW(VDSM, TDISP_START_INTERFACE_CMD, void *)
#define VDSM_TDISP_STOP_INTERFACE		_IOW(VDSM, TDISP_STOP_INTERFACE_CMD, void *)

#define VDSM_ADISP_GET_VERSION			_IOR(VDSM, ADISP_GET_VERSION_CMD, void *)
#define VDSM_ADISP_GET_CAPABILITIES		_IOR(VDSM, ADISP_GET_CAPABILITIES_CMD, void *)
#define VDSM_ADISP_LOCK_INTERFACE		_IOW(VDSM, ADISP_LOCK_INTERFACE_CMD, void *)
#define VDSM_ADISP_GET_DEVICE_INTERFACE_REPORT	_IOWR(VDSM, ADISP_GET_DEVICE_INTERFACE_REPORT_CMD, void *)
#define VDSM_ADISP_GET_DEVICE_INTERFACE_STATE	_IOR(VDSM, ADISP_GET_DEVICE_INTERFACE_STATE_CMD, void *)
#define VDSM_ADISP_START_INTERFACE_MMIO		_IOW(VDSM, ADISP_START_INTERFACE_MMIO_CMD, void *)
#define VDSM_ADISP_START_INTERFACE_DMA		_IOW(VDSM, ADISP_START_INTERFACE_DMA_CMD, void *)
#define VDSM_ADISP_STOP_INTERFACE		_IOW(VDSM, ADISP_STOP_INTERFACE_CMD, void *)

#define SUB_STREAM(ctx) \
	((uint32_t)(ctx.key_sub_stream & VDSM_IDE_KM_KEY_SUB_STREAM_MASK) >> 4)
#define DIRECTION(ctx) \
	((ctx.key_sub_stream & VDSM_IDE_KM_KEY_DIRECTION_MASK) >> 1)

#define GET_DEV_MMIO_END(_mmio) \
	((_mmio)->first_page + (_mmio)->number_of_pages * PAGE_SIZE - 1)
#define MSIX_TABLE_SIZE(flags) ((flags & PCI_MSIX_FLAGS_QSIZE) + 1)
#define PCI_TPH_CTRL 8
#define PCIE_DEVICE_ID_CAMBRIA 0x0d52

int vdsm_bind_eventfd(struct vdsm_kernel_stub *vdks, void *arg);
spdm_request_t *generate_request_to_user(struct vdsm_kernel_stub *vdks);
void receive_response_from_user(struct vdsm_kernel_stub *vdks, spdm_response_t *resp);

/* IDE KM */
int ide_km_init(struct vdsm_kernel_stub *vdks, void *context);
int ide_km_query(struct vdsm_kernel_stub *vdks, void *context);
int ide_km_key_prog(struct vdsm_kernel_stub *vdks, void *context);
int ide_km_key_set_go(struct vdsm_kernel_stub *vdks, void *context);
int ide_km_key_set_stop(struct vdsm_kernel_stub *vdks, void *context);
int ide_km_deinit(struct vdsm_kernel_stub *vdks, void *context);

/* TDISP */
int tdisp_get_version(struct vdsm_kernel_stub *vdks, void *context);
int tdisp_get_capabilities(struct vdsm_kernel_stub *vdks, void *context);
int tdisp_lock_interface(struct vdsm_kernel_stub *vdks, void *context);
int tdisp_get_device_interface_report(struct vdsm_kernel_stub *vdks, void *context);
int tdisp_get_device_interface_state(struct vdsm_kernel_stub *vdks, void *context);
int tdisp_start_interface(struct vdsm_kernel_stub *vdks, void *context);
int tdisp_stop_interface(struct vdsm_kernel_stub *vdks, void *context);

/* ADISP */
int adisp_get_version(struct vdsm_kernel_stub *vdks, void *context);
int adisp_get_capabilities(struct vdsm_kernel_stub *vdks, void *context);
int adisp_lock_interface(struct vdsm_kernel_stub *vdks, void *context);
int adisp_get_device_interface_report(struct vdsm_kernel_stub *vdks, void *context);
int adisp_get_device_interface_state(struct vdsm_kernel_stub *vdks, void *context);
int adisp_start_interface_mmio(struct vdsm_kernel_stub *vdks, void *context);
int adisp_start_interface_dma(struct vdsm_kernel_stub *vdks, void *context);
int adisp_stop_interface(struct vdsm_kernel_stub *vdks, void *context);

#endif
