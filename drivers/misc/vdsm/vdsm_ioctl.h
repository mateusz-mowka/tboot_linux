/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __VDSM_IOCTL_H__
#define __VDSM_IOCTL_H__

#include "ide_km.h"
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

#define VDSM_BIND_EVFD			_IOW(VDSM, BIND_EVFD, void *)
#define VDSM_RECV_REQUEST		_IOR(VDSM, RECV_REQUEST, void *)
#define VDSM_SEND_RESPONSE		_IOW(VDSM, SEND_RESPONSE, void *)

#define VDSM_IDE_KM_INIT		_IOW(VDSM, IDE_KM_INIT_CMD, void *)
#define VDSM_IDE_KM_QUERY		_IOWR(VDSM, IDE_KM_QUERY_CMD, void *)
#define VDSM_IDE_KM_KEY_PROG		_IOW(VDSM, IDE_KM_KEY_PROG_CMD, void *)
#define VDSM_IDE_KM_KEY_SET_GO		_IOWR(VDSM, IDE_KM_KEY_SET_GO_CMD, void *)
#define VDSM_IDE_KM_KEY_SET_STOP	_IOWR(VDSM, IDE_KM_KEY_SET_STOP_CMD, void *)
#define VDSM_IDE_KM_DEINIT		_IOW(VDSM, IDE_KM_DEINIT_CMD, void *)

#define SUB_STREAM(ctx) \
	((uint32_t)(ctx.key_sub_stream & VDSM_IDE_KM_KEY_SUB_STREAM_MASK) >> 4)
#define DIRECTION(ctx) \
	((ctx.key_sub_stream & VDSM_IDE_KM_KEY_DIRECTION_MASK) >> 1)

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

#endif
