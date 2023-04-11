/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __VDSM_IOCTL_H__
#define __VDSM_IOCTL_H__

#include "vdsm_internal.h"

#define VDSM				0xDD

/* Utilities */
#define BIND_EVFD			0x01
#define RECV_REQUEST			0x02
#define SEND_RESPONSE			0x03

#define VDSM_BIND_EVFD			_IOW(VDSM, BIND_EVFD, void *)
#define VDSM_RECV_REQUEST		_IOR(VDSM, RECV_REQUEST, void *)
#define VDSM_SEND_RESPONSE		_IOW(VDSM, SEND_RESPONSE, void *)

int vdsm_bind_eventfd(struct vdsm_kernel_stub *vdks, void *arg);
spdm_request_t *generate_request_to_user(struct vdsm_kernel_stub *vdks);
void receive_response_from_user(struct vdsm_kernel_stub *vdks, spdm_response_t *resp);

#endif
