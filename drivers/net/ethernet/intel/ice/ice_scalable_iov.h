/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2021, Intel Corporation. */

#ifndef _ICE_SCALABLE_IOV_H_
#define _ICE_SCALABLE_IOV_H_

#include "ice.h"
#include "ice_devlink_port.h"
#include <linux/vfio.h>

#define ICE_DFLT_QS_PER_SIOV_VF		4
#define ICE_ADI_BAR0_SIZE		SZ_64M

int
ice_scalable_dev_activate(struct ice_dynamic_port *dyn_port,
			  struct netlink_ext_ack *extack);
void ice_scalable_dev_deactivate(struct ice_dynamic_port *dyn_port);

bool ice_is_siov_capable(struct ice_pf *pf);
void ice_restore_pasid_config(struct ice_pf *pf, enum ice_reset_req reset_type);
int ice_init_siov_resources(struct ice_pf *pf, struct netlink_ext_ack *extack);
void ice_deinit_siov_resources(struct ice_pf *pf);

#endif /* _ICE_SCALABLE_IOV_H_ */
