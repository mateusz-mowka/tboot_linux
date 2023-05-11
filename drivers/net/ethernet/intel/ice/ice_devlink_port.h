/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023, Intel Corporation. */

#ifndef _ICE_DEVLINK_PORT_H_
#define _ICE_DEVLINK_PORT_H_

#include "ice.h"

struct ice_sf_dev;
struct ice_scalable_dev;

/**
 * struct ice_dynamic_port - Track dynamically added devlink port instance
 * @hw_addr: the HW address for this port
 * @active: true if the port has been activated
 * @devlink_port: the associated devlink port structure
 * @pf: pointer to the PF private structure
 * @vsi: the VSI associated with this port
 * @priv: flavour-specific private data
 *
 * An instance of a dynamically added devlink port. Each port flavour
 */
struct ice_dynamic_port {
	u8 hw_addr[ETH_ALEN];
	u8 active : 1;
	struct devlink_port devlink_port;
	struct ice_pf *pf;
	struct ice_vsi *vsi;
	/* Flavour-specific implementation data */
	union {
		struct ice_sf_dev *sf_dev;
		struct ice_scalable_dev *scalable_dev;
	};
};

void ice_dealloc_all_dynamic_ports(struct ice_pf *pf);

int
ice_devlink_port_split(struct devlink *devlink, struct devlink_port *port,
		       unsigned int count, struct netlink_ext_ack *extack);

int
ice_devlink_port_unsplit(struct devlink *devlink, struct devlink_port *port,
			 struct netlink_ext_ack *extack);

int ice_devlink_create_pf_port(struct ice_pf *pf);
void ice_devlink_destroy_pf_port(struct ice_pf *pf);
int ice_devlink_create_vf_port(struct ice_vf *vf);
void ice_devlink_destroy_vf_port(struct ice_vf *vf);
int ice_devlink_create_sf_dev_port(struct ice_sf_dev *sf_dev);

#define ice_devlink_port_to_dyn(p) \
	container_of(port, struct ice_dynamic_port, devlink_port)

int
ice_dl_port_new(struct devlink *devlink,
		const struct devlink_port_new_attrs *new_attr,
		struct netlink_ext_ack *extack,
		unsigned int *new_port_index);

int
ice_dl_port_del(struct devlink *devlink, unsigned int port_index,
		struct netlink_ext_ack *extack);

int
ice_dl_port_fn_hw_addr_set(struct devlink_port *port, const u8 *hw_addr,
			   int hw_addr_len, struct netlink_ext_ack *extack);

int
ice_dl_port_fn_hw_addr_get(struct devlink_port *port, u8 *hw_addr,
			   int *hw_addr_len, struct netlink_ext_ack *extack);

int
ice_dl_port_fn_state_set(struct devlink_port *port,
			 enum devlink_port_fn_state state,
			 struct netlink_ext_ack *extack);

int
ice_dl_port_fn_state_get(struct devlink_port *port,
			 enum devlink_port_fn_state *state,
			 enum devlink_port_fn_opstate *opstate,
			 struct netlink_ext_ack *extack);

#endif /* _ICE_DEVLINK_PORT_H_ */
