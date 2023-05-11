/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2021, Intel Corporation. */

#ifndef _ADI_H_
#define _ADI_H_

#include <linux/auxiliary_bus.h>

/**
 * struct adi_aux_dev - Assignable Device Interface structure
 * @adev: auxiliary device structure
 *
 * The Assignable Device Interface defines the communication between a PF
 * driver exposing a portion of its device and a peer driver which exposes
 * that device to user space via VFIO. The two drivers connect over auxiliary
 * bus.
 */
struct adi_aux_dev {
	struct auxiliary_device adev;
};

#endif /* _ADI_H_ */
