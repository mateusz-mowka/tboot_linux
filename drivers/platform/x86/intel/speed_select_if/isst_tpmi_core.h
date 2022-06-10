/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Intel Speed Select Interface: Drivers Internal defines
 * Copyright (c) 2019, Intel Corporation.
 * All rights reserved.
 *
 * Author: Srinivas Pandruvada <srinivas.pandruvada@linux.intel.com>
 */

#ifndef _ISST_TPMI_CORE_H
#define _ISST_TPMI_CORE_H

int tpmi_sst_init(void);
void tpmi_sst_exit(void);
int tpmi_sst_dev_add(struct auxiliary_device *auxdev);
void tpmi_sst_dev_remove(struct auxiliary_device *auxdev);
void tpmi_sst_dev_suspend(struct auxiliary_device *auxdev);
void tpmi_sst_dev_resume(struct auxiliary_device *auxdev);
#endif
