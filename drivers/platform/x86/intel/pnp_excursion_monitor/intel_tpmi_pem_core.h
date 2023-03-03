/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Intel PEM Interface: Drivers Internal interfaces
 * Copyright (c) 2022, Intel Corporation.
 * All rights reserved.
 *
 */

#ifndef _INTEL_TPMI_PEM_CORE_H
#define _INTEL_TPMI_PEM_CORE_H

int tpmi_pem_pmu_init(void);
void tpmi_pem_pmu_exit(void);
int tpmi_pem_dev_add(struct auxiliary_device *auxdev);
void tpmi_pem_dev_remove(struct auxiliary_device *auxdev);

#endif
