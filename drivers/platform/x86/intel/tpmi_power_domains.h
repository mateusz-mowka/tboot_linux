/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * tpmi_power_domains: Mapping of TPMI power domain and CPUs
 * Copyright (c) 2023, Intel Corporation.
 * All rights reserved.
 *
 */

#ifndef _TPMI_POWER_DOMAINS_H_
#define _TPMI_POWER_DOMAINS_H_

int tpmi_get_linux_cpu_number(int package_id, int die_id, int punit_core_id);
int tpmi_get_punit_core_number(int cpu_no);
int tpmi_get_power_domain_id(int cpu_no);
cpumask_t *tpmi_get_power_domain_mask(int cpu_no);

#endif
