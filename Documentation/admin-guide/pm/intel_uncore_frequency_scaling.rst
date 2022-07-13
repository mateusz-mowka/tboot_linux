.. SPDX-License-Identifier: GPL-2.0
.. include:: <isonum.txt>

==============================
Intel Uncore Frequency Scaling
==============================

:Copyright: |copy| 2022 Intel Corporation

:Author: Srinivas Pandruvada <srinivas.pandruvada@linux.intel.com>

Introduction
------------

The uncore can consume significant amount of power in Intel's Xeon servers based
on the workload characteristics. To optimize the total power and improve overall
performance, SoCs have internal algorithms for scaling uncore frequency. These
algorithms monitor workload usage of uncore and set a desirable frequency.

It is possible that users have different expectations of uncore performance and
want to have control over it. The objective is similar to allowing users to set
the scaling min/max frequencies via cpufreq sysfs to improve CPU performance.
Users may have some latency sensitive workloads where they do not want any
change to uncore frequency. Also, users may have workloads which require
different core and uncore performance at distinct phases and they may want to
use both cpufreq and the uncore scaling interface to distribute power and
improve overall performance.

Sysfs Interface
---------------

To control uncore frequency, a sysfs interface is provided in the directory:
`/sys/devices/system/cpu/intel_uncore_frequency/`.

The scope of control for uncore frequency is at package/die level for
processor generations prior to Granite Rapids CPUs. Granite Rapids generation
and later SoCs can provide more granular interface. They can contain multiple
power domains with individual or collection of mesh partitions. Each of this
partition is called fabric cluster.

When there is no power domain level control, there is one directory
for each package and die combination. The scope of uncore scaling control
is per die in multiple die/package SoCs or per package for single die per
package SoCs. The name represents the scope of control.
For example: 'package_00_die_00' is for package id 0 and die 0.

When there are multiple power domains present, then an unique instance
id is appended. For example
package_00_die_00.00, package_00_die_00.01 etc. The sysfs attributes
present inside the folder identify power domain and fabric cluster.

Each package_*_die_* directory can contain the following attributes:

``initial_max_freq_khz``
	Out of reset, this attribute represent the maximum possible frequency.
	This is a read-only attribute. If users adjust max_freq_khz,
	they can always go back to maximum using the value from this attribute.

``initial_min_freq_khz``
	Out of reset, this attribute represent the minimum possible frequency.
	This is a read-only attribute. If users adjust min_freq_khz,
	they can always go back to minimum using the value from this attribute.

``max_freq_khz``
	This attribute is used to set the maximum uncore frequency.

``min_freq_khz``
	This attribute is used to set the minimum uncore frequency.

``current_freq_khz``
	This attribute is used to get the current uncore frequency.

``domain_id``
	This attribute is used to get the power domain id of this instance.
	Present only when there are multiple power domains.

``fabric_cluster_id``
	This attribute is used to get the fabric cluster id of this instance.
	Present only when there are multiple power domains.
