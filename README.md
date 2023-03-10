Purpose
=======
Provide Best Known Configuration (BKC) kernel for EMR customers.

The BKC kernel is based on v6.2 kernel. 

WARNING this kernel contains technology preview code that is
subject to change once it goes upstream. This kernel is
strictly for hardware validation, not production. Applications
tested against this kernel may behave differently, or may not
operate at all once the code is finalized in the mainline kernel.
Use at your own risk.

Release History
===============

emr-bkc-6.2-v1.4
================
4. SIOV IMS bring up for 6.2 emr-bkc kernel Basic functions verified
   (PF/DWQ/SWQ passthourhg and dmatest

emr-bkc-6.2-v1.3
================
3. iommu: Adjust host addr_width info with no5lvl
   https://jira.devtools.intel.com/browse/LFE-4914
   reinable 5Level

emr-bkc-6.2-v1.2
================
2. added arch/x86/configs/emr.config for for holding the build config for use
   with this kernel.
   CONFIG_INTEL_TCC_COOLING=m
   CONFIG_TDX_GUEST_DRIVER=m
   disable 5Level

emr-bkc-6.2-v1.1
================
1. harvest from the 6.2 intel-next kernel  See the bkc directory for the
   intel-next manifest of PR's used to start the emg-bkc-6.2 kernel.
