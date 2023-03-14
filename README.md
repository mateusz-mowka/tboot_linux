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
emr-bkc-6.2-v1.8
----------------
8.  KVM: TDX: Fix the private/shared check of gfn
	https://jira.devtools.intel.com/browse/LFE-7263

emr-bkc-6.2-v1.7
----------------
7. iommufd: detach all hwpts before device unbind
	https://jira.devtools.intel.com/browse/LFE-7250

emr-bkc-6.2-v1.6
----------------
6. CONFIG_X86_KERNEL_IBT=y
	https://jira.devtools.intel.com/browse/LFE-7224

emr-bkc-6.2-v1.5
----------------
5. Fix an issue reported in https://jira.devtools.intel.com/browse/LFE-4901 that host ping/SSH VM failed while performing SRIOV VF NIC passthrough to VM with scalable mode vIOMMU while qemu command adds "iommufd=iommufd0"
    iommu/vt-d: Detach from old domain early
    iommu/vt-d: Get domain reference from device_domain_info
    iommu/vt-d: Add detach_dev callback
    iommu: detach from nested domain before blocking
    iommu/vt-d: Setup pasid binding for PASID_RID2PASID

emr-bkc-6.2-v1.4
----------------
4. SIOV IMS bring up for 6.2 emr-bkc kernel Basic functions verified
   (PF/DWQ/SWQ passthourhg and dmatest

emr-bkc-6.2-v1.3
----------------
3. iommu: Adjust host addr_width info with no5lvl
   https://jira.devtools.intel.com/browse/LFE-4914
   reinable 5Level

emr-bkc-6.2-v1.2
----------------
2. added arch/x86/configs/emr.config for for holding the build config for use
   with this kernel.
   CONFIG_INTEL_TCC_COOLING=m
   CONFIG_TDX_GUEST_DRIVER=m
   disable 5Level

emr-bkc-6.2-v1.1
----------------
1. harvest from the 6.2 intel-next kernel  See the bkc directory for the
   intel-next manifest of PR's used to start the emg-bkc-6.2 kernel.
