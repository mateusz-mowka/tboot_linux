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
emr-bkc-6.2-v3.6
----------------
23. add missing config options related to testing IAA_CRYPTO

emr-bkc-6.2-v3.5
----------------
22. Fix resume IMS durring migration

emr-bkc-6.2-v3.4
----------------
21. When doing live migration, the qemu uses s2 domain hwpt to operate

emr-bkc-6.2-v3.3
----------------
20. Reduce fequency of unsatble TSC events
	https://hsdes.intel.com/appstore/article/#/14016951426

emr-bkc-6.2-v3.2
----------------
19. ACPI: tools: pfrut: Check if the input of level and type is in the right
    numeric range
	https://hsdes.intel.com/appstore/article/#/15012857647

emr-bkc-6.2-v3.1
----------------
18. Split lock enumeration update
	https://jira.devtools.intel.com/browse/LFE-3635
	
emr-bkc-6.2-v2.7
----------------
17. cherry-picked fixes from emr 5.19 kernel for:
	https://hsdes.intel.com/appstore/article/#/22016309793 
	https://hsdes.intel.com/appstore/article/#/22015866177 

emr-bkc-6.2-v2.6
----------------
16. Add backport of IAA-Crypto from 6.3-rc1

 emr-bkc-6.2-v2.5
----------------
15. There are some build errors under certain configurations (i.e., if
    CONFIG_SMP is not set or CONFIG_UNACCEPTED_MEMORY is not set)

emr-bkc-6.2-v2.4
----------------
15. TD mwait/tsx support.

emr-bkc-6.2-v2.3
----------------
14. update to the change that went into emr-bkc-6.2-v1.10
    to include some pr_info outpput.
    Rather than rebase I did a revert and applied the updated version of the
    patch provided by Weijiang.

semr-bkc-6.2-v2.2
----------------
13. missing fixes WRT the 5.19 EMR BKC
swiotlb: ensure swiotlb buffer size is 2MB aligned
swiotlb: handle the quirk of accept_memory() when allocating unaccept memory
tools/perf/kvm: provide a TDCALL breakdown
swiotlb: fast shared memory allocation
	https://jira.devtools.intel.com/browse/LFE-6243

virtio_ring: accelerate DMA mapping setup/teardown for small buffers
swiotlb: lockless memory allocation and free
x86/tdx: Use direct paravirt call for APIC_ICR MSR write
	https://jira.devtools.intel.com/browse/LFE-108

x86/tdx: Virtualize CPUID leaf 0x2
	https://jira.devtools.intel.com/browse/BLR-708

emr-bkc-6.2-v2.1
----------------
12. iommufd: remove wrong area in iopt while domain attached
	https://jira.devtools.intel.com/browse/LFE-4915

emr-bkc-6.2-v1.11
----------------
11. vfio: Fix bind/unbind mismatch
	https://jira.devtools.intel.com/browse/LFE-6622

emr-bkc-6.2-v1.10
----------------
10. vtd: iommu: Skip invalid list node when flush device iotlb
	https://jira.devtools.intel.com/browse/LFE-7082 

emr-bkc-6.2-v1.9
----------------
9.  Fix bug for TDX init in guest: correct cpus_mask
	https://jira.devtools.intel.com/browse/BLR-809

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
