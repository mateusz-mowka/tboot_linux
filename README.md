Purpose
=======
Provide Best Known Configuration (BKC) kernel for GNR customers.

The BKC kernel is based on v6.2 kernel + EMR 6.2 kernel.

WARNING this kernel contains technology preview code that is
subject to change once it goes upstream. This kernel is
strictly for hardware validation, not production. Applications
tested against this kernel may behave differently, or may not
operate at all once the code is finalized in the mainline kernel.
Use at your own risk.

Release History
===============
gnr-bkc-6.2-v1.2
----------------
4. Merged features:
    IFS (In Field Scan) extra patches
    PM
    emr-bkc-6.2-v4.4 tag
    IAA Crypto

    73069aef89b7 Merge branch 'for_gnr-bkc-6.2' 74834ae of https://github.com/intel-sandbox/drivers.saf
    7a8c021a1ecd Merge commit '7b18706fc91e0e3bfe2029feefa5eaadf2104a8d' of https://github.com/intel-sandbox/debox1.linux debox_pm_for_intel_next
    180153e86587 Merge tag 'emr-bkc-6.2-v4.4' of https://github.com/intel-innersource/os.linux.emeraldrapids.thirdparty.kernel into gnr-staging-6.2
    7684e8224a2c Merge commit '9737f12c611368d1191c0c3264cc0b004db78ab0' of https://github.com/intel-sandbox/idxd tzanussi/emr-bkc-6.2-iaa-crypto

gnr-bkc-6.2-v1.1
----------------
3. Merged features:

    ce532dc34fa9 Merge commit 'ddbd3771abf385e3731c7674b725bab7ae1619bc' of https://github.com/intel-sandbox/rzhang1 for-intel-next-tpmi
    f1550e460099 Merge commit '8d4eac3cea41adfee7eb75d3b9ef45de5b9a709f' of https://github.com/intel-sandbox/linux-kernel-rjingar pson_counter
    f5bbcc90c479 Merge commit '3136bccda667a45456dab9fd05da8dee6fb62a56' of https://github.com/intel-innersource/os.linux.validation.svos-next.svos-next svos-next-tdx-pull-6.2
    e83d241827e7 Merge commit '61b07a74bfd2c7c1f0a96071315ed77693e7473c' of https://github.com/intel-innersource/os.linux.validation.svos-next.svos-next svos-next-pull-6.2
    dd077570e3eb Merge commit 'c600f9c2babba00df0c0fba95c35c8da353f9989' of https://github.com/intel-sandbox/otc_power_kernel mtl_dids_linus_rc
    4bde2623a0d3 Merge commit '73e16e7b8eb287481d5bdf0179bc031e899b4a1e' of https://github.com/intel-sandbox/kernel split_lock
    fb77228e23a1 Merge commit '2665e52fe74141620270448539c874045b34b66c' of https://github.com/mchinth/linux socwatch_linux_6_1
    8b3c880fbafe Merge commit '881a9c9e0cf5317618d7182e34475ca67c519b73' of https://github.com/intel-sandbox/jarkkoni.linux.kernel for-intel-next
    0bfedfc18f9c Merge commit 'f0e1aaf7701c9a4dc30dbbf8b3db5a553e741228' of https://github.com/intel-sandbox/agluck-linux next-6.2-mba4.0
    1dd6c4da9d7a Merge commit 'e686c32590f40bffc45f105c04c836ffad3e531a' of https://git.kernel.org/pub/scm/linux/kernel/git/cxl/cxl next
    8c0d11beea7f Merge commit '304560253856f99302727e2f3da6ccec7aabaa55' of https://github.com/intel-sandbox/mwesterb-linux.git for-eywa
    a06fcf5543b9 Merge commit 'e037e956d2f20ea55c10a2ba8892b8552605fb1b' of https://github.com/intel-sandbox/kernel-works lass-6.2-rc2
    e8f8203670ad Merge branch 'fix-mc-recovery-on-sierra-forest-for-atom-cores' into gnr-staging-6.2
    10a2c19b997d Merge branch 'perf-fix-lfe7417' into gnr-staging-6.2
    3e60295c6085 Merge commit 'c4e1a74d9b20b1dc4276f5182bc3aca2c3b0a35e' of https://github.com/intel-sandbox/ranerica.linux rneri/hybrid-for-intel-next
    f2130fcd38ac Merge commit '14cbc7d8eb33a81d6753319df887bbb85103c530' of https://github.com/intel-sandbox/otc_power_kernel nvme_simics_fix
    a820bd495024 Merge commit 'c20485f76eac84a32cd19417e7b529d341e75a71' of https://github.com/intel-sandbox/xi_linux pmc_core_intel_next
    ede2e2faf5b8 Merge commit '85b93bbd1c9768d09adebbe9f33bab0d4ec94404' of https://git.kernel.org/pub/scm/linux/kernel/git/jarkko/linux-tpmdd next
    56765352f84b Merge commit 'ea150b53b1fd250a0c49f9ade353634dd7976fbf' of https://git.kernel.org/pub/scm/linux/kernel/git/rafael/linux-pm testing
    9f3f2cad5e81 Merge commit 'a5133d2dd58afda9f9a38fda98e6bf79f2862008' https://github.com/intel-sandbox/ahunter6.next.git intel-th-v6.2
    673c49994188 Merge commit '13099ff445858bc2bb6f5d0cd2afa8ceb93ae2ca' of https://github.com/intel-sandbox/ashevche.linux.kernel intel/for-next
    8a7f23b971f0 Merge commit '27addb311d82bc4a40c8a5719f63b3020552b241' of https://github.com/intel-sandbox/mnyman-linux for-intel-next
    c54e7c0f1cb3 Merge commit '728eea85c941caa37eceb166b9721cded05a29e3' https://github.com/intel-sandbox/ahunter6.next.git scs-v6.2

gnr-bkc-6.2-v1.0
----------------
2. ACPI: APEI: EINJ: Add CXL error types
1. Add gnr config

emr-bkc-6.2-v4.4
----------------
26. Remove workaround wrong area in iopt while domain attached.
	fixes https://jira.devtools.intel.com/browse/LFE-7359

emr-bkc-6.2-v4.3
----------------
26. . Update the SEAM loader to SEAMLDR_1.5.00.15.147 and TDX module to
	TDX_1.5.00.19.481 in next EMR BKC release, it will solve the TDX LM
	issue https://hsdes.intel.com/appstore/article/#/15012768412

emr-bkc-6.2-v4.2
----------------
25.Long login time fix
	https://jira.devtools.intel.com/browse/LFE-459

emr-bkc-6.2-v4.1
----------------
24.cherry pick fix from 5.19 emr-bkc kernel:
	https://hsdes.intel.com/appstore/article/#/16020142180
	5.19 issue : https://hsdes.intel.com/appstore/article/#/16018901612

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
