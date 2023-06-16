Purpose
=======
Provide Best Known Configuration (BKC) kernel for SRF customers.

The BKC kernel is based on v6.2 kernel + GNR 6.2 kernel.

Where the GNR kernel is based on v6.2 kernel + EMR 6.2 kernel.

WARNING this kernel contains technology preview code that is
subject to change once it goes upstream. This kernel is
strictly for hardware validation, not production. Applications
tested against this kernel may behave differently, or may not
operate at all once the code is finalized in the mainline kernel.
Use at your own risk.

Release History
===============
srf-bkc-6.2-v3.10
----------------
53. Issue: work around TD launch issue by setting 
    CONFIG_INTEL_TDX_HOST_DEBUG_MEMORY_CORRUPT
    https://jira.devtools.intel.com/browse/LFE-8652

srf-bkc-6.2-v3.9
----------------
52. Issue: enable FW_LOADER_COMPRESS_XZ for out of tree ICE driver support.
    https://hsdes.intel.com/appstore/article/#/15013303281

bkc-6.2-v3.8
----------------
51. Issue: missing some eBPF related kernel configs
    https://jira.devtools.intel.com/browse/LINUXBKC3-12

srf-bkc-6.2-v3.7
----------------
50. Issue: fix for the TD booting fail caused by MSR TSX_CTRL
    https://jira.devtools.intel.com/browse/LFE-8557

srf-bkc-6.2-v3.6
----------------
49. Issue: Cannot launch container on EMB BKC kernel 6.2.0-emr.bkc.6.2.5.6.33.x86_64
    https://jira.devtools.intel.com/browse/LINUXBKC3-11
    https://hsdes.intel.com/appstore/article/#/14019589887
    Fix:
    CONFIG_CGROUP_BPF=y
    CONFIG_CGROUP_MISC=y
    CONFIG_BLK_CGROUP_IOLATENCY=y
    CONFIG_BLK_CGROUP_FC_APPID=y

srf-bkc-6.2-v3.5
----------------
48. Port missing DSA patches from GNR BKC 5.19 kernel to SRF BKC 6.2 kernel

srf-bkc-6.2-v3.4
----------------
47. backport upstream IFS and uCode changes from v6.4-rc4
    unblocks some uCode test cases.

srf-bkc-6.2-v3.3
----------------
46. backport upstream rapl changes from v6.4-rc4

srf-bkc-6.2-v3.2
----------------
46. add CONFIG_X86_KERNEL_IBT=y
    https://hsdes.intel.com/appstore/article/#/15013164115

srf-bkc-6.2-v3.1
-----------------
45. IFS cli test tool will not work without this change.
    Fix SBFT device enumeration

srf-bkc-6.2-v2.12
-----------------
44. cleaned up the README.md

srf-bkc-6.2-v2.11
-----------------
44. Linear Address Masking support enabled in the kernel config
    CONFIG_ADDRESS_MASKING=y

srf-bkc-6.2-v2.10
-----------------
43. srf-bkc: add srf.config
    added the srf.config file to arch/x86/configs

srf-bkc-6.2-v2.9
-----------------
42. srf-bkc: Backport fixes from GNR BKC kernel
    dmaengine: idxd: Fix multiple submitters issue
    Source:
    https://github.com/intel-sandbox/os.linux.sierraforest.poweron/tree/bkc-v1.6


srf-bkc-6.2-v2.8
-----------------
41. srf-bkc: Enable softlokup debug option and C1 state fix
    Force enable C1 state
    Enable BOOTPARAM_SOFTLOCKUP_PANIC debug option
    Source:
    https://github.com/intel-sandbox/os.linux.sierraforest.poweron/tree/bkc-v1.6


srf-bkc-6.2-v2.7
-----------------
40. srf-bkc: Fixes for PMU, ACPI and KVM features
    Enable ACPI debugger support
    Remove ZBBed PMU feature (RDPMC_USER_DISABLE)
    Fixed nested VM issue
    Source:
    https://github.com/intel-sandbox/os.linux.sierraforest.poweron/tree/bkc-v1.6

srf-bkc-6.2-v2.6
-----------------
39. srf-bkc: Fixes for PMU LBR event logging
    Update PMU LBR event logging format
    Source:
    https://github.com/intel-sandbox/os.linux.sierraforest.poweron/tree/bkc-v1.6

srf-bkc-6.2-v2.5
-----------------
38. srf-bkc: Fix LASS vsyscall issue
    Fix LASS vsyscall issue
    Source:
    https://github.com/intel-sandbox/os.linux.sierraforest.poweron/tree/bkc-v1.6

srf-bkc-6.2-v2.4
-----------------
37. srf-bkc: Enable IBT and Intel idle support
    Enable CONFIG_X86_KERNEL_IBT config
    Add Intel IDLE support for SRF platform
    Source:
    https://github.com/intel-sandbox/os.linux.sierraforest.poweron/tree/bkc-v1.6

srf-bkc-6.2-v2.3
-----------------
36. srf-bkc: Add in-field driver support for SRF platform
    * Add in-field driver support for SRF platform
    Source:
    https://github.com/intel-sandbox/os.linux.sierraforest.poweron/tree/bkc-v1.6

srf-bkc-6.2-v2.2
-----------------
35. srf-bkc:Bug fixes related to MSRLIST and LBR
    * Add KVM MSRLIST CPUID enabling support
    * Fix active group check for LBR log event
    * Fix load and snoop events issue 
    Sources:
    https://github.com/intel-sandbox/os.linux.sierraforest.poweron/tree/bkc-v1.6
    https://github.com/intel-innersource/os.linux.intelnext.kernel

srf-bkc-6.2-v2.1
-----------------
34. srf-bkc: Add KVM LAM feature support
    Source: https://github.com/binbinwu1/linux/commits/v6.3-rc6-kvm-lam-new

gnr-bkc-6.2-v1.30
-----------------
33. dmaengine: idxd: Workaround Inter-domain PASID table entry flush issue

gnr-bkc-6.2-v1.29
-----------------
32. Bug: https://hsdes.intel.com/appstore/article/#/16020360586
    Fix: Use fuse enabled mask instead of allowed levels

gnr-bkc-6.2-v1.28
-----------------
31. Merge TDX2.0/TDXIO feature patches.

gnr-bkc-6.2-v1.27
-----------------
30. Merge IAA Crypto ZSWAP patches and test cases.

gnr-bkc-6.2-v1.26
-----------------
29. Feature: https://jira.devtools.intel.com/browse/LFE-7259
    Implements the QEMU/KVM side feature for VTPM of INTEL TDX guest, includes:
    1. Add Unix datagram socket supporting for QEMU
    2. Add basic VMCALL.SERVICE<vTPM> supporting for KVM/QEMU
    3. Add new properties on QEMU for vTPM
    4. Add VMCALL.SERVICE<vTPM.sendmessage> for TDVF/TD guest
    5. Add VMCALL.SERVICE<vTPM.recvmessage> for TDVF/TD guest
    6. Add VMCALL.SERVICE<vTPM.ReportStatus> for TDVF/TD guest
    7. Add VMCALL.SERVICE<vTPM.WaitForRequest> for TDVF/TD guest
    Patch:
    KVM: TDX: return userspace for VTPM/VTPMTD service call

gnr-bkc-6.2-v1.25
-----------------
28. Bug: TDVM hang when run perf FIO test with specific configurations
    https://jira.devtools.intel.com/browse/BLR-840
    Fix: Add more conditions to prevent multiple vCPU read/write on one slot, which will make system hang.
    swiotlb: fix system hang when multiple vCPU operate one slot

gnr-bkc-6.2-v1.24
-----------------
27. Bug: MSR value of Kernel IBT reset to 0 after VM created
    https://jira.devtools.intel.com/browse/LFE-7602
    https://jira.devtools.intel.com/browse/LFE-7601
    Fix:
    KVM:x86: Store host S_CET msr data to vmcs field before vm-entry

gnr-bkc-6.2-v1.23
-----------------
26. TDX guest driver exposes /dev/tdx_guest to support TDX attestation.
    https://jira.devtools.intel.com/browse/LFE-7348
    x86/tdx: Add tdx_guest to list of allowed devices

gnr-bkc-6.2-v1.22
-----------------
25. [TDX] Wrong assumption in KVM about TSX_CTRL MSR value after TD-exit
    https://jira.devtools.intel.com/browse/BLR-852
    KVM: TDX: Correct the reset value of MSR_SYSCALL_MASK
    KVM: TDX: Fix wrong assumption about TSX_CTRL MSR value after TD-exit

gnr-bkc-6.2-v1.21
-----------------
24. Support multi-page, multi-stream, and post-copy migration for TDX
    https://jira.devtools.intel.com/browse/LFE-7540
    https://jira.devtools.intel.com/browse/LFE-7541
    gnr.config: update for post-copy migration
    TDX: fix premigration #PF issue
    KVM: TDX_MIG: support Multi-page, Multi-stream and Postcopy

gnr-bkc-6.2-v1.20
-----------------
23. Disable and enable some ACPI tables for x86/tdx.

    https://jira.devtools.intel.com/browse/BLR-669
    x86/tdx: Allow SRAT ACPI table

    https://hsdes.intel.com/appstore/article/#/15013318560
    x86/tdx: Allow CCEL ACPI table
    Revert "x86/tdx: Allow TDEL ACPI table"

gnr-bkc-6.2-v1.19
-----------------
22. add some missing config options
    gnr.config: enable Realtek RTL8152/8153 USB ethernet adapter driver
    gnr.config: update for VFIO IOMMUFD
    gnr.config: update for TDX 1.0, TDX 1.5, TDX guest
    gnr.config: update for rapl/intel_idle
    gnr.config: update for CET IBT SHAWDOW_STACK

gnr-bkc-6.2-v1.18
-----------------
21. Merge the IO RDT feature patches.
    12484bb59fac Merge branch 'fyu/gnr.bkc.6.2.iordt' of https://github.com/intel-sandbox/idxd into gnr-staging-6.2

gnr-bkc-6.2-v1.17
-----------------
20. Merge the following features:
    1/ DSA 2.0 Event Log
    2/ IAA 2.0
    3/ DSA 2.0 Inter-Domain PASID
    f824a981e2d5 Merge branch 'fyu/6.2.iaa2.evl.idp' of https://github.com/intel-sandbox/idxd into gnr-staging-6.2    

gnr-bkc-6.2-v1.16
-----------------
19. Revert "uapi/kvm: Correct the type" since it breaks LTP (Linux Test Program) building.
    https://jira.devtools.intel.com/browse/LFE-7594

gnr-bkc-6.2-v1.15
-----------------
18. Fix a bug reported in https://jira.devtools.intel.com/browse/LFE-7412 that ioasid is leaked during repeated tests.
    vfio: Fix bug which causes ioasid cannot be freed

gnr-bkc-6.2-v1.14
-----------------
17. https://hsdes.intel.com/appstore/article/#/22017183194
    uapi/kvm: Correct the type

gnr-bkc-6.2-v1.13
-----------------
16. Fix an issue reported in https://jira.devtools.intel.com/browse/LFE-7360 that DMAR page fault is observed when enabling QAT vSVM. The fix is to add vdev into dmar_domain subdevices when doing nested attach.
    iommu/vt-d: Add vdev into dmar_domain subdevices when doing nested attach

gnr-bkc-6.2-v1.12
-----------------
15. fix for PMT bug https://hsdes.intel.com/appstore/article/#/14017832501
    platform/x86/intel/pmt: Ignore uninitialized entries

gnr-bkc-6.2-v1.11
-----------------
14. Fix an issue reported in https://jira.devtools.intel.com/browse/LFE-4904 that dmatest failed while performing VM VDEV passthrough with legacy mode and without vIOMMU.
    iommufd/vfio-compat: Open device before attachment to ioas

gnr-bkc-6.2-v1.10
-----------------
13. Add support for new ucore unid MSF_SB0 and fix opt of b2ci and b2upi

gnr-bkc-6.2-v1.9
----------------
12. Like avx2_p1 and avx512_p1, don't display amx_p1 frequency when it is Zero.
    This fixes https://hsdes.intel.com/appstore/article/#/16019865009
    tools/power/x86/intel-speed-select: ignore invalid amx_p1

gnr-bkc-6.2-v1.8
----------------
11. Fix an issue that a vdev is created without a work queue bound to it. The fix is to have the just created vdev to be removed if this vdev cannot be bound to the dedicated work queue.
    https://hsdes.intel.com/appstore/article/#/22015866268
    vfio: idxd: Fix vdev bound to DWQ

gnr-bkc-6.2-v1.7
----------------
10. Fix QAT device address translation issue with invalidation completion ordering, by issuing an extra dTLB flush for QAT devices on impacted platforms of all SPR/EMR steppings, GNR stepping A0 and B0, SRF stepping A0, and GNR-D steppping A0.
    https://hsdes.intel.com/appstore/article/#/22015770501
    https://jira.devtools.intel.com/browse/LFE-6307
    [Pre-Production] iommu/vt-d: Extra dTLB flush for QAT devices on GNR and SRF platforms
    iommu/vt-d: Fix buggy QAT device mask - upstreamed
    iommu/vt-d: Add a fix for devices need extra dtlb flush - upstreamed

gnr-bkc-6.2-v1.6
----------------
9. This fixes an failure of the tool when running on GNR Q2TK, which supports PP level4 only.
    https://hsdes.intel.com/resource/16019627423
    tools/power/x86/intel-speed-select: return failure for unsupported PP level

gnr-bkc-6.2-v1.5
----------------
8. Add Confidential Computing Event Log (CCEL) support,
    https://jira.devtools.intel.com/browse/LFE-6431
    https://hsdes.intel.com/appstore/article/#/16019570262
    https://hsdes.intel.com/appstore/article/#/15012454062
    ACPICA: Add CCEL table header - upstreamed as 407144ebd445 ACPICA: iASL: Add CCEL table to both compiler/disassembler
    ACPI/sysfs: Enable ACPI sysfs support for CCEL records

gnr-bkc-6.2-v1.4
----------------
7. intel_idle: add initial GNR support
    https://jira.devtools.intel.com/browse/LFE-7137

gnr-bkc-6.2-v1.3
----------------
6. https://jira.devtools.intel.com/browse/HQM-701
    PASID is enabled by default in vfio-pci dirver. Intel DLB HW assumes
    that the system is in the SIOV mode when PASID id enabled. User needs
    to disable PASID when using DLB in PF mode.
    vfio/pci: add write permission to PCI_PASID_CTRL

5. Update README.md

gnr-bkc-6.2-v1.2
----------------
4. Merged features:
    IFS (In Field Scan) extra patches;
    David Box's Power Management;
    emr-bkc-6.2-v4.4 tag;
    IAA Crypto;

    73069aef89b7 Merge branch 'for_gnr-bkc-6.2' 74834ae of https://github.com/intel-sandbox/drivers.saf;
    7a8c021a1ecd Merge commit '7b18706fc91e0e3bfe2029feefa5eaadf2104a8d' of https://github.com/intel-sandbox/debox1.linux debox_pm_for_intel_next;
    180153e86587 Merge tag 'emr-bkc-6.2-v4.4' of https://github.com/intel-innersource/os.linux.emeraldrapids.thirdparty.kernel into gnr-staging-6.2;
    7684e8224a2c Merge commit '9737f12c611368d1191c0c3264cc0b004db78ab0' of https://github.com/intel-sandbox/idxd tzanussi/emr-bkc-6.2-iaa-crypto;

gnr-bkc-6.2-v1.1
----------------
3. Merged features:
    Rui Zhang's TPMI, RAPL Driver, ISST;
    pson_counter;
    SVOS;
    PCI VMD Meteor Lake;
    split lock;
    socwatch driver;
    I2C/I3C;
    RDT MBA-4.0;
    CXL;
    SPI-NOR/PCI/Thunderbolt/USB4;
    LASS;
    fix-mc-recovery-on-sierra-forest-for-atom-cores;
    perf-fix for LFE-7417;
    Thermal / HFI;
    nvme pci simics fix;
    David Box's PMC;
    TPM Module;
    Rafeal Wysocki's Power Management;
    Trace Hub;
    XHCI / USB;
    SCSI;

    ce532dc34fa9 Merge commit 'ddbd3771abf385e3731c7674b725bab7ae1619bc' of https://github.com/intel-sandbox/rzhang1 for-intel-next-tpmi;
    f1550e460099 Merge commit '8d4eac3cea41adfee7eb75d3b9ef45de5b9a709f' of https://github.com/intel-sandbox/linux-kernel-rjingar pson_counter;
    f5bbcc90c479 Merge commit '3136bccda667a45456dab9fd05da8dee6fb62a56' of https://github.com/intel-innersource/os.linux.validation.svos-next.svos-next svos-next-tdx-pull-6.2;
    e83d241827e7 Merge commit '61b07a74bfd2c7c1f0a96071315ed77693e7473c' of https://github.com/intel-innersource/os.linux.validation.svos-next.svos-next svos-next-pull-6.2;
    dd077570e3eb Merge commit 'c600f9c2babba00df0c0fba95c35c8da353f9989' of https://github.com/intel-sandbox/otc_power_kernel mtl_dids_linus_rc;
    4bde2623a0d3 Merge commit '73e16e7b8eb287481d5bdf0179bc031e899b4a1e' of https://github.com/intel-sandbox/kernel split_lock;
    fb77228e23a1 Merge commit '2665e52fe74141620270448539c874045b34b66c' of https://github.com/mchinth/linux socwatch_linux_6_1;
    8b3c880fbafe Merge commit '881a9c9e0cf5317618d7182e34475ca67c519b73' of https://github.com/intel-sandbox/jarkkoni.linux.kernel for-intel-next;
    0bfedfc18f9c Merge commit 'f0e1aaf7701c9a4dc30dbbf8b3db5a553e741228' of https://github.com/intel-sandbox/agluck-linux next-6.2-mba4.0;
    1dd6c4da9d7a Merge commit 'e686c32590f40bffc45f105c04c836ffad3e531a' of https://git.kernel.org/pub/scm/linux/kernel/git/cxl/cxl next;
    8c0d11beea7f Merge commit '304560253856f99302727e2f3da6ccec7aabaa55' of https://github.com/intel-sandbox/mwesterb-linux.git for-eywa;
    a06fcf5543b9 Merge commit 'e037e956d2f20ea55c10a2ba8892b8552605fb1b' of https://github.com/intel-sandbox/kernel-works lass-6.2-rc2;
    e8f8203670ad Merge branch 'fix-mc-recovery-on-sierra-forest-for-atom-cores' into gnr-staging-6.2;
    10a2c19b997d Merge branch 'perf-fix-lfe7417' into gnr-staging-6.2;
    3e60295c6085 Merge commit 'c4e1a74d9b20b1dc4276f5182bc3aca2c3b0a35e' of https://github.com/intel-sandbox/ranerica.linux rneri/hybrid-for-intel-next;
    f2130fcd38ac Merge commit '14cbc7d8eb33a81d6753319df887bbb85103c530' of https://github.com/intel-sandbox/otc_power_kernel nvme_simics_fix;
    a820bd495024 Merge commit 'c20485f76eac84a32cd19417e7b529d341e75a71' of https://github.com/intel-sandbox/xi_linux pmc_core_intel_next;
    ede2e2faf5b8 Merge commit '85b93bbd1c9768d09adebbe9f33bab0d4ec94404' of https://git.kernel.org/pub/scm/linux/kernel/git/jarkko/linux-tpmdd next;
    56765352f84b Merge commit 'ea150b53b1fd250a0c49f9ade353634dd7976fbf' of https://git.kernel.org/pub/scm/linux/kernel/git/rafael/linux-pm testing;
    9f3f2cad5e81 Merge commit 'a5133d2dd58afda9f9a38fda98e6bf79f2862008' https://github.com/intel-sandbox/ahunter6.next.git intel-th-v6.2;
    673c49994188 Merge commit '13099ff445858bc2bb6f5d0cd2afa8ceb93ae2ca' of https://github.com/intel-sandbox/ashevche.linux.kernel intel/for-next;
    8a7f23b971f0 Merge commit '27addb311d82bc4a40c8a5719f63b3020552b241' of https://github.com/intel-sandbox/mnyman-linux for-intel-next;
    c54e7c0f1cb3 Merge commit '728eea85c941caa37eceb166b9721cded05a29e3' https://github.com/intel-sandbox/ahunter6.next.git scs-v6.2;

gnr-bkc-6.2-v1.0
----------------
2. ACPI: APEI: EINJ: Add CXL error types
1. Add gnr config
0. EMR merged features:
    RAPL, intel_idle;
    DLB2;
    IOMMUFD, DSA, Live Migration;
    TDX 1.0 KVM;
    TDX 1.5 KVM;
    TDX guest;
    IFS (In Field Scan);
    Srinivas' TPMI;
    EDAC;
    PRM;
    Shadow Stack / CET - Native Kernel;
    CET - KVM support;
    perf;
    SGX microcode seamless update;

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
