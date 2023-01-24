Purpose
=======
Provide Best Known Configuration (BKC) kernel for Granite Rapids (GNR)
customers.

The BKC kernel is based on v5.19 intel-next. New GNR feautre patches which are not
in v5.19 intel-next are added to the BKC kernel.

WARNING this kernel contains technology preview code that is
subject to change once it goes upstream. This kernel is
strictly for hardware validation, not production. Applications
tested against this kernel may behave differently, or may not
operate at all once the code is finalized in the mainline kernel.
Use at your own risk.

Release History
===============
GNR-BKC-V2.1
---------------
3. platform/x86/intel/sdsi: Change mailbox timeout
    https://hsdes.intel.com/appstore/article/#/15012398271
2. HMAT: ACPI HMAT fixes
	Add a couple of HMAT initiator registration fixes as requested in:
	https://hsdes.intel.com/appstore/article/#/22015826573
1. ISST: fixes for below HSD
	https://hsdes.intel.com/resource/16019322179
	https://hsdes.intel.com/resource/16019270446

GNR PO bkc-v1.5
===============
1. RAS: Add error handling for copy on write fault for uncorrectable error
   Fixes https://hsdes.intel.com/resource/14018142780
2. PFRU: Fix PFRU device unsupported problem on GNR
   https://hsdes.intel.com/resource/16019132988
3. MDEV: Fix mdev device release bug
   https://hsdes.intel.com/appstore/article/#/15012302820
4. DSA: Fix DSA vdev device removal bug
   https://hsdes.intel.com/resource/15012455341
5. SDSi: Debug code for SDSi provisioning
6. TDXIO/IOMMU/IDE: Various fixes:
	i. IDE fixes for RPB card.
	ii. TDXIO related seamcall retry for recoverable errors
	iii. IOMMU driver changes for trusted domain been detach/replaced.
7. CXL: Update CXL XOR Interleave Math (CXIMS)
   revert original implementation in commit 1771feaff
   and replace with new one.
8. ISST: Fix uncore min frequency display
9. ISST: Update memory frequency read method
10. TDXIO: Various fixes
	i.   RPB: fixes RPB device cannot be shared passthrough to TD for multiple times, https://jira.devtools.intel.com/browse/LFE-6588
	ii.  IDE: Workaround for avoiding MCA in IDE cleanup flow, https://jira.devtools.intel.com/browse/LFE-6497
	iii. Fix panic when tdxio capable dmar is disabled, https://jira.devtools.intel.com/browse/LFE-6587
	iv.  change SPTE_MMU_PRESENT_MASK to bit 61, https://jira.devtools.intel.com/browse/LFE-6655
	v.   set tdev to NULL when closing device, https://jira.devtools.intel.com/browse/LFE-6662

GNR PO bkc-v1.4
===============
1. IDXD-DSA: Fix initialization of event log size
   (Follow up to https://jira.devtools.intel.com/browse/LCK-11678)
2. UFS: Early enable Runtime PM, fix uncore freq bug
   (Fix for https://hsdes.intel.com/appstore/article/#/15012141935)
3. IDXD: Fix crc_val field from 32bit to 64bit for completion record.
4. TDX: Fix TDX guest failed to boot up with vcpu num larger than 1
   (https://jira.devtools.intel.com/browse/LFE-4892)
5. IDXD: Fix for KVA sparse mapping support
   (https://hsdes.intel.com/appstore/article/#/14017928408)
6. PMT: maintain contiguous entry list
7. EDAC: Fix miscalculation of memory controller MMIO offsets.
8. PMT: Revert "Ignore regions with all 0xF"
   Fixes slow reboot problem: https://hsdes.intel.com/resource/22016170922
9. KVM: TDX: fixes local var retries initialization error
10.DSA: Live migration feature, supports
	IDXD VDEV migration for non-vIOMMU case.
	Changes vdev name from vdevX to vdevN.M (where N is dsa number and M is index within dsa)
11.Vt-d: Fix devices list corruption, causing host hang while boot up a guest with DSA PF passthrough
	https://jira.devtools.intel.com/browse/LFE-6343
12.Config: Add kernel config options to support hyperv
13.IDXD-DSA: Add workaround for ENQ latency problem.
	https://hsdes.intel.com/appstore/article/#/14014470913
	https://hsdes.intel.com/appstore/article/#/14014513672


GNR PO bkc-v1.3
===============
1. EDAC: Add Intel Sierra Forest server support
2. PMT: Fix order of cleanup operations when probe fails. Mitigate two
   issues:
	a. Simics reporting bogus telemetry entries
	   https://hsdes.intel.com/appstore/article/#/14017832501
	b. SOC watchtool not working due to LTM causing probe failure.
	   https://hsdes.intel.com/appstore/article/#/16018199387)
3. IDXD: Fix 2 issues (pull from https://github.com/intel-sandbox/idxd/commits/fyu/gnr.bkc)
	a. Event log has random failure when running 1b and 6b tests
	   (https://jira.devtools.intel.com/browse/LCK-11678 )
	b. Kernel panic when try to cat /sys/kernel/debug/idxd/dsa0/event_l
	   (https://jira.devtools.intel.com/browse/LFE-3775)
4.NETDEV NTB: Add GNR support for Intel PCIe gen5 NTB
5. PMT: Enhancement of fix in issue (2) above.
6. IDXD: Fix inter-domain pasid opcode bug (https://hsdes.intel.com/appstore/article/#/14017868570)
7. PMU/IOMMU Fix unsupported PW_OCCUPANCY (https://hsdes.intel.com/appstore/article/#/15012234453)
8. TDX,TDX/IO: Various fixes

GNR PO bkc-v1.2
===============
1. ACPI: Enable CONFIG_ACPI_PFRUT to support SMM error injection.
2. IXGBE: Built it in kernel so network driver is always loaded for PO systems.
3. I3C: Turn on support for I3C devices
4. SAF: Pull in fixes from https://github.com/intel-sandbox/drivers.saf/commits/for_gnrbkcv
	a. No separate ARRAY_BIST_STATUS MSR
	b. Trace support for SBFT test
	c. EMR CPUID for IFS driver
5. TDX: Pull in 3 fixes from https://github.com/intel-sandbox/yilun-gnr-po-folk/commits/bkc-v1.2
	a. Fix compile error when KVM_MMU_PRIVATE is not configured.
	b. Fix failure to seamcall(TDH_MEM_SHARED_SEPT_WR) when tdxio is not supported
	c. Revert simics workaround commit 6b284d6b44f3f46bb68d9e2157aa92ec7f7c3409 after simics
	   fixed in VTC 5.0.pre693, PV WW40 release
6. WATCHDOG: Enable CONFIG_SOFTLOCKUP_DETECTOR to allow turning on soft lockup detector with nmi-watchdog.
	     Enable CONFIG_HARDLOCKUP_DETECTOR to make nmi_watchdog enabled by default.
7. TDX: Pull in 5 fixes for TDX.
8. RPB: Pull in 2 fixes for Race Point Beach card for testing TDXIO.

GNR PO bkc-v1.1
===============
1. IDXD: Merge Fenghua's patches for shared work queue (from https://github.com/intel-sandbox/kernel/commits/gnr.bkc-v1.0,
commit 52c8cfd9 8cffde75)
2. KVM: Merge support of vENQCMD (from https://github.com/yisun-git/os.linux.graniterapids.poweron/tree/gnr_po_enqcmds-v1.0 commit c931e3b to 1955f24)
3. VFIO/MSI: Merge 6 fixes to vdev (from https://github.com/intel-sandbox/kernel/commits/gnr.bkc-v1.1-staging commit 81167ta to 0c8a98f)
   (See https://jira.devtools.intel.com/browse/LCK-11783)
4. Fix 3 TDX bugs in bkc-v1.0 (See https://github.com/intel-sandbox/os.linux.graniterapids.poweron/pull/11)
5. Pull TDXIO support patches, including support for RPB test card. (https://github.com/intel-sandbox/os.linux.graniterapids.poweron/pull/12)
6. ISST (intel-speed-select): bug fix - add cpu id check for power domain availability
   (https://github.com/intel-sandbox/os.linux.graniterapids.poweron/pull/14/commits/477b49bd33211f4a8d93acef3b5d5ec1437e7d8b)
7. ISST: Update SST-BF offsets (pull from https://github.com/intel-sandbox/os.linux.spandruv_graniterapids.poweron/tree/po_pull)
8. TPMI: Update retry count to accommodate slow Simics response
9. Pull TDXIO bug fixes, additional RPB card support patches (https://github.com/intel-sandbox/yilun-gnr-po-folk/tree/bkc-v1.1)

GNR PO bkc-v1.0
===============
1. Merge fix to IAX operation code name and add OPcode for Fetch, Decrypt, Encrypt, Zcomress/decompress8
2. Disable signature verification in SDSi for now till it can be properly fixed.
3. Fix duplicate user file name causing error in inter-domain pasid (https://jira.devtools.intel.com/browse/LCK-11871)
4. TDX: Merge x86/tdx: Set shared bit in GetQuote hypercall request
5. RAPL/TPMI: tpmi rapl rework patches including recent fixes with GNR Simics test result.  All the current tpmi rapl patches are reverted, and new patches are appended.
   (Pull from https://github.com/zhang-rui/os.linux.graniterapids.poweron/tree/rapl-rework)
6. Intel SST: Rework the Intel Speed Select tool (Pull from: https://github.com/zhang-rui/os.linux.graniterapids.poweron/tree/isst-rework)

GNR PO bkc-v0.5
===============
1. Merge fix by Fengwei on large page, causing this issue report https://hsdes.intel.com/resource/14016634556
[SPR] [RAS] Simple single-thread poison test fail under Linux Kernel 5.18 & 5.19 - thp split failed - due to large folio THP
2. Fix compile error when CTE is not configured
3. Fix SDSi build and a request lenght issue (pull https://github.com/sathyaintel/os.linux.graniterapids.poweron.git sdsi)

GNR PO bkc-v0.4
===============
1. Merge 7 fixes for TDX.

GNR PO bkc-v0.3
===============
1. Move to intel-next based on 5.19.0
2. Pull branch gnr.bkc-v0.3 from intel-sandbox/kernel.git for idxd enable vSVM https://github.com/intel-sandbox/kernel/commits/gnr.bkc-v0.3 (commit: 52f7b5146a836f19439eb8788af1c6f9a68f8edd)
3. Pull saf repo  branch for_gnrbkcv https://github.com/intel-sandbox/drivers.saf/commits/for_gnrbkcv (commit: 2f3924f796eba75e8a4abe6fbf30e9dce7fa7252)
4. Pull IAA1.0 update patches from https://github.com/intel-sandbox/idxd/commits/tzanussi/iaa-crypto-5.19-gnr-bkc-v2 (commit: 3c3bc984e1e2cdc955d0a702b96a19e10d32e189)
5. Fix uniform microcode update error check and report, potentially causing a hang (commit 088084b5004023db7f2ea9d82af724e2e0dcbc29)
6. Disable IBT to work around firmware bugs
7. Pull interdomain PASID code for idxd driver https://github.com/intel-sandbox/idxd/tree/fyu/gnr.bkc (commit e0e555a82bc87d9ce3b191782b15fa46449e033d)
