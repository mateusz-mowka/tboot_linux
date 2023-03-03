EMR BKC Linux v6.2 base built on 03-03-23

This build passed allyesconfig/allmodconfig. It also passed intel-next build tests and boot tests with intel-next configs.

It was generated with:
./merge_bkc.py -w tdx_kvm_support,tdx_guest,kvm_arch_lbr_cet,microcode_sgx,perf,shadow_stacks,prm_linux_support,edac,tpmi,kvm_tdx_1_5,siov_vfio_iommufd_pasid_idxd,siov_vfio_iommufd_pasid_idxd_fixup,dlb2,"In Field Scan","rapl/idle"

The shortlog diff from staging/WW8.5
$ git shortlog staging/WW8.5-bkc-6.2..HEAD --no-merges
Artem Bityutskiy (1):
      intel_idle: add Emerald Rapids Xeon support

Chenyi Qiang (1):
      KVM: TDX: Skip TDX hardware unsetup if EPT/TDX is disabled

Kan Liang (1):
      x86/cpu: Add Lunar Lake M

Kyle Pelton (1):
      EMR-BKC: Add mainfest, rr-cache and README.txt

Wei Wang (9):
      KVM: TDX: drop "add initialized check to is_td/vcpu_created"
      KVM: TDX: clear td_initialized and vcpu_initialized flags on destroy
      KVM: TDX: remove is_td_vcpu_created
      KVM: TDX_MIG: don't re-create the migration stream for each session
      KVM: TDX_MIG: fix tdx_mig_gpa_list_setup
      KVM: MMU: fix undefined reference to kvm_prealloc_private_pages
      KVM: TDX_MIG: support migration abort and restore
      KVM: TDX_MIG: unmap the sept tables if it's not mapped on the source
      KVM: TDX_MIG: set up the private page's SEPT tables before import mem

Yi Liu (1):
      iommu/vt-d: Enable pasid when attach nested

Zhang Rui (13):
      x86/topology: fix errornous smp_num_siblings on Intel Hybrid platform
      idle: intel_idle: introduce debugfs I/F
      idle: intel_idle: Introduce dummy_cstates
      idle: intel_idle: Add RaptorLake support
      idle: intel_idle: add support for MeteorLake
      powercap: intel_rapl: add support for METEORLAKE
      powercap: intel_rapl: add support for EMERALDRAPIDS
      powercap: intel-rapl: Add support for LNL-M paltform
      perf/x86/rapl: Add support for Intel Meteor Lake
      perf/x86/rapl: Add support for Intel Emerald Rapids
      tools/turbostat: use different graphics sysfs knob
      tools/power turbostat: Introduce support for EMR
      tools/power turbostat: Introduce support for GNR

Merge manifest:

d917636c621e1 EMR BKC: Merge commit d857942d5a89483d53bc092a8d4dcf090aef5d2e from https://github.com/intel-sandbox/rzhang1.git for-intel-next
No pull request -  email from Rui
Intel Next is using the following configs:
CONFIG_INTEL_RAPL=m
CONFIG_INTEL_TCC_COOLING=m

2a378ad4e86ab EMR BKC: Merge commit b1f03d65f3a9943136fa4b43a008d0d43d613ec5 from https://github.com/intel-sandbox/drivers.saf.git for_intel_nxt_v6.2
https://eclists.intel.com/sympa/arc/intel-next/2023-01/msg00014.html
CONFIG_INTEL_IFS=m

3bf09ca67ae1c EMR BKC: Merge commit 5c055b70c7f6a001dd98b760d506ab0483b6d97d from https://github.com/intel-innersource/drivers.scheduling.dynamic-load-balancer.upstreamed-dlb-linux-driver.git dlb2-for-intel-next-v6.2-rc7
https://eclists.intel.com/sympa/arc/intel-next/2023-02/msg00027.html
CONFIG_INTEL_DLB2=m
CONFIG_INTEL_DLB2_DATAPATH=y
CONFIG_INTEL_DLB2_SIOV=n
CONFIG_INTEL_IOMMU=y
CONFIG_VFIO=y
CONFIG_VFIO_MDEV=y
CONFIG_VFIO_MDEV_DEVICE=y
CONFIG_PCI_IOV=y
CONFIG_IOMMUFD=y

f780a61f2d250 EMR BKC: Merge commit cecf55707fea2cbad665af907ca62ca908e1ee65 from https://github.com/intel-sandbox/otc_power_kernel siov_vfio_iommufd_pasid_idxd_fixup
No email This is a fixup patch for TDX-KVM/SIOV. TDX-KVM has moved x86_ops struct to arch/x86/kvm/vmx/main.c

464743d48a75e EMR BKC: Merge commit d251c71565f884d7d0a7c1a4d06b2ffc20734c96 from https://github.com/intel-sandbox/idxd fyu/idxd.vdev.6.2
https://eclists.intel.com/sympa/arc/intel-next/2023-02/msg00012.html
CONFIG_VFIO_DEVICE_IDXD=m
CONFIG_IOMMUFD=y
CONFIG_IMS_MSI=y
CONFIG_IMS_MSI_ARRAY=y
CONFIG_IOMMUFD_TEST=y
CONFIG_FAULT_INJECTION=y
CONFIG_VFIO_CONTAINER=n
CONFIG_IOMMUFD_VFIO_CONTAINER=y
CONFIG_PCI_INTEL_IDXD_IMS=m
CONFIG_INTEL_IDXD_PAGE_CLEAR=m

ff14bf94c31f3 EMR BKC: Merge commit 5a8f46b1acadaf31b5aa9f8e19e2aa857a5f97a4 from https://github.com/intel-sandbox/cqiang-tdx-kvm.git for-intel-next
https://eclists.intel.com/sympa/arc/intel-next/2023-02/msg00003.html
CONFIG_INTEL_TDX_MODULE_UPDATE=y

30b9725034096 EMR BKC: Merge commit da3fb854602ea0aafe3b56fdbcbbe44a5fb5493d from https://github.com/intel-sandbox/spandruv.linux.git tpmi_intel_next
https://eclists.intel.com/sympa/arc/intel-next/2023-01/msg00025.html
CONFIG_INTEL_RAPL_TPMI=m

a5f7cd87f5970 EMR BKC: Merge commit 22ade685d705a20dcb7a5e01fda58109c1c951d6 from https://github.com/intel-sandbox/qzhuo-linux.git edac-for-intel-next
https://eclists.intel.com/sympa/arc/intel-next/2023-01/msg00000.html

3da8f51d52ff6 EMR BKC: Merge commit a4157e8e6d107606e54ea5e7732357229ad4a1b7 from https://github.com/intel-sandbox/aubrey-linux.git prm_v6.2_for_intel_next
https://eclists.intel.com/sympa/arc/intel-next/2023-01/msg00107.html
CONFIG_ACPI_DEBUGGER=y
CONFIG_ACPI_DEBUGGER_USER=m

042a4a57529cd EMR BKC: Merge commit 957d335ebd0672a1a921d85584c353b40919e0d4 from https://github.com/intel-sandbox/rpedgeco.linux.git user_shstk_on_v6.2-rc4
https://eclists.intel.com/sympa/arc/intel-next/2023-01/msg00063.html
CONFIG_X86_USER_SHADOW_STACK=y

3eb06b3b846e9 EMR BKC: Merge commit 07899f84aa176dc25ee6111f46c1b476bd89a5e0 from https://github.com/intel-innersource/os.linux.perf.intel-next.git perf-intel-next
https://eclists.intel.com/sympa/arc/intel-next/2023-01/msg00021.html
No configs

0243703963fc5 EMR BKC: Merge commit 856c08458ea30f3ebbebfa1b12f418f317c4945a from https://github.com/wenqian77/os.linux.intelnext.kernel.git dev-v6.2-rc3-sgxseamless
https://eclists.intel.com/sympa/arc/intel-next/2023-01/msg00042.html
CONFIG_X86_SGX=y
CONFIG_X86_SGX_KVM=y

5bf29230a9703 EMR BKC: Merge commit ffd36634a712a8ae5365bb6a6fb9dfb31f349bd4 from https://github.com/intel-sandbox/weijiang.linux.kvm.git v6.2-rc4-kvm-arch-lbr-cet-rebase
https://eclists.intel.com/sympa/arc/intel-next/2023-01/msg00079.html
No Configs

3855a29a6920b EMR BKC: Merge commit a9fe7e5b76f30be16e10d52a91a7a4328bb2d085 from https://github.com/intel/tdx.git guest-next
https://eclists.intel.com/sympa/arc/intel-next/2023-01/msg00008.html
CONFIG_INTEL_TDX_GUEST=y
TDX_GUEST_DRIVER=y

e0e9812b48ebc EMR BKC: Merge commit 8605954d580914c8f845d1adf14a127356121acc from https://github.com/intel-innersource/virtualization.hypervisors.tdx.linux.git intel-nex
https://eclists.intel.com/sympa/arc/intel-next/2023-01/msg00004.html
CONFIG_INTEL_TDX_HOST=y

