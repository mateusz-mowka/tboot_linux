// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2021, Intel Corporation. */

#include "ice_scalable_iov.h"

/* Scalable IOV device configuration functions */

/**
 * ice_is_siov_capable - Check if device supports Scalable IOV
 * @pf: PF pointer structure
 *
 * Return: true if the device supports Scalable IOV, false otherwise.
 */
bool ice_is_siov_capable(struct ice_pf *pf)
{
	struct pci_dev *pdev = pf->pdev;

	/* The device must have the PASID extended PCI capability, and its
	 * BAR0 size must be at least 128MB
	 */
	return (pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_PASID) &&
		pci_resource_len(pdev, ICE_BAR0) >= SZ_128M);
}

/**
 * ice_restore_pasid_config - restore PASID mbx support
 * @pf: PF pointer structure
 * @reset_type: type of reset
 *
 * On CORER/GLOBER, the global PASID mbx support bit gets
 * cleared. For successful restoration of Scalable IOV VFs
 * on these kind of resets, we need to reenable PASID mbx
 * support.
 */
void ice_restore_pasid_config(struct ice_pf *pf, enum ice_reset_req reset_type)
{
	if (reset_type == ICE_RESET_CORER || reset_type == ICE_RESET_GLOBR)
		wr32(&pf->hw, GL_MBX_PASID, GL_MBX_PASID_PASID_MODE_M);
}

/**
 * ice_init_siov_resources - initialize Scalable IOV related resources
 * @pf: PF pointer structure
 * @extack: netlink extended ACK for error reporting
 *
 * Check if Scalable IOV can be enabled by the device and that Single Root IOV
 * is not currently in use. If capable, initialize the device features
 * required for Scalable VFs.
 *
 * Returns: zero on success, or an error code on failure.
 */
int ice_init_siov_resources(struct ice_pf *pf, struct netlink_ext_ack *extack)
{
	struct device *dev = ice_pf_to_dev(pf);
	int err;

	if (test_bit(ICE_FLAG_SIOV_ENA, pf->flags)) {
		dev_dbg(dev, "Driver has already enabled Scalable IOV\n");
		return 0;
	}

	if (!test_bit(ICE_FLAG_SIOV_CAPABLE, pf->flags)) {
		NL_SET_ERR_MSG_MOD(extack, "Device does not support Scalable IOV");
		return -EOPNOTSUPP;
	}

	if (test_bit(ICE_FLAG_SRIOV_ENA, pf->flags)) {
		NL_SET_ERR_MSG_MOD(extack, "Single Root IOV and Scalable IOV are mutually exclusive. Disable all active SR-IOV VFs before adding a Scalable VF");
		return -EBUSY;
	}

	err = iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_PASID);
	if (err) {
		NL_SET_ERR_MSG_FMT_MOD(extack, "Failed to enable PASID support, err %pe",
				       ERR_PTR(err));
		return err;
	}

	/* enable PASID mailbox support */
	wr32(&pf->hw, GL_MBX_PASID, GL_MBX_PASID_PASID_MODE_M);

	/* set default Scalable IOV VF resources */
	pf->vfs.num_msix_per = ICE_NUM_VF_MSIX_SMALL;
	pf->vfs.num_qps_per = ICE_DFLT_QS_PER_SIOV_VF;

	set_bit(ICE_FLAG_SIOV_ENA, pf->flags);

	return 0;
}

/**
 * ice_deinit_siov_resources - De-initialize Scalable IOV related resources
 * @pf: PF pointer structure
 *
 * Clear the Scalable IOV enabled feature flag and disable the PASID mailbox
 * hardware support.
 */
void ice_deinit_siov_resources(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);

	if (test_and_clear_bit(ICE_FLAG_SIOV_ENA, pf->flags)) {
		struct ice_hw *hw = &pf->hw;
		u32 val;

		if (ice_has_vfs(pf))
			dev_warn(dev, "Disabling Scalable IOV with %u active VFs\n",
				 ice_get_num_vfs(pf));


		/* disable PASID mailbox */
		val = rd32(hw, GL_MBX_PASID);
		val &= ~GL_MBX_PASID_PASID_MODE_M;
		wr32(hw, GL_MBX_PASID, val);
	}
}
