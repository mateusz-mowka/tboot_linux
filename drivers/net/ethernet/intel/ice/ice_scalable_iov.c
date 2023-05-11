// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2021, Intel Corporation. */

#include "ice_scalable_iov.h"
#include <linux/limits.h>
#include <linux/xarray.h>
#include <linux/auxiliary_bus.h>
#include <linux/net/intel/adi.h>

/* ADI auxiliary device ID table */
static DEFINE_XARRAY_ALLOC(ice_adi_aux_ids);

/**
 * struct ice_scalable_dev - Private structure for a VFIO dynamic port
 * @adi: auxiliary device for registering an ADI
 * @dyn_port: pointer to the associated dynamic port instance
 *
 * The ice_scalable_dev structure is the main structure representing
 * a Scalable IOV assignable device instance. This structure keeps track of
 * the private data used by the PF for managing the ADI.
 */
struct ice_scalable_dev {
	struct adi_aux_dev adi;
	struct ice_dynamic_port *dyn_port;
};

/**
 * adi_to_priv - Get private ice_scalable_dev pointer from its ADI pointer
 * @adi: pointer to the ADI auxiliary interface structure
 *
 * Return: pointer to the ice_scalable_dev private structure.
 */
static inline struct ice_scalable_dev *adi_to_priv(struct adi_aux_dev *adi)
{
	return container_of(adi, struct ice_scalable_dev, adi);
}

/**
 * adev_to_priv - Get private ice_scalable_dev pointer from auxiliary device
 * @adev: an ADI auxiliary device
 *
 * Return: pointer to the ice_scalable_dev private structure.
 */
static inline struct ice_scalable_dev *adev_to_priv(struct auxiliary_device *adev)
{
	struct adi_aux_dev *adi;

	adi = container_of(adev, struct adi_aux_dev, adev);

	return adi_to_priv(adi);
}

/* ADI setup functions */

/**
 * ice_scalable_dev_release - Release resources associated with this port
 * @dev: device pointer
 *
 * The auxiliary bus release function for the ice_scalable_dev.adev. This will be
 * called only once all references to the auxiliary device are dropped. We
 * must not free the ADI or its associated resources before that.
 */
static void ice_scalable_dev_release(struct device *dev)
{
	struct auxiliary_device *adev = to_auxiliary_dev(dev);
	struct ice_scalable_dev *priv = adev_to_priv(adev);

	xa_erase(&ice_adi_aux_ids, adev->id);
	kfree(priv);
}

/**
 * ice_scalable_dev_activate - Allocate and register an ADI for a VFIO subfunction
 * @dyn_port: the dynamic port being activated
 * @extack: netlink extended ACK structure
 *
 * Called when the user activates a subfunction port with the desired type set
 * to DEVLINK_PORT_TYPE_VFIO.
 *
 * Allocates an ADI and the associated resources, including an auxiliary
 * device instance that will be used to communicate with the ADI driver.
 *
 * Return: zero on success, -ENOMEM on failure to allocate private structure,
 *         or another non-zero errno value on failure to setup auxiliary
 *         device.
 */
int
ice_scalable_dev_activate(struct ice_dynamic_port *dyn_port,
			  struct netlink_ext_ack *extack)
{
	struct auxiliary_device *adev;
	struct ice_scalable_dev *priv;
	struct pci_dev *pdev;
	struct ice_pf *pf;
	int err;
	u32 id;

	pf = dyn_port->pf;
	pdev = pf->pdev;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		NL_SET_ERR_MSG_MOD(extack, "Could not allocate ADI structure");
		return -ENOMEM;
	}

	priv->dyn_port = dyn_port;

	err = xa_alloc(&ice_adi_aux_ids, &id, NULL, XA_LIMIT(1, U32_MAX),
		       GFP_KERNEL);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Could not allocate auxiliary device ID");
		goto err_free_adi;
	}

	adev = &priv->adi.adev;

	adev->id = id;
	adev->name = "adi";
	adev->dev.release = ice_scalable_dev_release;
	adev->dev.parent = &pdev->dev;

	err = auxiliary_device_init(adev);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to initialize auxiliary device");
		goto err_erase_id;
	}

	dyn_port->scalable_dev = priv;

	return 0;

err_erase_id:
	xa_erase(&ice_adi_aux_ids, id);
err_free_adi:
	kfree(priv);

	return err;
}

/**
 * ice_scalable_dev_deactivate - Delete a VFIO port
 * @dyn_port: dynamic devlink port instance
 *
 * Grab the private ADI pointer from the dynamic port structure and inform
 * auxiliary bus that the device is going away. The bus will call
 * ice_scalable_dev_release once all references to the auxiliary device instance
 * are dropped.
 */
void ice_scalable_dev_deactivate(struct ice_dynamic_port *dyn_port)
{
	struct ice_scalable_dev *priv = dyn_port->scalable_dev;

	if (priv)
		auxiliary_device_uninit(&priv->adi.adev);

	dyn_port->scalable_dev = NULL;
}

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
