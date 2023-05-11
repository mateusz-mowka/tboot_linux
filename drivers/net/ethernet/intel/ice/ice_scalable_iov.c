// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2021, Intel Corporation. */

#include "ice_scalable_iov.h"
#include "ice_lib.h"
#include "ice_virtchnl_allowlist.h"
#include "ice_fltr.h"
#include "ice_vf_lib_private.h"
#include <linux/limits.h>
#include <linux/xarray.h>
#include <linux/auxiliary_bus.h>
#include <linux/net/intel/adi.h>

/* ADI auxiliary device ID table */
static DEFINE_XARRAY_ALLOC(ice_adi_aux_ids);

struct ice_mbx_regs {
	u32 mbx_asqh;
	u32 mbx_asqt;
	u32 mbx_asqbal;
	u32 mbx_asqbah;
	u32 mbx_arqh;
	u32 mbx_arqt;
	u32 mbx_arqbal;
	u32 mbx_arqbah;
};

/**
 * struct ice_scalable_dev - Private structure for a VFIO dynamic port
 * @adi: auxiliary device for registering an ADI
 * @vf: VF associated with this ADI
 * @pasid: PASID associated with this ADI
 * @update_hash_entry: work item for updating VF hash entry
 * @reset_state: the reset state reported to VF by register
 * @mbx_regs: storage for restoring mailbox registers during reset
 * @dyn_port: pointer to the associated dynamic port instance
 *
 * The ice_scalable_dev structure is the main structure representing
 * a Scalable IOV assignable device instance. This structure keeps track of
 * the private data used by the PF for managing the ADI.
 */
struct ice_scalable_dev {
	struct adi_aux_dev adi;
	struct ice_vf vf;
	struct work_struct update_hash_entry;
	struct ice_mbx_regs mbx_regs;
	struct ice_dynamic_port *dyn_port;
	enum virtchnl_vfr_states reset_state;
	u32 pasid;
	struct msi_map non_q_vector;
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

/**
 * vf_to_priv - Get private ice_scalable_dev pointer from VF structure
 * @vf: a Scalable IOV VF
 *
 * Return: pointer to the ice_scalable_dev private structure.
 */
static inline struct ice_scalable_dev *vf_to_priv(struct ice_vf *vf)
{
	return (struct ice_scalable_dev *)container_of(vf, struct ice_scalable_dev, vf);
}

/* Scalable IOV VF operations */

/**
 * ice_dis_siov_vf_mapping - disable Scalable IOV VF MSIX mapping
 * @vf: pointer to the VF structure
 *
 * Return: zero on success, or -EFAULT if the VF VSI cannot be found.
 */
static int ice_dis_siov_vf_mapping(struct ice_vf *vf)
{
	struct ice_hw *hw = &vf->pf->hw;
	struct ice_vsi *vsi;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi)
		return -EFAULT;

	wr32(hw, VPINT_MBX_CTL(vsi->vsi_num), 0);

	return 0;
}

/**
 * ice_adi_alloc_non_q_vector - Allocate IRQ for non-queue vector
 * @pf: pointer to the PF private structure
 * @priv: pointer to the ADI private data
 *
 * Reserve an MSI-X IRQ for the control vector not associated with a queue.
 */
static int
ice_adi_alloc_non_q_vector(struct ice_pf *pf, struct ice_scalable_dev *priv)
{
	priv->non_q_vector = ice_alloc_irq(pf, true);

	if (priv->non_q_vector.index < 0)
		return priv->non_q_vector.index;

	return 0;
}

/**
 * ice_adi_release_non_q_vector - Release non-queue vector IRQ
 * @pf: pointer to the PF private structure
 * @priv: pointer to the ADI private data
 *
 * Release the MSI-X IRQ associated with the control vector that was
 * previously allocated by ice_adi_alloc_non_q_vector.
 */
static void
ice_adi_release_non_q_vector(struct ice_pf *pf, struct ice_scalable_dev *priv)
{
	ice_free_irq(pf, priv->non_q_vector);
	priv->non_q_vector.index = -ENOENT;
}

/**
 * ice_siov_free_vf - Free VF memory after all references are dropped
 * @vf: the VF to free
 *
 * Called by ice_put_vf through ice_release_vf when the last VF reference is
 * dropped. Do not call this or the .free function directly. Instead, use
 * ice_put_vf to ensure that the memory is only released once all references
 * are finished.
 */
static void ice_siov_free_vf(struct ice_vf *vf)
{
	struct ice_scalable_dev *priv = vf_to_priv(vf);
	struct ice_vsi *vsi;

	/* ice_free_adi() takes care of removing the VF from the hash table */
	ice_dis_siov_vf_mapping(vf);
	vsi = ice_get_vf_vsi(vf);
	if (vsi)
		ice_vsi_decfg(vsi);
	if (priv->non_q_vector.index >= 0)
		ice_adi_release_non_q_vector(vf->pf, priv);
	mutex_destroy(&vf->cfg_lock);
}

/**
 * ice_siov_clear_reset_state - clears S-IOV VF Reset status indication
 * @vf: the vf to configure
 */
static void ice_siov_clear_reset_state(struct ice_vf *vf)
{
	struct ice_scalable_dev *priv = vf_to_priv(vf);

	/* Clear the reset status so that VF does not get a mistaken
	 * indication of an active VF when reading VFGEN_RSTAT.
	 */
	priv->reset_state = VIRTCHNL_VFR_INPROGRESS;
}

/**
 * ice_siov_clear_mbx_register - clears S-IOV VF's mailbox registers
 * @vf: the vf to configure
 */
static void ice_siov_clear_mbx_register(struct ice_vf *vf)
{
	struct ice_scalable_dev *priv = vf_to_priv(vf);
	struct ice_hw *hw = &vf->pf->hw;

	/* Save mailbox registers. MBX_ARQLEN and MBX_ATQLEN won't
	 * be saved and restored because AVF driver will check
	 * ARQLEN to determine whether reset has been triggered.
	 */
	priv->mbx_regs.mbx_asqh = rd32(hw, VSI_MBX_ATQH(vf->vf_id));
	priv->mbx_regs.mbx_asqt = rd32(hw, VSI_MBX_ATQT(vf->vf_id));
	priv->mbx_regs.mbx_asqbal = rd32(hw, VSI_MBX_ATQBAL(vf->vf_id));
	priv->mbx_regs.mbx_asqbah = rd32(hw, VSI_MBX_ATQBAH(vf->vf_id));
	priv->mbx_regs.mbx_arqh = rd32(hw, VSI_MBX_ARQH(vf->vf_id));
	priv->mbx_regs.mbx_arqt = rd32(hw, VSI_MBX_ARQT(vf->vf_id));
	priv->mbx_regs.mbx_arqbal = rd32(hw, VSI_MBX_ARQBAL(vf->vf_id));
	priv->mbx_regs.mbx_arqbah = rd32(hw, VSI_MBX_ARQBAH(vf->vf_id));

	wr32(hw, VSI_MBX_ARQLEN(vf->vf_id), 0);
	wr32(hw, VSI_MBX_ATQLEN(vf->vf_id), 0);

	wr32(hw, VSI_MBX_ATQH(vf->vf_id), 0);
	wr32(hw, VSI_MBX_ATQT(vf->vf_id), 0);
	wr32(hw, VSI_MBX_ATQBAL(vf->vf_id), 0);
	wr32(hw, VSI_MBX_ATQBAH(vf->vf_id), 0);
	wr32(hw, VSI_MBX_ARQH(vf->vf_id), 0);
	wr32(hw, VSI_MBX_ARQT(vf->vf_id), 0);
	wr32(hw, VSI_MBX_ARQBAL(vf->vf_id), 0);
	wr32(hw, VSI_MBX_ARQBAH(vf->vf_id), 0);
}

/**
 * ice_siov_trigger_reset_register - trigger VF reset for S-IOV VF
 * @vf: pointer to VF structure
 * @is_vflr: true if reset occurred due to VFLR
 *
 * Trigger and cleanup a reset for a Scalable IOV VF.
 */
static void ice_siov_trigger_reset_register(struct ice_vf *vf, bool is_vflr)
{
	struct ice_scalable_dev *priv = vf_to_priv(vf);
	struct ice_pf *pf = vf->pf;
	struct ice_hw *hw;
	u32 reg;
	int i;

	hw = &pf->hw;

	/* VF hardware reset is about to start, so we need to clear the
	 * VFR_VFACTIVE state now.
	 */
	priv->reset_state = VIRTCHNL_VFR_INPROGRESS;

	/* In the case of VFLR, HW has already reset the VF and we just need
	 * to cleanup. Otherwise we need to trigger the reset using the
	 * VSIGEN_RTRIG register.
	 */
	if (!is_vflr) {
		reg = rd32(hw, VSIGEN_RTRIG(vf->vf_id));
		reg |= VSIGEN_RTRIG_VMSWR_M;
		wr32(hw, VSIGEN_RTRIG(vf->vf_id), reg);
		ice_flush(hw);
	}

	wr32(hw, PFPCI_VMINDEX, vf->vf_id);
	for (i = 0; i < ICE_PCI_CIAD_WAIT_COUNT; i++) {
		reg = rd32(hw, PFPCI_VMPEND);
		/* no transactions pending so stop polling */
		if ((reg & VF_TRANS_PENDING_M) == 0)
			break;

		dev_err(ice_pf_to_dev(pf), "VM %u PCI transactions stuck\n",
			vf->vf_id);
		udelay(ICE_PCI_CIAD_WAIT_DELAY_US);
	}
}

/**
 * ice_siov_poll_reset_status - poll Scalable IOV VF reset status
 * @vf: pointer to VF structure
 *
 * Return: true if the reset has completed, false otherwise
 */
static bool ice_siov_poll_reset_status(struct ice_vf *vf)
{
	struct ice_scalable_dev *priv = vf_to_priv(vf);
	struct ice_hw *hw = &vf->pf->hw;
	unsigned int i;
	u32 reg;

	for (i = 0; i < 10; i++) {
		/* VF reset requires driver to first reset the VF and then
		 * poll the status register to make sure that the reset
		 * completed successfully.
		 */
		reg = rd32(hw, VSIGEN_RSTAT(vf->vf_id));
		if (reg & VSIGEN_RSTAT_VMRD_M) {
			priv->reset_state = VIRTCHNL_VFR_COMPLETED;
			return true;
		}

		/* only sleep if the reset is not done */
		usleep_range(10, 20);
	}
	return false;
}

/**
 * ice_siov_clear_reset_trigger - enable VF to access hardware
 * @vf: VF to enabled hardware access for
 */
static void ice_siov_clear_reset_trigger(struct ice_vf *vf)
{
	struct ice_hw *hw = &vf->pf->hw;
	u32 reg;

	reg = rd32(hw, VSIGEN_RTRIG(vf->vf_id));
	reg &= ~VSIGEN_RTRIG_VMSWR_M;
	wr32(hw, VSIGEN_RTRIG(vf->vf_id), reg);
	ice_flush(hw);
}

/**
 * ice_siov_irq_close - Close any IRQ data prior to resetting the VF
 * @vf: the VF to process
 *
 * Called by generic virtualization code during reset to close any previous
 * IRQ configuration before rebuilding a new VSI.
 */
static void ice_siov_irq_close(struct ice_vf *vf)
{
}

/**
 * ice_ena_siov_vf_mapping - enable Scalable IOV VF MSIX mapping
 * @vf: pointer to the VF structure
 *
 * Return: zero on success, or -EFAULT if the VSI or queue vector pointer
 *         cannot be determined.
 */
static int ice_ena_siov_vf_mapping(struct ice_vf *vf)
{
	struct ice_scalable_dev *priv = vf_to_priv(vf);
	struct ice_hw *hw = &vf->pf->hw;
	struct ice_vsi *vsi;
	u32 reg;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi || priv->non_q_vector.index < 0)
		return -EFAULT;

	reg = ((priv->non_q_vector.index << VPINT_MBX_CTL_MSIX_INDX_S) &
		VPINT_MBX_CTL_MSIX_INDX_M) | VPINT_MBX_CTL_CAUSE_ENA_M;
	wr32(hw, VPINT_MBX_CTL(vsi->vsi_num), reg);

	return 0;
}

/**
 * ice_vsi_configure_pasid - config pasid for VSI
 * @vf: VF pointer
 * @pasid: pasid value
 * @ena: enable
 *
 * Return: zero on success, -EFAULT of the VF's VSI cannot be determined, or
 *         -ENOMEM if the temporary VSI context structure could not be
 *         allocated, or another non-zero errno value if we fail to update the
 *         VSI configuration.
 */
static int ice_vsi_configure_pasid(struct ice_vf *vf, u32 pasid, bool ena)
{
	struct ice_scalable_dev *priv = vf_to_priv(vf);
	struct ice_vsi_ctx *ctxt;
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_hw *hw;
	int err;

	hw = &vf->pf->hw;
	dev = ice_pf_to_dev(vf->pf);

	vsi = ice_get_vf_vsi(vf);
	if (!vsi)
		return -EFAULT;

	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return -ENOMEM;

	ctxt->info.valid_sections =
		cpu_to_le16(ICE_AQ_VSI_PROP_PASID_VALID);
	pasid &= ICE_AQ_VSI_PASID_ID_M;
	if (ena)
		pasid |= ICE_AQ_VSI_PASID_ID_VALID;
	else
		pasid &= ~ICE_AQ_VSI_PASID_ID_VALID;
	ctxt->info.pasid_id = cpu_to_le32(pasid);
	err = ice_update_vsi(hw, vsi->idx, ctxt, NULL);
	if (err) {
		dev_err(dev, "Failed to update pasid id in VSI context, err %d aq_err %s\n",
			err, ice_aq_str(hw->adminq.sq_last_status));
	} else {
		vsi->info.pasid_id = pasid;
		priv->pasid = pasid;
	}

	kfree(ctxt);
	return err;
}

/**
 * ice_siov_post_vsi_rebuild - post S-IOV VSI rebuild operations
 * @vf: pointer to VF structure
 *
 * After a VSI is re-created or rebuilt, perform the necessary operations to
 * complete the VSI rebuild. This function is called after an individual VF
 * reset or after a global PF reset.
 */
static void ice_siov_post_vsi_rebuild(struct ice_vf *vf)
{
	struct ice_scalable_dev *priv = vf_to_priv(vf);
	bool update_hash_entry;
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_hw *hw;
	int err;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		dev_err(dev, "Unable to determine VSI for VF %u\n", vf->vf_id);
		return;
	}

	dev = ice_pf_to_dev(vf->pf);
	hw = &vf->pf->hw;

	/* If the VSI number has changed after the rebuild, we need to update
	 * the VF ID and move the entry in the hash table
	 */
	if (vsi->vsi_num != vf->vf_id) {
		vf->vf_id = vsi->vsi_num;
		update_hash_entry = true;
	} else {
		update_hash_entry = false;
	}

	err = ice_vsi_configure_pasid(vf, priv->pasid, true);
	if (err)
		dev_err(dev, "Failed to reconfigure PASID for VF %u, error %d\n",
			vf->vf_id, err);

	if (ice_ena_siov_vf_mapping(vf))
		dev_err(dev, "Failed to enable Scalable IOV mapping for VF %u\n",
			vf->vf_id);

	/* If the VSI number has changed after the rebuild, we need to update
	 * the hash table. This can't be done immediately in this thread
	 * because we might be iterating the hash table in this thread, and we
	 * can't take the table lock without causing a deadlock here. Schedule
	 * a thread to update the hash table.
	 *
	 * If we don't need to update the hash entry, its safe to let the VF
	 * driver activate. Otherwise, delay this until we finish updating the
	 * hash entry.
	 */
	if (update_hash_entry)
		schedule_work(&priv->update_hash_entry);
	else
		priv->reset_state = VIRTCHNL_VFR_VFACTIVE;

	/* Restore mailbox values. Don't restore MBX_ARQLEN and
	 * MBX_ATQLEN as explained in ice_siov_clear_mbx_register.
	 */
	wr32(hw, VSI_MBX_ATQH(vf->vf_id), priv->mbx_regs.mbx_asqh);
	wr32(hw, VSI_MBX_ATQT(vf->vf_id), priv->mbx_regs.mbx_asqt);
	wr32(hw, VSI_MBX_ATQBAL(vf->vf_id), priv->mbx_regs.mbx_asqbal);
	wr32(hw, VSI_MBX_ATQBAH(vf->vf_id), priv->mbx_regs.mbx_asqbah);
	wr32(hw, VSI_MBX_ARQH(vf->vf_id), priv->mbx_regs.mbx_arqh);
	wr32(hw, VSI_MBX_ARQT(vf->vf_id), priv->mbx_regs.mbx_arqt);
	wr32(hw, VSI_MBX_ARQBAL(vf->vf_id), priv->mbx_regs.mbx_arqbal);
	wr32(hw, VSI_MBX_ARQBAH(vf->vf_id), priv->mbx_regs.mbx_arqbah);
}

static const struct ice_vf_ops ice_siov_vf_ops = {
	.reset_type = ICE_VM_RESET,
	.free = ice_siov_free_vf,
	.clear_reset_state = ice_siov_clear_reset_state,
	.clear_mbx_register = ice_siov_clear_mbx_register,
	.trigger_reset_register = ice_siov_trigger_reset_register,
	.poll_reset_status = ice_siov_poll_reset_status,
	.clear_reset_trigger = ice_siov_clear_reset_trigger,
	.irq_close = ice_siov_irq_close,
	.post_vsi_rebuild = ice_siov_post_vsi_rebuild,
};

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
