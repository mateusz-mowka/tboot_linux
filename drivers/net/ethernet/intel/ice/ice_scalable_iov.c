// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2021, Intel Corporation. */

#include "ice_scalable_iov.h"
#include "ice_lib.h"
#include "ice_virtchnl_allowlist.h"
#include "ice_fltr.h"
#include "siov_regs.h"
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
 * @ops: ADI driver operations table
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
	const struct adi_drv_ops *ops;
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
 *
 * Note this will always be after auxiliary_device_uninit because we do not
 * free the main reference of the VF until inside the ice_scalable_dev_release
 * function.
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
	kfree_rcu(priv, vf.rcu);
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
	struct ice_scalable_dev *priv = vf_to_priv(vf);

	if (!priv->ops)
		return;

	/* Release the previous VSI IRQ context */
	priv->ops->pre_rebuild_irqctx(&priv->adi);
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
 * ice_siov_update_hash_entry - work task to fix VF hash entry
 * @work: the work task structure
 *
 * Work item scheduled to fix the VF hash entry after a rebuild. Called when
 * the VSI number, and thus the VF ID has changed. This update cannot be done
 * in the same thread because it cannot guarantee a safe method of acquiring
 * the table lock mutex, and because the calling thread might be iterating the
 * hash table using the standard iterator which is not protected against hash
 * table modification.
 */
static void ice_siov_update_hash_entry(struct work_struct *work)
{
	struct ice_scalable_dev *priv = container_of(work,
						     struct ice_scalable_dev,
						     update_hash_entry);
	struct ice_vf *vf = &priv->vf;
	struct ice_vfs *vfs;

	vfs = &vf->pf->vfs;

	mutex_lock(&vfs->table_lock);
	mutex_lock(&vf->cfg_lock);

	hash_del_rcu(&vf->entry);
	hash_add_rcu(vfs->table, &vf->entry, vf->vf_id);

	/* We've finished cleaning up in software. Update the reset
	 * state, allowing the VF to detect that its safe to proceed.
	 */
	priv->reset_state = VIRTCHNL_VFR_VFACTIVE;

	mutex_unlock(&vf->cfg_lock);
	mutex_unlock(&vfs->table_lock);
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

	if (!priv->ops)
		goto skip_rebuild_irqctx;

	err = priv->ops->rebuild_irqctx(&priv->adi);
	if (err)
		dev_err(dev, "failed to rebuild irq context, error %d\n", err);

	/* Make sure to zap all the pages only after the new VSI is setup.
	 * When ice_siov_vsi_rebuild is called by VF_RESET virtchnl, this
	 * function is scheduled in a kernel thread. At the same time, VM
	 * will keep accessing old VSI's mbx register set.
	 *
	 * If we zapped the pages before the new VSI was setup, the VF might
	 * read the mailbox register while we're still setting up the new VSI.
	 * This would trigger a page fault that generates a new GPA to HPA
	 * mapping, but with the old VSI registers.
	 *
	 * By zapping the pages only after the new VSI is setup, we avoid
	 * this possibility.
	 */
	priv->ops->zap_vma_map(&priv->adi);

skip_rebuild_irqctx:
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

/* ADI operations called by ADI driver */

/**
 * ice_adi_init_drv_ops - Initialize PF to ADI driver ops table
 * @adi: ADI auxiliary device pointer
 * @ops: the ops table;
 */
static void
ice_adi_init_drv_ops(struct adi_aux_dev *adi, const struct adi_drv_ops *ops)
{
	struct ice_scalable_dev *priv = adi_to_priv(adi);

	priv->ops = ops;
}

/**
 * ice_adi_get_vector_num - get number of vectors assigned to this ADI
 * @adi: ADI auxiliary device pointer
 *
 * Return: the (positive) number of queue vectors, or -EFAULT if unable to
 *         determine the VF VSI pointer.
 */
static int ice_adi_get_vector_num(struct adi_aux_dev *adi)
{
	struct ice_scalable_dev *priv = adi_to_priv(adi);
	struct ice_vf *vf = &priv->vf;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		dev_err(ice_pf_to_dev(pf), "Invalid VSI pointer");
		return -EFAULT;
	}

	/* Account for the queue vectors plus 1 for the non-queue vector */
	return vsi->num_q_vectors + 1;
}

/**
 * ice_adi_get_vector_irq - get OS IRQ number per vector
 * @adi: ADI auxiliary device pointer
 * @idx: IRQ vector index
 *
 * Return: the Linux IRQ number associated with a vector on success, or
 *         -EFAULT if unable to determine the VF VSI pointer, or -EINVAL if
 *         the requested vector index is not valid.
 */
static int ice_adi_get_vector_irq(struct adi_aux_dev *adi, u32 idx)
{
	struct ice_scalable_dev *priv = adi_to_priv(adi);
	struct ice_vf *vf = &priv->vf;
	struct msi_map *irq;
	struct ice_vsi *vsi;

	vsi = ice_get_vf_vsi(vf);
	if (WARN_ON(!vsi))
		return -EFAULT;

	if (idx >= vsi->num_q_vectors + 1)
		return -EINVAL;

	/* Index 0 is the non-queue vector */
	if (!idx) {
		irq = &priv->non_q_vector;
	} else {
		struct ice_q_vector *q_vector;

		q_vector = vsi->q_vectors[idx - 1];
		if (!q_vector)
			return -EINVAL;

		irq = &q_vector->irq;
	}

	return irq->virq;
}

/**
 * ice_adi_reset - reset VF associated with this ADI auxiliary device
 * @adi: ADI auxiliary device pointer
 *
 * Return: zero on success, or a non-zero errno value on failure to reset the
 *         associated VF.
 */
static int ice_adi_reset(struct adi_aux_dev *adi)
{
	struct ice_scalable_dev *priv;
	struct ice_vf *vf;

	priv = adi_to_priv(adi);
	vf = &priv->vf;

	return ice_reset_vf(vf, ICE_VF_RESET_NOTIFY | ICE_VF_RESET_LOCK);
}

/**
 * ice_adi_cfg_pasid - configure PASID for this ADI auxiliary device
 * @adi: ADI auxiliary device pointer
 * @pasid: pasid value
 * @ena: enable
 *
 * Return: zero on success, or a non-zero errno value on failure to configure
 *         PASID value for the associated VF.
 */
static int ice_adi_cfg_pasid(struct adi_aux_dev *adi, u32 pasid, bool ena)
{
	struct ice_scalable_dev *priv;
	struct ice_vf *vf;

	priv = adi_to_priv(adi);
	vf = &priv->vf;

	return ice_vsi_configure_pasid(vf, pasid, ena);
}

/**
 * ice_adi_close - close this ADI auxiliary device
 * @adi: ADI auxiliary device pointer
 *
 * Return: zero on success, or -EFAULT if unable to determine the VSI pointer
 *         associated with this ADI.
 */
static int ice_adi_close(struct adi_aux_dev *adi)
{
	struct ice_scalable_dev *priv = adi_to_priv(adi);
	struct ice_vf *vf = &priv->vf;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		dev_err(ice_pf_to_dev(pf), "Invalid VSI pointer");
		return -EFAULT;
	}

	ice_vsi_stop_lan_tx_rings(vsi, ICE_NO_RESET, vf->vf_id);
	ice_vsi_stop_all_rx_rings(vsi);

	ice_set_vf_state_dis(vf);

	return 0;
}

/**
 * ice_adi_read_reg32 - read device register
 * @adi: ADI auxiliary device pointer
 * @offs: register offset
 *
 * Return: the register value at the associated ADI register offset, or
 * 0xdeadbeef if an error reading the register occurred.
 */
static u32 ice_adi_read_reg32(struct adi_aux_dev *adi, size_t offs)
{
	struct ice_scalable_dev *priv = adi_to_priv(adi);
	struct ice_vf *vf = &priv->vf;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	u32 index, reg_val;
	struct ice_hw *hw;

	if (test_bit(ICE_VF_STATE_DIS, vf->vf_states)) {
		if (offs == VFGEN_RSTAT1)
			return VIRTCHNL_VFR_INPROGRESS;
		else
			return 0xdeadbeef;
	}

	hw = &pf->hw;
	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		dev_err(ice_pf_to_dev(pf), "Invalid VSI pointer");
		return 0xdeadbeef;
	}

	/* check for 4-byte aligned register access */
	if (!IS_ALIGNED(offs, 4))
		return 0xdeadbeef;

	switch (offs) {
	case VFGEN_RSTAT1:
		reg_val = rd32(hw, VSIGEN_RSTAT(vsi->vsi_num));

		if (reg_val & VSIGEN_RSTAT_VMRD_M) {
			if (priv->reset_state == VIRTCHNL_VFR_VFACTIVE)
				return VIRTCHNL_VFR_VFACTIVE;
			else
				return VIRTCHNL_VFR_COMPLETED;
		}

		return VIRTCHNL_VFR_INPROGRESS;
	case VF_MBX_ATQBAL1:
		return rd32(hw, VSI_MBX_ATQBAL(vsi->vsi_num));
	case VF_MBX_ATQBAH1:
		return rd32(hw, VSI_MBX_ATQBAH(vsi->vsi_num));
	case VF_MBX_ATQLEN1:
		return rd32(hw, VSI_MBX_ATQLEN(vsi->vsi_num));
	case VF_MBX_ATQH1:
		return rd32(hw, VSI_MBX_ATQH(vsi->vsi_num));
	case VF_MBX_ATQT1:
		return rd32(hw, VSI_MBX_ATQT(vsi->vsi_num));
	case VF_MBX_ARQBAL1:
		return rd32(hw, VSI_MBX_ARQBAL(vsi->vsi_num));
	case VF_MBX_ARQBAH1:
		return rd32(hw, VSI_MBX_ARQBAH(vsi->vsi_num));
	case VF_MBX_ARQLEN1:
		return rd32(hw, VSI_MBX_ARQLEN(vsi->vsi_num));
	case VF_MBX_ARQH1:
		return rd32(hw, VSI_MBX_ARQH(vsi->vsi_num));
	case VF_MBX_ARQT1:
		return rd32(hw, VSI_MBX_ARQT(vsi->vsi_num));
	case VFINT_DYN_CTL0:
		if (WARN_ON_ONCE(priv->non_q_vector.index < 0))
			return 0xdeadbeef;
		return rd32(hw, GLINT_DYN_CTL(priv->non_q_vector.index));
	case VFINT_ITR0(0):
	case VFINT_ITR0(1):
	case VFINT_ITR0(2):
		if (WARN_ON_ONCE(priv->non_q_vector.index < 0))
			return 0xdeadbeef;
		index = (offs - VFINT_ITR0(0)) / 4;
		return rd32(hw, GLINT_ITR(index, priv->non_q_vector.index));
	case VFINT_DYN_CTLN(0) ... VFINT_DYN_CTLN(63):
		index = (offs - VFINT_DYN_CTLN(0)) / 4;
		if (index >= vsi->num_q_vectors || !vsi->q_vectors[index]) {
			dev_warn_once(ice_pf_to_dev(pf), "Invalid vector pointer for VSI %d\n",
				      vsi->vsi_num);
			return 0xdeadbeef;
		}
		return rd32(hw, GLINT_DYN_CTL(vsi->q_vectors[index]->reg_idx));
	default:
		return 0xdeadbeef;
	}
}

/**
 * ice_adi_write_reg32 - write device register
 * @adi: ADI auxiliary device pointer
 * @offs: register offset
 * @data: register value
 */
static void
ice_adi_write_reg32(struct adi_aux_dev *adi, size_t offs, u32 data)
{
	struct ice_scalable_dev *priv = adi_to_priv(adi);
	struct ice_vf *vf = &priv->vf;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	struct ice_hw *hw;
	u32 index;

	if (test_bit(ICE_VF_STATE_DIS, vf->vf_states))
		return;

	hw = &pf->hw;
	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		dev_err(ice_pf_to_dev(pf), "Invalid VSI pointer");
		return;
	}

	/* check for 4-byte aligned register access */
	if (!IS_ALIGNED(offs, 4))
		return;

	switch (offs) {
	case VF_MBX_ATQBAL1:
		wr32(hw, VSI_MBX_ATQBAL(vsi->vsi_num), data);
		break;
	case VF_MBX_ATQBAH1:
		wr32(hw, VSI_MBX_ATQBAH(vsi->vsi_num), data);
		break;
	case VF_MBX_ATQLEN1:
		wr32(hw, VSI_MBX_ATQLEN(vsi->vsi_num), data);
		break;
	case VF_MBX_ATQH1:
		wr32(hw, VSI_MBX_ATQH(vsi->vsi_num), data);
		break;
	case VF_MBX_ATQT1:
		wr32(hw, VSI_MBX_ATQT(vsi->vsi_num), data);
		break;
	case VF_MBX_ARQBAL1:
		wr32(hw, VSI_MBX_ARQBAL(vsi->vsi_num), data);
		break;
	case VF_MBX_ARQBAH1:
		wr32(hw, VSI_MBX_ARQBAH(vsi->vsi_num), data);
		break;
	case VF_MBX_ARQLEN1:
		wr32(hw, VSI_MBX_ARQLEN(vsi->vsi_num), data);
		break;
	case VF_MBX_ARQH1:
		wr32(hw, VSI_MBX_ARQH(vsi->vsi_num), data);
		break;
	case VF_MBX_ARQT1:
		wr32(hw, VSI_MBX_ARQT(vsi->vsi_num), data);
		break;
	case VFINT_DYN_CTL0:
		if (priv->non_q_vector.index < 0)
			goto err_resource;
		wr32(hw, GLINT_DYN_CTL(priv->non_q_vector.index), data);
		break;
	case VFINT_ITR0(0):
	case VFINT_ITR0(1):
	case VFINT_ITR0(2):
		if (priv->non_q_vector.index < 0)
			goto err_resource;
		index = (offs - VFINT_ITR0(0)) / 4;
		wr32(hw, GLINT_ITR(index, priv->non_q_vector.index), data);
		break;
	case VFINT_DYN_CTLN(0) ... VFINT_DYN_CTLN(63):
		index = (offs - VFINT_DYN_CTLN(0)) / 4;
		if (index >= vsi->num_q_vectors || !vsi->q_vectors[index])
			goto err_resource;
		wr32(hw, GLINT_DYN_CTL(vsi->q_vectors[index]->reg_idx), data);
		break;
	case QTX_TAIL(0) ... QTX_TAIL(255):
		index = (offs - QTX_TAIL(0)) / 4;
		if (!vsi->txq_map || index >= vsi->alloc_txq)
			goto err_resource;
		wr32(hw, QTX_COMM_DBELL_PAGE(vsi->txq_map[index]), data);
		break;
	case QRX_TAIL1(0) ... QRX_TAIL1(255):
		index = (offs - QRX_TAIL1(0)) / 4;
		if (!vsi->rxq_map || index >= vsi->alloc_rxq)
			goto err_resource;
		wr32(hw, QRX_TAIL_PAGE(vsi->rxq_map[index]), data);
		break;
	default:
		break;
	}
	return;

err_resource:
	dev_warn_once(ice_pf_to_dev(pf), "Invalid resource access for VF VSI %d\n",
		      vsi->vsi_num);
}

/**
 * ice_adi_get_sparse_mmap_hpa - get VDEV HPA
 * @adi: pointer to assignable device interface
 * @index: VFIO BAR index
 * @vm_pgoff: page offset of virtual memory area
 * @addr: VDEV address
 *
 * Return: zero on success, -EFAULT if the associated VSI cannot be
 *         determined, -EINVAL if the index or address is invalid, or another
 *         non-zero errno value if unable to get the sparse memory map.
 */
static int
ice_adi_get_sparse_mmap_hpa(struct adi_aux_dev *adi, u32 index, u64 vm_pgoff,
			    u64 *addr)
{
	struct ice_scalable_dev *priv;
	struct pci_dev *pdev;
	struct ice_vsi *vsi;
	struct ice_vf *vf;
	u64 reg_off;
	int q_idx;

	if (!addr || index != VFIO_PCI_BAR0_REGION_INDEX)
		return -EINVAL;

	priv = adi_to_priv(adi);
	vf = &priv->vf;
	vsi = ice_get_vf_vsi(vf);
	if (!vsi)
		return -EFAULT;

	pdev = vf->pf->pdev;
	switch (vm_pgoff) {
	case PHYS_PFN(VDEV_MBX_START):
		/* MBX Registers */
		reg_off = VSI_MBX_ATQBAL(vsi->vsi_num);
		break;
	case PHYS_PFN(VDEV_QRX_TAIL_START) ...
				(PHYS_PFN(VDEV_QRX_BUFQ_TAIL_START) - 1):
		/* RXQ tail register */
		q_idx = vm_pgoff - PHYS_PFN(VDEV_QRX_TAIL_START);
		if (q_idx >= vsi->alloc_rxq)
			return -EINVAL;
		reg_off = QRX_TAIL_PAGE(vsi->rxq_map[q_idx]);
		break;
	case PHYS_PFN(VDEV_QTX_TAIL_START) ...
				(PHYS_PFN(VDEV_QTX_COMPL_TAIL_START) - 1):
		/* TXQ tail register */
		q_idx = vm_pgoff - PHYS_PFN(VDEV_QTX_TAIL_START);
		if (q_idx >= vsi->alloc_txq)
			return -EINVAL;
		reg_off = QTX_COMM_DBELL_PAGE(vsi->txq_map[q_idx]);
		break;
	case PHYS_PFN(VDEV_INT_DYN_CTL01):
		/* INT DYN CTL01, ITR0/1/2 */
		if (priv->non_q_vector.index < 0)
			return -EINVAL;
		reg_off = PF0INT_DYN_CTL(priv->non_q_vector.index);
		break;
	case PHYS_PFN(VDEV_INT_DYN_CTL(0)) ...
					(PHYS_PFN(ICE_ADI_BAR0_SIZE) - 1):
		/* INT DYN CTL, ITR0/1/2 */
		q_idx = vm_pgoff - PHYS_PFN(VDEV_INT_DYN_CTL(0));
		if (q_idx >= vsi->num_q_vectors)
			return -EINVAL;
		reg_off = PF0INT_DYN_CTL(vsi->q_vectors[q_idx]->reg_idx);
		break;
	default:
		return -EFAULT;
	}

	/* add BAR0 start address */
	*addr = pci_resource_start(pdev, 0) + reg_off;
	return 0;
}

enum ice_adi_sparse_mmap_type {
	ICE_ADI_SPARSE_MBX = 0,
	ICE_ADI_SPARSE_RXQ,
	ICE_ADI_SPARSE_TXQ,
	ICE_ADI_SPARSE_DYN_CTL01,
	ICE_ADI_SPARSE_DYN_CTL,
	ICE_ADI_SPARSE_MAX,
};

struct ice_adi_sparse_mmap_pattern {
	u64 start;
	u64 end;
	u64 cnt;
	u64 phy_addr;
};

struct ice_adi_sparse_mmap_info {
	struct ice_adi_sparse_mmap_pattern patterns[ICE_ADI_SPARSE_MAX];
};

/**
 * ice_adi_get_sparse_patterns - Get sparse patterns information
 * @adi: pointer to assignable device interface
 * @info: storage for pattern info
 *
 * On return the pattern array in info will contain the sparse pattern
 * information.
 *
 * Return: the (positive) number of sparse memory areas defined by the pattern
 *         array, or -EFAULT if unable to determine the associated VSI
 *         structure.
 */
static int
ice_adi_get_sparse_patterns(struct adi_aux_dev *adi,
			    struct ice_adi_sparse_mmap_info *info)
{
	struct ice_adi_sparse_mmap_pattern *pattern;
	struct ice_scalable_dev *priv;
	struct ice_vsi *vsi;
	struct ice_vf *vf;
	int i, nr_areas;

	priv = adi_to_priv(adi);
	vf = &priv->vf;
	vsi = ice_get_vf_vsi(vf);
	if (!vsi)
		return -EFAULT;

	pattern = &info->patterns[ICE_ADI_SPARSE_MBX];
	pattern->start = 0;
	pattern->cnt = 1;
	pattern->end = pattern->start + pattern->cnt;
	pattern->phy_addr = VDEV_MBX_START;

	pattern = &info->patterns[ICE_ADI_SPARSE_RXQ];
	pattern->start = pattern[i - 1].end;
	pattern->cnt = vsi->alloc_rxq;
	pattern->end = pattern->start + pattern->cnt;
	pattern->phy_addr = VDEV_QRX_TAIL_START;

	pattern = &info->patterns[ICE_ADI_SPARSE_TXQ];
	pattern->start = pattern[i - 1].end;
	pattern->cnt = vsi->alloc_txq;
	pattern->end = pattern->start + pattern->cnt;
	pattern->phy_addr = VDEV_QTX_TAIL_START;

	pattern = &info->patterns[ICE_ADI_SPARSE_DYN_CTL01];
	pattern->start = pattern[i - 1].end;
	pattern->cnt = 1;
	pattern->end = pattern->start + pattern->cnt;
	pattern->phy_addr = VDEV_INT_DYN_CTL01;

	pattern = &info->patterns[ICE_ADI_SPARSE_DYN_CTL];
	pattern->start = pattern[i - 1].end;
	pattern->cnt = vsi->num_q_vectors;
	pattern->end = pattern->start + pattern->cnt;
	pattern->phy_addr = VDEV_INT_DYN_CTL(0);

	for (nr_areas = 0, i = 0; i < ARRAY_SIZE(info->patterns); i++)
		nr_areas += info->patterns[i].cnt;

	return nr_areas;
}

/**
 * ice_adi_get_sparse_mmap_num - get number of sparse memory
 * @adi: pointer to assignable device interface
 *
 * Return: the (positive) number of sparse memory areas, or -EFAULT if unable
 *         to determine the associated VSI structure.
 */
static int
ice_adi_get_sparse_mmap_num(struct adi_aux_dev *adi)
{
	struct ice_adi_sparse_mmap_info info = {};

	return ice_adi_get_sparse_patterns(adi, &info);
}

/**
 * ice_adi_get_sparse_mmap_area - get sparse memory layout for mmap
 * @adi: pointer to assignable device interface
 * @index: index of sparse memory
 * @offset: pointer to sparse memory areas offset
 * @size: pointer to sparse memory areas size
 *
 * Return: zero on success, -EINVAL if the index offset or size are invalid,
 *         -EFAULT if unable to determine the VSI for this ADI.
 */
static int
ice_adi_get_sparse_mmap_area(struct adi_aux_dev *adi, int index, u64 *offset,
			     u64 *size)
{
	struct ice_adi_sparse_mmap_pattern *pattern;
	struct ice_adi_sparse_mmap_info info = {};
	int nr_areas = 0;
	u64 ai;
	int i;

	nr_areas = ice_adi_get_sparse_patterns(adi, &info);
	if (nr_areas < 0)
		return nr_areas;

	if (index < 0 || index >= nr_areas)
		return -EINVAL;

	ai = (u64)index;

	for (i = 0; i < ARRAY_SIZE(info.patterns); i++) {
		pattern = &info.patterns[i];
		if (ai >= pattern->start && ai < pattern->end) {
			*offset = pattern->phy_addr +
					PAGE_SIZE * (ai - pattern->start);
			*size   = PAGE_SIZE;
			break;
		}
	}

	return (i == ARRAY_SIZE(info.patterns)) ? -EINVAL : 0;
}

static const struct adi_dev_ops ice_adi_ops = {
	.init_drv_ops = ice_adi_init_drv_ops,
	.get_vector_num = ice_adi_get_vector_num,
	.get_vector_irq = ice_adi_get_vector_irq,
	.reset = ice_adi_reset,
	.cfg_pasid = ice_adi_cfg_pasid,
	.close = ice_adi_close,
	.read_reg32 = ice_adi_read_reg32,
	.write_reg32 = ice_adi_write_reg32,
	.get_sparse_mmap_hpa = ice_adi_get_sparse_mmap_hpa,
	.get_sparse_mmap_num = ice_adi_get_sparse_mmap_num,
	.get_sparse_mmap_area = ice_adi_get_sparse_mmap_area,
};

/* ADI setup functions */

/**
 * ice_scalable_dev_release - Release resources associated with this port
 * @dev: device pointer
 *
 * The auxiliary bus release function for the ice_scalable_dev.adev. This will be
 * called only once all references to the auxiliary device are dropped. We
 * must not free the ADI or its associated resources before that.
 *
 * Once the auxiliary devices are uninitialized it will be safe to release the
 * VF reference. Once all VF references are released, the ice_siov_free_vf
 * function will be called.
 */
static void ice_scalable_dev_release(struct device *dev)
{
	struct auxiliary_device *adev = to_auxiliary_dev(dev);
	struct ice_scalable_dev *priv = adev_to_priv(adev);

	xa_erase(&ice_adi_aux_ids, adev->id);
	ice_put_vf(&priv->vf);
}

/**
 * ice_adi_vf_init - Initialize VF structure and reference count
 * @pf: pointer to PF structure
 * @priv: the ADI whose VF to initialize
 *
 * Initialize the VF structure associated with the ADI. Once this is done, the
 * ADI must be released using ice_put_vf, rather than directly releasing it.
 */
static void ice_adi_vf_init(struct ice_pf *pf, struct ice_scalable_dev *priv)
{
	struct ice_vf *vf = &priv->vf;

	kref_init(&vf->refcnt);
	vf->pf = pf;
	vf->vf_ops = &ice_siov_vf_ops;
	vf->hw_lan_addr = priv->dyn_port->hw_addr;

	ice_initialize_vf_entry(vf);
	INIT_WORK(&priv->update_hash_entry, ice_siov_update_hash_entry);

	vf->vf_sw_id = pf->first_sw;

	mutex_init(&vf->cfg_lock);
}

/**
 * ice_adi_vf_setup - Setup the ADI's VF structure
 * @pf: pointer to the PF private structure
 * @priv: pointer to the ADI private data
 *
 * Initialize the VF structure for this ADI, and register it with the PF.
 *
 * Return: zero on success, or a non-zero errno value on failure to setup the
 *         VF structure.
 */
static int ice_adi_vf_setup(struct ice_pf *pf, struct ice_scalable_dev *priv)
{
	struct ice_vsi_cfg_params params = {};
	struct ice_vf *vf = &priv->vf;
	struct ice_hw *hw = &pf->hw;
	struct ice_vsi *vsi;
	struct device *dev;
	int err;

	dev = ice_pf_to_dev(pf);
	vsi = priv->dyn_port->vsi;

	err = ice_adi_alloc_non_q_vector(pf, priv);
	if (err) {
		dev_err(dev, "ADI VSI unable to reserve non-queue vector, %pe\n",
			ERR_PTR(err));
		return err;
	}

	params.type = ICE_VSI_ADI;
	params.pi = ice_vf_get_port_info(vf);
	params.vf = vf;
	params.flags = ICE_VSI_FLAG_INIT;

	err = ice_vsi_cfg(vsi, &params);
	if (err) {
		dev_err(dev, "ADI VSI configuration failed, %pe\n",
			ERR_PTR(err));
		goto err_release_non_q_vectors;
	}

	vf->lan_vsi_idx = vsi->idx;
	vf->lan_vsi_num = vsi->vsi_num;
	vf->vf_id = vsi->vsi_num;

	err = ice_vf_init_host_cfg(vf, vsi);
	if (err) {
		dev_err(dev, "Failed to initialize host configuration, %pe\n",
			ERR_PTR(err));
		goto err_decfg_vsi;
	}

	err = ice_ena_siov_vf_mapping(vf);
	if (err) {
		dev_err(dev, "Failed to map Scalable IOV VF, %pe\n",
			ERR_PTR(err));
		goto err_decfg_vsi;
	}

	set_bit(ICE_VF_STATE_INIT, vf->vf_states);
	wr32(hw, VSIGEN_RSTAT(vf->vf_id), VIRTCHNL_VFR_VFACTIVE);
	ice_flush(hw);

	mutex_lock(&pf->vfs.table_lock);
	hash_add_rcu(pf->vfs.table, &vf->entry, vf->vf_id);
	mutex_unlock(&pf->vfs.table_lock);

	return 0;

err_decfg_vsi:
	ice_vsi_decfg(vsi);
	vsi->vf = NULL;
err_release_non_q_vectors:
	ice_adi_release_non_q_vector(pf, priv);

	return err;
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
	if (ice_get_avail_txq_count(pf) < ICE_DFLT_QS_PER_SIOV_VF ||
	    ice_get_avail_rxq_count(pf) < ICE_DFLT_QS_PER_SIOV_VF) {
		NL_SET_ERR_MSG_MOD(extack, "Not enough available queues");
		return -ENOSPC;
	}

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		NL_SET_ERR_MSG_MOD(extack, "Could not allocate ADI structure");
		return -ENOMEM;
	}

	priv->dyn_port = dyn_port;
	ice_adi_vf_init(pf, priv);

	err = ice_adi_vf_setup(pf, priv);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Could not setup VF structure");
		goto err_free_adi;
	}

	err = xa_alloc(&ice_adi_aux_ids, &id, NULL, XA_LIMIT(1, U32_MAX),
		       GFP_KERNEL);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Could not allocate auxiliary device ID");
		goto err_free_adi;
	}

	priv->adi.ops = &ice_adi_ops;
	priv->adi.cfg_lock = &priv->vf.cfg_lock;

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

	err = auxiliary_device_add(adev);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to probe auxiliary device");
		goto err_auxiliary_uninit;
	}

	dyn_port->scalable_dev = priv;

	return 0;

err_auxiliary_uninit:
	/* This will call ice_scalable_dev_release and take care of tearing
	 * down and releasing the ADI
	 */
	auxiliary_device_uninit(adev);

	return err;

err_erase_id:
	xa_erase(&ice_adi_aux_ids, id);
err_free_adi:
	/* ice_put_vf will take care of releasing the private structure */
	ice_put_vf(&priv->vf);

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

	if (priv) {
		auxiliary_device_delete(&priv->adi.adev);
		auxiliary_device_uninit(&priv->adi.adev);
	}

	dyn_port->scalable_dev = NULL;
}

/**
 * ice_scalable_dev_update_hw_addr - Update VF MAC address on change
 * @dyn_port: the dynamic port instance for this VF
 *
 * Returns: zero on success, or a non-zero errno value on failure.
 */
int ice_scalable_dev_update_hw_addr(struct ice_dynamic_port *dyn_port)
{
	return ice_vf_notify_mac_addr(&dyn_port->scalable_dev->vf);
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
