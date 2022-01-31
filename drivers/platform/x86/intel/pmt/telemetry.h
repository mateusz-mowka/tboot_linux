/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _INTEL_PMT_TELEM_H
#define _INTEL_PMT_TELEM_H

struct pci_dev;

/**
 * pmt_telem_read() - Read qwords from counter sram using sample id
 * @pdev:   PCI device inside the Intel vsec
 * @guid:   GUID of the telemetry space
 * @pos:    Instance of the guid in case of multiple instances
 * @id:     The beginning sample id of the metric(s) to be read
 * @count:  Number of qwords requested
 * @data:   Allocated qword buffer
 *
 * Callers must ensure reads are aligned. When the call returns -ENODEV,
 * the device has been removed and callers should unregister the telemetry
 * endpoint.
 *
 * Return:
 * * 0           - Success
 * * -ENODEV     - The device is not present.
 * * -EINVAL     - The offset is out bounds
 */
int pmt_telem_read(struct pci_dev *pdev, u32 guid, u16 pos, u16 id, u16 count, u64 *data);
#endif
