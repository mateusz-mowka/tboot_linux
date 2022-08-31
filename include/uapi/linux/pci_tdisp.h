/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * pci_tdisp.h
 *
 * PCIe TEE Device Interface Security Protocol (TDISP) Spec definitions
 */

#ifndef _UAPILINUX_PCI_TDISP_H
#define _UAPILINUX_PCI_TDISP_H

/* PCIe TEE Device Interface Security Protocol (TDISP) Message Code */
#define TDISP_GET_VERSION		0x81
#define TDISP_VERSION			0x01
#define TDISP_GET_CAPABILITY		0x82
#define TDISP_CAPABILITY		0x02
#define TDISP_LOCK_INTF_REQ		0x83
#define TDISP_LOCK_INTF_RESP		0x03
#define TDISP_GET_DEVIF_REPORT		0x84
#define TDISP_DEVIF_REPORT		0x04
#define TDISP_GET_DEVIF_STATE		0x85
#define TDISP_DEVIF_STATE		0x05
#define TDISP_START_DEVIF_MMIO_REQ	0x86
#define TDISP_START_DEVIF_MMIO_RESP	0x06
#define TDISP_START_DEVIF_DMA_REQ	0x87
#define TDISP_START_DEVIF_DMA_RESP	0x07
#define TDISP_STOP_INTF_REQ		0x88
#define TDISP_STOP_INTF_RESP		0x08
#define TDISP_DRAIN_INTF_REQ		0x89
#define TDISP_DRAIN_INTF_RESP		0x09
#define TDISP_BIND_PASID_REQ		0x8a
#define TDISP_BIND_PASID_RESP		0x0a
#define TDISP_BIND_P2P_STREAM_REQ	0x8b
#define TDISP_BIND_P2P_STREAM_RESP	0x0b
#define TDISP_UNBIND_P2P_STREAM_REQ	0x8c
#define TDISP_UNBIND_P2P_STREAM_RESP	0x0c
#define TDISP_SET_MMIO_ATTR_REQ		0x8d
#define TDISP_SET_MMIO_ATTR_RESP		0x0d
#define TDISP_ERROR			0x7f

/*
 * Device Interface Report - header
 * The TDISP header is not taken into account. This is because TDX module will
 * strip the TDISP header for DEVIF_REPORT seamcall.
 */
#define DEVIF_RP_LEN			0x0
#define DEVIF_RP_LEN_PORTION(v)		((v) & 0xffff)
#define DEVIF_RP_LEN_REMAIN(v)		(((v) >> 16) & 0xffff)
#define DEVIF_RP_HDR_SIZE		4

/*
 * Device Interface Report - content
 * The Device Interface Report header is taken into account, but the TDISP
 * header is not.
 */
#define DEVIF_RP_INTF_INFO		0x4
#define DEVIF_RP_MSIX_CTRL(v)		(((v) >> 16) & 0xffff)
#define DEVIF_RP_MMIO_NUM		0x14
#define DEVIF_RP_MMIO_ADDR_LO(n)	(0x18 + (n) * 16)
#define DEVIF_RP_MMIO_ADDR_HI(n)	(0x1c + (n) * 16)
#define DEVIF_RP_MMIO_PAGES(n)		(0x20 + (n) * 16)
#define DEVIF_RP_MMIO_ATTR(n)		(0x24 + (n) * 16)
#define DEVIF_RP_MMIO_ATTR_MSIX(v)	((v) & 0x1)
#define DEVIF_RP_MMIO_ATTR_PBA(v)	(((v) >> 1) & 0x1)
#define DEVIF_RP_MMIO_ATTR_ID(v)	(((v) >> 16) & 0xffff)

#endif
