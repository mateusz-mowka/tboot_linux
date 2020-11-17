// SPDX-License-Identifier: GPL-2.0
/*
 * attest.c - TDX attestation feature support.
 *
 * Implements attestation related IOCTL handlers.
 *
 * Copyright (C) 2022 Intel Corporation
 *
 */

#include <linux/mm.h>
#include <linux/io.h>
#include <asm/tdx.h>

#include "tdx.h"

/* TDREPORT module call leaf ID */
#define TDX_GET_REPORT			4

long tdx_get_report(void __user *argp)
{
	u8 *reportdata = NULL, *tdreport = NULL;
	struct tdx_report_req req;
	long ret;

	/* Copy request struct from the user buffer */
	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	/*
	 * Per TDX Module 1.0 specification, section titled
	 * "TDG.MR.REPORT", REPORTDATA and TDREPORT length
	 * is fixed as TDX_REPORTDATA_LEN and TDX_REPORT_LEN.
	 */
	if (req.rpd_len != TDX_REPORTDATA_LEN || req.tdr_len != TDX_REPORT_LEN)
		return -EINVAL;

	/* Allocate kernel buffers for REPORTDATA and TDREPORT */
	reportdata = kzalloc(req.rpd_len, GFP_KERNEL);
	if (!reportdata) {
		ret = -ENOMEM;
		goto report_failed;
	}

	tdreport = kzalloc(req.tdr_len, GFP_KERNEL);
	if (!tdreport) {
		ret = -ENOMEM;
		goto report_failed;
	}


	/* Copy REPORTDATA from user to kernel buffer */
	if (copy_from_user(reportdata, (void *)req.reportdata, req.rpd_len)) {
		ret = -EFAULT;
		goto report_failed;
	}

	/*
	 * Generate TDREPORT using "TDG.MR.REPORT" TDCALL.
	 *
	 * Get the TDREPORT using REPORTDATA as input. Refer to
	 * section 22.3.3 TDG.MR.REPORT leaf in the TDX Module 1.0
	 * Specification for detailed information.
	 */
	ret = __tdx_module_call(TDX_GET_REPORT, virt_to_phys(tdreport),
				virt_to_phys(reportdata), req.subtype,
				0, NULL);
	if (ret) {
		ret = -EIO;
		goto report_failed;
	}

	/* Copy TDREPORT data back to the user buffer */
	if (copy_to_user((void *)req.tdreport, tdreport, req.tdr_len))
		ret = -EFAULT;

report_failed:
	kfree(reportdata);
	kfree(tdreport);
	return ret;
}
