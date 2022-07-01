// SPDX-License-Identifier: GPL-2.0
/*
 * Test TDX attestation feature
 *
 * Copyright (C) 2022 Intel Corporation. All rights reserved.
 *
 * Author: Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>
 */


#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "../kselftest_harness.h"
#include "../../../../arch/x86/include/uapi/asm/tdx.h"

#define devname         "/dev/tdx-guest"
#define HEX_DUMP_SIZE	8

/*
 * struct td_info - It contains the measurements and initial configuration of
 * the TD that was locked at initialization and a set of measurement
 * registers that are run-time extendable. These values are copied from the
 * TDCS by the TDG.MR.REPORT function.
 */
struct td_info {
	/* TD attributes (like debug, spet_disable, etc) */
	__u8 attr[8];
	__u64 xfam;
	/* Measurement registers */
	__u64 mrtd[6];
	__u64 mrconfigid[6];
	__u64 mrowner[6];
	__u64 mrownerconfig[6];
	/* Runtime measurement registers */
	__u64 rtmr[24];
	__u64 reserved[14];
};

/*
 * Trusted Execution Environment (TEE) report (TDREPORT_STRUCT) type,
 * sub type and version..
 */
struct tdreport_type {
	/* 0 - SGX, 81 -TDX, rest are reserved */
	__u8 type;
	/* Default value is 0 */
	__u8 sub_type;
	/* Default value is 0 */
	__u8 version;
	__u8 reserved;
};

/*
 * struct reportmac - First field in the TEE report structure
 * (TRDREPORT_STRUCT). It is common to Intel’s TEE's e.g., SGX and TDX.
 * It is MAC-protected and contains hashes of the remainder of the report
 * structure which includes the TEE’s measurements, and where applicable,
 * the measurements of additional TCB elements not reflected in CPUSVN –
 * e.g., a SEAM’s measurements.
 */
struct reportmac {
	struct tdreport_type type;
	__u8 reserved1[12];
	/* CPU security version */
	__u8 cpu_svn[16];
	/* SHA384 hash of TEE TCB INFO */
	__u8 tee_tcb_info_hash[48];
	/* SHA384 hash of TDINFO_STRUCT */
	__u8 tee_td_info_hash[48];
	/* User defined unique data passed in TDG.MR.REPORT request */
	__u8 reportdata[64];
	__u8 reserved2[32];
	__u8 mac[32];
};

struct tee_tcb_info {
	__u8 data[239];
};

struct tdreport_data {
	struct reportmac _reportmac;
	struct tee_tcb_info _tcb_info;
	__u8 reserved[17];
	struct td_info _tdinfo;
};

#ifdef DEBUG
static void print_array_hex(const char *title, const char *prefix_str,
		const void *buf, int len)
{
	const __u8 *ptr = buf;
	int i, rowsize = HEX_DUMP_SIZE;

	if (!len || !buf)
		return;

	printf("\t\t%s", title);

	for (i = 0; i < len; i++) {
		if (!(i % rowsize))
			printf("\n%s%.8x:", prefix_str, i);
		printf(" %.2x", ptr[i]);
	}

	printf("\n");
}
#endif

TEST(verify_report)
{
	__u8 reportdata[TDX_REPORTDATA_LEN];
	struct tdreport_data *tdr_data;
	__u8 tdreport[TDX_REPORT_LEN];
	struct tdx_report_req req;
	int devfd, i;

	devfd = open(devname, O_RDWR | O_SYNC);

	ASSERT_LT(0, devfd);

	/* Generate sample report data */
	for (i = 0; i < TDX_REPORTDATA_LEN; i++)
		reportdata[i] = i;

	/* Initialize IOCTL request */
	req.subtype     = 0;
	req.reportdata  = (__u64)reportdata;
	req.rpd_len     = TDX_REPORTDATA_LEN;
	req.tdreport    = (__u64)tdreport;
	req.tdr_len     = TDX_REPORT_LEN;

	/* Get TDREPORT */
	ASSERT_EQ(0, ioctl(devfd, TDX_CMD_GET_REPORT, &req));

	tdr_data = (struct tdreport_data *)tdreport;

#ifdef DEBUG
	print_array_hex("\n\t\tTDX report data\n", "", reportdata,
			sizeof(reportdata));

	print_array_hex("\n\t\tTDX tdreport data\n", "", &tdreport,
			sizeof(tdreport));
#endif

	/* Make sure TDREPORT data includes the REPORTDATA passed */
	ASSERT_EQ(0, memcmp(&tdr_data->_reportmac.reportdata[0], reportdata,
				sizeof(reportdata)));

	ASSERT_EQ(0, close(devfd));
}

TEST_HARNESS_MAIN
