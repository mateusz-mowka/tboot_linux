// SPDX-License-Identifier: GPL-2.0
/*
 * sdsi: Intel Software Defined Silicon tool for provisioning certificates
 * and activation payloads on supported cpus.
 *
 * See https://github.com/intel/intel-sdsi/blob/master/os-interface.rst
 * for register descriptions.
 *
 * Copyright (C) 2022 Intel Corporation. All rights reserved.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <gcrypt.h>
#include <keyutils.h>	// libkeyutils-dev
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sdsi_spdm.h"

#pragma pack(1)

#define SDSI_DEV		"intel_vsec.sdsi"
#define AUX_DEV_PATH		"/sys/bus/auxiliary/devices/"
#define SDSI_PATH		(AUX_DEV_DIR SDSI_DEV)
#define GUID_V1			0x6dd191
#define GUID_V2			0xF210D9EF
#define REGISTERS_MIN_SIZE	72

#define __round_mask(x, y) ((__typeof__(x))((y) - 1))
#define round_up(x, y) ((((x) - 1) | __round_mask(x, y)) + 1)

struct nvram_content_auth_err_sts {
	uint64_t reserved:3;
	uint64_t sdsi_content_auth_err:1;
	uint64_t reserved1:1;
	uint64_t sdsi_telemetry_auth_err:1;
	uint64_t reserved2:58;
};

struct enabled_features {
	uint64_t reserved:3;
	uint64_t sdsi:1;
	uint64_t reserved1:8;
	uint64_t attestation:1;
	uint64_t reserved2:13;
	uint64_t metering:1;
	uint64_t reserved3:37;
};

struct key_provision_status {
	uint64_t reserved:1;
	uint64_t license_key_provisioned:1;
	uint64_t reserved2:62;
};

struct auth_fail_count {
	uint64_t key_failure_count:3;
	uint64_t key_failure_threshold:3;
	uint64_t auth_failure_count:3;
	uint64_t auth_failure_threshold:3;
	uint64_t reserved:52;
};

struct availability {
	uint64_t reserved:48;
	uint64_t available:3;
	uint64_t threshold:3;
	uint64_t reserved2:10;
};

struct nvram_update_limit {
	uint64_t reserved:12;
	uint64_t sdsi_50_pct:1;
	uint64_t sdsi_75_pct:1;
	uint64_t sdsi_90_pct:1;
	uint64_t reserved2:49;
};

struct sdsi_regs {
	uint64_t ppin;
	struct nvram_content_auth_err_sts auth_err_sts;
	struct enabled_features en_features;
	struct key_provision_status key_prov_sts;
	struct auth_fail_count auth_fail_count;
	struct availability prov_avail;
	struct nvram_update_limit limits;
	uint64_t pcu_cr3_capid_cfg;
	union {
		struct {
			uint64_t socket_id;
		} v1;
		struct {
			uint64_t reserved;
			uint64_t socket_id;
			uint64_t reserved2;
		} v2;
	} extra;
};
#define CONTENT_TYPE_LK_ENC		0xD
#define CONTENT_TYPE_LK_BLOB_ENC	0xE

struct state_certificate {
	uint32_t content_type;
	uint32_t region_rev_id;
	uint32_t header_size;
	uint32_t total_size;
	uint32_t key_size;
	uint32_t num_licenses;
};

// License Group Types
#define LBT_ONE_TIME_UPGRADE	1
#define LBT_METERED_UPGRADE	2
#define LBT_TIMED_UPGRADE	3

struct license_region {
	uint32_t type;
	uint64_t id;
	uint64_t ppin;
	uint64_t previous_ppin;
	uint32_t rev_id;
	uint32_t num_bundles;
};

struct bundle_encoding {
	uint32_t encoding;
	uint32_t encoding_rsvd[7];
};

struct meter_certificate {
	uint32_t block_signature;
	uint32_t counter_unit;
	uint64_t ppin;
	uint32_t bundle_length;
	uint32_t reserved;
	uint32_t mmrc_encoding;
	uint32_t mmrc_counter;
};

struct bundle_encoding_counter {
	uint32_t encoding;
	uint32_t counter;
};

struct sdsi_dev {
	struct sdsi_regs regs;
	struct state_certificate sc;
	char *dev_name;
	char *dev_path;
	uint32_t guid;
};

enum command {
	CMD_SOCKET_INFO,
	CMD_METER_CERT,
	CMD_STATE_CERT,
	CMD_PROV_AKC,
	CMD_PROV_CAP,
	CMD_VERIFY,
	CMD_ADD_KEY,
	CMD_MEASUREMENT,
};

enum cert_slot {
	CERT_SLOT_STATE,
	CERT_SLOT_METER,
};

enum meas_slot {
	MEAS_SLOT_COUNT,
	MEAS_SLOT_STATE,
	MEAS_SLOT_METER,
	MEAS_SLOT_ALL = 0xFF,
};

static void sdsi_list_devices(void)
{
	struct dirent *entry;
	DIR *aux_dir;
	bool found = false;

	aux_dir = opendir(AUX_DEV_PATH);
	if (!aux_dir) {
		fprintf(stderr, "Cannot open directory %s\n", AUX_DEV_PATH);
		return;
	}

	while ((entry = readdir(aux_dir))) {
		if (!strncmp(SDSI_DEV, entry->d_name, strlen(SDSI_DEV))) {
			found = true;
			printf("%s\n", entry->d_name);
		}
	}

	if (!found)
		fprintf(stderr, "No sdsi devices found.\n");
}

static int sdsi_update_registers(struct sdsi_dev *s)
{
	FILE *regs_ptr;
	int ret;

	memset(&s->regs, 0, sizeof(s->regs));

	/* Open the registers file */
	ret = chdir(s->dev_path);
	if (ret == -1) {
		perror("chdir");
		return ret;
	}

	regs_ptr = fopen("registers", "r");
	if (!regs_ptr) {
		perror("Could not open 'registers' file");
		return -1;
	}

	if (s->guid != GUID_V1 && s->guid != GUID_V2) {
		fprintf(stderr, "Unrecognized guid, 0x%x\n", s->guid);
		fclose(regs_ptr);
		return -1;
	}

	/* Update register info for this guid */
	ret = fread(&s->regs, sizeof(uint8_t), sizeof(s->regs), regs_ptr);
	if (ret > (int)sizeof(s->regs)) { /* FIXME: Check size by guid */
		fprintf(stderr, "Could not read 'registers' file\n");
		fclose(regs_ptr);
		return -1;
	}

	fclose(regs_ptr);

	return 0;
}

static int sdsi_read_reg(struct sdsi_dev *s)
{
	int ret;

	ret = sdsi_update_registers(s);
	if (ret)
		return ret;

	printf("\n");
	printf("Socket information for device %s\n", s->dev_name);
	printf("\n");
	printf("PPIN:                           0x%lx\n", s->regs.ppin);
	printf("NVRAM Content Authorization Error Status\n");
	printf("    SDSi Auth Err Sts:          %s\n", !!s->regs.auth_err_sts.sdsi_content_auth_err ? "Error" : "Okay");

	if (!!s->regs.en_features.metering)
		printf("    Telemetry Auth Err Sts:     %s\n", !!s->regs.auth_err_sts.sdsi_telemetry_auth_err ? "Error" : "Okay");

	printf("Enabled Features\n");
	printf("    Attestation:                %s\n", !!s->regs.en_features.attestation ? "Enabled" : "Disabled");
	printf("    SDSi:                       %s\n", !!s->regs.en_features.sdsi ? "Enabled" : "Disabled");
	printf("    Telemetry:                  %s\n", !!s->regs.en_features.metering ? "Enabled" : "Disabled");
	printf("License Key (AKC) Provisioned:  %s\n", !!s->regs.key_prov_sts.license_key_provisioned ? "Yes" : "No");
	printf("Authorization Failure Count\n");
	printf("    AKC Failure Count:          %d\n", s->regs.auth_fail_count.key_failure_count);
	printf("    AKC Failure Threshold:      %d\n", s->regs.auth_fail_count.key_failure_threshold);
	printf("    CAP Failure Count:          %d\n", s->regs.auth_fail_count.auth_failure_count);
	printf("    CAP Failure Threshold:      %d\n", s->regs.auth_fail_count.auth_failure_threshold);
	printf("Provisioning Availability\n");
	printf("    Updates Available:          %d\n", s->regs.prov_avail.available);
	printf("    Updates Threshold:          %d\n", s->regs.prov_avail.threshold);
	printf("NVRAM Udate Limit\n");
	printf("    50%% Limit Reached:          %s\n", !!s->regs.limits.sdsi_50_pct ? "Yes" : "No");
	printf("    75%% Limit Reached:          %s\n", !!s->regs.limits.sdsi_75_pct ? "Yes" : "No");
	printf("    90%% Limit Reached:          %s\n", !!s->regs.limits.sdsi_90_pct ? "Yes" : "No");
	if (s->guid == GUID_V1)
		printf("Socket ID:                      %ld\n", s->regs.extra.v1.socket_id & 0xF);
	else
		printf("Socket ID:                      %ld\n", s->regs.extra.v2.socket_id & 0xF);

	return 0;
}

static char *license_blob_type(uint32_t type)
{
	switch (type) {
	case LBT_ONE_TIME_UPGRADE:
		return "One Time Upgrade";
	case LBT_METERED_UPGRADE:
		return "Metered Upgrade";
	case LBT_TIMED_UPGRADE:
		return "Time Upgrade";
	default:
		return "Unknown Upgrade Type";
	}
}

static void get_feature(uint32_t encoding, char *feature)
{
	char *name = (char *)&encoding;

	feature[3] = name[0];
	feature[2] = name[1];
	feature[1] = name[2];
	feature[0] = name[3];
}

static int sdsi_meter_cert_show(struct sdsi_dev *s)
{
	struct meter_certificate *mc;
	uint64_t data[512] = {0};
	FILE *cert_ptr;
	uint32_t count = 0;
	int ret, size;

	ret = sdsi_update_registers(s);
	if (ret)
		return ret;

	if (!s->regs.en_features.sdsi) {
		fprintf(stderr, "SDSi feature is present but not enabled.\n");
		fprintf(stderr, " Unable to read meter certificate\n");
		return -1;
	}

	if (!s->regs.en_features.metering) {
		fprintf(stderr, "Metering not supporting on this socket.\n");
		return -1;
	}

	ret = chdir(s->dev_path);
	if (ret == -1) {
		perror("chdir");
		return ret;
	}

	cert_ptr = fopen("meter_certificate", "r");
	if (!cert_ptr) {
		perror("Could not open 'meter_certificate' file");
		return -1;
	}

	size = fread(data, 1, sizeof(data), cert_ptr);
	if (!size) {
		fprintf(stderr, "Could not read 'meter_certificate' file\n");
		fclose(cert_ptr);
		return -1;
	}
	fclose(cert_ptr);

	mc = (struct meter_certificate *)data;

	printf("\n");
	printf("Meter certificate for device %s\n", s->dev_name);
	printf("\n");
	printf("Block Signature:       0x%x\n", mc->block_signature);
	printf("Count Unit:            %dms\n", mc->counter_unit);
	printf("PPIN:                  0x%lx\n", mc->ppin);
	printf("Feature Bundle Length: %d\n", mc->bundle_length);
	printf("MMRC encoding:         %d\n", mc->mmrc_encoding);
	printf("MMRC counter:          %d\n", mc->mmrc_counter);
	if (mc->bundle_length % 8) {
		fprintf(stderr, "Invalid bundle length\n");
		return -1;
	}

	printf("Feature Counters:          %d\n", mc->mmrc_counter);
	while (count++ < mc->mmrc_counter / 8) {
		struct bundle_encoding_counter *bec = (void *)(mc) + sizeof(mc);
		char feature[5];

		feature[4] = '\0';
		get_feature(bec[count].encoding, feature);
		printf("    %s:          %d\n", feature, bec->counter);
	}

	return 0;
}

static int sdsi_state_cert_show(struct sdsi_dev *s)
{
	struct state_certificate *sc;
	uint64_t data[512] = {0};
	FILE *cert_ptr;
	uint32_t count = 0;
	int ret, size;
	uint32_t offset = 0;

	ret = sdsi_update_registers(s);
	if (ret)
		return ret;

	if (!s->regs.en_features.sdsi) {
		fprintf(stderr, "SDSi feature is present but not enabled.");
		fprintf(stderr, " Unable to read state certificate");
		return -1;
	}

	ret = chdir(s->dev_path);
	if (ret == -1) {
		perror("chdir");
		return ret;
	}

	cert_ptr = fopen("state_certificate", "r");
	if (!cert_ptr) {
		perror("Could not open 'state_certificate' file");
		return -1;
	}

	size = fread(data, 1, sizeof(data), cert_ptr);
	if (!size) {
		fprintf(stderr, "Could not read 'state_certificate' file\n");
		fclose(cert_ptr);
		return -1;
	}
	fclose(cert_ptr);

	sc = (struct state_certificate *)data;

	printf("\n");
	printf("State certificate for device %s\n", s->dev_name);
	printf("\n");
	printf("Content Type:          %s\n", sc->content_type == CONTENT_TYPE_LK_ENC ? "Licencse Key Encoding" :
					      (sc->content_type == CONTENT_TYPE_LK_BLOB_ENC ? "License Key + Group Encoding" : "Unknown"));
	printf("Region Revision ID:    %d\n", sc->region_rev_id);
	printf("Header Size:           %d\n", sc->header_size * 4);
	printf("Total Size:            %d\n", sc->total_size);
	printf("OEM Key Size:          %d\n", sc->key_size * 4);
	printf("Number of Licenses:    %d\n", sc->num_licenses);

	void *body = ((void *)data) + 0x14 + (sc->num_licenses * 4) + 4;
	uint64_t *ic = body + 4;
	printf("License Group Info:    \n");
	printf("    License Key Revision ID:    0x%x\n", *(uint32_t *)body);
	printf("    License Key Image Content:  0x%lx%lx%lx%lx%lx%lx\n", ic[5], ic[4], ic[3], ic[2], ic[1], ic[0]);
	while (count++ < sc->num_licenses) {
		uint32_t *body_size_p = (uint32_t *)(((void *)data) + 0x14 + count * 4);
		uint32_t body_size = *body_size_p;
		struct license_region *lr = (void *)(ic) + 48 + offset;
		struct bundle_encoding *be = (void *)(lr) + sizeof(struct license_region);
		char feature[5];
		uint32_t enc;

		printf("    Group %d:    \n", count - 1);
		printf("        License Group size:         %u\n", (body_size & 0x7fffffff) * 4);
		printf("        License is valid:           %s\n", !!(body_size & 0x80000000) ? "Yes" : "No");
		printf("        License Group Type:         %s\n", license_blob_type(lr->type));
		printf("        License Group ID:           0x%lx\n", lr->id);
		printf("        PPIN:                       0x%lx\n", lr->ppin);
		printf("        Previous PPIN:              0x%lx\n", lr->previous_ppin);
		printf("        Group Revision ID:          %u\n", lr->rev_id);
		printf("        Number of Features:         %u\n", lr->num_bundles);
		feature[4] = '\0';
		if (lr->num_bundles > 6) { /* FIXME: Determine max number */
			fprintf(stderr, "        ERROR: More than 6 features reported. Skipping.\n");
			offset += (body_size & 0x7fffffff) * 4;
			continue;
		}

		for (enc = 0; enc < lr->num_bundles; enc++) {
			get_feature(be[enc].encoding, feature);
			printf("                 Feature %d:         %s\n", enc, feature);
		}
		offset += (body_size & 0x7fffffff) * 4;
	};

	return 0;
}

static int sdsi_verify(struct sdsi_dev *s, int slot_no)
{
	struct sdsi_spdm_handle *hndl;
	struct sdsi_spdm_device *spdm_dev, *spdm_dev_list;
	bool device_found = false;
	int ret;

	/* Initialize netlink connection */
	hndl = sdsi_spdm_init();
	if (!hndl)
		return -1;

	/* Get list of devices */
	ret = sdsi_spdm_get_devices(hndl, &spdm_dev_list);
	if (ret)
		goto finish;

	if (!spdm_dev_list)
		return -1;

	spdm_dev = spdm_dev_list;
	while (spdm_dev->id != -1) {
		if (strncmp(spdm_dev->name, s->dev_name, strlen(s->dev_name)) == 0) {
			device_found = true;
			break;
		}
		spdm_dev++;
	}

	if (!device_found) {
		fprintf(stderr, "Could not find device %s to verify\n",
			s->dev_name);
		ret = -1;
		goto free_spdm_dev_list;
	}

	spdm_dev->cert_slot_no = slot_no;
	ret = sdsi_spdm_authorize(hndl, spdm_dev);
	if (ret) {
		fprintf(stderr, "Authorization failed\n");
		goto free_spdm_dev_list;
	} else {
		puts("Device authorization successful");

		if (spdm_dev->cert_chain) {
			uint32_t *buf = (uint32_t *)spdm_dev->cert_chain;
			size_t i;

			puts("Device Certficate:");
			for (i = 0; i < spdm_dev->cert_chain_size / 4; i++)
				printf("\t%08x\n", buf[i]);
			if (spdm_dev->cert_chain_size % 4)
				printf("\t%08x\n", buf[i]);
		}
	}

free_spdm_dev_list:
	free(spdm_dev_list);
finish:
	sdsi_spdm_exit(hndl);

	return ret;
}

static int sdsi_get_measurements(struct sdsi_dev *s, int slot_no, bool sign)
{
	struct sdsi_spdm_handle *hndl;
	struct sdsi_spdm_device *spdm_dev, *spdm_dev_list;
	bool device_found = false;
	int ret, i;

	hndl = sdsi_spdm_init();
	if (!hndl)
		return -1;

	ret = sdsi_spdm_get_devices(hndl, &spdm_dev_list);
	if (ret)
		goto finish;

	if (!spdm_dev_list)
		return -1;


	/* Find matching device */
	spdm_dev = spdm_dev_list;
	while (spdm_dev->id != -1) {
		if (strncmp(spdm_dev->name, s->dev_name, strlen(s->dev_name)) == 0) {
			device_found = true;
			break;
		}
		spdm_dev++;
	}

	if (!device_found) {
		fprintf(stderr, "Could not find device %s to get measurement\n",
			spdm_dev->name);
		ret = -1;
		goto free_spdm_dev_list;
	}

	/* Select measurement index and sign request */
	spdm_dev->meas_slot_index = slot_no;
	spdm_dev->sign_meas = sign;

	/* Call into driver to get measurement */
	ret = sdsi_spdm_get_measurement(hndl, spdm_dev);
	if (ret) {
		fprintf(stderr, "Get measurements failed\n");
		goto free_spdm_dev_list;
	}

	/* Display Measurement Data */
	printf("%sMeasurement for %s configuration, size %ld:\n",
	       spdm_dev->sign_meas ? "Signed " : "",
	       slot_no == 0 ? "State" : "Meter", spdm_dev->meas_size);
	printf("\t");
	for (i = spdm_dev->meas_size - 1; i >= 0; i--)
		printf("%02x", spdm_dev->meas[i]);
	puts("");

	/* Done with measurement data */
	free(spdm_dev->meas);

	/* Print the measurement signature that was signed by the device */
	if (spdm_dev->meas_sig) {
		printf("Signature, size %ld:\n\t", spdm_dev->meas_sig_size);
		for (i = spdm_dev->meas_sig_size - 1; i >= 0; i--)
			printf("%02x", spdm_dev->meas_sig[i]);

		/* Done with signature */
		free(spdm_dev->meas_sig);
	}

	/* Print the transcript that was recorded by the kernel */
	if (spdm_dev->meas_ts) {
		uint32_t *buf = (uint32_t *)spdm_dev->meas_ts;
		size_t i;

		printf("\nTranscript, size %ld:\n", spdm_dev->meas_ts_size);
		for (i = 0; i < spdm_dev->meas_ts_size / 4; i++)
			printf("\t%08x\n", buf[i]);
		if (spdm_dev->meas_ts_size % 4 == 3)
			printf("\t%06x\n", buf[i] & 0xFFFFFF);
		else if (spdm_dev->meas_ts_size % 4 == 2)
			printf("\t%04x\n", buf[i] & 0xFFFF);
		else if (spdm_dev->meas_ts_size % 4 == 1)
			printf("\t%02x\n", buf[i] & 0xFF);

		/* Done with transcript */
		free(spdm_dev->meas_ts);
	}

free_spdm_dev_list:
	free(spdm_dev_list);
finish:
	sdsi_spdm_exit(hndl);

	return ret;
}

static int sdsi_add_key(const char *keyfile)
{
	key_serial_t kst;
	struct stat st;
	int ret, fd;
	off_t size;
	char buf[4096];

	fd = open(keyfile, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Error: Could not open keyfile %s: %s\n", keyfile, strerror(errno));
		return errno;
	}

	ret = stat(keyfile, &st);
	if (ret == -1) {
		fprintf(stderr, "Error: Could not get size of keyfile %s: %s\n", keyfile, strerror(errno));
		close(fd);
		return errno;
	}

	size = st.st_size;
	if (size == 0) {
		fprintf(stderr, "Error: The keyfile %s is empty\n", keyfile);
		close(fd);
		return -1;
	} else if (size > 4096) {
		fprintf(stderr, "Error: The keyfile size is > 4096\n");
		close(fd);
		return -1;
	}

	size = read(fd, buf, size);
	if (size == -1) {
		fprintf(stderr, "Error: Could not read keyfile %s: %s\n", keyfile, strerror(errno));
		close(fd);
		return errno;
	}

	kst = add_key("asymmetric", SDSI_ROOT_CERT_NAME, buf, size,
		      KEY_SPEC_USER_KEYRING);
	if (kst == -1) {
		fprintf(stderr, "Error: Could not add key: %s\n",
			strerror(errno));
		return errno;
	}

	printf("Key %s add SUCCESS. Entry in /proc/keys\n", keyfile);

	return 0;
}

static int sdsi_provision(struct sdsi_dev *s, char *bin_file, enum command command)
{
	int bin_fd, prov_fd, size, ret;
	char buf[4096] = { 0 };
	char cap[] = "provision_cap";
	char akc[] = "provision_akc";
	char *prov_file;

	if (!bin_file) {
		fprintf(stderr, "No binary file provided\n");
		return -1;
	}

	/* Open the binary */
	bin_fd = open(bin_file, O_RDONLY);
	if (bin_fd == -1) {
		fprintf(stderr, "Could not open file %s: %s\n", bin_file, strerror(errno));
		return bin_fd;
	}

	prov_file = (command == CMD_PROV_AKC) ? akc : cap;

	ret = chdir(s->dev_path);
	if (ret == -1) {
		perror("chdir");
		close(bin_fd);
		return ret;
	}

	/* Open the provision file */
	prov_fd = open(prov_file, O_WRONLY);
	if (prov_fd == -1) {
		fprintf(stderr, "Could not open file %s: %s\n", prov_file, strerror(errno));
		close(bin_fd);
		return prov_fd;
	}

	/* Read the binary file into the buffer */
	size = read(bin_fd, buf, 4096);
	if (size == -1) {
		close(bin_fd);
		close(prov_fd);
		return -1;
	}

	ret = write(prov_fd, buf, size);
	if (ret == -1) {
		close(bin_fd);
		close(prov_fd);
		perror("Provisioning failed");
		return ret;
	}

	printf("Provisioned %s file %s successfully\n", prov_file, bin_file);

	close(bin_fd);
	close(prov_fd);

	return 0;
}

static int sdsi_provision_akc(struct sdsi_dev *s, char *bin_file)
{
	int ret;

	ret = sdsi_update_registers(s);
	if (ret)
		return ret;

	if (!s->regs.en_features.sdsi) {
		fprintf(stderr, "SDSi feature is present but not enabled. Unable to provision");
		return -1;
	}

	if (!s->regs.prov_avail.available) {
		fprintf(stderr, "Maximum number of updates (%d) has been reached.\n",
			s->regs.prov_avail.threshold);
		return -1;
	}

	if (s->regs.auth_fail_count.key_failure_count ==
	    s->regs.auth_fail_count.key_failure_threshold) {
		fprintf(stderr, "Maximum number of AKC provision failures (%d) has been reached.\n",
			s->regs.auth_fail_count.key_failure_threshold);
		fprintf(stderr, "Power cycle the system to reset the counter\n");
		return -1;
	}

	return sdsi_provision(s, bin_file, CMD_PROV_AKC);
}

static int sdsi_provision_cap(struct sdsi_dev *s, char *bin_file)
{
	int ret;

	ret = sdsi_update_registers(s);
	if (ret)
		return ret;

	if (!s->regs.en_features.sdsi) {
		fprintf(stderr, "SDSi feature is present but not enabled. Unable to provision");
		return -1;
	}

	if (!s->regs.prov_avail.available) {
		fprintf(stderr, "Maximum number of updates (%d) has been reached.\n",
			s->regs.prov_avail.threshold);
		return -1;
	}

	if (s->regs.auth_fail_count.auth_failure_count ==
	    s->regs.auth_fail_count.auth_failure_threshold) {
		fprintf(stderr, "Maximum number of CAP provision failures (%d) has been reached.\n",
			s->regs.auth_fail_count.auth_failure_threshold);
		fprintf(stderr, "Power cycle the system to reset the counter\n");
		return -1;
	}

	return sdsi_provision(s, bin_file, CMD_PROV_CAP);
}

static int read_sysfs_data(const char *file, int *value)
{
	char buff[16];
	FILE *fp;

	fp = fopen(file, "r");
	if (!fp) {
		perror(file);
		return -1;
	}

	if (!fgets(buff, 16, fp)) {
		fprintf(stderr, "Failed to read file '%s'", file);
		fclose(fp);
		return -1;
	}

	fclose(fp);
	*value = strtol(buff, NULL, 0);

	return 0;
}

static struct sdsi_dev *sdsi_create_dev(char *dev_no)
{
	int dev_name_len = sizeof(SDSI_DEV) + strlen(dev_no) + 1;
	struct sdsi_dev *s;
	int guid;
	DIR *dir;

	s = (struct sdsi_dev *)malloc(sizeof(*s));
	if (!s) {
		perror("malloc");
		return NULL;
	}

	s->dev_name = (char *)malloc(sizeof(SDSI_DEV) + strlen(dev_no) + 1);
	if (!s->dev_name) {
		perror("malloc");
		free(s);
		return NULL;
	}

	snprintf(s->dev_name, dev_name_len, "%s.%s", SDSI_DEV, dev_no);

	s->dev_path = (char *)malloc(sizeof(AUX_DEV_PATH) + dev_name_len);
	if (!s->dev_path) {
		perror("malloc");
		free(s->dev_name);
		free(s);
		return NULL;
	}

	snprintf(s->dev_path, sizeof(AUX_DEV_PATH) + dev_name_len, "%s%s", AUX_DEV_PATH,
		 s->dev_name);
	dir = opendir(s->dev_path);
	if (!dir) {
		fprintf(stderr, "Could not open directory '%s': %s\n", s->dev_path,
			strerror(errno));
		free(s->dev_path);
		free(s->dev_name);
		free(s);
		return NULL;
	}

	if (chdir(s->dev_path) == -1) {
		perror("chdir");
		free(s->dev_path);
		free(s->dev_name);
		free(s);
		return NULL;
	}

	if (read_sysfs_data("guid", &guid)) {
		free(s->dev_path);
		free(s->dev_name);
		free(s);
		return NULL;
	}

	s->guid = guid;

	return s;
}

static void sdsi_free_dev(struct sdsi_dev *s)
{
	free(s->dev_path);
	free(s->dev_name);
	free(s);
}

static void usage(char *prog)
{
	printf("Usage: %s [-l] [-d DEVNO [-i] [-s] [-m] [-a FILE] [-c FILE] [-v SLOTNO] [-M state|meter]]\n"
	       "          [-k KEY_FILE]\n", prog);
}

static void show_help(void)
{
	printf("Commands:\n");
	printf("  %-18s\t%s\n", "-l, --list",           "list available sdsi devices");
	printf("  %-18s\t%s\n", "-d, --devno DEVNO",    "sdsi device number");
	printf("  %-18s\t%s\n", "-i, --info",           "show socket information");
	printf("  %-18s\t%s\n", "-s, --state",          "show state certificate data");
	printf("  %-18s\t%s\n", "-m, --meter",          "show meter certificate data");
	printf("  %-18s\t%s\n", "-a, --akc FILE",       "provision socket with AKC FILE");
	printf("  %-18s\t%s\n", "-c, --cap FILE>",      "provision socket with CAP FILE");
	printf("  %-18s\t%s\n", "-v, --verify SLOTNO",  "verify certificate chain of select slot");
	printf("  %-18s\t%s\n", "-M, --measurement",    "get SDSi firmware measurements");
	printf("  %-18s\t%s\n", "    state",            "    get state measurement");
	printf("  %-18s\t%s\n", "    state+",           "    get signed state measurement");
	printf("  %-18s\t%s\n", "    meter",            "    get meter measurement");
	printf("  %-18s\t%s\n", "    meter+",           "    get signed meter measurement");
	printf("  %-18s\t%s\n", "-k, --key KEY_FILE",   "add root key");
}

int main(int argc, char *argv[])
{
	char bin_file[PATH_MAX], keyfile[PATH_MAX], *dev_no = NULL;
	bool device_selected = false, sign = false;
	char *progname;
	enum command command = -1;
	struct sdsi_dev *s;
	int option_index = 0, opt;
	int meas_slot_no = -1, cert_slot_no = -1;
	int ret = 0;
	size_t len;

	static struct option long_options[] = {
		{"akc",		required_argument,	0, 'a'},
		{"cap",		required_argument,	0, 'c'},
		{"devno",	required_argument,	0, 'd'},
		{"help",	no_argument,		0, 'h'},
		{"info",	no_argument,		0, 'i'},
		{"key",		required_argument,	0, 'k'},
		{"list",	no_argument,		0, 'l'},
		{"measurement",	required_argument,	0, 'M'},
		{"meter",	no_argument,		0, 'm'},
		{"state",	no_argument,		0, 's'},
		{"verify",	required_argument,	0, 'v'},
		{0,		0,			0, 0 }
	};


	progname = argv[0];

	while ((opt = getopt_long_only(argc, argv, "+a:c:d:hik:lmM:rsv:", long_options,
			&option_index)) != -1) {

		/*
		 * All cases must specify a command or perform and action and
		 * immediately exit the program.
		 */
		switch (opt) {
		case 'd':
			dev_no = optarg;
			device_selected = true;
			break;
		case 'l':
			sdsi_list_devices();
			return 0;
		case 'i':
			command = CMD_SOCKET_INFO;
			break;
		case 'm':
		case 's':
			command = (opt == 'm') ? CMD_METER_CERT : CMD_STATE_CERT;
			break;
		case 'a':
		case 'c':
			if (!access(optarg, F_OK) == 0) {
				fprintf(stderr, "Could not access file '%s': %s\n", optarg,
					strerror(errno));
				return -1;
			}

			if (!realpath(optarg, bin_file)) {
				perror("realpath");
				return -1;
			}

			command = (opt == 'a') ? CMD_PROV_AKC : CMD_PROV_CAP;
			break;
		case 'M':
			len = strlen(optarg);
			if (!strncmp(optarg, "meter", 5))
			       meas_slot_no = MEAS_SLOT_METER;
			else if (!strncmp(optarg, "state", 5))
			       meas_slot_no = MEAS_SLOT_STATE;
			else {
				fprintf(stderr, "Invalid option for -%c\n", opt);
				return -1;
			}

			if (len == 6 && optarg[len - 1] == '+')
				sign = true;

			command = CMD_MEASUREMENT;
			break;
		case 'v':
			cert_slot_no = strtol(optarg, NULL, 10);
			if (cert_slot_no != 0 && cert_slot_no != 1) {
				fprintf(stderr, "Avialable slots are 0 and 1\n");
				return -1;
			}

			command = CMD_VERIFY;
			break;
		case 'k':
			if (!access(optarg, F_OK) == 0) {
				fprintf(stderr, "Could not access file '%s': %s\n", optarg,
					strerror(errno));
				return -1;
			}

			if (!realpath(optarg, keyfile)) {
				perror("realpath");
				return -1;
			}

			command = CMD_ADD_KEY;
			break;
		case 'h':
			usage(progname);
			show_help();
			return 0;
		default:
			usage(progname);
			return -1;
		}
	}

	if (device_selected) {
		s = sdsi_create_dev(dev_no);
		if (!s)
			return -1;

		switch (command) {
		case CMD_SOCKET_INFO:
			ret = sdsi_read_reg(s);
			break;
		case CMD_METER_CERT:
			ret = sdsi_meter_cert_show(s);
			break;
		case CMD_STATE_CERT:
			ret = sdsi_state_cert_show(s);
			break;
		case CMD_PROV_AKC:
			ret = sdsi_provision_akc(s, bin_file);
			break;
		case CMD_PROV_CAP:
			ret = sdsi_provision_cap(s, bin_file);
			break;
		case CMD_VERIFY:
			ret = sdsi_verify(s, cert_slot_no);
			break;
		case CMD_MEASUREMENT:
			ret = sdsi_get_measurements(s, meas_slot_no, sign);
			break;
		default:
			fprintf(stderr, "No command specified\n");
			return -1;
		}

		sdsi_free_dev(s);

	} else {
		switch (command) {
		case CMD_ADD_KEY:
			ret = sdsi_add_key(keyfile);
			break;
		default:
			fprintf(stderr, "No device specified\n");
			return -1;
		}
	}

	return ret;
}
