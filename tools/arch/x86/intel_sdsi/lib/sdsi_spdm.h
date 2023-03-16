#ifndef __SDSI_H
#define __SDSI_H

#include <stdint.h>

#ifndef SDSI_GENL_NAME_LENGTH
#define SDSI_GENL_NAME_LENGTH 32
#endif

#ifndef LIBSDSI_API
#define LIBSDSI_API __attribute__((visibility("default")))
#endif

/* Name to give the root certificate to be added to the Linux key management system */
#define SDSI_ROOT_CERT_NAME "intel_sdsi:rootkey"

/**
 * struct sdsi_spdm_device - Instance of an SDSi SPDM device
 *
 * sdsi_spdm_get_devices() fields
 * @name:            Returned name of the device (i.e. intel_vsec.sdsi.0).
 * @id:              Returned id number (last number in name).
 *
 * sdsi_spdm_authorize() fields
 * @cert_slot_no:    Set slot number of the certificate chain to get.
 * @cert_chain:      Returned allocated pointer to the certificate chain. Must be freed after use.
 * @cert_chain_size: Returned size of the certificate chain.
 *
 * sdsi_spdm_get_measurement() fields
 * @meas_slot_index: Set measurement index to get.
 * @sign_meas:       Set request for hash/sign of the accrued measurement transcript.
 * @meas:            Returned allocated pointer to the measurement record. Must be freed after use.
 * @meas_size:       Returned size of the measurement record.
 * @meas_sig:        Returned allocated pointer to the measurement signature when sign_meas is
 *                   true. Must be freed after use.
 * @meas_sig_size:   Returned size of the measurement signature.
 * @meas_ts:         Returned allocated pointer to the measurement transcript that was hashed and
 *                   verified against the measurement signature. Must be freed after use.
 * @meas_ts_size:    Returned size of the measurement transcript.
 */
struct sdsi_spdm_device {
	char	name[SDSI_GENL_NAME_LENGTH];
	int	id;
	int	cert_slot_no;
	uint8_t	*cert_chain;
	size_t	cert_chain_size;
	int	meas_slot_index;
	bool	sign_meas;
	uint8_t	*meas;
	size_t	meas_size;
	uint8_t	*meas_sig;
	size_t	meas_sig_size;
	uint8_t	*meas_ts;
	size_t	meas_ts_size;
};

typedef enum {
	SDSI_ERROR = -1,
	SDSI_SUCCESS = 0,
} sdsi_error_t;

struct sdsi_spdm_handle;

/**
 * sdsi_spdm_init - Open a generic netlink connection to the sdsi kernel driver
 *
 * Needs to be ran just once to connect to the driver. On success returns a handle
 * to be used in other calls to communicate with the driver to perform SPDM operations.
 * On failure returns NULL.
 */
LIBSDSI_API struct sdsi_spdm_handle *sdsi_spdm_init(void);

/**
 * sdsi_spdm_get_devices - Returns a list of available sdsi_spdm devices
 * @hndl:    Handle to the driver, received from sdsi_spdm_init()
 * @s:       Unallocated double pointer to be allocated and filled by call. Must be
 *           freed after use.
 *
 * On success returns SDSI_SUCCESS and s will contain an allocated array of the available
 * sdsi_spdm devices. The name field of each s device may be used to cross reference
 * against the device name in sysfs for selection. The id field will be set to -1 to
 * allow iteration. On failure returns SDSI_ERROR. If no devices are found s will be set
 * to NULL.
 */
LIBSDSI_API sdsi_error_t
sdsi_spdm_get_devices(struct sdsi_spdm_handle *hndl, struct sdsi_spdm_device **s);

/**
 * sdsi_spdm_authorize - Perform a trust/verification of the device certificate
 * @hndl:    Handle to the driver, received from sdsi_spdm_init()
 * @s:       Pointer to configured device with fields set for authorize operation
 *
 * Requires that the device root key with name SDSI_ROOT_CERT_NAME be registered with
 * the Linux kernel. Will perform the following attestation flow through the driver:
 *
 * GET_VERSION,GET_CAPABILITIES,NEGOTIATE_ALGORITHMS,GET_DIGEST,GET_CERTIFICATES,CHALLENGE
 *
 * On success will return SDSI_SUCCESS and s->cert_chain will contain the certificate chain
 * received during GET_CERTIFICATES. Returns SDSI_ERROR on failure.
 */
LIBSDSI_API sdsi_error_t
sdsi_spdm_authorize(struct sdsi_spdm_handle *hndl, struct sdsi_spdm_device *s);

/**
 * sdsi_spdm_get_measurement - Retrieve a measurement from an sdsi_spdm device
 * @hndl:    Handle to the driver, received from sdsi_spdm_init()
 * @s:       Pointer to configured device with fields set for measurement operation
 *
 * Retrieves a measurement from the selected measurement slot index set in s. On
 * success will return SDSI_SUCCESS and s->meas will contain the measurement data. If called
 * multiple times without signing, the transcript will accrue. When signing it requested,
 * a signature request will be performed. If successfully verified, the transcript and
 * signature will also be returned in the meas_sig and meas_ts fields of s. Returns
 * SDSI_ERROR on failure.
 *
 * Note: For signature request to succeed, sdsi_spdm_authorize must be last ran on
 * slot 0.
 */
LIBSDSI_API sdsi_error_t
sdsi_spdm_get_measurement(struct sdsi_spdm_handle *hndl, struct sdsi_spdm_device *s);

/**
 * sdsi_spdm_exit - Close a netlink connection to the sdsi kernel driver
 * @hndl:    Handle to the driver to close.
 */
LIBSDSI_API void sdsi_spdm_exit(struct sdsi_spdm_handle *hndl);

#endif /* __LIBSDSI_H */
