#ifndef __SDSI_H
#define __SDSI_H

#include <stdint.h>

#ifndef SDSI_GENL_NAME_LENGTH
#define SDSI_GENL_NAME_LENGTH 32
#endif

#ifndef LIBSDSI_API
#define LIBSDSI_API __attribute__((visibility("default")))
#endif

/**
 * struct sdsi_spdm_device - Instance of as SDSi SPDM device
 * @name:            Name of the device (i.e. intel_vsec.sdsi.0).
 * @id:              The last number in name.
 * @cert_slot_no:    The slot number of the certificate chain to get in sdsi_spdm_authorize().
 * @cert_chain:      Allocated pointer to the certificate chain retrieved sdssi_spdm_authorize().
 *                   Must be freed after use.
 * @cert_chain_size: Size of the certificate chain.
 * @meas_slot_index: The measurement index to retrieve during sdsi_spdm_get_measurement().
 * @sign_meas:       If true, request hash/sign of the measurement transcript accrued up to now.
 * @meas:            Allocated pointer to the measurement record retrieved after
 *                   sdsi_spdm_get_measurement(). Must be freed after use.
 * @meas_size:       Size of the measurement record.
 * @meas_sig:        Allocated pointer to the measurement signature retrieved after
 *                   sdsi_spdm_get_measurement() when sign_meas is true. Must be freed after use.
 * @meas_sig_size:   Size of the measurement signature.
 * @meas_ts:         Allocated pointer to the measurement transcript that was hashed and verified
 *                   against the measurement signature during sdsi_spdm_get_measurement() when
 *                   sign_meas was set to true. Must be freed after use.
 * @meas_ts_size:    Size of the measurement transcript.
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

LIBSDSI_API struct sdsi_spdm_handle *sdsi_spdm_init(void);
LIBSDSI_API void sdsi_spdm_exit(struct sdsi_spdm_handle *hndl);


LIBSDSI_API sdsi_error_t
sdsi_spdm_get_measurement(struct sdsi_spdm_handle *hndl, struct sdsi_spdm_device *s);
LIBSDSI_API sdsi_error_t
sdsi_spdm_authorize(struct sdsi_spdm_handle *hndl, struct sdsi_spdm_device *s);
LIBSDSI_API sdsi_error_t
sdsi_spdm_get_devices(struct sdsi_spdm_handle *hndl, struct sdsi_spdm_device **s);
#endif /* __LIBSDSI_H */
