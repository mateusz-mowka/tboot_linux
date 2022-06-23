#ifndef __SDSI_H
#define __SDSI_H

#include <stdint.h>

#ifndef SDSI_GENL_NAME_LENGTH
#define SDSI_GENL_NAME_LENGTH 32
#endif

#ifndef LIBSDSI_API
#define LIBSDSI_API __attribute__((visibility("default")))
#endif

struct digests {
	uint8_t *digests;
	size_t size;
	int count;
};

struct sdsi_device {
	int id;
	char name[SDSI_GENL_NAME_LENGTH];
	int cert_slot_no;
	int meas_slot_no;
	bool sign;
	uint8_t *measurement;
	size_t meas_size;
	uint8_t *meas_sig;
	size_t meas_sig_size;
	uint8_t *meas_ts;
	size_t meas_ts_size;
	uint8_t *dev_cert;
	size_t cert_size;
};

typedef enum {
	SDSI_ERROR = -1,
	SDSI_SUCCESS = 0,
} sdsi_error_t;

struct sdsi_handler;

LIBSDSI_API struct sdsi_handler *sdsi_init(void);
LIBSDSI_API void sdsi_exit(struct sdsi_handler *th);


LIBSDSI_API sdsi_error_t
sdsi_cmd_get_measurements(struct sdsi_handler *hndlr, struct sdsi_device *s);
LIBSDSI_API sdsi_error_t
sdsi_cmd_authorize(struct sdsi_handler *hndlr, struct sdsi_device *s);
LIBSDSI_API sdsi_error_t
sdsi_cmd_get_devices(struct sdsi_handler *hndlr, struct sdsi_device **s);
#endif /* __LIBSDSI_H */
