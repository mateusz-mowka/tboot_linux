#ifndef _SPDM_NL_H
#define _SPDM_NL_H

#include <netlink/netlink.h>

struct sdsi_spdm_handle {
	int done;
	int error;
	struct nl_msg *msg;
	struct nl_sock *sk;
	struct nl_cb *cb;
};

struct sdsi_handle_param {
	struct sdsi_handler *th;
	void *arg;
};


extern int nl_send_msg(struct nl_sock *sock, struct nl_cb *cb, struct nl_msg *msg,
		       int (*rx_handler)(struct nl_msg *, void *), void *data);
extern int nl_sdsi_connect(struct nl_sock **nl_sock, struct nl_cb **nl_cb);
extern void nl_sdsi_disconnect(struct nl_sock *nl_sock, struct nl_cb *nl_cb);

#endif
