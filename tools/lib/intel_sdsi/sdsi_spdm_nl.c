#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>

#include "sdsi_spdm_nl.h"

static __thread int err;
static __thread int done;

static int nl_seq_check_handler(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}

static int nl_error_handler(struct sockaddr_nl *nla, struct nlmsgerr *nl_err,
			    void *arg)
{
	int *ret = arg;

	if (ret)
		*ret = nl_err->error;

	return NL_STOP;
}

static int nl_finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;

	if (ret)
		*ret = 1;

	return NL_OK;
}

static int nl_ack_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;

	if (ret)
		*ret = 1;

	return NL_OK;
}

int nl_send_msg(struct nl_sock *sock, struct nl_cb *cb, struct nl_msg *msg,
		int (*rx_handler)(struct nl_msg *, void *), void *data)
{
	if (!rx_handler)
		return -1;

	err = nl_send_auto_complete(sock, msg);
	if (err < 0)
		return err;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, rx_handler, data);

	err = done = 0;

	while (err == 0 && done == 0)
		nl_recvmsgs(sock, cb);

	return err;
}

int nl_sdsi_connect(struct nl_sock **nl_sock, struct nl_cb **nl_cb)
{
	struct nl_cb *cb;
	struct nl_sock *sock;

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb)
		return -1;

	sock = nl_socket_alloc();
	if (!sock)
		goto out_cb_free;

	if (genl_connect(sock))
		goto out_socket_free;

	if (nl_cb_err(cb, NL_CB_CUSTOM, nl_error_handler, &err) ||
	    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, nl_finish_handler, &done) ||
	    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, nl_ack_handler, &done) ||
	    nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, nl_seq_check_handler, &done))
		return -1;

	*nl_sock = sock;
	*nl_cb = cb;

	return 0;

out_socket_free:
	nl_socket_free(sock);
out_cb_free:
	nl_cb_put(cb);
	return -1;
}

void nl_sdsi_disconnect(struct nl_sock *nl_sock, struct nl_cb *nl_cb)
{
	nl_close(nl_sock);
	nl_socket_free(nl_sock);
	nl_cb_put(nl_cb);
}
