#include <errno.h>
#include <linux/kernel.h>
#include <netlink/genl/genl.h>	// nla_policy
#include <netlink/genl/mngt.h>	// ops_resolve
#include <netlink/genl/ctrl.h>  // genl_ctrl_resolve
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sdsi_genl.h"
#include "sdsi_nl.h"
#include "sdsi.h"

static struct nla_policy sdsi_genl_policy[SDSI_GENL_ATTR_MAX + 1] = {
	[SDSI_GENL_ATTR_DEVS]			= { .type = NLA_NESTED },
	[SDSI_GENL_ATTR_DEV_ID]			= { .type = NLA_U32 },
	[SDSI_GENL_ATTR_DEV_NAME]		= { .type = NLA_STRING },
	[SDSI_GENL_ATTR_DEV_CERT]		= { .type = NLA_BINARY },

	[SDSI_GENL_ATTR_CERT_SLOT_NO]		= { .type = NLA_U8 },
	[SDSI_GENL_ATTR_MEAS_SLOT_NO]		= { .type = NLA_U8 },
	[SDSI_GENL_ATTR_SIGN_MEAS]		= { .type = NLA_U8 },
	[SDSI_GENL_ATTR_MEASUREMENT]		= { .type = NLA_BINARY },
	[SDSI_GENL_ATTR_MEAS_TRANSCRIPT]	= { .type = NLA_BINARY },
	[SDSI_GENL_ATTR_MEAS_SIG]		= { .type = NLA_BINARY },
};

static int __parse_id(struct genl_info *info, struct sdsi_device *s)
{
	int id = -1;

	if (info->attrs[SDSI_GENL_ATTR_DEV_ID])
		id = nla_get_u32(info->attrs[SDSI_GENL_ATTR_DEV_ID]);

	if (s->id != id)
		return SDSI_ERROR;

	return SDSI_SUCCESS;
}

static int parse_authorize(struct genl_info *info, struct sdsi_device *s)
{
	int ret;

	ret = __parse_id(info, s);
	if (ret)
		return ret;

	if (info->attrs[SDSI_GENL_ATTR_DEV_CERT]) {
		s->cert_size = nla_len(info->attrs[SDSI_GENL_ATTR_DEV_CERT]);

		s->dev_cert = malloc(s->cert_size);
		if (!s->dev_cert) {
			fprintf(stderr, "%s: Could not allocate memory for measurement:\n%s\n",
				__func__, strerror(errno));
			return SDSI_ERROR;
		}

		memcpy(s->dev_cert,
		       nla_data(info->attrs[SDSI_GENL_ATTR_DEV_CERT]),
		       s->cert_size);
	} else {
		s->dev_cert = NULL;
		s->cert_size = 0;
	}

	return SDSI_SUCCESS;
}

static int parse_measurements(struct genl_info *info, struct sdsi_device *s)
{
	int ret;

	ret = __parse_id(info, s);
	if (ret)
		return ret;

	if (info->attrs[SDSI_GENL_ATTR_MEASUREMENT]) {
		s->meas_size = nla_len(info->attrs[SDSI_GENL_ATTR_MEASUREMENT]);

		s->measurement = malloc(s->meas_size);
		if (!s->measurement) {
			fprintf(stderr, "%s: Could not allocate memory for measurement:\n%s\n",
				__func__, strerror(errno));
			return SDSI_ERROR;
		}

		memcpy(s->measurement,
		       nla_data(info->attrs[SDSI_GENL_ATTR_MEASUREMENT]),
		       s->meas_size);
	} else {
		fprintf(stderr, "%s: Could not get measurement\n", __func__);
		s->meas_size = 0;
		s->measurement = NULL;
		return SDSI_ERROR;
	}

	if (info->attrs[SDSI_GENL_ATTR_MEAS_SIG]) {
		s->meas_sig_size = nla_len(info->attrs[SDSI_GENL_ATTR_MEAS_SIG]);

		s->meas_sig = malloc(s->meas_sig_size);
		if (!s->meas_sig) {
			fprintf(stderr, "%s: Could not allocate memory for measurement signature:\n%s\n",
				__func__, strerror(errno));
			s->meas_sig_size = 0;
			s->meas_sig = NULL;
			return SDSI_ERROR;
		}

		memcpy(s->meas_sig,
		       nla_data(info->attrs[SDSI_GENL_ATTR_MEAS_SIG]),
		       s->meas_sig_size);
	} else {
		s->meas_sig_size = 0;
		s->meas_sig = NULL;
	}

	if (info->attrs[SDSI_GENL_ATTR_MEAS_TRANSCRIPT]) {
		s->meas_ts_size = nla_len(info->attrs[SDSI_GENL_ATTR_MEAS_TRANSCRIPT]);

		s->meas_ts = malloc(s->meas_ts_size);
		if (!s->meas_ts) {
			fprintf(stderr, "%s: Could not allocate memory for measurement:\n%s\n",
				__func__, strerror(errno));
			return SDSI_ERROR;
		}

		memcpy(s->meas_ts,
		       nla_data(info->attrs[SDSI_GENL_ATTR_MEAS_TRANSCRIPT]),
		       s->meas_ts_size);
	} else {
		s->meas_ts_size = 0;
		s->meas_ts = NULL;
	}

	return SDSI_SUCCESS;
}

static int handle_spdm(struct nl_cache_ops *unused, struct genl_cmd *cmd,
		       struct genl_info *info, void *arg)
{
	struct sdsi_device *s = arg;
	int ret; int id = -1;

	if (info->attrs[SDSI_GENL_ATTR_DEV_ID])
		id = nla_get_u32(info->attrs[SDSI_GENL_ATTR_DEV_ID]);

	if (s->id != id)
		return SDSI_ERROR;

	switch (cmd->c_id) {
	case SDSI_GENL_CMD_AUTHORIZE:
		ret = parse_authorize(info, s);
		break;

	case SDSI_GENL_CMD_GET_MEASUREMENTS:
		ret = parse_measurements(info, arg);
		break;

	default:
		return SDSI_ERROR;
	}

	return ret;
}

static int handle_get_devs(struct nl_cache_ops *unused, struct genl_cmd *cmd,
			   struct genl_info *info, void *arg)
{
	struct nlattr *attr;
	struct sdsi_device **s = arg;;
	struct sdsi_device *__s = NULL;
	size_t size = 0;
	int rem;

	nla_for_each_nested(attr, info->attrs[SDSI_GENL_ATTR_DEVS], rem) {
		if (nla_type(attr) == SDSI_GENL_ATTR_DEV_ID) {

			size++;

			__s = realloc(__s, sizeof(*__s) * (size + 2));
			if (!__s)
				return SDSI_ERROR;

			__s[size - 1].id = nla_get_u32(attr);
		}


		if (nla_type(attr) == SDSI_GENL_ATTR_DEV_NAME)
			nla_strlcpy(__s[size - 1].name, attr,
				    SDSI_GENL_NAME_LENGTH);
	}

	if (__s)
		__s[size].id = -1;

	*s = __s;

	return SDSI_SUCCESS;
}

static struct genl_cmd sdsi_cmds[] = {
	{
		.c_id		= SDSI_GENL_CMD_GET_DEVS,
		.c_name		= (char *)"List devices",
		.c_msg_parser	= handle_get_devs,
		.c_maxattr	= SDSI_GENL_ATTR_MAX,
		.c_attr_policy	= sdsi_genl_policy,
	},
	{
		.c_id		= SDSI_GENL_CMD_AUTHORIZE,
		.c_name		= (char *)"Verify the device certificate",
		.c_msg_parser	= handle_spdm,
		.c_maxattr	= SDSI_GENL_ATTR_MAX,
		.c_attr_policy	= sdsi_genl_policy,
	},
	{
		.c_id		= SDSI_GENL_CMD_GET_MEASUREMENTS,
		.c_name		= (char *)"Get device measurements",
		.c_msg_parser	= handle_spdm,
		.c_maxattr	= SDSI_GENL_ATTR_MAX,
		.c_attr_policy	= sdsi_genl_policy,
	},
};

static struct genl_ops sdsi_cmd_ops = {
	.o_name		= (char *)"intel-sdsi",
	.o_cmds		= sdsi_cmds,
	.o_ncmds	= ARRAY_SIZE(sdsi_cmds),
};

static int sdsi_genl_simple(struct sdsi_handler *hndlr, int id, int cmd,
			    int flags, void *arg)
{
	struct sdsi_device *dev = arg;
	struct nl_msg *msg;
	void *hdr;

	msg = nlmsg_alloc();
	if (!msg)
		return SDSI_ERROR;

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, sdsi_cmd_ops.o_id,
			  0, flags, cmd, SDSI_GENL_VERSION);
	if (!hdr)
		return SDSI_ERROR;

	if (id >= 0 && nla_put_u32(msg, SDSI_GENL_ATTR_DEV_ID, id))
		return SDSI_ERROR;

	if (cmd == SDSI_GENL_CMD_AUTHORIZE) {
		if (nla_put_u8(msg, SDSI_GENL_ATTR_CERT_SLOT_NO, dev->cert_slot_no))
			return SDSI_ERROR;
	} else if (cmd == SDSI_GENL_CMD_GET_MEASUREMENTS) {
		if (nla_put_u8(msg, SDSI_GENL_ATTR_MEAS_SLOT_NO, dev->meas_slot_no))
			return SDSI_ERROR;
		if (nla_put_u8(msg, SDSI_GENL_ATTR_SIGN_MEAS, dev->sign))
			return SDSI_ERROR;
	}

	if (nl_send_msg(hndlr->sk, hndlr->cb, msg, genl_handle_msg, arg))
		return SDSI_ERROR;

	nlmsg_free(msg);

	return SDSI_SUCCESS;
}

int sdsi_cmd_get_measurements(struct sdsi_handler *hndlr, struct sdsi_device *dev)
{
	return sdsi_genl_simple(hndlr, dev->id, SDSI_GENL_CMD_GET_MEASUREMENTS, 0, dev);
}

int sdsi_cmd_authorize(struct sdsi_handler *hndlr, struct sdsi_device *dev)
{
	return sdsi_genl_simple(hndlr, dev->id, SDSI_GENL_CMD_AUTHORIZE, 0, dev);
}

int sdsi_cmd_get_devices(struct sdsi_handler *hndlr, struct sdsi_device **dev)
{
	return sdsi_genl_simple(hndlr, -1, SDSI_GENL_CMD_GET_DEVS,
				NLM_F_DUMP | NLM_F_ACK, dev);
}

static int sdsi_cmd_exit(struct sdsi_handler *hndlr)
{
	if (genl_unregister_family(&sdsi_cmd_ops))
		return SDSI_ERROR;

	nl_sdsi_disconnect(hndlr->sk, hndlr->cb);

	return SDSI_SUCCESS;
}

static int sdsi_cmd_init(struct sdsi_handler *hndlr)
{
	int ret;
	int family;

	if (nl_sdsi_connect(&hndlr->sk, &hndlr->cb))
		return SDSI_ERROR;

	ret = genl_register_family(&sdsi_cmd_ops);
	if (ret)
		return SDSI_ERROR;

	ret = genl_ops_resolve(hndlr->sk, &sdsi_cmd_ops);
	if (ret)
		return SDSI_ERROR;

	family = genl_ctrl_resolve(hndlr->sk, "nlctrl");
	if (family != GENL_ID_CTRL)
		return SDSI_ERROR;

	return SDSI_SUCCESS;
}

void sdsi_exit(struct sdsi_handler *hndlr)
{
	sdsi_cmd_exit(hndlr);

	free(hndlr);
}

struct sdsi_handler *sdsi_init(void)
{
	struct sdsi_handler *hndlr;

	hndlr = malloc(sizeof(*hndlr));
	if (!hndlr)
		return NULL;

	if (sdsi_cmd_init(hndlr))
		goto out_free;

	return hndlr;

out_free:
	free(hndlr);

	return NULL;
}
