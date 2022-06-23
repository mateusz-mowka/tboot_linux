// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021, Intel Corporation.
 * All Rights Reserved.
 *
 * Author: David E. Box <david.e.box@linux.intel.com>
 *
 * Generic netlink for Intel SDSi (On Demand) SPDM protocol
 */
#include <linux/bitfield.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <net/genetlink.h>

#include <keys/asymmetric-type.h>
#include <keys/user-type.h>

#include "sdsi.h"
#include "sdsi_genl.h"

static const struct nla_policy sdsi_genl_policy[SDSI_GENL_ATTR_MAX + 1] = {
	[SDSI_GENL_ATTR_DEVS]			= { .type = NLA_NESTED },
	[SDSI_GENL_ATTR_DEV_ID]			= { .type = NLA_U32 },
	[SDSI_GENL_ATTR_DEV_NAME]		= { .type = NLA_STRING },
	[SDSI_GENL_ATTR_CERT_SLOT_NO]		= { .type = NLA_U8 },
	[SDSI_GENL_ATTR_MEAS_SLOT_NO]		= { .type = NLA_U8 },
	[SDSI_GENL_ATTR_MEASUREMENT]		= { .type = NLA_BINARY },
};

struct param {
	struct nlattr **attrs;
	struct sk_buff *msg;
	const char *name;
};

typedef int (*cb_t)(struct param *);

static struct genl_family sdsi_gnl_family;

static int sdsi_measurements(size_t count, u8 *measurement, void *arg)
{
	struct param *p = arg;
	struct sk_buff *msg = p->msg;

	if (!measurement) {
		pr_warn("%s: There are %ld measurements\n", __func__, count);
		return 0;
	}

	if (nla_put(msg, SDSI_GENL_ATTR_MEASUREMENT, count, measurement))
		return -EMSGSIZE;

	return 0;
}

static int sdsi_meas_transcript(size_t count, u8 *meas_transcript, void *arg)
{
	struct param *p = arg;
	struct sk_buff *msg = p->msg;

	if (nla_put(msg, SDSI_GENL_ATTR_MEAS_TRANSCRIPT, count, meas_transcript))
		return -EMSGSIZE;

	return 0;
}

static int sdsi_meas_sig(size_t count, u8 *meas_sig, void *arg)
{
	struct param *p = arg;
	struct sk_buff *msg = p->msg;

	if (nla_put(msg, SDSI_GENL_ATTR_MEAS_SIG, count, meas_sig))
		return -EMSGSIZE;

	return 0;
}

static int sdsi_genl_cmd_get_measurements(struct param *p)
{
	struct sk_buff *msg = p->msg;
	struct sdsi_priv *priv;
	int ret, id, a;
	bool sign;
	u8 slot_no;

	if (!p->attrs[SDSI_GENL_ATTR_DEV_ID])
		return -EINVAL;

	id = nla_get_u32(p->attrs[SDSI_GENL_ATTR_DEV_ID]);
	slot_no = nla_get_u8(p->attrs[SDSI_GENL_ATTR_MEAS_SLOT_NO]);
	sign = !!nla_get_u8(p->attrs[SDSI_GENL_ATTR_SIGN_MEAS]);

	priv = sdsi_dev_get_by_id(id);
	if (!priv)
		return -EINVAL;

	priv->spdm_state->measurement_cb = sdsi_measurements;
	priv->spdm_state->meas_transcript_cb = sdsi_meas_transcript;
	priv->spdm_state->meas_sig_cb = sdsi_meas_sig;
	priv->spdm_state->cb_data = p;
	priv->spdm_state->meas_slot_no = slot_no;
	priv->spdm_state->measurement_sign = sign;

	if (nla_put_u32(msg, SDSI_GENL_ATTR_DEV_ID, id))
		return -EMSGSIZE;

	ret = spdm_get_measurements(priv->spdm_state);
	if (ret)
		return ret;

	a = priv->spdm_state->measurement_sign ? 1 : 0;
	if (nla_put(msg, SDSI_GENL_ATTR_SIGN_MEAS, sizeof(u8), &a))
			return -EMSGSIZE;

	return 0;
}

static int sdsi_get_leaf_cert(size_t len, u8 *cert, void *arg)
{
	struct param *p = arg;
	struct sk_buff *msg = p->msg;

	if (nla_put(msg, SDSI_GENL_ATTR_DEV_CERT, len, cert))
		return -EMSGSIZE;

	return 0;
}

static int sdsi_genl_cmd_authorize(struct param *p)
{
	struct sk_buff *msg = p->msg;
	struct sdsi_priv *priv;
	struct key *key;
	int ret, id;
	u8 slot_no;

	if (!p->attrs[SDSI_GENL_ATTR_DEV_ID])
		return -EINVAL;

	id = nla_get_u32(p->attrs[SDSI_GENL_ATTR_DEV_ID]);

	if (!p->attrs[SDSI_GENL_ATTR_CERT_SLOT_NO]) {
		pr_err("No cert slot no provided\n");
		return -EINVAL;
	}

	slot_no = nla_get_u8(p->attrs[SDSI_GENL_ATTR_CERT_SLOT_NO]);

	priv = sdsi_dev_get_by_id(id);
	if (!priv)
		return -EINVAL;

	if (!priv->spdm_state)
		return -ENOTSUPP;

	key = request_key(&key_type_asymmetric, "intel_sdsi:rootkey", NULL);
	if (IS_ERR(key)) {
		dev_err(priv->dev, "Could not request root key, %ld\n",
			PTR_ERR(key));
		return PTR_ERR(key);
	}

	priv->spdm_state->rootkey = key;
	priv->spdm_state->cert_slot_no = slot_no;
	priv->spdm_state->cb_data = p;
	priv->spdm_state->certificate_cb =
		sdsi_get_leaf_cert;

	ret = spdm_authenticate(priv->spdm_state);
	key_put(priv->spdm_state->rootkey);

	if (nla_put_u32(msg, SDSI_GENL_ATTR_DEV_ID, id))
		return -EMSGSIZE;

	return ret;
}

static int sdsi_genl_cmd_get_dev(struct sdsi_priv *priv, void *data)
{
	struct sk_buff *msg = data;

	if (nla_put_u32(msg, SDSI_GENL_ATTR_DEV_ID, priv->id) ||
	    nla_put_string(msg, SDSI_GENL_ATTR_DEV_NAME, priv->name))
		return -EMSGSIZE;

	return 0;
}

static int sdsi_genl_cmd_get_devs(struct param *p)
{
	struct sk_buff *msg = p->msg;
	struct nlattr *nest_start;
	int ret;

	nest_start = nla_nest_start(msg, SDSI_GENL_ATTR_DEVS);
	if (!nest_start)
		return -EMSGSIZE;

	ret = for_each_sdsi_device(sdsi_genl_cmd_get_dev, msg);
	if (ret)
		goto out_cancel_nest;

	nla_nest_end(msg, nest_start);

	return 0;

out_cancel_nest:
	nla_nest_cancel(msg, nest_start);

	return ret;
}

static cb_t cmd_cb[] = {
	[SDSI_GENL_CMD_GET_DEVS]		= sdsi_genl_cmd_get_devs,
	[SDSI_GENL_CMD_AUTHORIZE]		= sdsi_genl_cmd_authorize,
	[SDSI_GENL_CMD_GET_MEASUREMENTS]	= sdsi_genl_cmd_get_measurements,
};

static int sdsi_genl_cmd_dumpit(struct sk_buff *skb,
				struct netlink_callback *cb)
{
	struct param p = { .msg = skb };
	const struct genl_dumpit_info *info = genl_dumpit_info(cb);
	int cmd = info->op.cmd;
	int ret;
	void *hdr;

	hdr = genlmsg_put(skb, 0, 0, &sdsi_gnl_family, 0, cmd);
	if (!hdr)
		return -EMSGSIZE;

	ret = cmd_cb[cmd](&p);
	if (ret)
		goto out_cancel_msg;

	genlmsg_end(skb, hdr);

	return 0;

out_cancel_msg:
	genlmsg_cancel(skb, hdr);

	return ret;
}

static int sdsi_genl_cmd_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct param p = { .attrs = info->attrs };
	struct sk_buff *msg;
	void *hdr;
	int cmd = info->genlhdr->cmd;
	int ret = -EMSGSIZE;

	msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	p.msg = msg;

	hdr = genlmsg_put_reply(msg, info, &sdsi_gnl_family, 0, cmd);
	if (!hdr)
		goto out_free_msg;

	ret = cmd_cb[cmd](&p);
	if (ret)
		goto out_cancel_msg;

	genlmsg_end(msg, hdr);

	return genlmsg_reply(msg, info);

out_cancel_msg:
	genlmsg_cancel(msg, hdr);
out_free_msg:
	nlmsg_free(msg);

	return ret;
}

static const struct genl_ops sdsi_genl_ops[] = {
	{
		.cmd = SDSI_GENL_CMD_GET_DEVS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.dumpit = sdsi_genl_cmd_dumpit,
	},
	{
		.cmd = SDSI_GENL_CMD_AUTHORIZE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = sdsi_genl_cmd_doit,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = SDSI_GENL_CMD_GET_MEASUREMENTS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = sdsi_genl_cmd_doit,
		.flags = GENL_ADMIN_PERM,
	},
};

static struct genl_family sdsi_gnl_family __ro_after_init = {
	.hdrsize	= 0,
	.name		= SDSI_GENL_FAMILY_NAME,
	.version	= SDSI_GENL_VERSION,
	.maxattr	= SDSI_GENL_ATTR_MAX,
	.policy		= sdsi_genl_policy,
	.ops		= sdsi_genl_ops,
	.n_ops		= ARRAY_SIZE(sdsi_genl_ops),
};

int __init sdsi_netlink_init(void)
{
	return genl_register_family(&sdsi_gnl_family);
}

/* May be needed in caller's __init function */
int sdsi_netlink_exit(void)
{
	return genl_unregister_family(&sdsi_gnl_family);
}
