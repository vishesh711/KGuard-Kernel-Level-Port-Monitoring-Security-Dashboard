// SPDX-License-Identifier: GPL-2.0
/*
 * KGuard Kernel Module - Generic Netlink control interface
 *
 * Family "kguard" (see include/uapi/linux/kguard.h):
 *   KGUARD_CMD_GET_STATS    any user: counters
 *   KGUARD_CMD_GET_CONFIG   any user: runtime configuration
 *   KGUARD_CMD_SET_CONFIG   CAP_NET_ADMIN: change configuration
 * Every configuration change is multicast to the "events" group as
 * KGUARD_CMD_CONFIG_CHANGED with the full new configuration.
 */

#include "kguard.h"

#include <linux/mutex.h>
#include <net/genetlink.h>

static DEFINE_MUTEX(kguard_cfg_lock);

static const struct nla_policy kguard_genl_policy[KGUARD_ATTR_MAX + 1] = {
	[KGUARD_ATTR_CFG_CAPTURE_IN]	= NLA_POLICY_MAX(NLA_U8, 1),
	[KGUARD_ATTR_CFG_CAPTURE_OUT]	= NLA_POLICY_MAX(NLA_U8, 1),
	[KGUARD_ATTR_CFG_CAPTURE_FWD]	= NLA_POLICY_MAX(NLA_U8, 1),
	[KGUARD_ATTR_CFG_CAPTURE_IPV6]	= NLA_POLICY_MAX(NLA_U8, 1),
	[KGUARD_ATTR_CFG_SOCKET_LOOKUP]	= NLA_POLICY_MAX(NLA_U8, 1),
	[KGUARD_ATTR_CFG_WAKEUP_EVENTS]	= NLA_POLICY_MIN(NLA_U32, 1),
};

static const struct genl_multicast_group kguard_mcgrps[] = {
	{ .name = KGUARD_GENL_MCGRP },
};

static struct genl_family kguard_genl_family;

static int kguard_put_config(struct sk_buff *msg)
{
	if (nla_put_u8(msg, KGUARD_ATTR_CFG_CAPTURE_IN, READ_ONCE(kguard_cfg.capture_in)) ||
	    nla_put_u8(msg, KGUARD_ATTR_CFG_CAPTURE_OUT, READ_ONCE(kguard_cfg.capture_out)) ||
	    nla_put_u8(msg, KGUARD_ATTR_CFG_CAPTURE_FWD, READ_ONCE(kguard_cfg.capture_fwd)) ||
	    nla_put_u8(msg, KGUARD_ATTR_CFG_CAPTURE_IPV6, READ_ONCE(kguard_cfg.capture_ipv6)) ||
	    nla_put_u8(msg, KGUARD_ATTR_CFG_SOCKET_LOOKUP, READ_ONCE(kguard_cfg.socket_lookup)) ||
	    nla_put_u32(msg, KGUARD_ATTR_CFG_WAKEUP_EVENTS, READ_ONCE(kguard_cfg.wakeup_events)))
		return -EMSGSIZE;
	return 0;
}

static int kguard_put_stats(struct sk_buff *msg)
{
	struct kguard_stats_total t;

	kguard_stats_read(&t);
	if (nla_put_u64_64bit(msg, KGUARD_ATTR_STAT_PACKETS, t.packets, KGUARD_ATTR_PAD) ||
	    nla_put_u64_64bit(msg, KGUARD_ATTR_STAT_EVENTS, t.events, KGUARD_ATTR_PAD) ||
	    nla_put_u64_64bit(msg, KGUARD_ATTR_STAT_DROPPED, t.dropped, KGUARD_ATTR_PAD) ||
	    nla_put_u64_64bit(msg, KGUARD_ATTR_STAT_FILTERED, t.filtered, KGUARD_ATTR_PAD) ||
	    nla_put_u64_64bit(msg, KGUARD_ATTR_STAT_NS_PER_PKT, t.ns_per_packet, KGUARD_ATTR_PAD) ||
	    nla_put_u64_64bit(msg, KGUARD_ATTR_STAT_RING_FILL, t.ring_fill, KGUARD_ATTR_PAD) ||
	    nla_put_u64_64bit(msg, KGUARD_ATTR_STAT_NETNS, t.netns, KGUARD_ATTR_PAD))
		return -EMSGSIZE;
	return 0;
}

/* Build a message with one command's payload: a reply or a notification */
static struct sk_buff *kguard_build(struct genl_info *info, u8 cmd,
				    int (*fill)(struct sk_buff *msg))
{
	struct sk_buff *msg;
	void *hdr;

	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return ERR_PTR(-ENOMEM);

	if (info)
		hdr = genlmsg_put_reply(msg, info, &kguard_genl_family, 0, cmd);
	else
		hdr = genlmsg_put(msg, 0, 0, &kguard_genl_family, 0, cmd);
	if (!hdr || fill(msg)) {
		nlmsg_free(msg);
		return ERR_PTR(-EMSGSIZE);
	}
	genlmsg_end(msg, hdr);
	return msg;
}

static int kguard_reply(struct genl_info *info, u8 cmd,
			int (*fill)(struct sk_buff *msg))
{
	struct sk_buff *msg = kguard_build(info, cmd, fill);

	if (IS_ERR(msg))
		return PTR_ERR(msg);
	return genlmsg_reply(msg, info);
}

static int kguard_cmd_get_stats(struct sk_buff *skb, struct genl_info *info)
{
	return kguard_reply(info, KGUARD_CMD_GET_STATS, kguard_put_stats);
}

static int kguard_cmd_get_config(struct sk_buff *skb, struct genl_info *info)
{
	return kguard_reply(info, KGUARD_CMD_GET_CONFIG, kguard_put_config);
}

static void kguard_set_bool(struct genl_info *info, int attr, bool *field)
{
	if (info->attrs[attr])
		WRITE_ONCE(*field, nla_get_u8(info->attrs[attr]));
}

static int kguard_cmd_set_config(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *note;

	mutex_lock(&kguard_cfg_lock);
	kguard_set_bool(info, KGUARD_ATTR_CFG_CAPTURE_IN, &kguard_cfg.capture_in);
	kguard_set_bool(info, KGUARD_ATTR_CFG_CAPTURE_OUT, &kguard_cfg.capture_out);
	kguard_set_bool(info, KGUARD_ATTR_CFG_CAPTURE_FWD, &kguard_cfg.capture_fwd);
	kguard_set_bool(info, KGUARD_ATTR_CFG_CAPTURE_IPV6, &kguard_cfg.capture_ipv6);
	kguard_set_bool(info, KGUARD_ATTR_CFG_SOCKET_LOOKUP, &kguard_cfg.socket_lookup);
	if (info->attrs[KGUARD_ATTR_CFG_WAKEUP_EVENTS])
		WRITE_ONCE(kguard_cfg.wakeup_events,
			   min_t(u32, nla_get_u32(info->attrs[KGUARD_ATTR_CFG_WAKEUP_EVENTS]),
				 1U << 20));
	mutex_unlock(&kguard_cfg_lock);

	kguard_info("Configuration changed (netlink port %u)", info->snd_portid);

	/* Tell listeners; having none is not an error */
	note = kguard_build(NULL, KGUARD_CMD_CONFIG_CHANGED, kguard_put_config);
	if (!IS_ERR(note))
		genlmsg_multicast(&kguard_genl_family, note, 0, 0, GFP_KERNEL);

	return kguard_reply(info, KGUARD_CMD_GET_CONFIG, kguard_put_config);
}

static const struct genl_small_ops kguard_genl_ops[] = {
	{
		.cmd	= KGUARD_CMD_GET_STATS,
		.doit	= kguard_cmd_get_stats,
	},
	{
		.cmd	= KGUARD_CMD_GET_CONFIG,
		.doit	= kguard_cmd_get_config,
	},
	{
		.cmd	= KGUARD_CMD_SET_CONFIG,
		.doit	= kguard_cmd_set_config,
		.flags	= GENL_ADMIN_PERM,
	},
};

static struct genl_family kguard_genl_family __ro_after_init = {
	.name		= KGUARD_GENL_NAME,
	.version	= KGUARD_GENL_VERSION,
	.maxattr	= KGUARD_ATTR_MAX,
	.policy		= kguard_genl_policy,
	.netnsok	= true,
	.module		= THIS_MODULE,
	.small_ops	= kguard_genl_ops,
	.n_small_ops	= ARRAY_SIZE(kguard_genl_ops),
	.resv_start_op	= KGUARD_CMD_CONFIG_CHANGED + 1,
	.mcgrps		= kguard_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(kguard_mcgrps),
};

int kguard_genl_init(void)
{
	return genl_register_family(&kguard_genl_family);
}

void kguard_genl_cleanup(void)
{
	genl_unregister_family(&kguard_genl_family);
}
