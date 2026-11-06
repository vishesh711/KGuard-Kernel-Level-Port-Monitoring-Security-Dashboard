// SPDX-License-Identifier: GPL-2.0
/*
 * KGuard Kernel Module - Generic Netlink control interface
 *
 * Family "kguard" (see include/uapi/linux/kguard.h):
 *   GET_STATS, GET_CONFIG              any user
 *   SET_CONFIG                         CAP_NET_ADMIN
 *   BLOCK_ADD, BLOCK_DEL               CAP_NET_ADMIN
 *   BLOCK_LIST (dump), ALLOW_LIST      any user
 *   ALLOW_ADD, ALLOW_DEL               CAP_NET_ADMIN
 * Multicast group "events":
 *   CONFIG_CHANGED  full configuration after every change
 *   ALERT           guard alerts (sent from the packet path, GFP_ATOMIC)
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
	[KGUARD_ATTR_CFG_ENFORCE]	= NLA_POLICY_MAX(NLA_U8, 1),
	[KGUARD_ATTR_CFG_AUTO_BLOCK]	= NLA_POLICY_MAX(NLA_U8, 1),
	[KGUARD_ATTR_CFG_SCAN_THRESHOLD] = NLA_POLICY_MIN(NLA_U32, 2),
	[KGUARD_ATTR_CFG_SCAN_WINDOW_MS] = NLA_POLICY_MIN(NLA_U32, 100),
	[KGUARD_ATTR_CFG_SYN_RATE]	= NLA_POLICY_MIN(NLA_U32, 1),
	[KGUARD_ATTR_CFG_SYN_BURST]	= NLA_POLICY_MIN(NLA_U32, 1),
	[KGUARD_ATTR_CFG_BLOCK_TIMEOUT]	= { .type = NLA_U32 },
	[KGUARD_ATTR_ADDR]		= { .type = NLA_BINARY, .len = 16 },
	[KGUARD_ATTR_PREFIX_LEN]	= NLA_POLICY_MAX(NLA_U8, 128),
	[KGUARD_ATTR_TIMEOUT]		= { .type = NLA_U32 },
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
	    nla_put_u32(msg, KGUARD_ATTR_CFG_WAKEUP_EVENTS, READ_ONCE(kguard_cfg.wakeup_events)) ||
	    nla_put_u8(msg, KGUARD_ATTR_CFG_ENFORCE, READ_ONCE(kguard_cfg.enforce)) ||
	    nla_put_u8(msg, KGUARD_ATTR_CFG_AUTO_BLOCK, READ_ONCE(kguard_cfg.auto_block)) ||
	    nla_put_u32(msg, KGUARD_ATTR_CFG_SCAN_THRESHOLD,
			READ_ONCE(kguard_cfg.scan_threshold)) ||
	    nla_put_u32(msg, KGUARD_ATTR_CFG_SCAN_WINDOW_MS,
			READ_ONCE(kguard_cfg.scan_window_ms)) ||
	    nla_put_u32(msg, KGUARD_ATTR_CFG_SYN_RATE, READ_ONCE(kguard_cfg.syn_rate)) ||
	    nla_put_u32(msg, KGUARD_ATTR_CFG_SYN_BURST, READ_ONCE(kguard_cfg.syn_burst)) ||
	    nla_put_u32(msg, KGUARD_ATTR_CFG_BLOCK_TIMEOUT, READ_ONCE(kguard_cfg.block_timeout)))
		return -EMSGSIZE;
	return 0;
}

static int kguard_put_u64(struct sk_buff *msg, int attr, u64 value)
{
	return nla_put_u64_64bit(msg, attr, value, KGUARD_ATTR_PAD);
}

static int kguard_put_stats(struct sk_buff *msg)
{
	struct kguard_stats_total t;

	kguard_stats_read(&t);
	if (kguard_put_u64(msg, KGUARD_ATTR_STAT_PACKETS, t.packets) ||
	    kguard_put_u64(msg, KGUARD_ATTR_STAT_EVENTS, t.events) ||
	    kguard_put_u64(msg, KGUARD_ATTR_STAT_DROPPED, t.dropped) ||
	    kguard_put_u64(msg, KGUARD_ATTR_STAT_FILTERED, t.filtered) ||
	    kguard_put_u64(msg, KGUARD_ATTR_STAT_NS_PER_PKT, t.ns_per_packet) ||
	    kguard_put_u64(msg, KGUARD_ATTR_STAT_RING_FILL, t.ring_fill) ||
	    kguard_put_u64(msg, KGUARD_ATTR_STAT_NETNS, t.netns) ||
	    kguard_put_u64(msg, KGUARD_ATTR_STAT_SOURCES, t.sources) ||
	    kguard_put_u64(msg, KGUARD_ATTR_STAT_TRACK_FULL, t.track_full) ||
	    kguard_put_u64(msg, KGUARD_ATTR_STAT_ALERTS, t.alerts) ||
	    kguard_put_u64(msg, KGUARD_ATTR_STAT_BLOCK_DROPS, t.block_drops) ||
	    kguard_put_u64(msg, KGUARD_ATTR_STAT_RATE_DROPS, t.rate_drops) ||
	    kguard_put_u64(msg, KGUARD_ATTR_STAT_WOULD_DROP, t.would_drop) ||
	    kguard_put_u64(msg, KGUARD_ATTR_STAT_SPOOFED, t.spoofed) ||
	    kguard_put_u64(msg, KGUARD_ATTR_STAT_BLOCKS, t.blocks))
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

static void kguard_set_u32(struct genl_info *info, int attr, u32 *field, u32 max)
{
	if (info->attrs[attr])
		WRITE_ONCE(*field, min(nla_get_u32(info->attrs[attr]), max));
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
	kguard_set_u32(info, KGUARD_ATTR_CFG_WAKEUP_EVENTS, &kguard_cfg.wakeup_events, 1U << 20);
	kguard_set_bool(info, KGUARD_ATTR_CFG_ENFORCE, &kguard_cfg.enforce);
	kguard_set_bool(info, KGUARD_ATTR_CFG_AUTO_BLOCK, &kguard_cfg.auto_block);
	kguard_set_u32(info, KGUARD_ATTR_CFG_SCAN_THRESHOLD, &kguard_cfg.scan_threshold, 65536);
	kguard_set_u32(info, KGUARD_ATTR_CFG_SCAN_WINDOW_MS, &kguard_cfg.scan_window_ms,
		       3600 * 1000);
	kguard_set_u32(info, KGUARD_ATTR_CFG_SYN_RATE, &kguard_cfg.syn_rate, 1000000);
	kguard_set_u32(info, KGUARD_ATTR_CFG_SYN_BURST, &kguard_cfg.syn_burst, 1000000);
	kguard_set_u32(info, KGUARD_ATTR_CFG_BLOCK_TIMEOUT, &kguard_cfg.block_timeout,
		       30 * 24 * 3600);
	mutex_unlock(&kguard_cfg_lock);

	kguard_info("Configuration changed (netlink port %u)%s", info->snd_portid,
		    READ_ONCE(kguard_cfg.enforce) ? ", enforcing" : "");

	/* Tell listeners; having none is not an error */
	note = kguard_build(NULL, KGUARD_CMD_CONFIG_CHANGED, kguard_put_config);
	if (!IS_ERR(note))
		genlmsg_multicast(&kguard_genl_family, note, 0, 0, GFP_KERNEL);

	return kguard_reply(info, KGUARD_CMD_GET_CONFIG, kguard_put_config);
}

/* ---- blocklist and allowlist ---- */

static int kguard_get_addr(struct genl_info *info, struct kguard_addr *a)
{
	struct nlattr *attr = info->attrs[KGUARD_ATTR_ADDR];

	if (!attr) {
		GENL_SET_ERR_MSG(info, "address missing");
		return -EINVAL;
	}
	if (kguard_addr_from_nla(a, nla_data(attr), nla_len(attr))) {
		GENL_SET_ERR_MSG(info, "address must be 4 (IPv4) or 16 (IPv6) bytes");
		return -EINVAL;
	}
	return 0;
}

static int kguard_cmd_block_add(struct sk_buff *skb, struct genl_info *info)
{
	struct kguard_addr a;
	u32 timeout = 0;
	int ret;

	ret = kguard_get_addr(info, &a);
	if (ret)
		return ret;
	if (info->attrs[KGUARD_ATTR_TIMEOUT])
		timeout = nla_get_u32(info->attrs[KGUARD_ATTR_TIMEOUT]);

	ret = kguard_block_add(genl_info_net(info), &a, timeout, KGUARD_REASON_MANUAL,
			       GFP_KERNEL);
	if (ret == -EADDRNOTAVAIL)
		GENL_SET_ERR_MSG(info, "refusing to block a local or allowlisted address");
	else if (ret == -ENOSPC)
		GENL_SET_ERR_MSG(info, "blocklist is full");
	return ret;
}

static int kguard_cmd_block_del(struct sk_buff *skb, struct genl_info *info)
{
	struct kguard_addr a;
	int ret = kguard_get_addr(info, &a);

	return ret ? ret : kguard_block_del(&a);
}

struct kguard_dump_ctx {
	struct sk_buff *skb;
	struct netlink_callback *cb;
};

static int kguard_dump_block_one(void *ctx, const struct kguard_addr *a,
				 u64 expires_ms, u8 reason)
{
	struct kguard_dump_ctx *d = ctx;
	void *hdr;

	hdr = genlmsg_put(d->skb, NETLINK_CB(d->cb->skb).portid, d->cb->nlh->nlmsg_seq,
			  &kguard_genl_family, NLM_F_MULTI, KGUARD_CMD_BLOCK_LIST);
	if (!hdr)
		return 1;
	if (nla_put(d->skb, KGUARD_ATTR_ADDR, kguard_addr_len(a), a->bytes) ||
	    kguard_put_u64(d->skb, KGUARD_ATTR_EXPIRES_MS, expires_ms) ||
	    nla_put_u8(d->skb, KGUARD_ATTR_REASON, reason)) {
		genlmsg_cancel(d->skb, hdr);
		return 1;
	}
	genlmsg_end(d->skb, hdr);
	return 0;
}

/* One message per block; cb->args[0] counts entries already sent */
static int kguard_cmd_block_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct kguard_dump_ctx d = { .skb = skb, .cb = cb };

	cb->args[0] += kguard_block_walk(kguard_dump_block_one, &d, cb->args[0]);
	return skb->len;
}

static u8 kguard_prefix_len(struct genl_info *info, const struct kguard_addr *a)
{
	struct nlattr *attr = info->attrs[KGUARD_ATTR_PREFIX_LEN];

	return attr ? nla_get_u8(attr) : kguard_addr_len(a) * 8;
}

static int kguard_cmd_allow_add(struct sk_buff *skb, struct genl_info *info)
{
	struct kguard_addr a;
	int ret = kguard_get_addr(info, &a);

	if (ret)
		return ret;
	ret = kguard_allow_add(&a, kguard_prefix_len(info, &a));
	if (ret == -EINVAL)
		GENL_SET_ERR_MSG(info, "prefix length too long for this address family");
	return ret;
}

static int kguard_cmd_allow_del(struct sk_buff *skb, struct genl_info *info)
{
	struct kguard_addr a;
	int ret = kguard_get_addr(info, &a);

	return ret ? ret : kguard_allow_del(&a, kguard_prefix_len(info, &a));
}

static int kguard_put_allow_one(void *ctx, const struct kguard_addr *a, u8 prefix_len)
{
	struct sk_buff *msg = ctx;
	struct nlattr *nest = nla_nest_start(msg, KGUARD_ATTR_ALLOW_ENTRY);

	if (!nest)
		return -EMSGSIZE;
	if (nla_put(msg, KGUARD_ATTR_ADDR, kguard_addr_len(a), a->bytes) ||
	    nla_put_u8(msg, KGUARD_ATTR_PREFIX_LEN, prefix_len)) {
		nla_nest_cancel(msg, nest);
		return -EMSGSIZE;
	}
	nla_nest_end(msg, nest);
	return 0;
}

static int kguard_cmd_allow_list(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;

	/* Up to 256 prefixes of at most 32 bytes each */
	msg = genlmsg_new(16384, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;
	hdr = genlmsg_put_reply(msg, info, &kguard_genl_family, 0, KGUARD_CMD_ALLOW_LIST);
	if (!hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}
	kguard_allow_walk(kguard_put_allow_one, msg);
	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);
}

/* ---- alerts ---- */

/* Multicast one guard alert. Called from the packet path. */
void kguard_genl_alert(const struct kguard_alert *a)
{
	struct sk_buff *msg;
	void *hdr;

	msg = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!msg)
		return;
	hdr = genlmsg_put(msg, 0, 0, &kguard_genl_family, 0, KGUARD_CMD_ALERT);
	if (!hdr ||
	    kguard_put_u64(msg, KGUARD_ATTR_TIMESTAMP, a->timestamp_ns) ||
	    nla_put(msg, KGUARD_ATTR_ADDR, kguard_addr_len(&a->src), a->src.bytes) ||
	    nla_put_u32(msg, KGUARD_ATTR_NETNS, a->netns) ||
	    nla_put_u8(msg, KGUARD_ATTR_ALERT_TYPE, a->type) ||
	    nla_put_u8(msg, KGUARD_ATTR_ALERT_ACTION, a->action) ||
	    nla_put_u32(msg, KGUARD_ATTR_ALERT_PORTS, a->ports) ||
	    nla_put_u32(msg, KGUARD_ATTR_ALERT_ATTEMPTS, a->attempts) ||
	    (a->type == KGUARD_ALERT_SPOOF &&
	     (nla_put_u8(msg, KGUARD_ATTR_SPOOF_REASON, a->spoof_reason) ||
	      nla_put_u32(msg, KGUARD_ATTR_IFINDEX, a->ifindex)))) {
		nlmsg_free(msg);
		return;
	}
	genlmsg_end(msg, hdr);
	/* -ESRCH just means nobody is listening */
	genlmsg_multicast(&kguard_genl_family, msg, 0, 0, GFP_ATOMIC);
}

static const struct genl_small_ops kguard_genl_ops[] = {
	{ .cmd = KGUARD_CMD_GET_STATS,	.doit = kguard_cmd_get_stats },
	{ .cmd = KGUARD_CMD_GET_CONFIG,	.doit = kguard_cmd_get_config },
	{ .cmd = KGUARD_CMD_SET_CONFIG,	.doit = kguard_cmd_set_config, .flags = GENL_ADMIN_PERM },
	{ .cmd = KGUARD_CMD_BLOCK_ADD,	.doit = kguard_cmd_block_add, .flags = GENL_ADMIN_PERM },
	{ .cmd = KGUARD_CMD_BLOCK_DEL,	.doit = kguard_cmd_block_del, .flags = GENL_ADMIN_PERM },
	{ .cmd = KGUARD_CMD_BLOCK_LIST,	.dumpit = kguard_cmd_block_dump },
	{ .cmd = KGUARD_CMD_ALLOW_ADD,	.doit = kguard_cmd_allow_add, .flags = GENL_ADMIN_PERM },
	{ .cmd = KGUARD_CMD_ALLOW_DEL,	.doit = kguard_cmd_allow_del, .flags = GENL_ADMIN_PERM },
	{ .cmd = KGUARD_CMD_ALLOW_LIST,	.doit = kguard_cmd_allow_list },
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
	/* Commands from ALERT on get strict attribute validation */
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
