// SPDX-License-Identifier: GPL-2.0
/*
 * KGuard Kernel Module - guard hook (in-kernel detection and enforcement)
 *
 * Runs at PRE_ROUTING with the highest priority, before connection tracking,
 * so a blocked or flooding source costs as little as possible:
 *
 *   1. Allowlisted source        -> accept, skip everything else
 *   2. Blocked source            -> drop (enforce) or count "would drop"
 *   3. Connection attempt (TCP SYN without ACK, or UDP):
 *        per-source distinct ports in a window -> SCAN alert
 *                                               (+ automatic block)
 *        per-source SYN token bucket           -> SYN_RATE alert, drop
 *                                               excess SYNs (enforce)
 *
 * enforce is off by default: nothing is ever dropped, and alerts report
 * KGUARD_ACTION_NONE. Local addresses (loopback, this host's own
 * addresses) are tracked and alerted on but never dropped or blocked.
 *
 * Alerts go to the Generic Netlink "events" group (rate-limited to 100/s
 * overall, and to one per source and kind every 10 s) and to the
 * kguard:kguard_alert tracepoint.
 */

#include "kguard.h"

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/ratelimit.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include "kguard_trace.h"

static DEFINE_RATELIMIT_STATE(kguard_alert_rs, HZ, 100);

/*
 * Extract the source address and, for TCP/UDP first fragments, the
 * destination port and whether this is a connection attempt.
 */
static int kguard_guard_parse(struct sk_buff *skb, u8 pf, struct kguard_addr *src,
			      u16 *dport, bool *syn, bool *attempt)
{
	int offset;
	u8 proto;

	memset(src, 0, sizeof(*src));
	*dport = 0;
	*syn = false;
	*attempt = false;

	if (pf == NFPROTO_IPV4) {
		const struct iphdr *iph = ip_hdr(skb);

		src->family = AF_INET;
		memcpy(src->bytes, &iph->saddr, sizeof(iph->saddr));
		if (ntohs(iph->frag_off) & IP_OFFSET)
			return 0;
		proto = iph->protocol;
		offset = skb_network_offset(skb) + ip_hdrlen(skb);
	} else {
		const struct ipv6hdr *ip6h = ipv6_hdr(skb);
		__be16 frag_off = 0;
		u8 nexthdr = ip6h->nexthdr;

		src->family = AF_INET6;
		memcpy(src->bytes, &ip6h->saddr, sizeof(ip6h->saddr));
		offset = ipv6_skip_exthdr(skb, skb_network_offset(skb) + sizeof(*ip6h),
					  &nexthdr, &frag_off);
		if (offset < 0 || (frag_off & htons(IP6_OFFSET)))
			return 0;
		proto = nexthdr;
	}

	if (proto == IPPROTO_TCP) {
		struct tcphdr buf;
		const struct tcphdr *th = skb_header_pointer(skb, offset, sizeof(buf), &buf);

		if (!th)
			return -EINVAL;
		*dport = ntohs(th->dest);
		*syn = th->syn && !th->ack;
		*attempt = *syn;
	} else if (proto == IPPROTO_UDP) {
		struct udphdr buf;
		const struct udphdr *uh = skb_header_pointer(skb, offset, sizeof(buf), &buf);

		if (!uh)
			return -EINVAL;
		*dport = ntohs(uh->dest);
		*attempt = true;
	}
	return 0;
}

static void kguard_raise(struct net *net, const struct kguard_addr *src, u8 type,
			 u8 action, const struct kguard_attempt_result *r)
{
	struct kguard_alert alert = {
		.timestamp_ns	= ktime_get_real_ns(),
		.src		= *src,
		.netns		= net->ns.inum,
		.ports		= r->ports,
		.attempts	= r->attempts,
		.type		= type,
		.action		= action,
	};

	this_cpu_inc(kguard_pcpu_stats.alerts);
	trace_kguard_alert(&alert);
	if (__ratelimit(&kguard_alert_rs))
		kguard_genl_alert(&alert);
}

unsigned int kguard_guard_hook(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	struct kguard_attempt_result r;
	unsigned int verdict = NF_ACCEPT;
	struct kguard_addr src;
	bool syn, attempt, enforce;
	u16 dport;
	u8 action;

	if (kguard_guard_parse(skb, state->pf, &src, &dport, &syn, &attempt))
		return NF_ACCEPT;
	if (kguard_allow_match(&src))
		return NF_ACCEPT;

	enforce = READ_ONCE(kguard_cfg.enforce);

	/* Block entries can only hold non-local, non-allowlisted addresses */
	if (kguard_block_check(&src)) {
		if (enforce) {
			this_cpu_inc(kguard_pcpu_stats.block_drops);
			return NF_DROP;
		}
		this_cpu_inc(kguard_pcpu_stats.would_drop);
	}

	if (!attempt || kguard_track_attempt(state->net, &src, dport, syn, &r))
		return NF_ACCEPT;

	if (r.over_rate && !r.protected) {
		if (enforce) {
			this_cpu_inc(kguard_pcpu_stats.rate_drops);
			verdict = NF_DROP;
		} else {
			this_cpu_inc(kguard_pcpu_stats.would_drop);
		}
	}

	if (r.rate_alert)
		kguard_raise(state->net, &src, KGUARD_ALERT_SYN_RATE,
			     enforce && !r.protected ? KGUARD_ACTION_DROPPED : KGUARD_ACTION_NONE,
			     &r);

	if (r.scan) {
		action = KGUARD_ACTION_NONE;
		if (enforce && READ_ONCE(kguard_cfg.auto_block) && !r.protected &&
		    !kguard_block_add(state->net, &src, READ_ONCE(kguard_cfg.block_timeout),
				      KGUARD_REASON_SCAN, GFP_ATOMIC))
			action = KGUARD_ACTION_BLOCKED;
		kguard_raise(state->net, &src, KGUARD_ALERT_SCAN, action, &r);
	}

	return verdict;
}
