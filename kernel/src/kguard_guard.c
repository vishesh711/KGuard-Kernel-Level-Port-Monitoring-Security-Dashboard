// SPDX-License-Identifier: GPL-2.0
/*
 * KGuard Kernel Module - guard hook (in-kernel detection and enforcement)
 *
 * Runs at PRE_ROUTING with the highest priority, before connection tracking,
 * so a blocked or flooding source costs as little as possible:
 *
 *   1. Spoofed source: a packet from a real interface claiming a loopback
 *      address, one of this host's own addresses, or a source no host can
 *      have (multicast, broadcast, zero)  -> SPOOF alert, drop (enforce)
 *   2. Allowlisted source        -> accept, skip everything else
 *   3. Blocked source            -> drop (enforce) or count "would drop"
 *   4. Connection attempt (TCP SYN without ACK, or UDP):
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
 * overall, to one per source and kind every 10 s, and for spoofing to one
 * per reason every 10 s) and to the kguard:kguard_alert tracepoint.
 */

#include "kguard.h"

#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/ipv6.h>
#include <linux/ratelimit.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/addrconf.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/route.h>
#include "kguard_trace.h"

static DEFINE_RATELIMIT_STATE(kguard_alert_rs, HZ, 100);

/*
 * SPOOF alerts: one per reason every 10 s, carrying the number of spoofed
 * packets since the previous one. Spoofed sources are usually random, so
 * per-source state would only fill up (and per-source alerts would flood).
 */
#define KGUARD_SPOOF_COOLDOWN	(10 * HZ)
static struct {
	unsigned long last;	/* jiffies of the last alert, 0 = never */
	atomic_t packets;	/* spoofed packets since then */
} kguard_spoof_state[KGUARD_SPOOF_MARTIAN + 1];

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

static void kguard_send(struct kguard_alert *alert)
{
	this_cpu_inc(kguard_pcpu_stats.alerts);
	trace_kguard_alert(alert);
	if (__ratelimit(&kguard_alert_rs))
		kguard_genl_alert(alert);
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

	kguard_send(&alert);
}

/*
 * Return a kguard_spoof_reason when the source address cannot be genuine on
 * this (non-loopback) interface, 0 otherwise. The routing code drops most of
 * these later as martians, silently unless log_martians is set; here they
 * are reported. The address checks are a few comparisons; the routing table
 * lookup for this host's own addresses is done for connection attempts only.
 */
static u8 kguard_spoof_check(struct net *net, const struct sk_buff *skb, u8 pf,
			     u16 dport, bool attempt)
{
	if (pf == NFPROTO_IPV4) {
		const struct iphdr *iph = ip_hdr(skb);
		__be32 saddr = iph->saddr;

		if (ipv4_is_loopback(saddr))
			return KGUARD_SPOOF_LOOPBACK;
		/* 0.0.0.0 is legal only for DHCP clients without an address */
		if (ipv4_is_zeronet(saddr))
			return saddr == 0 && iph->protocol == IPPROTO_UDP && dport == 67 ?
			       0 : KGUARD_SPOOF_MARTIAN;
		if (ipv4_is_multicast(saddr) || ipv4_is_lbcast(saddr))
			return KGUARD_SPOOF_MARTIAN;
		if (attempt && inet_addr_type(net, saddr) == RTN_LOCAL)
			return KGUARD_SPOOF_LOCAL;
		return 0;
	}
#if IS_ENABLED(CONFIG_IPV6)
	{
		const struct ipv6hdr *ip6h = ipv6_hdr(skb);

		if (ipv6_addr_loopback(&ip6h->saddr))
			return KGUARD_SPOOF_LOOPBACK;
		if (ipv6_addr_is_multicast(&ip6h->saddr))
			return KGUARD_SPOOF_MARTIAN;
		/* :: is used by duplicate address detection and MLD */
		if (ipv6_addr_any(&ip6h->saddr))
			return 0;
		if (attempt && ipv6_chk_addr(net, &ip6h->saddr, NULL, 0))
			return KGUARD_SPOOF_LOCAL;
	}
#endif
	return 0;
}

static void kguard_raise_spoof(const struct nf_hook_state *state,
			       const struct kguard_addr *src, u8 reason, u8 action)
{
	unsigned long last = READ_ONCE(kguard_spoof_state[reason].last);
	struct kguard_alert alert = {
		.timestamp_ns	= ktime_get_real_ns(),
		.src		= *src,
		.netns		= state->net->ns.inum,
		.ifindex	= state->in ? state->in->ifindex : 0,
		.type		= KGUARD_ALERT_SPOOF,
		.action		= action,
		.spoof_reason	= reason,
	};

	atomic_inc(&kguard_spoof_state[reason].packets);
	if (last && time_before(jiffies, last + KGUARD_SPOOF_COOLDOWN))
		return;
	/* Only one CPU wins the slot; the others' packets go into the next alert */
	if (cmpxchg(&kguard_spoof_state[reason].last, last, jiffies | 1) != last)
		return;
	alert.attempts = atomic_xchg(&kguard_spoof_state[reason].packets, 0);
	kguard_send(&alert);
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

	enforce = READ_ONCE(kguard_cfg.enforce);

	/*
	 * Before the allowlist, so a forged allowlisted address cannot pass.
	 * Locally generated traffic arrives on loopback with any local source.
	 */
	if (state->in && !(state->in->flags & IFF_LOOPBACK)) {
		u8 reason = kguard_spoof_check(state->net, skb, state->pf, dport, attempt);

		if (reason) {
			this_cpu_inc(kguard_pcpu_stats.spoofed);
			kguard_raise_spoof(state, &src, reason,
					   enforce ? KGUARD_ACTION_DROPPED : KGUARD_ACTION_NONE);
			if (enforce)
				return NF_DROP;
		}
	}

	if (kguard_allow_match(&src))
		return NF_ACCEPT;

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
