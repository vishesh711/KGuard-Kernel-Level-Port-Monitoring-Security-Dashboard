// SPDX-License-Identifier: GPL-2.0
/*
 * KGuard Kernel Module - Netfilter hooks
 *
 * Hooks LOCAL_IN, LOCAL_OUT and FORWARD for IPv4 and IPv6 in every network
 * namespace (pernet_operations), so traffic inside containers is captured
 * and tagged with its namespace. The guard hook (PRE_ROUTING) is registered
 * with the same operations.
 *
 * The hooks run just after connection tracking (NF_IP_PRI_CONNTRACK + 1),
 * so each packet's conntrack state is known. They never drop packets.
 *
 * Process attribution:
 *   - Outgoing packets sent from a process's own context (connect(),
 *     sendmsg(), ...) record that process's PID and name.
 *   - For any packet tied to a socket (skb->sk, or a lookup of the listening
 *     or connected socket for incoming TCP/UDP), the socket's owner UID and
 *     inode number are recorded. User space maps the inode to processes via
 *     /proc/<pid>/fd, as ss -p does.
 */

#include "kguard.h"

#include <linux/cred.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/net_namespace.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_socket.h>
#include <net/netns/generic.h>
#include <net/sock.h>
#include "kguard_trace.h"

static bool conntrack = true;
module_param(conntrack, bool, 0444);
MODULE_PARM_DESC(conntrack, "Enable connection tracking to report packet state (default on)");

/* Measure hook cost on one packet in this many */
#define KGUARD_SAMPLE_MASK	63

struct kguard_net {
	bool ct_active;
};

static unsigned int kguard_net_id __read_mostly;
static atomic_t kguard_netns_hooked = ATOMIC_INIT(0);

unsigned int kguard_netns_count(void)
{
	return atomic_read(&kguard_netns_hooked);
}

static bool kguard_direction_enabled(u8 dir)
{
	switch (dir) {
	case KGUARD_DIR_IN:
		return READ_ONCE(kguard_cfg.capture_in);
	case KGUARD_DIR_OUT:
		return READ_ONCE(kguard_cfg.capture_out);
	case KGUARD_DIR_FWD:
		return READ_ONCE(kguard_cfg.capture_fwd);
	default:
		return false;
	}
}

/* Fill addresses and protocol; return the transport header offset or -1 */
static int kguard_parse_ipv4(struct sk_buff *skb, struct kguard_event *ev)
{
	const struct iphdr *iph = ip_hdr(skb);

	ev->family = AF_INET;
	memcpy(ev->src_addr, &iph->saddr, sizeof(iph->saddr));
	memcpy(ev->dst_addr, &iph->daddr, sizeof(iph->daddr));
	ev->protocol = iph->protocol;

	/* Only the first fragment carries the transport header */
	if (ntohs(iph->frag_off) & IP_OFFSET) {
		ev->info |= KGUARD_EVF_FRAGMENT;
		return -1;
	}
	return skb_network_offset(skb) + ip_hdrlen(skb);
}

static int kguard_parse_ipv6(struct sk_buff *skb, struct kguard_event *ev)
{
	const struct ipv6hdr *ip6h = ipv6_hdr(skb);
	u8 nexthdr = ip6h->nexthdr;
	__be16 frag_off = 0;
	int offset;

	ev->family = AF_INET6;
	memcpy(ev->src_addr, &ip6h->saddr, sizeof(ip6h->saddr));
	memcpy(ev->dst_addr, &ip6h->daddr, sizeof(ip6h->daddr));

	/* Walk extension headers to the upper-layer protocol */
	offset = ipv6_skip_exthdr(skb, skb_network_offset(skb) + sizeof(*ip6h),
				  &nexthdr, &frag_off);
	ev->protocol = nexthdr;
	if (offset < 0)
		return -1;
	if (frag_off & htons(IP6_OFFSET)) {
		ev->info |= KGUARD_EVF_FRAGMENT;
		return -1;
	}
	return offset;
}

/* Copy ports and TCP flags out of possibly non-linear packet data */
static void kguard_parse_ports(const struct sk_buff *skb, int offset,
			       struct kguard_event *ev)
{
	if (ev->protocol == IPPROTO_TCP) {
		struct tcphdr buf;
		const struct tcphdr *th;

		th = skb_header_pointer(skb, offset, sizeof(buf), &buf);
		if (!th)
			return;
		ev->src_port = ntohs(th->source);
		ev->dst_port = ntohs(th->dest);
		ev->tcp_flags = (th->fin ? KGUARD_TCP_FIN : 0) |
				(th->syn ? KGUARD_TCP_SYN : 0) |
				(th->rst ? KGUARD_TCP_RST : 0) |
				(th->psh ? KGUARD_TCP_PSH : 0) |
				(th->ack ? KGUARD_TCP_ACK : 0) |
				(th->urg ? KGUARD_TCP_URG : 0);
	} else if (ev->protocol == IPPROTO_UDP) {
		struct udphdr buf;
		const struct udphdr *uh;

		uh = skb_header_pointer(skb, offset, sizeof(buf), &buf);
		if (!uh)
			return;
		ev->src_port = ntohs(uh->source);
		ev->dst_port = ntohs(uh->dest);
	}
}

static void kguard_set_ct(const struct sk_buff *skb, struct kguard_event *ev,
			  bool ct_active)
{
	enum ip_conntrack_info ctinfo;

	if (!skb_nfct(skb)) {
		/* With conntrack active, an untracked packet was judged invalid */
		ev->ct_state = ct_active ? KGUARD_CT_INVALID : KGUARD_CT_NONE;
		return;
	}

	nf_ct_get(skb, &ctinfo);
	if (ctinfo == IP_CT_UNTRACKED) {
		ev->ct_state = KGUARD_CT_UNTRACKED;
		return;
	}

	if (CTINFO2DIR(ctinfo) == IP_CT_DIR_REPLY)
		ev->info |= KGUARD_EVF_CT_REPLY;

	switch (ctinfo) {
	case IP_CT_NEW:
		ev->ct_state = KGUARD_CT_NEW;
		break;
	case IP_CT_RELATED:
	case IP_CT_RELATED_REPLY:
		ev->ct_state = KGUARD_CT_RELATED;
		break;
	default:
		ev->ct_state = KGUARD_CT_ESTABLISHED;
		break;
	}
}

/* Find the local socket an incoming TCP/UDP packet belongs to (referenced) */
static struct sock *kguard_lookup_sock(struct sk_buff *skb,
				       const struct nf_hook_state *state,
				       const struct kguard_event *ev)
{
	if (!state->in || (ev->info & KGUARD_EVF_FRAGMENT))
		return NULL;
	if (ev->protocol != IPPROTO_TCP && ev->protocol != IPPROTO_UDP)
		return NULL;

	if (ev->family == AF_INET)
		return nf_sk_lookup_slow_v4(state->net, skb, state->in);
	return nf_sk_lookup_slow_v6(state->net, skb, state->in);
}

static void kguard_set_owner(struct sk_buff *skb,
			     const struct nf_hook_state *state,
			     struct kguard_event *ev)
{
	struct sock *found = NULL;
	struct sock *sk = skb->sk;

	/*
	 * In process context the sender is the current task. Packets sent
	 * later from softirq (retransmits, ACKs) cannot be attributed this way.
	 */
	if (ev->direction == KGUARD_DIR_OUT && in_task() && sk) {
		ev->pid = task_tgid_nr(current);
		get_task_comm(ev->comm, current);
		ev->info |= KGUARD_EVF_PROC;
	}

	if (!sk && ev->direction == KGUARD_DIR_IN &&
	    READ_ONCE(kguard_cfg.socket_lookup)) {
		found = kguard_lookup_sock(skb, state, ev);
		sk = found;
	}

	/* A request socket (SYN received) stands for its listener */
	if (sk)
		sk = sk_to_full_sk(sk);
	/* Kernel-internal sockets (e.g. the ICMP reply socket) have no user owner */
	if (sk && sk_fullsock(sk) && !sk->sk_kern_sock && sk->sk_socket) {
		ev->uid = from_kuid_munged(&init_user_ns, sk->sk_uid);
		ev->sock_ino = sock_i_ino(sk);
		ev->info |= KGUARD_EVF_SOCK;
	}

	if (found)
		sock_gen_put(found);
}

static unsigned int kguard_hook(void *priv, struct sk_buff *skb,
				const struct nf_hook_state *state)
{
	u8 dir = (u8)(unsigned long)priv;
	struct kguard_event ev;
	struct net_device *dev;
	struct kguard_net *kn;
	bool sample;
	u64 t0 = 0;
	int offset;

	this_cpu_inc(kguard_pcpu_stats.packets);
	sample = !(this_cpu_read(kguard_pcpu_stats.packets) & KGUARD_SAMPLE_MASK);
	if (sample)
		t0 = local_clock();

	if (!kguard_direction_enabled(dir) ||
	    (state->pf == NFPROTO_IPV6 && !READ_ONCE(kguard_cfg.capture_ipv6))) {
		this_cpu_inc(kguard_pcpu_stats.filtered);
		return NF_ACCEPT;
	}

	memset(&ev, 0, sizeof(ev));
	ev.timestamp_ns = ktime_get_real_ns();
	ev.direction = dir;
	ev.netns = state->net->ns.inum;
	dev = dir == KGUARD_DIR_OUT ? state->out : state->in;
	if (dev)
		ev.ifindex = dev->ifindex;

	if (state->pf == NFPROTO_IPV4)
		offset = kguard_parse_ipv4(skb, &ev);
	else
		offset = kguard_parse_ipv6(skb, &ev);
	if (offset >= 0)
		kguard_parse_ports(skb, offset, &ev);

	kn = net_generic(state->net, kguard_net_id);
	kguard_set_ct(skb, &ev, kn->ct_active);
	kguard_set_owner(skb, state, &ev);

	kguard_ring_write(&ev);
	trace_kguard_event(&ev);

	if (sample) {
		this_cpu_add(kguard_pcpu_stats.ns_total, local_clock() - t0);
		this_cpu_inc(kguard_pcpu_stats.ns_samples);
	}
	return NF_ACCEPT;
}

#define KGUARD_HOOK(family, num, prio, dir) {		\
	.hook		= kguard_hook,			\
	.pf		= family,			\
	.hooknum	= num,				\
	.priority	= prio,				\
	.priv		= (void *)(unsigned long)(dir),	\
}

#define KGUARD_GUARD_HOOK(family, prio) {		\
	.hook		= kguard_guard_hook,		\
	.pf		= family,			\
	.hooknum	= NF_INET_PRE_ROUTING,		\
	.priority	= prio,				\
}

static const struct nf_hook_ops kguard_nf_ops[] = {
	/* Guard first, before defragmentation and conntrack (kguard_guard.c) */
	KGUARD_GUARD_HOOK(NFPROTO_IPV4, NF_IP_PRI_FIRST),
	KGUARD_GUARD_HOOK(NFPROTO_IPV6, NF_IP6_PRI_FIRST),
	/* Monitoring, just after conntrack */
	KGUARD_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN, NF_IP_PRI_CONNTRACK + 1, KGUARD_DIR_IN),
	KGUARD_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_OUT, NF_IP_PRI_CONNTRACK + 1, KGUARD_DIR_OUT),
	KGUARD_HOOK(NFPROTO_IPV4, NF_INET_FORWARD, NF_IP_PRI_CONNTRACK + 1, KGUARD_DIR_FWD),
	KGUARD_HOOK(NFPROTO_IPV6, NF_INET_LOCAL_IN, NF_IP6_PRI_CONNTRACK + 1, KGUARD_DIR_IN),
	KGUARD_HOOK(NFPROTO_IPV6, NF_INET_LOCAL_OUT, NF_IP6_PRI_CONNTRACK + 1, KGUARD_DIR_OUT),
	KGUARD_HOOK(NFPROTO_IPV6, NF_INET_FORWARD, NF_IP6_PRI_CONNTRACK + 1, KGUARD_DIR_FWD),
};

static int __net_init kguard_net_init(struct net *net)
{
	struct kguard_net *kn = net_generic(net, kguard_net_id);
	int ret;

	if (conntrack) {
		ret = nf_ct_netns_get(net, NFPROTO_INET);
		kn->ct_active = !ret;
		if (ret)
			kguard_warn("conntrack unavailable in netns %u: %d",
				    net->ns.inum, ret);
	}

	ret = nf_register_net_hooks(net, kguard_nf_ops, ARRAY_SIZE(kguard_nf_ops));
	if (ret) {
		if (kn->ct_active)
			nf_ct_netns_put(net, NFPROTO_INET);
		return ret;
	}

	atomic_inc(&kguard_netns_hooked);
	kguard_debug("Hooked netns %u", net->ns.inum);
	return 0;
}

static void __net_exit kguard_net_exit(struct net *net)
{
	struct kguard_net *kn = net_generic(net, kguard_net_id);

	nf_unregister_net_hooks(net, kguard_nf_ops, ARRAY_SIZE(kguard_nf_ops));
	if (kn->ct_active)
		nf_ct_netns_put(net, NFPROTO_INET);
	atomic_dec(&kguard_netns_hooked);
}

static struct pernet_operations kguard_net_ops = {
	.init	= kguard_net_init,
	.exit	= kguard_net_exit,
	.id	= &kguard_net_id,
	.size	= sizeof(struct kguard_net),
};

int kguard_netfilter_init(void)
{
	return register_pernet_subsys(&kguard_net_ops);
}

void kguard_netfilter_cleanup(void)
{
	unregister_pernet_subsys(&kguard_net_ops);
}
