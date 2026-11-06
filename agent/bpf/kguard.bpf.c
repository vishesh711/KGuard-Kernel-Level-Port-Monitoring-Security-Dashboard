// SPDX-License-Identifier: GPL-2.0
/*
 * KGuard eBPF capture engine
 *
 * Produces the same 128-byte struct kguard_event as the kernel module
 * (kernel/include/uapi/linux/kguard.h), so every reader works with both.
 *
 *   XDP (ingress)        parse, drop sources in the LPM blocklist, emit "in"
 *   TC clsact (egress)   parse, emit "out" with the socket's owner UID
 *   payloads             DNS messages and TLS ClientHellos, copied into a
 *                        second ring buffer for protocol analysis
 *   fentry/fexit/tp_btf  remember which process owns each TCP connection,
 *                        listening port and UDP port, so packets can be
 *                        attributed without any per-packet process lookup
 *
 * CO-RE: kernel structures are declared below with only the fields used and
 * preserve_access_index, so libbpf relocates field offsets against the
 * running kernel's BTF. No generated vmlinux.h is needed.
 *
 * Process context is available only in the tracing programs; the packet
 * programs look owners up in maps keyed by connection tuple or local port.
 */

#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/kguard.h>

char LICENSE[] SEC("license") = "GPL";

/* ---- kernel structures (CO-RE, only what we read) ---- */

struct sock_common {
	__be32 skc_daddr;
	__be32 skc_rcv_saddr;
	__be16 skc_dport;
	__u16 skc_num;
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
	__u16 sk_protocol;
} __attribute__((preserve_access_index));

struct socket {
	struct sock *sk;
} __attribute__((preserve_access_index));

struct task_struct {
	struct task_struct *group_leader;
	char comm[16];
} __attribute__((preserve_access_index));

#define AF_INET		2
#define AF_INET6	10
#define TCP_CLOSE	7
#define TCP_LISTEN	10

/* ---- configuration, set by the agent before loading ---- */

const volatile __u32 kguard_netns;	/* inode of the agent's network namespace */
const volatile __u8 capture_in = 1;
const volatile __u8 capture_out = 1;
const volatile __u8 capture_payloads = 1;	/* DNS and TLS ClientHello samples */

/* ---- maps ---- */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 << 20);	/* resized by the agent */
} events SEC(".maps");

/* DNS and TLS ClientHello samples; a separate ring so large records cannot
 * crowd out packet events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} payloads SEC(".maps");

/* Blocked prefixes. IPv4 is stored IPv4-mapped (::ffff:a.b.c.d, length + 96) */
struct lpm_key {
	__u32 prefixlen;
	__u8 addr[16];
};

struct block_value {
	__u64 expires_ns;	/* bpf_ktime_get_ns() clock; 0 = never */
	__u64 drops;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65536);
	__type(key, struct lpm_key);
	__type(value, struct block_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} blocklist SEC(".maps");

struct owner {
	__u32 pid;
	__u32 uid;
	char comm[16];
};

/* A TCP connection seen from this host */
struct conn_key {
	__u8 laddr[16];
	__u8 raddr[16];
	__u16 lport;
	__u16 rport;
	__u8 family;
	__u8 pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct conn_key);
	__type(value, struct owner);
} conn_owner SEC(".maps");

/* A local port: TCP listeners, bound or sending UDP sockets */
struct port_key {
	__u16 port;
	__u8 protocol;
	__u8 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct port_key);
	__type(value, struct owner);
} port_owner SEC(".maps");

/* A TLS ClientHello larger than its first segment: keep copying this flow */
struct flow_key {
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 sport;
	__u16 dport;
	__u8 family;
	__u8 pad[3];
};

struct hello_state {
	__u32 next_seq;		/* sequence number after the bytes seen */
	__u32 remaining;	/* ClientHello bytes still to come */
	__u32 segments;		/* continuation segments copied so far */
};

/* Chrome's ClientHello (with a post-quantum key share) is about 1.8 KB */
#define MAX_HELLO_SEGMENTS	8

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct flow_key);
	__type(value, struct hello_state);
} hello_flows SEC(".maps");

struct counters {
	__u64 packets;
	__u64 events;
	__u64 ringbuf_full;
	__u64 blocked;
	__u64 payloads;
	__u64 payloads_full;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct counters);
} stats SEC(".maps");

static __always_inline struct counters *counters(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&stats, &zero);
}

/* ---- packet parsing (shared by XDP and TC) ---- */

struct pkt {
	__u8 family;
	__u8 protocol;
	__u8 tcp_flags;
	__u8 fragment;
	__u16 sport;
	__u16 dport;
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 ip_len;
	__u16 tcp_window;
	__u16 tcp_mss;
	__u8 ttl;
	__u8 ip_flags;
	__u8 tcp_wscale;
	__u8 tcp_opts_len;
	__u8 tcp_opts[KGUARD_TCP_MAX_OPTS];
	__u32 tcp_seq;
	__u32 payload_off;	/* from the start of the frame */
	__u32 payload_len;	/* from the IP length, so link padding is ignored */
};

/*
 * SYN options: kinds in order, MSS and window scale (OS fingerprinting).
 * Each loop pass records one option, so KGUARD_TCP_MAX_OPTS passes suffice.
 */
static __always_inline void parse_syn_options(struct tcphdr *th, void *end, struct pkt *p)
{
	__u8 *opt = (void *)(th + 1);
	__u32 len = th->doff * 4;
	__u32 off = 0;
	int n;

	p->tcp_wscale = 0xff;
	if (len <= sizeof(*th))
		return;
	len -= sizeof(*th);

	for (n = 0; n < KGUARD_TCP_MAX_OPTS; n++) {
		__u8 *cur = opt + (off & 63);	/* off < 40; the mask tells the verifier */
		__u8 kind, size;

		if (off >= len || (void *)(cur + 2) > end)
			break;
		kind = cur[0];
		p->tcp_opts[n] = kind;
		p->tcp_opts_len = n + 1;
		if (kind == KGUARD_TCPOPT_EOL)
			break;
		if (kind == KGUARD_TCPOPT_NOP) {
			off++;
			continue;
		}
		size = cur[1];
		if (size < 2 || off + size > len)
			break;
		if (kind == KGUARD_TCPOPT_MSS && size == 4 && (void *)(cur + 4) <= end)
			p->tcp_mss = (cur[2] << 8) | cur[3];
		else if (kind == KGUARD_TCPOPT_WS && size == 3 && (void *)(cur + 3) <= end)
			p->tcp_wscale = cur[2];
		off += size;
	}
}

/* The IP length counts from the network header, which follows the 14-byte Ethernet header */
static __always_inline void set_payload(struct pkt *p, void *data, void *start)
{
	__u32 off = start - data;
	__u32 ip_end = sizeof(struct ethhdr) + p->ip_len;

	p->payload_off = off;
	p->payload_len = ip_end > off ? ip_end - off : 0;
}

static __always_inline int parse(void *data, void *end, struct pkt *p)
{
	struct ethhdr *eth = data;
	void *l4;
	__u16 proto;

	if ((void *)(eth + 1) > end)
		return -1;
	proto = bpf_ntohs(eth->h_proto);

	if (proto == ETH_P_IP) {
		struct iphdr *iph = (void *)(eth + 1);

		if ((void *)(iph + 1) > end || iph->ihl < 5)
			return -1;
		p->family = AF_INET;
		p->protocol = iph->protocol;
		p->ttl = iph->ttl;
		p->ip_len = bpf_ntohs(iph->tot_len);
		if (iph->frag_off & bpf_htons(0x4000))
			p->ip_flags |= KGUARD_IPF_DF;
		__builtin_memcpy(p->saddr, &iph->saddr, 4);
		__builtin_memcpy(p->daddr, &iph->daddr, 4);
		if (bpf_ntohs(iph->frag_off) & 0x1fff) {
			p->fragment = 1;
			return 0;
		}
		l4 = (void *)iph + iph->ihl * 4;
	} else if (proto == ETH_P_IPV6) {
		struct ipv6hdr *ip6h = (void *)(eth + 1);

		if ((void *)(ip6h + 1) > end)
			return -1;
		p->family = AF_INET6;
		p->protocol = ip6h->nexthdr;
		p->ttl = ip6h->hop_limit;
		p->ip_len = bpf_ntohs(ip6h->payload_len) + sizeof(*ip6h);
		__builtin_memcpy(p->saddr, &ip6h->saddr, 16);
		__builtin_memcpy(p->daddr, &ip6h->daddr, 16);
		/* Extension headers are not walked: ports only for plain TCP/UDP */
		l4 = ip6h + 1;
	} else {
		return -1;	/* not IP: ignore */
	}

	if (p->protocol == IPPROTO_TCP) {
		struct tcphdr *th = l4;

		if ((void *)(th + 1) > end)
			return 0;
		p->sport = bpf_ntohs(th->source);
		p->dport = bpf_ntohs(th->dest);
		p->tcp_flags = (th->fin ? KGUARD_TCP_FIN : 0) | (th->syn ? KGUARD_TCP_SYN : 0) |
			       (th->rst ? KGUARD_TCP_RST : 0) | (th->psh ? KGUARD_TCP_PSH : 0) |
			       (th->ack ? KGUARD_TCP_ACK : 0) | (th->urg ? KGUARD_TCP_URG : 0);
		p->tcp_window = bpf_ntohs(th->window);
		p->tcp_seq = bpf_ntohl(th->seq);
		if (th->syn)
			parse_syn_options(th, end, p);
		set_payload(p, data, (void *)th + th->doff * 4);
	} else if (p->protocol == IPPROTO_UDP) {
		struct udphdr *uh = l4;

		if ((void *)(uh + 1) > end)
			return 0;
		p->sport = bpf_ntohs(uh->source);
		p->dport = bpf_ntohs(uh->dest);
		set_payload(p, data, uh + 1);
	}
	return 0;
}

static __always_inline void lpm_key_for(struct lpm_key *k, const struct pkt *p)
{
	__builtin_memset(k, 0, sizeof(*k));
	k->prefixlen = 128;
	if (p->family == AF_INET) {
		k->addr[10] = 0xff;
		k->addr[11] = 0xff;
		__builtin_memcpy(&k->addr[12], p->saddr, 4);
	} else {
		__builtin_memcpy(k->addr, p->saddr, 16);
	}
}

static __always_inline struct owner *find_owner(const struct pkt *p, bool incoming)
{
	struct conn_key ck = {};
	struct port_key pk = {};
	struct owner *o = NULL;

	if (p->protocol == IPPROTO_TCP) {
		ck.family = p->family;
		if (incoming) {
			__builtin_memcpy(ck.laddr, p->daddr, 16);
			__builtin_memcpy(ck.raddr, p->saddr, 16);
			ck.lport = p->dport;
			ck.rport = p->sport;
		} else {
			__builtin_memcpy(ck.laddr, p->saddr, 16);
			__builtin_memcpy(ck.raddr, p->daddr, 16);
			ck.lport = p->sport;
			ck.rport = p->dport;
		}
		o = bpf_map_lookup_elem(&conn_owner, &ck);
	}
	if (!o && (p->protocol == IPPROTO_TCP || p->protocol == IPPROTO_UDP)) {
		pk.port = incoming ? p->dport : p->sport;
		pk.protocol = p->protocol;
		o = bpf_map_lookup_elem(&port_owner, &pk);
	}
	return o;
}

static __always_inline void emit(const struct pkt *p, __u8 direction, __u32 ifindex,
				 __u32 uid, bool have_uid)
{
	struct counters *c = counters();
	struct kguard_event *e;
	struct owner *o;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		if (c)
			c->ringbuf_full++;
		return;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->timestamp_ns = bpf_ktime_get_ns();	/* monotonic; the agent converts to realtime */
	__builtin_memcpy(e->src_addr, p->saddr, 16);
	__builtin_memcpy(e->dst_addr, p->daddr, 16);
	e->src_port = p->sport;
	e->dst_port = p->dport;
	e->family = p->family;
	e->protocol = p->protocol;
	e->tcp_flags = p->tcp_flags;
	e->direction = direction;
	e->ct_state = KGUARD_CT_NONE;
	e->netns = kguard_netns;
	e->ifindex = ifindex;
	if (p->fragment)
		e->info |= KGUARD_EVF_FRAGMENT;
	e->ttl = p->ttl;
	e->ip_len = p->ip_len;
	e->ip_flags = p->ip_flags;
	e->tcp_window = p->tcp_window;
	e->tcp_mss = p->tcp_mss;
	e->tcp_wscale = p->tcp_wscale;
	e->tcp_opts_len = p->tcp_opts_len;
	__builtin_memcpy(e->tcp_opts, p->tcp_opts, sizeof(e->tcp_opts));

	o = find_owner(p, direction == KGUARD_DIR_IN);
	if (o) {
		e->pid = o->pid;
		__builtin_memcpy(e->comm, o->comm, sizeof(e->comm));
		e->info |= KGUARD_EVF_PROC;
		if (!have_uid) {
			uid = o->uid;
			have_uid = true;
		}
	}
	if (have_uid) {
		e->uid = uid;
		e->info |= KGUARD_EVF_SOCK;	/* uid valid; sock_ino stays 0 */
	}

	bpf_ringbuf_submit(e, 0);
	if (c)
		c->events++;
}

/* ---- payload samples ---- */

static __always_inline int load_bytes(void *ctx, bool xdp, __u32 off, void *to, __u64 len)
{
	if (xdp)
		return bpf_xdp_load_bytes(ctx, off, to, len);
	return bpf_skb_load_bytes(ctx, off, to, len);
}

static __always_inline void flow_key_for(struct flow_key *k, const struct pkt *p)
{
	__builtin_memset(k, 0, sizeof(*k));
	__builtin_memcpy(k->saddr, p->saddr, 16);
	__builtin_memcpy(k->daddr, p->daddr, 16);
	k->sport = p->sport;
	k->dport = p->dport;
	k->family = p->family;
}

/* Copy payload bytes [off, off + KGUARD_PAYLOAD_MAX) of the packet into one record */
static __always_inline void emit_chunk(void *ctx, bool xdp, const struct pkt *p, __u8 direction,
				       __u32 ifindex, __u8 kind, __u32 off, const struct owner *o)
{
	struct counters *c = counters();
	struct kguard_payload *r;
	/*
	 * 64-bit on purpose: a 32-bit length gets bounds-checked on a
	 * zero-extended copy, which the verifier cannot tie back to it
	 */
	__u64 len;

	if (off >= p->payload_len)
		return;
	len = p->payload_len - off;
	if (len > KGUARD_PAYLOAD_MAX)
		len = KGUARD_PAYLOAD_MAX;
	/* The compiler knows 1 <= len here; make it test again, for the verifier */
	barrier_var(len);
	if (len < 1 || len > KGUARD_PAYLOAD_MAX)
		return;

	r = bpf_ringbuf_reserve(&payloads, sizeof(*r), 0);
	if (!r) {
		if (c)
			c->payloads_full++;
		return;
	}
	if (load_bytes(ctx, xdp, p->payload_off + off, r->data, len)) {
		bpf_ringbuf_discard(r, 0);
		return;
	}
	r->timestamp_ns = bpf_ktime_get_ns();
	__builtin_memcpy(r->src_addr, p->saddr, 16);
	__builtin_memcpy(r->dst_addr, p->daddr, 16);
	r->src_port = p->sport;
	r->dst_port = p->dport;
	r->family = p->family;
	r->protocol = p->protocol;
	r->direction = direction;
	r->kind = kind;
	r->netns = kguard_netns;
	r->ifindex = ifindex;
	r->tcp_seq = p->tcp_seq + off;
	r->len = len;
	r->orig_len = p->payload_len > 0xffff ? 0xffff : p->payload_len;
	r->info = 0;
	r->pid = 0;
	__builtin_memset(r->comm, 0, sizeof(r->comm));
	if (o) {
		r->pid = o->pid;
		__builtin_memcpy(r->comm, o->comm, sizeof(r->comm));
		r->info = KGUARD_EVF_PROC;
	}
	bpf_ringbuf_submit(r, 0);
	if (c)
		c->payloads++;
}

/*
 * One packet can carry more than a record holds: loopback's MTU is 64 KB,
 * and with segmentation offload TC sees one large "super-packet" that the
 * device splits later. TLS data is copied in up to MAX_PAYLOAD_CHUNKS
 * records (each with its own sequence number); DNS keeps only the start.
 */
#define MAX_PAYLOAD_CHUNKS	4

static __always_inline void emit_payload(void *ctx, bool xdp, const struct pkt *p, __u8 direction,
					 __u32 ifindex, __u8 kind)
{
	struct owner *found = find_owner(p, direction == KGUARD_DIR_IN);
	struct owner owner;
	const struct owner *o = NULL;
	int i;

	/* A stack copy: the map value may go away, and the verifier sees a plain pointer */
	if (found) {
		__builtin_memcpy(&owner, found, sizeof(owner));
		o = &owner;
	}
	if (kind == KGUARD_PAYLOAD_DNS) {
		emit_chunk(ctx, xdp, p, direction, ifindex, kind, 0, o);
		return;
	}
	for (i = 0; i < MAX_PAYLOAD_CHUNKS; i++)
		emit_chunk(ctx, xdp, p, direction, ifindex, kind, i * KGUARD_PAYLOAD_MAX, o);
}

/*
 * Copy DNS messages and TLS ClientHellos. A ClientHello is recognised by its
 * first bytes: record type 22 (handshake), version 3.x, handshake type 1.
 * When the record is longer than the segment, the rest of the flow's data is
 * copied until the record is complete (or MAX_HELLO_SEGMENTS).
 */
static __always_inline void sample_payload(void *ctx, bool xdp, const struct pkt *p,
					   __u8 direction, __u32 ifindex)
{
	struct hello_state *st, fresh = {};
	struct flow_key fk;
	__u8 head[6];
	__u32 record;

	if (p->fragment || !p->payload_len)
		return;

	if (p->protocol == IPPROTO_UDP) {
		if ((p->sport == 53 || p->dport == 53) && p->payload_len >= 12)
			emit_payload(ctx, xdp, p, direction, ifindex, KGUARD_PAYLOAD_DNS);
		return;
	}
	if (p->protocol != IPPROTO_TCP)
		return;

	flow_key_for(&fk, p);
	st = bpf_map_lookup_elem(&hello_flows, &fk);
	if (st) {
		if (p->tcp_seq != st->next_seq)
			return;	/* retransmission or out of order: the receiver sorts it out */
		emit_payload(ctx, xdp, p, direction, ifindex, KGUARD_PAYLOAD_TLS);
		st->next_seq += p->payload_len;
		st->segments++;
		if (p->payload_len >= st->remaining || st->segments >= MAX_HELLO_SEGMENTS)
			bpf_map_delete_elem(&hello_flows, &fk);
		else
			st->remaining -= p->payload_len;
		return;
	}

	if (p->payload_len < sizeof(head) || load_bytes(ctx, xdp, p->payload_off, head, sizeof(head)))
		return;
	if (head[0] != 22 || head[1] != 3 || head[5] != 1)
		return;
	emit_payload(ctx, xdp, p, direction, ifindex, KGUARD_PAYLOAD_TLS);
	record = 5 + ((__u32)head[3] << 8 | head[4]);
	if (record > p->payload_len) {
		fresh.next_seq = p->tcp_seq + p->payload_len;
		fresh.remaining = record - p->payload_len;
		bpf_map_update_elem(&hello_flows, &fk, &fresh, BPF_ANY);
	}
}

/* ---- packet programs ---- */

SEC("xdp")
int kguard_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	struct counters *c = counters();
	struct block_value *b;
	struct lpm_key key;
	struct pkt p = {};

	if (c)
		c->packets++;
	if (parse(data, end, &p))
		return XDP_PASS;

	lpm_key_for(&key, &p);
	b = bpf_map_lookup_elem(&blocklist, &key);
	if (b && (!b->expires_ns || bpf_ktime_get_ns() < b->expires_ns)) {
		__sync_fetch_and_add(&b->drops, 1);
		if (c)
			c->blocked++;
		return XDP_DROP;
	}

	if (capture_in) {
		emit(&p, KGUARD_DIR_IN, ctx->ingress_ifindex, 0, false);
		if (capture_payloads)
			sample_payload(ctx, true, &p, KGUARD_DIR_IN, ctx->ingress_ifindex);
	}
	return XDP_PASS;
}

SEC("tc")
int kguard_tc_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;
	struct counters *c = counters();
	struct pkt p = {};

	if (c)
		c->packets++;
	if (!capture_out || parse(data, end, &p))
		return TC_ACT_OK;

	/* Owner UID of the sending socket, when there is one */
	emit(&p, KGUARD_DIR_OUT, skb->ifindex, bpf_get_socket_uid(skb), skb->sk != NULL);
	if (capture_payloads)
		sample_payload(skb, false, &p, KGUARD_DIR_OUT, skb->ifindex);
	return TC_ACT_OK;
}

/* ---- ownership tracking ---- */

static __always_inline void current_owner(struct owner *o)
{
	o->pid = bpf_get_current_pid_tgid() >> 32;
	o->uid = (__u32)bpf_get_current_uid_gid();
	/*
	 * The process name, not the calling thread's: Chrome connects from a
	 * thread named "Chrome_IOThread", Firefox from "Socket Thread"
	 */
	if (BPF_CORE_READ_STR_INTO(&o->comm, bpf_get_current_task_btf(), group_leader, comm) <= 0)
		bpf_get_current_comm(o->comm, sizeof(o->comm));
}

static __always_inline int conn_key_from_sock(struct conn_key *k, struct sock *sk)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

	__builtin_memset(k, 0, sizeof(*k));
	k->lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	k->rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (family == AF_INET) {
		k->family = AF_INET;
		bpf_core_read(k->laddr, 4, &sk->__sk_common.skc_rcv_saddr);
		bpf_core_read(k->raddr, 4, &sk->__sk_common.skc_daddr);
	} else if (family == AF_INET6) {
		k->family = AF_INET6;
		bpf_core_read(k->laddr, 16, &sk->__sk_common.skc_v6_rcv_saddr);
		bpf_core_read(k->raddr, 16, &sk->__sk_common.skc_v6_daddr);
	} else {
		return -1;
	}
	return 0;
}

static __always_inline void remember_port(struct sock *sk, __u8 protocol)
{
	struct port_key pk = { .protocol = protocol };
	struct owner o;

	pk.port = BPF_CORE_READ(sk, __sk_common.skc_num);
	if (!pk.port)
		return;
	current_owner(&o);
	bpf_map_update_elem(&port_owner, &pk, &o, BPF_ANY);
}

/* Active open: the connecting process (runs before the SYN is sent) */
SEC("fentry/tcp_connect")
int BPF_PROG(kguard_tcp_connect, struct sock *sk)
{
	struct conn_key k;
	struct owner o;

	if (conn_key_from_sock(&k, sk))
		return 0;
	current_owner(&o);
	bpf_map_update_elem(&conn_owner, &k, &o, BPF_ANY);
	return 0;
}

/* Passive open: the accepting process. Return value via bpf_get_func_ret()
 * so this works whatever inet_csk_accept()'s arguments are on this kernel.
 */
SEC("fexit/inet_csk_accept")
int kguard_accept(__u64 *ctx)
{
	struct conn_key k;
	struct owner o;
	__u64 ret = 0;

	bpf_get_func_ret(ctx, &ret);
	if (!ret || conn_key_from_sock(&k, (struct sock *)ret))
		return 0;
	current_owner(&o);
	bpf_map_update_elem(&conn_owner, &k, &o, BPF_ANY);
	return 0;
}

/* Listening TCP port (after any automatic bind, hence fexit) */
SEC("fexit/inet_listen")
int kguard_listen(__u64 *ctx)
{
	struct socket *sock = (struct socket *)ctx[0];
	__u64 ret = 0;

	bpf_get_func_ret(ctx, &ret);
	if ((int)ret == 0)
		remember_port(BPF_CORE_READ(sock, sk), IPPROTO_TCP);
	return 0;
}

/* UDP: the port's owner is whoever bound it or sends from it */
static __always_inline int udp_bound(__u64 *ctx)
{
	struct socket *sock = (struct socket *)ctx[0];
	struct sock *sk = BPF_CORE_READ(sock, sk);
	__u64 ret = 0;

	bpf_get_func_ret(ctx, &ret);
	if ((int)ret == 0 && BPF_CORE_READ(sk, sk_protocol) == IPPROTO_UDP)
		remember_port(sk, IPPROTO_UDP);
	return 0;
}

SEC("fexit/inet_bind")
int kguard_inet_bind(__u64 *ctx)
{
	return udp_bound(ctx);
}

SEC("fexit/inet6_bind")
int kguard_inet6_bind(__u64 *ctx)
{
	return udp_bound(ctx);
}

static __always_inline int udp_sent(__u64 *ctx)
{
	struct sock *sk = (struct sock *)ctx[0];

	remember_port(sk, IPPROTO_UDP);
	return 0;
}

/*
 * Entry, not exit: the socket is already bound by the time udp_sendmsg()
 * runs (inet_send_prepare() autobinds first), and recording it at entry
 * lets the very first datagram be attributed.
 */
SEC("fentry/udp_sendmsg")
int kguard_udp_sendmsg(__u64 *ctx)
{
	return udp_sent(ctx);
}

SEC("fentry/udpv6_sendmsg")
int kguard_udpv6_sendmsg(__u64 *ctx)
{
	return udp_sent(ctx);
}

/* Forget connections and listeners when they close */
SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(kguard_state, struct sock *sk, int oldstate, int newstate)
{
	struct conn_key k;

	if (newstate != TCP_CLOSE)
		return 0;
	if (oldstate == TCP_LISTEN) {
		struct port_key pk = { .protocol = IPPROTO_TCP };

		pk.port = BPF_CORE_READ(sk, __sk_common.skc_num);
		bpf_map_delete_elem(&port_owner, &pk);
	} else if (!conn_key_from_sock(&k, sk)) {
		bpf_map_delete_elem(&conn_owner, &k);
	}
	return 0;
}
