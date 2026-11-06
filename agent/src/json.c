// SPDX-License-Identifier: GPL-2.0
/*
 * JSON encoding of events, in the same shape as /proc/kguard so the backend
 * parses agent batches with the same code.
 */

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "agent.h"

void buf_init(struct buf *b)
{
	b->cap = 4096;
	b->len = 0;
	b->data = malloc(b->cap);
	if (!b->data)
		abort();
	b->data[0] = '\0';
}

void buf_free(struct buf *b)
{
	free(b->data);
	b->data = NULL;
	b->len = b->cap = 0;
}

void buf_printf(struct buf *b, const char *fmt, ...)
{
	va_list ap;
	int need;

	for (;;) {
		va_start(ap, fmt);
		need = vsnprintf(b->data + b->len, b->cap - b->len, fmt, ap);
		va_end(ap);
		if (need < 0)
			abort();
		if ((size_t)need < b->cap - b->len) {
			b->len += need;
			return;
		}
		b->cap = (b->cap + need) * 2;
		b->data = realloc(b->data, b->cap);
		if (!b->data)
			abort();
	}
}

static const char *protocol_name(uint8_t p)
{
	switch (p) {
	case 6: return "TCP";
	case 17: return "UDP";
	case 1: return "ICMP";
	case 58: return "ICMPv6";
	default: return "OTHER";
	}
}

static const char *direction_name(uint8_t d)
{
	switch (d) {
	case KGUARD_DIR_IN: return "in";
	case KGUARD_DIR_OUT: return "out";
	case KGUARD_DIR_FWD: return "fwd";
	default: return "unknown";
	}
}

static const char *ct_name(uint8_t s)
{
	static const char *names[] = { "none", "new", "established", "related", "invalid", "untracked" };

	return s < sizeof(names) / sizeof(names[0]) ? names[s] : "none";
}

/* SYN options in p0f notation, e.g. "M,S,T,N,W" (same as /proc/kguard) */
static void tcp_options_text(const struct kguard_event *e, char *out, size_t size)
{
	unsigned int i, n = e->tcp_opts_len < KGUARD_TCP_MAX_OPTS ? e->tcp_opts_len : KGUARD_TCP_MAX_OPTS;
	size_t len = 0;

	out[0] = '\0';
	for (i = 0; i < n && len + 6 < size; i++) {
		const char *sep = i ? "," : "";

		switch (e->tcp_opts[i]) {
		case KGUARD_TCPOPT_EOL: len += snprintf(out + len, size - len, "%sE", sep); break;
		case KGUARD_TCPOPT_NOP: len += snprintf(out + len, size - len, "%sN", sep); break;
		case KGUARD_TCPOPT_MSS: len += snprintf(out + len, size - len, "%sM", sep); break;
		case KGUARD_TCPOPT_WS: len += snprintf(out + len, size - len, "%sW", sep); break;
		case KGUARD_TCPOPT_SACKOK: len += snprintf(out + len, size - len, "%sS", sep); break;
		case KGUARD_TCPOPT_TS: len += snprintf(out + len, size - len, "%sT", sep); break;
		default: len += snprintf(out + len, size - len, "%s?%u", sep, e->tcp_opts[i]);
		}
	}
}

void json_event(struct buf *b, const struct kguard_event *e)
{
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN], comm[17], opts[48];
	int af = e->family == 10 ? AF_INET6 : AF_INET;
	bool proc = e->info & KGUARD_EVF_PROC;
	bool sock = e->info & KGUARD_EVF_SOCK;
	int i;

	inet_ntop(af, e->src_addr, src, sizeof(src));
	inet_ntop(af, e->dst_addr, dst, sizeof(dst));

	/* Process names are user-controlled: keep only safe characters */
	for (i = 0; i < 16 && proc && e->comm[i]; i++) {
		char c = e->comm[i];

		comm[i] = (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') ? c : '?';
	}
	comm[i] = '\0';
	tcp_options_text(e, opts, sizeof(opts));

	buf_printf(b,
		   "{\"timestamp\":%llu,\"family\":%d,\"src_ip\":\"%s\",\"dst_ip\":\"%s\","
		   "\"src_port\":%u,\"dst_port\":%u,\"protocol\":\"%s\",\"flags\":%u,"
		   "\"direction\":\"%s\",\"ct_state\":\"%s\",\"netns\":%u,\"ifindex\":%u,"
		   "\"pid\":%d,\"comm\":\"%s\",\"uid\":%lld,\"sock_ino\":%llu,"
		   "\"ttl\":%u,\"ip_len\":%u,\"df\":%s,\"tcp_window\":%u,\"tcp_mss\":%u,"
		   "\"tcp_wscale\":%d,\"tcp_options\":\"%s\"}",
		   (unsigned long long)e->timestamp_ns, af == AF_INET6 ? 6 : 4, src, dst,
		   e->src_port, e->dst_port, protocol_name(e->protocol), e->tcp_flags,
		   direction_name(e->direction), ct_name(e->ct_state), e->netns, e->ifindex,
		   proc ? (int)e->pid : -1, comm, sock ? (long long)e->uid : -1LL,
		   sock ? (unsigned long long)e->sock_ino : 0ULL,
		   e->ttl, e->ip_len, (e->ip_flags & KGUARD_IPF_DF) ? "true" : "false",
		   e->tcp_window, e->tcp_mss,
		   e->tcp_opts_len && e->tcp_wscale != 0xff ? e->tcp_wscale : -1, opts);
}
