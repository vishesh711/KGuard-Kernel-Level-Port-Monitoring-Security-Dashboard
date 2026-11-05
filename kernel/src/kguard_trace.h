/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KGuard tracepoints (system "kguard")
 *
 *   kguard_event      every captured packet
 *   kguard_ring_full  an event lost because its CPU's ring was full
 *
 * Use with perf (perf record -e 'kguard:*') or tracefs
 * (/sys/kernel/tracing/events/kguard/).
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM kguard

#if !defined(_KGUARD_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _KGUARD_TRACE_H

#include <linux/in6.h>
#include <linux/tracepoint.h>
#include <net/ipv6.h>
#include <uapi/linux/kguard.h>

TRACE_EVENT(kguard_event,

	TP_PROTO(const struct kguard_event *ev),

	TP_ARGS(ev),

	TP_STRUCT__entry(
		__array(u8, saddr, 16)
		__array(u8, daddr, 16)
		__field(u16, sport)
		__field(u16, dport)
		__field(u8, protocol)
		__field(u8, direction)
		__field(u8, tcp_flags)
		__field(u32, pid)
	),

	TP_fast_assign(
		/* Show IPv4 as IPv4-mapped IPv6 so one format fits both */
		if (ev->family == AF_INET) {
			ipv6_addr_set_v4mapped(*(const __be32 *)ev->src_addr,
					       (struct in6_addr *)__entry->saddr);
			ipv6_addr_set_v4mapped(*(const __be32 *)ev->dst_addr,
					       (struct in6_addr *)__entry->daddr);
		} else {
			memcpy(__entry->saddr, ev->src_addr, 16);
			memcpy(__entry->daddr, ev->dst_addr, 16);
		}
		__entry->sport = ev->src_port;
		__entry->dport = ev->dst_port;
		__entry->protocol = ev->protocol;
		__entry->direction = ev->direction;
		__entry->tcp_flags = ev->tcp_flags;
		__entry->pid = ev->pid;
	),

	TP_printk("dir=%u proto=%u %pI6c:%u -> %pI6c:%u flags=0x%02x pid=%u",
		  __entry->direction, __entry->protocol,
		  __entry->saddr, __entry->sport, __entry->daddr, __entry->dport,
		  __entry->tcp_flags, __entry->pid)
);

TRACE_EVENT(kguard_ring_full,

	TP_PROTO(unsigned int cpu, u64 dropped),

	TP_ARGS(cpu, dropped),

	TP_STRUCT__entry(
		__field(unsigned int, cpu)
		__field(u64, dropped)
	),

	TP_fast_assign(
		__entry->cpu = cpu;
		__entry->dropped = dropped;
	),

	TP_printk("cpu=%u dropped=%llu", __entry->cpu, __entry->dropped)
);

#endif /* _KGUARD_TRACE_H */

/* This part must be outside the include guard */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE kguard_trace
#include <trace/define_trace.h>
