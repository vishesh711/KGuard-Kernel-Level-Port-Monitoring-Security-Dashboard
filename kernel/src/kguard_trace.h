/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KGuard tracepoints (system "kguard")
 *
 *   kguard_event      every captured packet
 *   kguard_ring_full  an event lost because its CPU's ring was full
 *   kguard_alert      the guard raised an alert
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

struct kguard_alert;

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

TRACE_EVENT(kguard_alert,

	TP_PROTO(const struct kguard_alert *alert),

	TP_ARGS(alert),

	TP_STRUCT__entry(
		__array(u8, saddr, 16)
		__field(u32, netns)
		__field(u32, ports)
		__field(u32, attempts)
		__field(u8, type)
		__field(u8, action)
	),

	TP_fast_assign(
		if (alert->src.family == AF_INET)
			ipv6_addr_set_v4mapped(*(const __be32 *)alert->src.bytes,
					       (struct in6_addr *)__entry->saddr);
		else
			memcpy(__entry->saddr, alert->src.bytes, 16);
		__entry->netns = alert->netns;
		__entry->ports = alert->ports;
		__entry->attempts = alert->attempts;
		__entry->type = alert->type;
		__entry->action = alert->action;
	),

	TP_printk("type=%u action=%u src=%pI6c netns=%u ports=%u attempts=%u",
		  __entry->type, __entry->action, __entry->saddr, __entry->netns,
		  __entry->ports, __entry->attempts)
);

#endif /* _KGUARD_TRACE_H */

/* This part must be outside the include guard */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE kguard_trace
#include <trace/define_trace.h>
