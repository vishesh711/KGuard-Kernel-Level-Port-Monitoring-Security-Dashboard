/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * KGuard user-space ABI
 *
 * Shared by the kernel module and its readers (C tools, the Python backend).
 *
 * Event stream (/dev/kguard)
 * --------------------------
 * The device exposes one ring buffer per possible CPU, all in a single
 * mmap()-able area:
 *
 *   offset 0                      struct kguard_mmap_info (one page)
 *   rings_offset + n * ring_stride  ring n: struct kguard_ring_header
 *                                   (ring_header_size bytes), then
 *                                   ring_slots * event_size bytes of events
 *
 * Each ring has exactly one producer (the CPU it belongs to) and one
 * consumer (the process that has /dev/kguard open). head and tail are
 * free-running 64-bit counters; the slot for counter value i is
 * i & (ring_slots - 1).
 *
 * Reader protocol for each ring:
 *   head = load_acquire(&hdr->head);
 *   for (i = hdr->tail; i != head; i++)
 *           consume(slot(i));
 *   store_release(&hdr->tail, head);
 *
 * When a ring is full the kernel drops the new event and increments
 * hdr->dropped. poll() reports POLLIN while any ring holds events.
 * Only one process may have /dev/kguard open at a time.
 *
 * Control (Generic Netlink family KGUARD_GENL_NAME)
 * -------------------------------------------------
 * See enum kguard_genl_cmd and enum kguard_genl_attr below.
 *
 * Guard (in-kernel detection and enforcement)
 * -------------------------------------------
 * A PRE_ROUTING hook keeps per-source state (distinct ports tried, SYN token
 * bucket) and raises KGUARD_CMD_ALERT multicasts. With enforce off (the
 * default) it never drops packets; alerts report what it would have done.
 * With enforce on it drops traffic from blocked sources and SYNs over the
 * rate limit. Allowlisted and local addresses are never dropped or blocked.
 */
#ifndef _UAPI_LINUX_KGUARD_H
#define _UAPI_LINUX_KGUARD_H

#include <linux/types.h>

#define KGUARD_ABI_VERSION	1
#define KGUARD_MMAP_MAGIC	0x4452474bU	/* "KGRD" little-endian */

/* Direction of the packet relative to this host */
enum kguard_direction {
	KGUARD_DIR_UNKNOWN	= 0,
	KGUARD_DIR_IN		= 1,	/* delivered to this host */
	KGUARD_DIR_OUT		= 2,	/* sent by this host */
	KGUARD_DIR_FWD		= 3,	/* routed through this host */
};

/* Connection tracking state of the packet */
enum kguard_ct_state {
	KGUARD_CT_NONE		= 0,	/* conntrack not active */
	KGUARD_CT_NEW		= 1,
	KGUARD_CT_ESTABLISHED	= 2,
	KGUARD_CT_RELATED	= 3,
	KGUARD_CT_INVALID	= 4,	/* conntrack active, packet not tracked */
	KGUARD_CT_UNTRACKED	= 5,	/* explicitly untracked (NOTRACK) */
};

/* struct kguard_event.info bits */
#define KGUARD_EVF_FRAGMENT	0x01	/* non-first IP fragment: no ports */
#define KGUARD_EVF_PROC		0x02	/* pid and comm are valid */
#define KGUARD_EVF_SOCK		0x04	/* uid and sock_ino are valid */
#define KGUARD_EVF_CT_REPLY	0x08	/* packet in the reply direction */

/* TCP flag bits in struct kguard_event.tcp_flags (same as the TCP header) */
#define KGUARD_TCP_FIN		0x01
#define KGUARD_TCP_SYN		0x02
#define KGUARD_TCP_RST		0x04
#define KGUARD_TCP_PSH		0x08
#define KGUARD_TCP_ACK		0x10
#define KGUARD_TCP_URG		0x20

/*
 * One captured packet. 96 bytes, no implicit padding.
 * Python: struct.Struct("<QQ16s16sHHBBBBBB2xIIII16s4x")
 */
struct kguard_event {
	__u64	timestamp_ns;	/* CLOCK_REALTIME */
	__u64	sock_ino;	/* socket inode number (KGUARD_EVF_SOCK) */
	__u8	src_addr[16];	/* network byte order; IPv4 uses bytes 0-3 */
	__u8	dst_addr[16];
	__u16	src_port;	/* host byte order, 0 if none */
	__u16	dst_port;
	__u8	family;		/* AF_INET (2) or AF_INET6 (10) */
	__u8	protocol;	/* IPPROTO_* */
	__u8	tcp_flags;	/* KGUARD_TCP_* */
	__u8	direction;	/* enum kguard_direction */
	__u8	ct_state;	/* enum kguard_ct_state */
	__u8	info;		/* KGUARD_EVF_* */
	__u16	__pad0;
	__u32	netns;		/* network namespace inode number */
	__u32	pid;		/* sending process (KGUARD_EVF_PROC) */
	__u32	uid;		/* socket owner (KGUARD_EVF_SOCK) */
	__u32	ifindex;	/* input or output interface */
	char	comm[16];	/* sending process name (KGUARD_EVF_PROC) */
	__u32	__pad1;
};

/* Page 0 of the mmap area */
struct kguard_mmap_info {
	__u32	magic;			/* KGUARD_MMAP_MAGIC */
	__u32	abi_version;		/* KGUARD_ABI_VERSION */
	__u32	nr_rings;
	__u32	event_size;		/* sizeof(struct kguard_event) */
	__u32	ring_slots;		/* power of two */
	__u32	ring_header_size;	/* bytes before the first slot */
	__u64	ring_stride;		/* bytes from one ring to the next */
	__u64	rings_offset;		/* offset of ring 0 */
	__u64	mmap_size;		/* total bytes to map */
};

/* Start of each ring; head, tail and dropped sit on separate cache lines */
struct kguard_ring_header {
	__u64	head;		/* next slot the kernel writes */
	__u64	__pad0[7];
	__u64	tail;		/* next slot the reader reads (reader writes) */
	__u64	__pad1[7];
	__u64	dropped;	/* events lost because the ring was full */
	__u32	cpu;
	__u32	__pad2;
	__u64	__pad3[6];
};

/* Generic Netlink control interface */
#define KGUARD_GENL_NAME	"kguard"
#define KGUARD_GENL_VERSION	1
#define KGUARD_GENL_MCGRP	"events"

enum kguard_genl_cmd {
	KGUARD_CMD_UNSPEC,
	KGUARD_CMD_GET_STATS,	/* reply: KGUARD_ATTR_STAT_* */
	KGUARD_CMD_GET_CONFIG,	/* reply: KGUARD_ATTR_CFG_* */
	KGUARD_CMD_SET_CONFIG,	/* request: any KGUARD_ATTR_CFG_* (admin only) */
	KGUARD_CMD_CONFIG_CHANGED,	/* multicast notification */
	KGUARD_CMD_ALERT,	/* multicast: KGUARD_ATTR_ALERT_*, ADDR, NETNS */
	KGUARD_CMD_BLOCK_ADD,	/* ADDR [TIMEOUT] (admin only) */
	KGUARD_CMD_BLOCK_DEL,	/* ADDR (admin only) */
	KGUARD_CMD_BLOCK_LIST,	/* dump: ADDR, EXPIRES_MS, REASON per entry */
	KGUARD_CMD_ALLOW_ADD,	/* ADDR [PREFIX_LEN] (admin only) */
	KGUARD_CMD_ALLOW_DEL,	/* ADDR [PREFIX_LEN] (admin only) */
	KGUARD_CMD_ALLOW_LIST,	/* reply: one ALLOW_ENTRY nest per prefix */
	__KGUARD_CMD_MAX,
};

#define KGUARD_CMD_MAX (__KGUARD_CMD_MAX - 1)

enum kguard_genl_attr {
	KGUARD_ATTR_UNSPEC,
	/* statistics (u64) */
	KGUARD_ATTR_STAT_PACKETS,	/* packets seen by the hooks */
	KGUARD_ATTR_STAT_EVENTS,	/* events written to the rings */
	KGUARD_ATTR_STAT_DROPPED,	/* events lost to full rings */
	KGUARD_ATTR_STAT_FILTERED,	/* packets skipped by configuration */
	KGUARD_ATTR_STAT_NS_PER_PKT,	/* average hook cost, sampled */
	KGUARD_ATTR_STAT_RING_FILL,	/* events waiting in all rings */
	KGUARD_ATTR_STAT_NETNS,		/* network namespaces hooked */
	KGUARD_ATTR_PAD,
	/* configuration (u8 booleans unless noted) */
	KGUARD_ATTR_CFG_CAPTURE_IN,
	KGUARD_ATTR_CFG_CAPTURE_OUT,
	KGUARD_ATTR_CFG_CAPTURE_FWD,
	KGUARD_ATTR_CFG_CAPTURE_IPV6,
	KGUARD_ATTR_CFG_SOCKET_LOOKUP,
	KGUARD_ATTR_CFG_WAKEUP_EVENTS,	/* u32: wake the reader every N events */
	/* guard statistics (u64) */
	KGUARD_ATTR_STAT_SOURCES,	/* sources being tracked */
	KGUARD_ATTR_STAT_TRACK_FULL,	/* new sources not tracked: table full */
	KGUARD_ATTR_STAT_ALERTS,	/* alerts raised */
	KGUARD_ATTR_STAT_BLOCK_DROPS,	/* packets dropped from blocked sources */
	KGUARD_ATTR_STAT_RATE_DROPS,	/* SYNs dropped over the rate limit */
	KGUARD_ATTR_STAT_WOULD_DROP,	/* drops skipped because enforce is off */
	KGUARD_ATTR_STAT_BLOCKS,	/* entries in the blocklist */
	/* guard configuration */
	KGUARD_ATTR_CFG_ENFORCE,	/* u8: 0 monitor only (default), 1 drop */
	KGUARD_ATTR_CFG_AUTO_BLOCK,	/* u8: block scanners automatically */
	KGUARD_ATTR_CFG_SCAN_THRESHOLD,	/* u32: distinct ports that make a scan */
	KGUARD_ATTR_CFG_SCAN_WINDOW_MS,	/* u32: window for counting ports */
	KGUARD_ATTR_CFG_SYN_RATE,	/* u32: new connections per second per source */
	KGUARD_ATTR_CFG_SYN_BURST,	/* u32: token bucket depth */
	KGUARD_ATTR_CFG_BLOCK_TIMEOUT,	/* u32: seconds an automatic block lasts */
	/* addresses, blocks and alerts */
	KGUARD_ATTR_ADDR,		/* binary: 4 bytes IPv4 or 16 bytes IPv6 */
	KGUARD_ATTR_PREFIX_LEN,		/* u8 */
	KGUARD_ATTR_TIMEOUT,		/* u32 seconds, 0 = until removed */
	KGUARD_ATTR_EXPIRES_MS,		/* u64 milliseconds left, 0 = never */
	KGUARD_ATTR_REASON,		/* u8: enum kguard_block_reason */
	KGUARD_ATTR_NETNS,		/* u32 */
	KGUARD_ATTR_TIMESTAMP,		/* u64 nanoseconds, CLOCK_REALTIME */
	KGUARD_ATTR_ALERT_TYPE,		/* u8: enum kguard_alert_type */
	KGUARD_ATTR_ALERT_ACTION,	/* u8: enum kguard_alert_action */
	KGUARD_ATTR_ALERT_PORTS,	/* u32: distinct ports in the window */
	KGUARD_ATTR_ALERT_ATTEMPTS,	/* u32: connection attempts in the window */
	KGUARD_ATTR_ALLOW_ENTRY,	/* nest: ADDR, PREFIX_LEN */
	__KGUARD_ATTR_MAX,
};

#define KGUARD_ATTR_MAX (__KGUARD_ATTR_MAX - 1)

enum kguard_alert_type {
	KGUARD_ALERT_SCAN	= 1,	/* many distinct ports from one source */
	KGUARD_ALERT_SYN_RATE	= 2,	/* new connections over the rate limit */
};

enum kguard_alert_action {
	KGUARD_ACTION_NONE	= 0,	/* monitor only, or source is protected */
	KGUARD_ACTION_DROPPED	= 1,	/* excess packets dropped */
	KGUARD_ACTION_BLOCKED	= 2,	/* source added to the blocklist */
};

enum kguard_block_reason {
	KGUARD_REASON_MANUAL	= 1,
	KGUARD_REASON_SCAN	= 2,
	KGUARD_REASON_SYN_RATE	= 3,
};

#endif /* _UAPI_LINUX_KGUARD_H */
