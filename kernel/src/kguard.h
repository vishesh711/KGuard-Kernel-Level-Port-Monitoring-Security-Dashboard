/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KGuard Kernel Module - internal definitions
 *
 * Data path:
 *   Netfilter hooks (one set per network namespace, kguard_netfilter.c)
 *     -> per-CPU lock-free rings (kguard_ring.c)
 *     -> /dev/kguard mmap + poll (kguard_dev.c), or /proc/kguard JSON
 *        debug view (kguard_proc.c)
 * Guard (in-kernel detection and enforcement):
 *   PRE_ROUTING hook (kguard_guard.c) -> per-source state, blocklist and
 *   allowlist (kguard_track.c) -> alerts over Generic Netlink
 * Control and statistics:
 *   Generic Netlink (kguard_genl.c), debugfs (kguard_stats.c),
 *   tracepoints (kguard_trace.h)
 */

#ifndef _KGUARD_H
#define _KGUARD_H

/* Prefix every log line with the module name */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <uapi/linux/kguard.h>

/* Module information */
#define KGUARD_MODULE_NAME	"kguard"
#define KGUARD_MODULE_VERSION	"3.0.0"
#define KGUARD_MODULE_DESC	"KGuard network port monitor"
#define KGUARD_MODULE_AUTHOR	"KGuard Development Team"

#define KGUARD_PROC_NAME	"kguard"

/* Ring size limits, in events per CPU (rounded up to a power of two) */
#define KGUARD_RING_DEFAULT	16384
#define KGUARD_RING_MIN		64
#define KGUARD_RING_MAX		BIT(18)

/*
 * Runtime configuration. Written by module parameters at load time and by
 * Generic Netlink later; read locklessly with READ_ONCE() in the hooks.
 */
struct kguard_config {
	bool capture_in;
	bool capture_out;
	bool capture_fwd;
	bool capture_ipv6;
	bool socket_lookup;
	u32 wakeup_events;
	/* guard */
	bool enforce;		/* false: monitor only, never drop */
	bool auto_block;	/* block scanners (only when enforcing) */
	u32 scan_threshold;	/* distinct ports in the window that make a scan */
	u32 scan_window_ms;
	u32 syn_rate;		/* new connections per second per source */
	u32 syn_burst;
	u32 block_timeout;	/* seconds an automatic block lasts */
};

extern struct kguard_config kguard_cfg;
extern int kguard_reader_gid;

/* Per-CPU counters (kguard_stats.c) */
struct kguard_stats {
	u64 packets;
	u64 events;
	u64 dropped;
	u64 filtered;
	u64 ns_total;	/* hook time of sampled packets */
	u64 ns_samples;
	u64 alerts;
	u64 block_drops;
	u64 rate_drops;
	u64 would_drop;
	u64 spoofed;
};

DECLARE_PER_CPU(struct kguard_stats, kguard_pcpu_stats);

struct kguard_stats_total {
	u64 packets;
	u64 events;
	u64 dropped;
	u64 filtered;
	u64 ns_per_packet;
	u64 ring_fill;
	u64 netns;
	u64 sources;
	u64 track_full;
	u64 alerts;
	u64 block_drops;
	u64 rate_drops;
	u64 would_drop;
	u64 spoofed;
	u64 blocks;
};

void kguard_stats_read(struct kguard_stats_total *total);
int kguard_debugfs_init(void);
void kguard_debugfs_cleanup(void);

/* Rings (kguard_ring.c) */
struct seq_file;
void kguard_ring_show(struct seq_file *m);
int kguard_ring_init(unsigned int slots);
void kguard_ring_cleanup(void);
void kguard_ring_write(const struct kguard_event *ev);
bool kguard_ring_has_data(void);
u64 kguard_ring_fill(void);
unsigned int kguard_ring_capacity(void);
unsigned int kguard_ring_drain(struct kguard_event *out, unsigned int max,
			       u64 *dropped);
void *kguard_ring_area(void);
size_t kguard_ring_area_size(void);
bool kguard_reader_claim(void);
void kguard_reader_release(void);

/* Character device (kguard_dev.c) */
int kguard_dev_init(void);
void kguard_dev_cleanup(void);
void kguard_dev_wakeup(void);
bool kguard_reader_allowed(void);

/* /proc/kguard (kguard_proc.c) */
int kguard_proc_init(void);
void kguard_proc_cleanup(void);
const char *kguard_protocol_name(u8 protocol);
const char *kguard_direction_name(u8 direction);
const char *kguard_ct_name(u8 state);

/* Netfilter hooks (kguard_netfilter.c) */
int kguard_netfilter_init(void);
void kguard_netfilter_cleanup(void);
unsigned int kguard_netns_count(void);

/* Generic Netlink (kguard_genl.c) */
int kguard_genl_init(void);
void kguard_genl_cleanup(void);

/* Guard: addresses, per-source state, blocklist, allowlist (kguard_track.c) */
struct kguard_addr {
	u8 bytes[16];	/* network byte order; IPv4 uses bytes 0-3 */
	u8 family;	/* AF_INET or AF_INET6 */
	u8 __pad[3];
};

struct kguard_alert {
	u64 timestamp_ns;
	struct kguard_addr src;
	u32 netns;
	u32 ports;
	u32 attempts;
	u32 ifindex;	/* arrival interface (SPOOF alerts) */
	u8 type;	/* enum kguard_alert_type */
	u8 action;	/* enum kguard_alert_action */
	u8 spoof_reason;	/* enum kguard_spoof_reason (SPOOF alerts) */
};

struct net;
struct netlink_callback;

int kguard_track_init(unsigned int max_sources, unsigned int idle_timeout,
		      const char *allow);
void kguard_track_cleanup(void);
u64 kguard_track_count(void);
u64 kguard_track_full(void);

bool kguard_addr_is_local(struct net *net, const struct kguard_addr *a);
int kguard_addr_from_nla(struct kguard_addr *a, const void *data, int len);
int kguard_addr_len(const struct kguard_addr *a);

/* Per-source accounting for one connection attempt; see kguard_guard.c */
struct kguard_attempt_result {
	bool scan;		/* crossed the scan threshold (alert due) */
	bool over_rate;		/* SYN beyond the token bucket */
	bool rate_alert;	/* rate alert due */
	bool protected;		/* local address: never drop or block */
	u32 ports;
	u32 attempts;
};

int kguard_track_attempt(struct net *net, const struct kguard_addr *src,
			 u16 dport, bool syn, struct kguard_attempt_result *res);

int kguard_block_add(struct net *net, const struct kguard_addr *a,
		     u32 timeout_s, u8 reason, gfp_t gfp);
int kguard_block_del(const struct kguard_addr *a);
bool kguard_block_check(const struct kguard_addr *a);
u64 kguard_block_count(void);
int kguard_block_walk(int (*fn)(void *ctx, const struct kguard_addr *a,
				u64 expires_ms, u8 reason),
		      void *ctx, unsigned long skip);

int kguard_allow_add(const struct kguard_addr *a, u8 prefix_len);
int kguard_allow_del(const struct kguard_addr *a, u8 prefix_len);
bool kguard_allow_match(const struct kguard_addr *a);
int kguard_allow_walk(int (*fn)(void *ctx, const struct kguard_addr *a, u8 prefix_len),
		      void *ctx);

/* Guard hook and alerts (kguard_guard.c, kguard_genl.c) */
unsigned int kguard_guard_hook(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state);
void kguard_genl_alert(const struct kguard_alert *alert);

/* Logging helpers; kguard_debug is enabled at runtime via dynamic debug */
#define kguard_debug(fmt, ...)	pr_debug(fmt "\n", ##__VA_ARGS__)
#define kguard_info(fmt, ...)	pr_info(fmt "\n", ##__VA_ARGS__)
#define kguard_warn(fmt, ...)	pr_warn(fmt "\n", ##__VA_ARGS__)
#define kguard_err(fmt, ...)	pr_err(fmt "\n", ##__VA_ARGS__)

#endif /* _KGUARD_H */
