/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KGuard Kernel Module - Header File
 *
 * This file contains shared definitions, structures, and function declarations
 * for the KGuard network monitoring kernel module.
 */

#ifndef _KGUARD_H
#define _KGUARD_H

/* Prefix every log line with the module name */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/time.h>
#include <linux/slab.h>

/* Module information */
#define KGUARD_MODULE_NAME    "kguard"
#define KGUARD_MODULE_VERSION "1.0.0"
#define KGUARD_MODULE_DESC    "KGuard Port Monitor"
#define KGUARD_MODULE_AUTHOR  "KGuard Development Team"

/* Proc filesystem */
#define KGUARD_PROC_NAME      "kguard"

/* Buffer configuration (size is set by the buffer_size module parameter) */
#define KGUARD_BUFFER_DEFAULT 65536
#define KGUARD_BUFFER_MIN     64
#define KGUARD_BUFFER_MAX     BIT(20)

/* Network event structure */
struct kguard_event {
	u64 timestamp;      /* High-resolution timestamp */
	u32 src_ip;         /* Source IP address */
	u32 dst_ip;         /* Destination IP address */
	u16 src_port;       /* Source port */
	u16 dst_port;       /* Destination port */
	u8  protocol;       /* Protocol (TCP=6, UDP=17, etc.) */
	u8  flags;          /* Protocol-specific flags */
	u16 reserved;       /* Reserved for future use */
};

/*
 * Circular buffer structure.
 * Holds up to size - 1 events. When full, the oldest event is overwritten
 * and counted in dropped.
 */
struct kguard_buffer {
	struct kguard_event *events;
	unsigned int head;
	unsigned int tail;
	unsigned int size;
	u64 dropped;
	spinlock_t lock;	/* protects head, tail and dropped */
};

/* Global variables (extern declarations) */
extern struct kguard_buffer *event_buffer;
extern struct proc_dir_entry *kguard_proc_entry;

/* Function declarations */

/* Main module functions */
int kguard_init_module(void);
void kguard_cleanup_module(void);

/* Buffer management functions */
int kguard_buffer_init(void);
void kguard_buffer_cleanup(void);
int kguard_buffer_add_event(const struct kguard_event *event);
int kguard_buffer_drain(struct kguard_event *events, unsigned int max_events,
			u64 *dropped);
unsigned int kguard_buffer_capacity(void);

/* Netfilter hook functions */
int kguard_netfilter_init(void);
void kguard_netfilter_cleanup(void);
unsigned int kguard_netfilter_hook(void *priv, struct sk_buff *skb,
				   const struct nf_hook_state *state);

/* Proc filesystem functions */
int kguard_proc_init(void);
void kguard_proc_cleanup(void);

/* Utility functions */
/* Wall-clock time in nanoseconds since the Unix epoch */
static inline u64 kguard_get_timestamp(void)
{
	return ktime_get_real_ns();
}

static inline const char *kguard_protocol_name(u8 protocol)
{
	switch (protocol) {
	case IPPROTO_TCP:
		return "TCP";
	case IPPROTO_UDP:
		return "UDP";
	case IPPROTO_ICMP:
		return "ICMP";
	default:
		return "OTHER";
	}
}

/* Logging helpers; kguard_debug is enabled at runtime via dynamic debug */
#define kguard_debug(fmt, ...) pr_debug(fmt "\n", ##__VA_ARGS__)
#define kguard_info(fmt, ...)  pr_info(fmt "\n", ##__VA_ARGS__)
#define kguard_warn(fmt, ...)  pr_warn(fmt "\n", ##__VA_ARGS__)
#define kguard_err(fmt, ...)   pr_err(fmt "\n", ##__VA_ARGS__)

#endif /* _KGUARD_H */
