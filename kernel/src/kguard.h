/*
 * KGuard Kernel Module - Header File
 * 
 * This file contains shared definitions, structures, and function declarations
 * for the KGuard network monitoring kernel module.
 */

#ifndef _KGUARD_H
#define _KGUARD_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
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

/* Buffer configuration */
#define KGUARD_BUFFER_SIZE    1024
#define KGUARD_MAX_EVENT_SIZE 256

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

/* Circular buffer structure */
struct kguard_buffer {
    struct kguard_event *events;
    unsigned int head;
    unsigned int tail;
    unsigned int size;
    spinlock_t lock;
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
int kguard_buffer_get_events(struct kguard_event *events, int max_events);

/* Netfilter hook functions */
int kguard_netfilter_init(void);
void kguard_netfilter_cleanup(void);
unsigned int kguard_netfilter_hook(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state);

/* Proc filesystem functions */
int kguard_proc_init(void);
void kguard_proc_cleanup(void);

/* Utility functions */
static inline u64 kguard_get_timestamp(void)
{
    return ktime_get_ns();
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

/* Debug macros */
#ifdef DEBUG
#define kguard_debug(fmt, ...) \
    printk(KERN_DEBUG KGUARD_MODULE_NAME ": " fmt "\n", ##__VA_ARGS__)
#else
#define kguard_debug(fmt, ...) do { } while (0)
#endif

#define kguard_info(fmt, ...) \
    printk(KERN_INFO KGUARD_MODULE_NAME ": " fmt "\n", ##__VA_ARGS__)

#define kguard_warn(fmt, ...) \
    printk(KERN_WARNING KGUARD_MODULE_NAME ": " fmt "\n", ##__VA_ARGS__)

#define kguard_err(fmt, ...) \
    printk(KERN_ERR KGUARD_MODULE_NAME ": " fmt "\n", ##__VA_ARGS__)

#endif /* _KGUARD_H */