/*
 * KGuard Kernel Module - Netfilter Hook Implementation
 * 
 * This file implements the Netfilter hooks for intercepting network packets
 * and extracting relevant metadata for security monitoring.
 */

#include "kguard.h"

/* Netfilter hook operations structure */
static struct nf_hook_ops kguard_nf_ops;

/*
 * Netfilter hook function
 * Called for each packet that matches our hook registration
 */
unsigned int kguard_netfilter_hook(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct kguard_event event;
    int ret;

    /* Basic packet validation */
    if (!skb) {
        return NF_ACCEPT;
    }

    /* Get IP header */
    ip_header = ip_hdr(skb);
    if (!ip_header) {
        return NF_ACCEPT;
    }

    /* Validate IP header length */
    if (skb->len < sizeof(struct iphdr)) {
        return NF_ACCEPT;
    }

    /* Initialize event structure */
    memset(&event, 0, sizeof(event));
    event.timestamp = kguard_get_timestamp();
    event.src_ip = ntohl(ip_header->saddr);
    event.dst_ip = ntohl(ip_header->daddr);
    event.protocol = ip_header->protocol;

    /* Extract port information based on protocol */
    switch (ip_header->protocol) {
    case IPPROTO_TCP:
        if (skb->len >= sizeof(struct iphdr) + sizeof(struct tcphdr)) {
            tcp_header = tcp_hdr(skb);
            if (tcp_header) {
                event.src_port = ntohs(tcp_header->source);
                event.dst_port = ntohs(tcp_header->dest);
                event.flags = tcp_header->syn ? 0x02 : 0;
                event.flags |= tcp_header->ack ? 0x10 : 0;
                event.flags |= tcp_header->fin ? 0x01 : 0;
                event.flags |= tcp_header->rst ? 0x04 : 0;
            }
        }
        break;

    case IPPROTO_UDP:
        if (skb->len >= sizeof(struct iphdr) + sizeof(struct udphdr)) {
            udp_header = udp_hdr(skb);
            if (udp_header) {
                event.src_port = ntohs(udp_header->source);
                event.dst_port = ntohs(udp_header->dest);
                event.flags = 0; /* UDP has no flags */
            }
        }
        break;

    case IPPROTO_ICMP:
        event.src_port = 0;
        event.dst_port = 0;
        event.flags = 0;
        break;

    default:
        /* For other protocols, we still capture IP information */
        event.src_port = 0;
        event.dst_port = 0;
        event.flags = 0;
        break;
    }

    /* Add event to buffer */
    ret = kguard_buffer_add_event(&event);
    if (ret) {
        kguard_debug("Failed to add event to buffer: %d", ret);
    }

    /* Always accept the packet - we're just monitoring */
    return NF_ACCEPT;
}

/*
 * Initialize Netfilter hooks
 * Registers the hook function with the kernel
 */
int kguard_netfilter_init(void)
{
    int ret;

    /* Initialize hook operations structure */
    kguard_nf_ops.hook = kguard_netfilter_hook;
    kguard_nf_ops.pf = PF_INET;                    /* IPv4 */
    kguard_nf_ops.hooknum = NF_INET_PRE_ROUTING;   /* Pre-routing hook */
    kguard_nf_ops.priority = NF_IP_PRI_FIRST;      /* High priority */

    /* Register the hook */
    ret = nf_register_net_hook(&init_net, &kguard_nf_ops);
    if (ret) {
        kguard_err("Failed to register Netfilter hook: %d", ret);
        return ret;
    }

    kguard_debug("Netfilter hook registered successfully");
    return 0;
}

/*
 * Cleanup Netfilter hooks
 * Unregisters the hook function from the kernel
 */
void kguard_netfilter_cleanup(void)
{
    /* Unregister the hook */
    nf_unregister_net_hook(&init_net, &kguard_nf_ops);
    kguard_debug("Netfilter hook unregistered");
}