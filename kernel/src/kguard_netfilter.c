// SPDX-License-Identifier: GPL-2.0
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
	const struct iphdr *ip_header;
	struct kguard_event event;
	unsigned int l4_offset;

	if (!skb)
		return NF_ACCEPT;

	/* The IP stack has already validated and pulled the IP header */
	ip_header = ip_hdr(skb);
	if (!ip_header)
		return NF_ACCEPT;

	memset(&event, 0, sizeof(event));
	event.timestamp = kguard_get_timestamp();
	event.src_ip = ntohl(ip_header->saddr);
	event.dst_ip = ntohl(ip_header->daddr);
	event.protocol = ip_header->protocol;

	/*
	 * Ports only exist in the first fragment. Transport headers may sit in
	 * non-linear packet data, so copy them out with skb_header_pointer()
	 * instead of dereferencing them in place.
	 */
	l4_offset = skb_network_offset(skb) + ip_hdrlen(skb);
	if (!(ntohs(ip_header->frag_off) & IP_OFFSET)) {
		switch (ip_header->protocol) {
		case IPPROTO_TCP: {
			struct tcphdr tcp_buf;
			const struct tcphdr *th;

			th = skb_header_pointer(skb, l4_offset, sizeof(tcp_buf), &tcp_buf);
			if (th) {
				event.src_port = ntohs(th->source);
				event.dst_port = ntohs(th->dest);
				event.flags = (th->fin ? 0x01 : 0) | (th->syn ? 0x02 : 0) |
					      (th->rst ? 0x04 : 0) | (th->psh ? 0x08 : 0) |
					      (th->ack ? 0x10 : 0) | (th->urg ? 0x20 : 0);
			}
			break;
		}
		case IPPROTO_UDP: {
			struct udphdr udp_buf;
			const struct udphdr *uh;

			uh = skb_header_pointer(skb, l4_offset, sizeof(udp_buf), &udp_buf);
			if (uh) {
				event.src_port = ntohs(uh->source);
				event.dst_port = ntohs(uh->dest);
			}
			break;
		}
		default:
			/* ICMP and other protocols have no ports */
			break;
		}
	}

	kguard_buffer_add_event(&event);

	/* Always accept the packet - KGuard only observes */
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
