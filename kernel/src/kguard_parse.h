/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KGuard - packet parsing shared by the kernel module and user-space tests
 *
 * The TCP options walk reads bytes an attacker chooses on every SYN, so it
 * lives here with no kernel dependencies: the module calls it on the
 * option bytes skb_header_pointer() returns, and the libFuzzer harness in
 * kernel/tests/fuzz/ calls the very same code on arbitrary input.
 */
#ifndef _KGUARD_PARSE_H
#define _KGUARD_PARSE_H

#include <uapi/linux/kguard.h>

#define KGUARD_OPT_EOL		0
#define KGUARD_OPT_NOP		1
#define KGUARD_OPT_MSS		2
#define KGUARD_OPT_WINDOW	3
#define KGUARD_OPTLEN_MSS	4
#define KGUARD_OPTLEN_WINDOW	3
/* A TCP header is at most 60 bytes: 40 bytes of options */
#define KGUARD_OPT_SPACE	40

/*
 * Record the TCP options of a SYN: their order, MSS and window scale. The
 * order and values identify the sender's operating system (p0f-style).
 * opt points to len bytes (at most KGUARD_OPT_SPACE); malformed options end
 * the walk, keeping what was read. Never reads outside opt[0..len).
 */
static inline void kguard_parse_tcp_opts(const __u8 *opt, unsigned int len,
					 struct kguard_event *ev)
{
	unsigned int i = 0;

	ev->tcp_wscale = 0xff;
	if (!len || len > KGUARD_OPT_SPACE)
		return;

	while (i < len && ev->tcp_opts_len < KGUARD_TCP_MAX_OPTS) {
		__u8 kind = opt[i];
		__u8 size;

		ev->tcp_opts[ev->tcp_opts_len++] = kind;
		if (kind == KGUARD_OPT_EOL)
			break;
		if (kind == KGUARD_OPT_NOP) {
			i++;
			continue;
		}
		if (i + 1 >= len)
			break;
		size = opt[i + 1];
		if (size < 2 || i + size > len)
			break;	/* malformed: keep what we have */
		if (kind == KGUARD_OPT_MSS && size == KGUARD_OPTLEN_MSS)
			ev->tcp_mss = (opt[i + 2] << 8) | opt[i + 3];
		else if (kind == KGUARD_OPT_WINDOW && size == KGUARD_OPTLEN_WINDOW)
			ev->tcp_wscale = opt[i + 2];
		i += size;
	}
}

#endif /* _KGUARD_PARSE_H */
