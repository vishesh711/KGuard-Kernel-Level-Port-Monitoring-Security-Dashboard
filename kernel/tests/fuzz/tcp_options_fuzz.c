// SPDX-License-Identifier: GPL-2.0
/*
 * libFuzzer harness for the module's TCP options parser (roadmap P8.8):
 * the exact function the kernel runs, from src/kguard_parse.h.
 *
 *   make -C kernel fuzz        build with ASan + UBSan
 *   kernel/tests/fuzz/tcp_options_fuzz -max_total_time=3600 corpus/
 *
 * The input is the option bytes of a SYN (as many as the fuzzer gives; the
 * kernel hands the parser at most 40). ASan catches any read outside them;
 * the checks below catch results the kernel would report wrongly.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "kguard_parse.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct kguard_event ev;
	uint8_t *copy;
	unsigned int len = size > KGUARD_OPT_SPACE ? KGUARD_OPT_SPACE + 1 : size;

	/* An exact-size heap copy, so ASan flags even a one-byte over-read */
	copy = malloc(len ? len : 1);
	memcpy(copy, data, len);
	memset(&ev, 0, sizeof(ev));
	kguard_parse_tcp_opts(copy, len, &ev);

	if (ev.tcp_opts_len > KGUARD_TCP_MAX_OPTS)
		abort();
	/* Over-long option space is refused outright */
	if (len > KGUARD_OPT_SPACE && (ev.tcp_opts_len || ev.tcp_mss || ev.tcp_wscale != 0xff))
		abort();
	/* Every recorded kind is a byte the input really has */
	for (unsigned int i = 0; i < ev.tcp_opts_len; i++)
		if (!memchr(copy, ev.tcp_opts[i], len))
			abort();
	/* An MSS is only reported when the input has a well-formed MSS option */
	if (ev.tcp_mss && !memmem(copy, len, "\x02\x04", 2))
		abort();
	free(copy);
	return 0;
}
