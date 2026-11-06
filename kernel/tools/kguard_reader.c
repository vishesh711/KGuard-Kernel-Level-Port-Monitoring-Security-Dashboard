// SPDX-License-Identifier: GPL-2.0
/*
 * kguard_reader - read KGuard events through the zero-copy mmap interface
 *
 * Maps /dev/kguard, sleeps in poll() until events arrive, and consumes them
 * straight from the shared rings: no read() calls and no copies through the
 * kernel. See include/uapi/linux/kguard.h for the ring protocol.
 *
 * Usage: kguard_reader [-q] [-n MAX_EVENTS] [-t SECONDS]
 *   -q  print only the final summary
 *   -n  stop after this many events
 *   -t  stop after this many seconds (default: run until interrupted)
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <linux/kguard.h>

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static const char *proto_name(uint8_t p)
{
	switch (p) {
	case 6: return "TCP";
	case 17: return "UDP";
	case 1: return "ICMP";
	case 58: return "ICMPv6";
	default: return "OTHER";
	}
}

static const char *dir_name(uint8_t d)
{
	static const char *names[] = { "?", "in", "out", "fwd" };

	return d < 4 ? names[d] : "?";
}

/* SYN options in p0f notation, e.g. "M,S,T,N,W" (same as /proc/kguard) */
static void tcp_options_text(const struct kguard_event *e, char *out, size_t size)
{
	unsigned int i, n = e->tcp_opts_len < KGUARD_TCP_MAX_OPTS ? e->tcp_opts_len : KGUARD_TCP_MAX_OPTS;
	size_t len = 0;

	out[0] = '\0';
	for (i = 0; i < n && len + 6 < size; i++) {
		const char *sep = i ? "," : "";

		switch (e->tcp_opts[i]) {
		case KGUARD_TCPOPT_EOL: len += snprintf(out + len, size - len, "%sE", sep); break;
		case KGUARD_TCPOPT_NOP: len += snprintf(out + len, size - len, "%sN", sep); break;
		case KGUARD_TCPOPT_MSS: len += snprintf(out + len, size - len, "%sM", sep); break;
		case KGUARD_TCPOPT_WS: len += snprintf(out + len, size - len, "%sW", sep); break;
		case KGUARD_TCPOPT_SACKOK: len += snprintf(out + len, size - len, "%sS", sep); break;
		case KGUARD_TCPOPT_TS: len += snprintf(out + len, size - len, "%sT", sep); break;
		default: len += snprintf(out + len, size - len, "%s?%u", sep, e->tcp_opts[i]);
		}
	}
}

static void print_event(const struct kguard_event *e)
{
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	int af = e->family == 10 ? AF_INET6 : AF_INET;

	inet_ntop(af, e->src_addr, src, sizeof(src));
	inet_ntop(af, e->dst_addr, dst, sizeof(dst));
	printf("%-3s %-6s %s:%u -> %s:%u flags=0x%02x ct=%u netns=%u",
	       dir_name(e->direction), proto_name(e->protocol), src, e->src_port,
	       dst, e->dst_port, e->tcp_flags, e->ct_state, e->netns);
	if (e->info & KGUARD_EVF_PROC)
		printf(" pid=%u comm=%.16s", e->pid, e->comm);
	if (e->info & KGUARD_EVF_SOCK)
		printf(" uid=%u ino=%llu", e->uid, (unsigned long long)e->sock_ino);
	printf(" ttl=%u len=%u", e->ttl, e->ip_len);
	if (e->tcp_opts_len) {
		char opts[48];

		tcp_options_text(e, opts, sizeof(opts));
		printf(" win=%u mss=%u opts=%s", e->tcp_window, e->tcp_mss, opts);
	}
	putchar('\n');
}

int main(int argc, char **argv)
{
	unsigned long long total = 0, max_events = 0, wakeups = 0;
	struct kguard_mmap_info info;
	double deadline = 0, start;
	int quiet = 0, opt, fd;
	uint32_t n;
	void *area;

	while ((opt = getopt(argc, argv, "qn:t:")) != -1) {
		switch (opt) {
		case 'q':
			quiet = 1;
			break;
		case 'n':
			max_events = strtoull(optarg, NULL, 10);
			break;
		case 't':
			deadline = atof(optarg);
			break;
		default:
			fprintf(stderr, "usage: %s [-q] [-n MAX_EVENTS] [-t SECONDS]\n", argv[0]);
			return 2;
		}
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	/* O_RDWR: the reader writes each ring's tail through the mapping */
	fd = open("/dev/kguard", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/kguard");
		return 1;
	}

	/* Map the info page first to learn the full size */
	area = mmap(NULL, sizeof(info), PROT_READ, MAP_SHARED, fd, 0);
	if (area == MAP_FAILED) {
		perror("mmap info");
		return 1;
	}
	memcpy(&info, area, sizeof(info));
	munmap(area, sizeof(info));

	if (info.magic != KGUARD_MMAP_MAGIC || info.abi_version != KGUARD_ABI_VERSION ||
	    info.event_size != sizeof(struct kguard_event)) {
		fprintf(stderr, "unsupported KGuard ABI (magic %#x, version %u, event %u bytes)\n",
			info.magic, info.abi_version, info.event_size);
		return 1;
	}

	area = mmap(NULL, info.mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (area == MAP_FAILED) {
		perror("mmap rings");
		return 1;
	}
	if (!quiet)
		fprintf(stderr, "mapped %u rings x %u events (%llu KiB)\n", info.nr_rings,
			info.ring_slots, (unsigned long long)info.mmap_size / 1024);

	start = now();
	while (!stop) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		int timeout = 1000;

		if (deadline) {
			double left = deadline - (now() - start);

			if (left <= 0)
				break;
			timeout = left < 1 ? (int)(left * 1000) + 1 : 1000;
		}

		if (poll(&pfd, 1, timeout) < 0) {
			if (errno == EINTR)
				continue;
			perror("poll");
			return 1;
		}
		if (!(pfd.revents & POLLIN))
			continue;
		wakeups++;

		for (n = 0; n < info.nr_rings; n++) {
			uint8_t *ring = (uint8_t *)area + info.rings_offset +
					(uint64_t)n * info.ring_stride;
			struct kguard_ring_header *hdr = (void *)ring;
			const struct kguard_event *slots = (void *)(ring + info.ring_header_size);
			/* Pairs with the kernel's release of head */
			uint64_t head = __atomic_load_n(&hdr->head, __ATOMIC_ACQUIRE);
			uint64_t tail = hdr->tail;

			for (; tail != head; tail++) {
				if (!quiet)
					print_event(&slots[tail & (info.ring_slots - 1)]);
				total++;
				if (max_events && total >= max_events) {
					tail++;
					stop = 1;
					break;
				}
			}
			/* Pairs with the kernel's acquire of tail: slots may be reused */
			__atomic_store_n(&hdr->tail, tail, __ATOMIC_RELEASE);
		}
	}

	{
		unsigned long long dropped = 0;

		for (n = 0; n < info.nr_rings; n++) {
			struct kguard_ring_header *hdr = (void *)((uint8_t *)area + info.rings_offset +
								  (uint64_t)n * info.ring_stride);
			dropped += __atomic_load_n(&hdr->dropped, __ATOMIC_RELAXED);
		}
		printf("events=%llu dropped=%llu wakeups=%llu seconds=%.2f\n",
		       total, dropped, wakeups, now() - start);
	}
	return 0;
}
