// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel module engine: consume /dev/kguard's per-CPU rings through mmap
 * (protocol in kernel/include/uapi/linux/kguard.h). Sockets the module
 * reports only by inode are resolved to their process via /proc.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "agent.h"

static int dev_fd = -1;
static uint8_t *area;
static struct kguard_mmap_info info;

static int module_open(const struct agent_config *cfg)
{
	void *first;

	(void)cfg;
	dev_fd = open("/dev/kguard", O_RDWR | O_CLOEXEC);
	if (dev_fd < 0) {
		log_err("open /dev/kguard: %s (is the module loaded? is another reader running?)",
			strerror(errno));
		return -1;
	}
	first = mmap(NULL, sizeof(info), PROT_READ, MAP_SHARED, dev_fd, 0);
	if (first == MAP_FAILED) {
		log_err("mmap /dev/kguard: %s", strerror(errno));
		return -1;
	}
	memcpy(&info, first, sizeof(info));
	munmap(first, sizeof(info));

	if (info.magic != KGUARD_MMAP_MAGIC || info.abi_version != KGUARD_ABI_VERSION ||
	    info.event_size != sizeof(struct kguard_event)) {
		log_err("unsupported KGuard ABI (version %u); rebuild agent and module together",
			info.abi_version);
		return -1;
	}
	area = mmap(NULL, info.mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, dev_fd, 0);
	if (area == MAP_FAILED) {
		log_err("mmap rings: %s", strerror(errno));
		return -1;
	}
	log_info("module engine: %u rings of %u events", info.nr_rings, info.ring_slots);
	return 0;
}

static struct kguard_ring_header *ring(uint32_t n)
{
	return (void *)(area + info.rings_offset + (uint64_t)n * info.ring_stride);
}

static int module_poll(int timeout_ms, event_cb cb, void *ctx)
{
	struct pollfd pfd = { .fd = dev_fd, .events = POLLIN };
	uint32_t n;

	if (poll(&pfd, 1, timeout_ms) < 0)
		return errno == EINTR ? 0 : -1;

	for (n = 0; n < info.nr_rings; n++) {
		struct kguard_ring_header *hdr = ring(n);
		const struct kguard_event *slots = (void *)((uint8_t *)hdr + info.ring_header_size);
		/* Pairs with the kernel's release of head */
		uint64_t head = __atomic_load_n(&hdr->head, __ATOMIC_ACQUIRE);
		uint64_t tail = hdr->tail;

		if (head - tail > info.ring_slots)	/* bogus tail from an earlier reader */
			tail = head;
		for (; tail != head; tail++) {
			struct kguard_event ev = slots[tail & (info.ring_slots - 1)];

			if (!(ev.info & KGUARD_EVF_PROC) && (ev.info & KGUARD_EVF_SOCK) && ev.sock_ino &&
			    procres_lookup(ev.sock_ino, &ev.pid, ev.comm))
				ev.info |= KGUARD_EVF_PROC;
			cb(&ev, ctx);
		}
		/* Pairs with the kernel's acquire of tail: slots may be reused */
		__atomic_store_n(&hdr->tail, tail, __ATOMIC_RELEASE);
	}
	return 0;
}

static uint64_t module_dropped(void)
{
	uint64_t total = 0;
	uint32_t n;

	for (n = 0; n < info.nr_rings; n++)
		total += __atomic_load_n(&ring(n)->dropped, __ATOMIC_RELAXED);
	return total;
}

static void module_close(void)
{
	if (area && area != MAP_FAILED)
		munmap(area, info.mmap_size);
	if (dev_fd >= 0)
		close(dev_fd);
	area = NULL;
	dev_fd = -1;
}

const struct engine module_engine = {
	.name		= "module",
	.open		= module_open,
	.poll		= module_poll,
	.kernel_dropped	= module_dropped,
	.close		= module_close,
	.block		= genl_block,
	.unblock	= genl_unblock,
	.enforcing	= genl_enforcing,
};
