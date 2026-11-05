// SPDX-License-Identifier: GPL-2.0
/*
 * KGuard Kernel Module - per-CPU lock-free event rings
 *
 * One ring per possible CPU, all inside a single vmalloc_user() area that
 * /dev/kguard maps into the reader's address space (layout in
 * include/uapi/linux/kguard.h).
 *
 * Producer (Netfilter hook on the ring's own CPU):
 *   Interrupts are disabled for the few instructions of a write, so a hook
 *   running in process context cannot be interleaved with one running in
 *   softirq context on the same CPU. That makes each CPU the only writer of
 *   its ring's head; no lock is shared between CPUs.
 *
 * Consumer (the single process holding /dev/kguard, or the /proc reader):
 *   Reads head with acquire semantics, consumes slots, then publishes the
 *   new tail with release semantics. The producer reads tail with acquire
 *   semantics before reusing a slot.
 *
 * The tail lives in memory the reader can write, so the kernel never relies
 * on it for memory safety: slot indexes are always masked, and an
 * implausible tail only makes the ring look full (events are dropped).
 */

#include "kguard.h"

#include <linux/atomic.h>
#include <linux/log2.h>
#include <linux/seq_file.h>
#include <linux/vmalloc.h>
#include "kguard_trace.h"

static void *ring_area;
static size_t ring_area_size;
static size_t ring_stride;
static unsigned int ring_slots;
static unsigned int nr_rings;

/* Set while a reader owns the consumer side of the rings */
static atomic_t reader_busy = ATOMIC_INIT(0);

static inline struct kguard_ring_header *ring_hdr(unsigned int n)
{
	return ring_area + PAGE_SIZE + (size_t)n * ring_stride;
}

static inline struct kguard_event *ring_slot(struct kguard_ring_header *hdr, u64 i)
{
	size_t idx = i & (ring_slots - 1);

	return (void *)hdr + PAGE_SIZE + idx * sizeof(struct kguard_event);
}

int kguard_ring_init(unsigned int slots)
{
	struct kguard_mmap_info *info;
	unsigned int n;

	BUILD_BUG_ON(sizeof(struct kguard_event) != 96);
	BUILD_BUG_ON(sizeof(struct kguard_ring_header) > PAGE_SIZE);
	BUILD_BUG_ON(offsetof(struct kguard_ring_header, tail) != 64);
	BUILD_BUG_ON(offsetof(struct kguard_ring_header, dropped) != 128);

	slots = clamp_t(unsigned int, slots, KGUARD_RING_MIN, KGUARD_RING_MAX);
	ring_slots = roundup_pow_of_two(slots);
	nr_rings = nr_cpu_ids;
	ring_stride = PAGE_SIZE +
		      PAGE_ALIGN((size_t)ring_slots * sizeof(struct kguard_event));
	ring_area_size = PAGE_SIZE + nr_rings * ring_stride;

	/* Zeroed, page-aligned and suitable for remap_vmalloc_range() */
	ring_area = vmalloc_user(ring_area_size);
	if (!ring_area)
		return -ENOMEM;

	info = ring_area;
	info->magic = KGUARD_MMAP_MAGIC;
	info->abi_version = KGUARD_ABI_VERSION;
	info->nr_rings = nr_rings;
	info->event_size = sizeof(struct kguard_event);
	info->ring_slots = ring_slots;
	info->ring_header_size = PAGE_SIZE;
	info->ring_stride = ring_stride;
	info->rings_offset = PAGE_SIZE;
	info->mmap_size = ring_area_size;

	for (n = 0; n < nr_rings; n++)
		ring_hdr(n)->cpu = n;

	kguard_info("%u rings of %u events (%zu KiB mapped)",
		    nr_rings, ring_slots, ring_area_size / 1024);
	return 0;
}

void kguard_ring_cleanup(void)
{
	vfree(ring_area);
	ring_area = NULL;
}

void *kguard_ring_area(void)
{
	return ring_area;
}

size_t kguard_ring_area_size(void)
{
	return ring_area_size;
}

unsigned int kguard_ring_capacity(void)
{
	return nr_rings * ring_slots;
}

/*
 * Write one event to the current CPU's ring. Called from Netfilter hooks
 * (softirq or process context, never hardirq).
 */
void kguard_ring_write(const struct kguard_event *ev)
{
	struct kguard_ring_header *hdr;
	unsigned long flags;
	unsigned int cpu;
	u64 head, tail, dropped;
	u32 every;

	local_irq_save(flags);
	cpu = smp_processor_id();
	hdr = ring_hdr(cpu);
	head = READ_ONCE(hdr->head);
	/* Pairs with the reader's release of tail: the slot is free to reuse */
	tail = smp_load_acquire(&hdr->tail);

	if (unlikely(head - tail >= ring_slots)) {
		dropped = READ_ONCE(hdr->dropped) + 1;
		WRITE_ONCE(hdr->dropped, dropped);
		__this_cpu_inc(kguard_pcpu_stats.dropped);
		local_irq_restore(flags);
		trace_kguard_ring_full(cpu, dropped);
		return;
	}

	memcpy(ring_slot(hdr, head), ev, sizeof(*ev));
	/* Pairs with the reader's acquire of head: the slot is complete */
	smp_store_release(&hdr->head, head + 1);
	__this_cpu_inc(kguard_pcpu_stats.events);
	local_irq_restore(flags);

	/* Wake a sleeping reader when the ring stops being empty, then every N events */
	every = READ_ONCE(kguard_cfg.wakeup_events);
	if (head == tail || (every && (head + 1) % every == 0))
		kguard_dev_wakeup();
}

/* Events waiting in one ring, treating a corrupt tail as an empty ring */
static u64 ring_pending(struct kguard_ring_header *hdr)
{
	/* Pairs with the producer's release of head */
	u64 pending = smp_load_acquire(&hdr->head) - READ_ONCE(hdr->tail);

	return pending <= ring_slots ? pending : 0;
}

bool kguard_ring_has_data(void)
{
	unsigned int n;

	for (n = 0; n < nr_rings; n++)
		if (ring_pending(ring_hdr(n)))
			return true;
	return false;
}

u64 kguard_ring_fill(void)
{
	unsigned int n;
	u64 fill = 0;

	for (n = 0; n < nr_rings; n++)
		fill += ring_pending(ring_hdr(n));
	return fill;
}

/*
 * Kernel-side consumer for /proc/kguard. Copies up to max events into out
 * and frees their slots. The caller must hold the reader claim.
 */
unsigned int kguard_ring_drain(struct kguard_event *out, unsigned int max,
			       u64 *dropped)
{
	unsigned int n, count = 0;
	u64 total_dropped = 0;

	for (n = 0; n < nr_rings; n++) {
		struct kguard_ring_header *hdr = ring_hdr(n);
		/* Pairs with the producer's release of head: slots are complete */
		u64 head = smp_load_acquire(&hdr->head);
		u64 tail = READ_ONCE(hdr->tail);

		/* A previous reader may have left a bogus tail: start over */
		if (head - tail > ring_slots)
			tail = head;

		while (tail != head && count < max)
			out[count++] = *ring_slot(hdr, tail++);

		/* Pairs with the producer's acquire of tail: slots may be reused */
		smp_store_release(&hdr->tail, tail);
		total_dropped += READ_ONCE(hdr->dropped);
	}

	if (dropped)
		*dropped = total_dropped;
	return count;
}

/* Per-ring state for debugfs */
void kguard_ring_show(struct seq_file *m)
{
	unsigned int n;

	seq_puts(m, "ring  waiting  dropped\n");
	for (n = 0; n < nr_rings; n++) {
		struct kguard_ring_header *hdr = ring_hdr(n);

		seq_printf(m, "%4u  %7llu  %7llu\n", n, ring_pending(hdr),
			   READ_ONCE(hdr->dropped));
	}
}

bool kguard_reader_claim(void)
{
	return atomic_cmpxchg(&reader_busy, 0, 1) == 0;
}

void kguard_reader_release(void)
{
	atomic_set(&reader_busy, 0);
}
