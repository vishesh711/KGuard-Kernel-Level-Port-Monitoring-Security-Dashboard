// SPDX-License-Identifier: GPL-2.0
/*
 * KGuard Kernel Module - Circular Buffer Implementation
 *
 * A circular buffer of network events shared between the Netfilter hook
 * (producer, softirq context) and /proc readers (consumer, process context).
 * A spinlock with interrupts disabled protects head, tail and the counters.
 */

#include "kguard.h"

static unsigned int buffer_size = KGUARD_BUFFER_DEFAULT;
module_param(buffer_size, uint, 0444);
MODULE_PARM_DESC(buffer_size,
		 "Number of events the buffer can hold (64 to 1048576, default 65536)");

/*
 * Initialize the circular buffer
 */
int kguard_buffer_init(void)
{
	unsigned int size = clamp_t(unsigned int, buffer_size,
				    KGUARD_BUFFER_MIN, KGUARD_BUFFER_MAX);

	if (size != buffer_size)
		kguard_warn("buffer_size %u out of range, using %u", buffer_size, size);

	event_buffer = kzalloc(sizeof(*event_buffer), GFP_KERNEL);
	if (!event_buffer)
		return -ENOMEM;

	/* One slot stays empty to tell "full" from "empty", so allocate size + 1 */
	event_buffer->events = kvcalloc(size + 1, sizeof(struct kguard_event),
					GFP_KERNEL);
	if (!event_buffer->events) {
		kfree(event_buffer);
		event_buffer = NULL;
		return -ENOMEM;
	}

	event_buffer->size = size + 1;
	spin_lock_init(&event_buffer->lock);

	kguard_info("Event buffer holds %u events", size);
	return 0;
}

/*
 * Free the circular buffer.
 * Called only after the Netfilter hook and /proc entry are gone.
 */
void kguard_buffer_cleanup(void)
{
	if (!event_buffer)
		return;

	kvfree(event_buffer->events);
	kfree(event_buffer);
	event_buffer = NULL;
}

/*
 * Number of events the buffer can hold at once
 */
unsigned int kguard_buffer_capacity(void)
{
	return event_buffer ? event_buffer->size - 1 : 0;
}

/*
 * Add an event, overwriting the oldest one when the buffer is full.
 * Called from the Netfilter hook in softirq context.
 */
int kguard_buffer_add_event(const struct kguard_event *event)
{
	unsigned long flags;
	unsigned int next_head;

	if (!event_buffer || !event)
		return -EINVAL;

	spin_lock_irqsave(&event_buffer->lock, flags);

	next_head = (event_buffer->head + 1) % event_buffer->size;

	if (next_head == event_buffer->tail) {
		/* Full: drop the oldest event to make room */
		event_buffer->tail = (event_buffer->tail + 1) % event_buffer->size;
		event_buffer->dropped++;
	}

	event_buffer->events[event_buffer->head] = *event;
	event_buffer->head = next_head;

	spin_unlock_irqrestore(&event_buffer->lock, flags);
	return 0;
}

/*
 * Move up to max_events events out of the buffer into the caller's array.
 * Returns the number of events copied. If dropped is not NULL, it receives
 * the total number of events overwritten since the module was loaded.
 */
int kguard_buffer_drain(struct kguard_event *events, unsigned int max_events,
			u64 *dropped)
{
	unsigned long flags;
	unsigned int count = 0;
	unsigned int pos;

	if (!event_buffer || !events)
		return -EINVAL;

	spin_lock_irqsave(&event_buffer->lock, flags);

	pos = event_buffer->tail;
	while (pos != event_buffer->head && count < max_events) {
		events[count++] = event_buffer->events[pos];
		pos = (pos + 1) % event_buffer->size;
	}
	event_buffer->tail = pos;

	if (dropped)
		*dropped = event_buffer->dropped;

	spin_unlock_irqrestore(&event_buffer->lock, flags);

	return count;
}
