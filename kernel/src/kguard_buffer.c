/*
 * KGuard Kernel Module - Circular Buffer Implementation
 * 
 * This file implements a thread-safe circular buffer for storing network events.
 * The buffer uses spinlocks to ensure thread safety in kernel context.
 */

#include "kguard.h"

/*
 * Initialize the circular buffer
 * Allocates memory and initializes the buffer structure
 */
int kguard_buffer_init(void)
{
    /* Allocate memory for the buffer structure */
    event_buffer = kmalloc(sizeof(struct kguard_buffer), GFP_KERNEL);
    if (!event_buffer) {
        kguard_err("Failed to allocate memory for event buffer");
        return -ENOMEM;
    }

    /* Allocate memory for the events array */
    event_buffer->events = kmalloc(sizeof(struct kguard_event) * KGUARD_BUFFER_SIZE, 
                                   GFP_KERNEL);
    if (!event_buffer->events) {
        kguard_err("Failed to allocate memory for events array");
        kfree(event_buffer);
        event_buffer = NULL;
        return -ENOMEM;
    }

    /* Initialize buffer parameters */
    event_buffer->head = 0;
    event_buffer->tail = 0;
    event_buffer->size = KGUARD_BUFFER_SIZE;
    spin_lock_init(&event_buffer->lock);

    kguard_debug("Buffer initialized with size %d", KGUARD_BUFFER_SIZE);
    return 0;
}

/*
 * Cleanup the circular buffer
 * Frees allocated memory and resets pointers
 */
void kguard_buffer_cleanup(void)
{
    if (event_buffer) {
        if (event_buffer->events) {
            kfree(event_buffer->events);
        }
        kfree(event_buffer);
        event_buffer = NULL;
    }
    kguard_debug("Buffer cleaned up");
}

/*
 * Add an event to the circular buffer
 * Thread-safe operation using spinlocks
 */
int kguard_buffer_add_event(const struct kguard_event *event)
{
    unsigned long flags;
    unsigned int next_head;

    if (!event_buffer || !event) {
        return -EINVAL;
    }

    spin_lock_irqsave(&event_buffer->lock, flags);

    /* Calculate next head position */
    next_head = (event_buffer->head + 1) % event_buffer->size;

    /* Check if buffer is full (head would catch up to tail) */
    if (next_head == event_buffer->tail) {
        /* Buffer is full, overwrite oldest entry by advancing tail */
        event_buffer->tail = (event_buffer->tail + 1) % event_buffer->size;
        kguard_debug("Buffer full, overwriting oldest entry");
    }

    /* Copy the event to the buffer */
    memcpy(&event_buffer->events[event_buffer->head], event, 
           sizeof(struct kguard_event));

    /* Update head pointer */
    event_buffer->head = next_head;

    spin_unlock_irqrestore(&event_buffer->lock, flags);

    kguard_debug("Event added to buffer at position %d", event_buffer->head);
    return 0;
}

/*
 * Get events from the circular buffer
 * Copies events to the provided array and returns the number of events copied
 */
int kguard_buffer_get_events(struct kguard_event *events, int max_events)
{
    unsigned long flags;
    int count = 0;
    unsigned int current;

    if (!event_buffer || !events || max_events <= 0) {
        return -EINVAL;
    }

    spin_lock_irqsave(&event_buffer->lock, flags);

    current = event_buffer->tail;

    /* Copy events from tail to head */
    while (current != event_buffer->head && count < max_events) {
        memcpy(&events[count], &event_buffer->events[current], 
               sizeof(struct kguard_event));
        current = (current + 1) % event_buffer->size;
        count++;
    }

    /* Update tail to mark events as read */
    event_buffer->tail = current;

    spin_unlock_irqrestore(&event_buffer->lock, flags);

    kguard_debug("Retrieved %d events from buffer", count);
    return count;
}

/*
 * Get the number of events currently in the buffer
 */
static int kguard_buffer_count(void)
{
    unsigned long flags;
    int count;

    if (!event_buffer) {
        return 0;
    }

    spin_lock_irqsave(&event_buffer->lock, flags);

    if (event_buffer->head >= event_buffer->tail) {
        count = event_buffer->head - event_buffer->tail;
    } else {
        count = event_buffer->size - event_buffer->tail + event_buffer->head;
    }

    spin_unlock_irqrestore(&event_buffer->lock, flags);

    return count;
}