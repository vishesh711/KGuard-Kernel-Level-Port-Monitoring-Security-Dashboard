// SPDX-License-Identifier: GPL-2.0
/*
 * Bounded FIFO of events between the reader and sender threads.
 * When full, new events are dropped and counted: the reader must never
 * block, or the kernel's own buffers would overflow instead.
 */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include "agent.h"

struct queue {
	pthread_mutex_t lock;
	pthread_cond_t ready;
	struct kguard_event *items;
	size_t capacity;
	size_t head;	/* next to pop */
	size_t count;
	uint64_t dropped;
};

struct queue *queue_new(size_t capacity)
{
	struct queue *q = calloc(1, sizeof(*q));

	if (!q)
		return NULL;
	q->items = calloc(capacity, sizeof(*q->items));
	if (!q->items) {
		free(q);
		return NULL;
	}
	q->capacity = capacity;
	pthread_mutex_init(&q->lock, NULL);
	pthread_cond_init(&q->ready, NULL);
	return q;
}

void queue_free(struct queue *q)
{
	if (!q)
		return;
	pthread_mutex_destroy(&q->lock);
	pthread_cond_destroy(&q->ready);
	free(q->items);
	free(q);
}

void queue_push(struct queue *q, const struct kguard_event *ev)
{
	pthread_mutex_lock(&q->lock);
	if (q->count == q->capacity) {
		q->dropped++;
	} else {
		q->items[(q->head + q->count) % q->capacity] = *ev;
		q->count++;
		pthread_cond_signal(&q->ready);
	}
	pthread_mutex_unlock(&q->lock);
}

/* Take up to max events, waiting up to wait_ms for the first one */
size_t queue_pop(struct queue *q, struct kguard_event *out, size_t max, unsigned int wait_ms)
{
	struct timespec deadline;
	size_t n = 0;

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += wait_ms / 1000;
	deadline.tv_nsec += (long)(wait_ms % 1000) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000L;
	}

	pthread_mutex_lock(&q->lock);
	while (!q->count && !agent_stop) {
		if (pthread_cond_timedwait(&q->ready, &q->lock, &deadline) == ETIMEDOUT)
			break;
	}
	while (q->count && n < max) {
		out[n++] = q->items[q->head];
		q->head = (q->head + 1) % q->capacity;
		q->count--;
	}
	pthread_mutex_unlock(&q->lock);
	return n;
}

uint64_t queue_dropped(struct queue *q)
{
	uint64_t d;

	pthread_mutex_lock(&q->lock);
	d = q->dropped;
	pthread_mutex_unlock(&q->lock);
	return d;
}

size_t queue_length(struct queue *q)
{
	size_t n;

	pthread_mutex_lock(&q->lock);
	n = q->count;
	pthread_mutex_unlock(&q->lock);
	return n;
}

void queue_wake(struct queue *q)
{
	pthread_mutex_lock(&q->lock);
	pthread_cond_broadcast(&q->ready);
	pthread_mutex_unlock(&q->lock);
}
