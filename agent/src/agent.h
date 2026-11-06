/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kguard-agent: collects KGuard events on one host and ships them to the
 * backend.
 *
 *   engine (kernel module via /dev/kguard, or eBPF via libbpf)
 *       -> reader thread -> bounded queue -> sender thread -> HTTPS backend
 *
 * The queue is the backpressure point: when the backend is slow or down,
 * the sender keeps retrying the same batch with backoff while the queue
 * fills; once full, new events are dropped and counted (and the count is
 * reported to the backend with the next successful batch).
 */
#ifndef KGUARD_AGENT_H
#define KGUARD_AGENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/kguard.h>

#define AGENT_VERSION "1.0.0"

struct agent_config {
	const char *engine;		/* "module" or "ebpf" */
	const char *server;		/* backend base URL; NULL with stdout_mode */
	const char *token;		/* bearer token */
	const char *state_dir;		/* where the token file lives */
	const char *ifaces;		/* ebpf: comma-separated interfaces, NULL = all */
	bool xdp_native;		/* ebpf: native XDP instead of generic (skb) */
	bool stdout_mode;		/* print JSON lines instead of sending */
	unsigned int batch_size;
	unsigned int flush_ms;
	unsigned int queue_capacity;
	unsigned int ringbuf_mb;	/* ebpf ring buffer size */
};

extern volatile int agent_stop;

/* logging */
void agent_log(const char *level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#define log_info(...)	agent_log("info", __VA_ARGS__)
#define log_warn(...)	agent_log("warn", __VA_ARGS__)
#define log_err(...)	agent_log("error", __VA_ARGS__)

/* queue.c: bounded FIFO of events shared by the reader and sender threads */
struct queue;
struct queue *queue_new(size_t capacity);
void queue_free(struct queue *q);
void queue_push(struct queue *q, const struct kguard_event *ev);
size_t queue_pop(struct queue *q, struct kguard_event *out, size_t max, unsigned int wait_ms);
uint64_t queue_dropped(struct queue *q);
size_t queue_length(struct queue *q);
void queue_wake(struct queue *q);

/* engines: each delivers events through a callback */
typedef void (*event_cb)(const struct kguard_event *ev, void *ctx);

struct engine {
	const char *name;
	int (*open)(const struct agent_config *cfg);
	/* Wait up to timeout_ms, then deliver everything waiting. <0 on error */
	int (*poll)(int timeout_ms, event_cb cb, void *ctx);
	uint64_t (*kernel_dropped)(void);
	void (*close)(void);
};

extern const struct engine module_engine;
extern const struct engine ebpf_engine;

/* ebpf blocklist commands (engine_ebpf.c), using the pinned map */
int ebpf_block(const char *prefix, unsigned int timeout_s);
int ebpf_unblock(const char *prefix);
int ebpf_list_blocks(void);

/* procres.c: socket inode -> owning process, by scanning /proc */
bool procres_lookup(uint64_t inode, uint32_t *pid, char comm[16]);

/* json.c */
struct buf {
	char *data;
	size_t len;
	size_t cap;
};

void buf_init(struct buf *b);
void buf_free(struct buf *b);
void buf_printf(struct buf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void json_event(struct buf *b, const struct kguard_event *ev);

/* sender.c */
int sender_enroll(const char *server, const char *key, const char *name, const char *state_dir);
char *sender_load_token(const char *state_dir);
int sender_run(const struct agent_config *cfg, struct queue *q, const struct engine *eng);

#endif
