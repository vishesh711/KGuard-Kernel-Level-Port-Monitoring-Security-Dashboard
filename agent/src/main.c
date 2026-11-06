// SPDX-License-Identifier: GPL-2.0
/*
 * kguard-agent
 *
 *   kguard-agent enroll --server URL --key KEY --name NAME [--state-dir DIR]
 *   kguard-agent run --engine module|ebpf (--server URL | --stdout) [options]
 *   kguard-agent block PREFIX [--timeout SECONDS]     (ebpf engine)
 *   kguard-agent unblock PREFIX
 *   kguard-agent blocks
 */

#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>
#include "agent.h"

volatile int agent_stop;

static struct queue *queue;
static struct strqueue *payload_queue;
static const struct engine *engine;

void agent_log(const char *level, const char *fmt, ...)
{
	char stamp[32];
	time_t now = time(NULL);
	va_list ap;

	strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%S", localtime(&now));
	fprintf(stderr, "%s kguard-agent %s: ", stamp, level);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static void on_signal(int sig)
{
	(void)sig;
	agent_stop = 1;
}

static void push_event(const struct kguard_event *ev, void *ctx)
{
	queue_push(ctx, ev);
}

static void push_payload(const struct kguard_payload *p, void *ctx)
{
	struct buf b;

	buf_init(&b);
	json_payload(&b, p);
	if (b.data)
		strqueue_push(ctx, b.data);	/* the queue now owns the string */
	else
		buf_free(&b);
}

static void *reader_thread(void *arg)
{
	(void)arg;
	while (!agent_stop) {
		if (engine->poll(200, push_event, queue) < 0) {
			log_err("engine %s failed; stopping", engine->name);
			agent_stop = 1;
		}
	}
	queue_wake(queue);
	return NULL;
}

static void usage(void)
{
	fprintf(stderr,
		"usage:\n"
		"  kguard-agent enroll --server URL --key KEY --name NAME [--state-dir DIR]\n"
		"  kguard-agent run --engine module|ebpf (--server URL | --stdout)\n"
		"                   [--state-dir DIR] [--token TOKEN] [--iface lo,eth0]\n"
		"                   [--xdp-native] [--batch N] [--flush-ms N] [--queue N]\n"
		"                   [--ringbuf-mb N] [--no-payloads]\n"
		"  kguard-agent block PREFIX [--timeout SECONDS]   (eBPF engine)\n"
		"  kguard-agent unblock PREFIX\n"
		"  kguard-agent blocks\n");
}

int main(int argc, char **argv)
{
	struct agent_config cfg = {
		.engine = "module",
		.state_dir = "/var/lib/kguard-agent",
		.batch_size = 5000,
		.flush_ms = 500,
		.queue_capacity = 200000,
		.ringbuf_mb = 8,
	};
	static const struct option opts[] = {
		{ "engine", required_argument, NULL, 'e' },
		{ "server", required_argument, NULL, 's' },
		{ "token", required_argument, NULL, 'T' },
		{ "key", required_argument, NULL, 'k' },
		{ "name", required_argument, NULL, 'n' },
		{ "state-dir", required_argument, NULL, 'd' },
		{ "iface", required_argument, NULL, 'i' },
		{ "xdp-native", no_argument, NULL, 'x' },
		{ "stdout", no_argument, NULL, 'o' },
		{ "batch", required_argument, NULL, 'b' },
		{ "flush-ms", required_argument, NULL, 'f' },
		{ "queue", required_argument, NULL, 'q' },
		{ "ringbuf-mb", required_argument, NULL, 'r' },
		{ "no-payloads", no_argument, NULL, 'P' },
		{ "timeout", required_argument, NULL, 't' },
		{ "help", no_argument, NULL, 'h' },
		{ 0 },
	};
	const char *command, *key = NULL, *name = NULL;
	unsigned int timeout = 0;
	pthread_t reader;
	int opt, ret;

	if (argc < 2) {
		usage();
		return 2;
	}
	command = argv[1];
	optind = 2;
	while ((opt = getopt_long(argc, argv, "h", opts, NULL)) != -1) {
		switch (opt) {
		case 'e': cfg.engine = optarg; break;
		case 's': cfg.server = optarg; break;
		case 'T': cfg.token = optarg; break;
		case 'k': key = optarg; break;
		case 'n': name = optarg; break;
		case 'd': cfg.state_dir = optarg; break;
		case 'i': cfg.ifaces = optarg; break;
		case 'x': cfg.xdp_native = true; break;
		case 'o': cfg.stdout_mode = true; break;
		case 'P': cfg.no_payloads = true; break;
		case 'b': cfg.batch_size = strtoul(optarg, NULL, 10); break;
		case 'f': cfg.flush_ms = strtoul(optarg, NULL, 10); break;
		case 'q': cfg.queue_capacity = strtoul(optarg, NULL, 10); break;
		case 'r': cfg.ringbuf_mb = strtoul(optarg, NULL, 10); break;
		case 't': timeout = strtoul(optarg, NULL, 10); break;
		default: usage(); return 2;
		}
	}

	if (!strcmp(command, "block") || !strcmp(command, "unblock")) {
		if (optind >= argc) {
			usage();
			return 2;
		}
		return !strcmp(command, "block") ? ebpf_block(argv[optind], timeout)
						 : ebpf_unblock(argv[optind]);
	}
	if (!strcmp(command, "blocks"))
		return ebpf_list_blocks();

	curl_global_init(CURL_GLOBAL_DEFAULT);

	if (!strcmp(command, "enroll")) {
		if (!cfg.server || !key || !name) {
			usage();
			return 2;
		}
		return sender_enroll(cfg.server, key, name, cfg.state_dir);
	}
	if (strcmp(command, "run")) {
		usage();
		return 2;
	}

	if (!strcmp(cfg.engine, "module")) {
		engine = &module_engine;
	} else if (!strcmp(cfg.engine, "ebpf")) {
		engine = &ebpf_engine;
	} else {
		fprintf(stderr, "unknown engine '%s' (module or ebpf)\n", cfg.engine);
		return 2;
	}
	if (!cfg.stdout_mode) {
		if (!cfg.server) {
			fprintf(stderr, "--server URL (or --stdout) is required\n");
			return 2;
		}
		if (!cfg.token)
			cfg.token = sender_load_token(cfg.state_dir);
		if (!cfg.token) {
			fprintf(stderr, "no token: run 'kguard-agent enroll' first, or pass --token\n");
			return 2;
		}
	}
	if (!cfg.batch_size || !cfg.queue_capacity || !cfg.ringbuf_mb) {
		fprintf(stderr, "--batch, --queue and --ringbuf-mb must be positive\n");
		return 2;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGPIPE, SIG_IGN);

	queue = queue_new(cfg.queue_capacity);
	payload_queue = strqueue_new(4096);
	if (!payload_queue)
		return 1;
	if (engine->set_payload_cb)
		engine->set_payload_cb(push_payload, payload_queue);
	if (!queue || engine->open(&cfg)) {
		if (engine)
			engine->close();
		return 1;
	}
	log_info("running: engine=%s, %s", engine->name,
		 cfg.stdout_mode ? "printing to stdout" : cfg.server);

	pthread_create(&reader, NULL, reader_thread, NULL);
	ret = sender_run(&cfg, queue, payload_queue, engine);
	agent_stop = 1;
	pthread_join(reader, NULL);

	log_info("kernel dropped %llu events", (unsigned long long)engine->kernel_dropped());
	engine->close();
	queue_free(queue);
	strqueue_free(payload_queue);
	curl_global_cleanup();
	return ret ? 1 : 0;
}
