// SPDX-License-Identifier: GPL-2.0
/*
 * Shipping events to the backend.
 *
 *   enroll:  POST {server}/api/agents/enroll   (X-Enrollment-Key)
 *            -> {"agent_id": N, "token": "..."}; token saved 0600
 *   ingest:  POST {server}/api/agents/ingest   (Authorization: Bearer)
 *            body: {"agent": {...}, "kernel_dropped": N, "queue_dropped": N,
 *                   "payload_dropped": N, "events": [ ... ], "payloads": [ ... ]}
 *
 * A batch is retried until the backend accepts it (exponential backoff up
 * to 30 s), so events are not lost while the backend restarts; meanwhile
 * the queue absorbs new events, dropping and counting them once full.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <curl/curl.h>
#include "agent.h"

#define TOKEN_FILE	"token"
#define MAX_BACKOFF_MS	30000

static size_t collect_body(char *data, size_t size, size_t nmemb, void *userp)
{
	struct buf *b = userp;

	buf_printf(b, "%.*s", (int)(size * nmemb), data);
	return size * nmemb;
}

/* POST JSON; returns the HTTP status (0 when the request did not complete) */
static long post_json(CURL *curl, const char *url, const char *auth_header,
		      const char *body, size_t len, struct buf *reply)
{
	struct curl_slist *headers = NULL;
	long status = 0;
	CURLcode rc;

	headers = curl_slist_append(headers, "Content-Type: application/json");
	if (auth_header)
		headers = curl_slist_append(headers, auth_header);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)len);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, collect_body);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, reply);
	rc = curl_easy_perform(curl);
	if (rc == CURLE_OK)
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
	else
		log_warn("POST %s: %s", url, curl_easy_strerror(rc));
	curl_slist_free_all(headers);
	return status;
}

static void hostname(char *out, size_t size)
{
	if (gethostname(out, size))
		snprintf(out, size, "unknown");
	out[size - 1] = '\0';
}

/* Pull a string value out of a flat JSON object (the server's own replies) */
static char *json_string(const char *json, const char *key)
{
	char pattern[64];
	const char *p, *end;

	snprintf(pattern, sizeof(pattern), "\"%s\"", key);
	p = strstr(json, pattern);
	if (!p)
		return NULL;
	p = strchr(p + strlen(pattern), '"');
	if (!p)
		return NULL;
	end = strchr(++p, '"');
	return end ? strndup(p, end - p) : NULL;
}

int sender_enroll(const char *server, const char *key, const char *name, const char *state_dir)
{
	char url[1024], header[512], host[256], path[1024];
	struct buf body, reply;
	char *token;
	long status;
	CURL *curl;
	FILE *f;

	hostname(host, sizeof(host));
	snprintf(url, sizeof(url), "%s/api/agents/enroll", server);
	snprintf(header, sizeof(header), "X-Enrollment-Key: %s", key);
	buf_init(&body);
	buf_init(&reply);
	/* name and hostname go through %s: keep them to safe characters */
	for (const char *c = name; *c; c++)
		if (*c == '"' || *c == '\\' || (unsigned char)*c < 0x20) {
			fprintf(stderr, "agent name contains characters that are not allowed\n");
			return 2;
		}
	buf_printf(&body, "{\"name\":\"%s\",\"hostname\":\"%s\"}", name, host);

	curl = curl_easy_init();
	status = post_json(curl, url, header, body.data, body.len, &reply);
	curl_easy_cleanup(curl);
	if (status != 200 && status != 201) {
		fprintf(stderr, "enrollment failed (HTTP %ld): %s\n", status, reply.data);
		return 1;
	}
	token = json_string(reply.data, "token");
	if (!token) {
		fprintf(stderr, "enrollment reply has no token: %s\n", reply.data);
		return 1;
	}

	mkdir(state_dir, 0700);
	snprintf(path, sizeof(path), "%s/%s", state_dir, TOKEN_FILE);
	umask(077);
	f = fopen(path, "w");
	if (!f || fprintf(f, "%s\n", token) < 0 || fclose(f)) {
		fprintf(stderr, "cannot write %s: %s\n", path, strerror(errno));
		return 1;
	}
	printf("enrolled as '%s'; token saved to %s\n", name, path);
	free(token);
	buf_free(&body);
	buf_free(&reply);
	return 0;
}

char *sender_load_token(const char *state_dir)
{
	char path[1024], line[512];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", state_dir, TOKEN_FILE);
	f = fopen(path, "r");
	if (!f)
		return NULL;
	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return NULL;
	}
	fclose(f);
	line[strcspn(line, "\r\n")] = '\0';
	return strdup(line);
}

static void sleep_ms(unsigned int ms)
{
	struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L };

	while (!agent_stop && nanosleep(&ts, &ts) && errno == EINTR)
		;
}

/* Payload samples per batch (each up to ~2 KB of JSON) */
#define PAYLOADS_PER_BATCH	256

static void free_strings(char **s, size_t n)
{
	while (n--)
		free(s[n]);
}

int sender_run(const struct agent_config *cfg, struct queue *q, struct strqueue *pq,
	       const struct engine *eng)
{
	struct kguard_event *batch = calloc(cfg->batch_size, sizeof(*batch));
	char *payloads[PAYLOADS_PER_BATCH];
	size_t np;
	char url[1024], auth[600], host[256];
	unsigned int backoff = 0;
	uint64_t sent = 0;
	CURL *curl = NULL;
	struct buf body;
	size_t n, i;

	if (!batch)
		return -1;
	hostname(host, sizeof(host));
	buf_init(&body);
	if (!cfg->stdout_mode) {
		curl = curl_easy_init();	/* reused: keeps the connection open */
		snprintf(url, sizeof(url), "%s/api/agents/ingest", cfg->server);
		snprintf(auth, sizeof(auth), "Authorization: Bearer %s", cfg->token);
	}

	while (!agent_stop || queue_length(q) || strqueue_length(pq)) {
		n = queue_pop(q, batch, cfg->batch_size, cfg->flush_ms);
		np = strqueue_pop(pq, payloads, PAYLOADS_PER_BATCH);
		if (!n && !np)
			continue;

		if (cfg->stdout_mode) {
			for (i = 0; i < n; i++) {
				body.len = 0;
				json_event(&body, &batch[i]);
				puts(body.data);
			}
			for (i = 0; i < np; i++)
				puts(payloads[i]);
			free_strings(payloads, np);
			fflush(stdout);
			continue;
		}

		body.len = 0;
		buf_printf(&body,
			   "{\"agent\":{\"engine\":\"%s\",\"version\":\"%s\",\"hostname\":\"%s\"},"
			   "\"kernel_dropped\":%llu,\"queue_dropped\":%llu,\"payload_dropped\":%llu,"
			   "\"events\":[",
			   eng->name, AGENT_VERSION, host,
			   (unsigned long long)eng->kernel_dropped(),
			   (unsigned long long)queue_dropped(q),
			   (unsigned long long)strqueue_dropped(pq));
		for (i = 0; i < n; i++) {
			if (i)
				buf_printf(&body, ",");
			json_event(&body, &batch[i]);
		}
		buf_printf(&body, "],\"payloads\":[");
		for (i = 0; i < np; i++)
			buf_printf(&body, "%s%s", i ? "," : "", payloads[i]);
		buf_printf(&body, "]}");
		free_strings(payloads, np);

		/* Retry this batch until accepted; the queue keeps filling meanwhile */
		for (;;) {
			struct buf reply;
			long status;

			buf_init(&reply);
			status = post_json(curl, url, auth, body.data, body.len, &reply);
			buf_free(&reply);
			if (status == 200) {
				sent += n;
				if (backoff)
					log_info("backend reachable again; %zu events queued", queue_length(q));
				backoff = 0;
				break;
			}
			if (status == 401 || status == 403)
				log_err("backend rejected the agent token (HTTP %ld); re-enroll?", status);
			else if (status == 413 || status == 422)
				log_err("backend refused the batch (HTTP %ld); dropping it", status);
			else
				log_warn("backend unavailable (HTTP %ld); retrying", status);
			if (status == 413 || status == 422)
				break;
			backoff = backoff ? (backoff * 2 > MAX_BACKOFF_MS ? MAX_BACKOFF_MS : backoff * 2) : 500;
			sleep_ms(backoff);
			if (agent_stop)
				break;
		}
		if (agent_stop && backoff)
			break;	/* backend down at shutdown: give up the rest */
	}

	log_info("sender stopped: %llu events sent, %llu dropped in queue",
		 (unsigned long long)sent, (unsigned long long)queue_dropped(q));
	if (curl)
		curl_easy_cleanup(curl);
	buf_free(&body);
	free(batch);
	return 0;
}
