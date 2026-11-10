// SPDX-License-Identifier: GPL-2.0
/*
 * Blocklist sync (roadmap S6.4): every --sync-seconds, fetch this host's
 * blocklist from the backend and make the engine match it.
 *
 *   GET /api/agents/blocklist?applied=<version>&failed=<n>&enforcing=<0|1>
 *
 *   version 3f2a9c0d1e4b5a6f
 *   lease 300
 *   block 203.0.113.7/32 1794250000      (expiry in Unix seconds, 0 = none)
 *
 * Every entry is installed as a lease: the engine drops it by itself after
 * min(lease, time left) seconds unless it is renewed, and the agent renews
 * it halfway. Entries that leave the list are removed at once. So:
 *   - an unblock reaches the kernel within one sync;
 *   - entries left behind by a crash or restart end within one lease;
 *   - while the backend is unreachable, the agent keeps renewing the last
 *     list it had (until each entry's own expiry), so blocks hold.
 *
 * Only entries this agent added are ever removed; blocks made by hand
 * (kguard-agent block, kguardctl) are left alone.
 */

#include <curl/curl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "agent.h"

struct entry {
	char prefix[64];
	int64_t expires;	/* Unix seconds, 0 = none */
	int64_t renew_at;	/* when to renew the lease */
	bool seen;		/* in the latest list */
};

static struct entry *managed;
static size_t n_managed, cap_managed;

static size_t collect(char *data, size_t size, size_t nmemb, void *userp)
{
	struct buf *b = userp;

	if (b->len + size * nmemb > 16 * 1024 * 1024)
		return 0;	/* refuse absurd replies */
	buf_printf(b, "%.*s", (int)(size * nmemb), data);
	return size * nmemb;
}

static struct entry *find(const char *prefix)
{
	for (size_t i = 0; i < n_managed; i++)
		if (!strcmp(managed[i].prefix, prefix))
			return &managed[i];
	return NULL;
}

static struct entry *add_managed(const char *prefix)
{
	if (n_managed == cap_managed) {
		size_t cap = cap_managed ? cap_managed * 2 : 64;
		struct entry *grown = realloc(managed, cap * sizeof(*grown));

		if (!grown)
			return NULL;
		managed = grown;
		cap_managed = cap;
	}
	memset(&managed[n_managed], 0, sizeof(*managed));
	snprintf(managed[n_managed].prefix, sizeof(managed->prefix), "%s", prefix);
	return &managed[n_managed++];
}

/* Install or renew one lease; returns 0 or -errno */
static int apply(const struct engine *eng, struct entry *e, int64_t now, unsigned int lease)
{
	int64_t timeout = lease;
	int ret;

	if (e->expires && e->expires - now < timeout)
		timeout = e->expires - now;
	if (timeout <= 0)
		return 0;
	ret = eng->block(e->prefix, (unsigned int)timeout);
	if (!ret)
		e->renew_at = now + timeout / 2;
	return ret;
}

/*
 * Make the engine match the list in `body`. Returns the number of entries
 * that could not be applied; *version gets the list's version.
 */
static unsigned int reconcile(const struct engine *eng, char *body, char version[32],
			      unsigned int *lease)
{
	int64_t now = time(NULL);
	unsigned int failed = 0;
	char *line, *save = NULL;

	for (size_t i = 0; i < n_managed; i++)
		managed[i].seen = false;

	for (line = strtok_r(body, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		char prefix[64];
		long long expires;
		struct entry *e;
		bool is_new;
		int ret;

		if (sscanf(line, "version %31s", version) == 1 || sscanf(line, "lease %u", lease) == 1)
			continue;
		if (sscanf(line, "block %63s %lld", prefix, &expires) != 2)
			continue;
		if (expires && expires <= now)
			continue;	/* already over */
		e = find(prefix);
		is_new = !e;
		if (is_new && !(e = add_managed(prefix))) {
			failed++;
			continue;
		}
		e->seen = true;
		if (!is_new && e->expires == expires && now < e->renew_at)
			continue;	/* lease still good */
		e->expires = expires;
		ret = apply(eng, e, now, *lease);
		if (ret) {
			failed++;
			log_warn("blocklist: cannot block %s: %s", prefix, strerror(-ret));
			if (is_new)
				n_managed--;	/* never installed */
		} else if (is_new) {
			log_info("blocklist: blocking %s%s", prefix, expires ? "" : " until unblocked");
		}
	}

	/* Gone from the list: remove now */
	for (size_t i = 0; i < n_managed;) {
		if (managed[i].seen) {
			i++;
			continue;
		}
		int ret = eng->unblock(managed[i].prefix);

		if (ret && ret != -ENOENT) {
			failed++;
			log_warn("blocklist: cannot unblock %s: %s", managed[i].prefix, strerror(-ret));
			i++;
			continue;
		}
		log_info("blocklist: unblocked %s", managed[i].prefix);
		managed[i] = managed[--n_managed];
	}
	return failed;
}

/* Backend unreachable: keep the last list's leases alive */
static void renew_known(const struct engine *eng, unsigned int lease)
{
	int64_t now = time(NULL);

	for (size_t i = 0; i < n_managed; i++) {
		struct entry *e = &managed[i];

		if (now >= e->renew_at && (!e->expires || e->expires > now))
			apply(eng, e, now, lease);
	}
}

static void sleep_seconds(unsigned int seconds)
{
	for (unsigned int i = 0; i < seconds * 5 && !agent_stop; i++) {
		struct timespec ts = { .tv_nsec = 200 * 1000000L };

		nanosleep(&ts, NULL);
	}
}

/* This host's listening ports and connections, for the dashboard's process view */
static void report_sockets(CURL *curl, const char *server, struct curl_slist *auth)
{
	struct curl_slist *headers = NULL;
	struct buf body, reply;
	char url[1100];

	for (struct curl_slist *h = auth; h; h = h->next)
		headers = curl_slist_append(headers, h->data);
	headers = curl_slist_append(headers, "Content-Type: application/json");
	buf_init(&body);
	buf_init(&reply);
	sockets_json(&body);
	snprintf(url, sizeof(url), "%s/api/agents/sockets", server);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.len);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &reply);
	curl_easy_perform(curl);	/* best effort: the next round sends a fresh one */
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, NULL);
	curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
	buf_free(&body);
	buf_free(&reply);
	curl_slist_free_all(headers);
}

void *blocksync_thread(void *arg)
{
	const struct blocksync_args *a = arg;
	const struct engine *eng = a->engine;
	char version[32] = "", auth[600], url[1200];
	unsigned int failed = 0, lease = 300;
	int last_enforcing = 1;
	bool warned = false;
	CURL *curl = curl_easy_init();
	struct curl_slist *headers;

	if (!curl)
		return NULL;
	snprintf(auth, sizeof(auth), "Authorization: Bearer %s", a->cfg->token);
	headers = curl_slist_append(NULL, auth);
	log_info("blocklist sync every %us", a->cfg->sync_seconds);

	while (!agent_stop) {
		struct buf body;
		long status = 0;
		int enforcing = eng->enforcing();

		buf_init(&body);
		snprintf(url, sizeof(url), "%s/api/agents/blocklist?applied=%s&failed=%u%s", a->cfg->server,
			 version, failed, enforcing < 0 ? "" : enforcing ? "&enforcing=1" : "&enforcing=0");
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, collect);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
		if (curl_easy_perform(curl) == CURLE_OK)
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

		if (status == 200 && body.data) {
			failed = reconcile(eng, body.data, version, &lease);
			if (warned)
				log_info("blocklist sync working again");
			warned = false;
		} else {
			if (!warned)
				log_warn("blocklist sync failed (HTTP %ld); keeping the last list", status);
			warned = true;
			renew_known(eng, lease);
		}
		if (enforcing == 0 && last_enforcing != 0)
			log_warn("kernel module is monitor-only (enforce=0): blocks are recorded, not enforced");
		last_enforcing = enforcing;
		buf_free(&body);
		report_sockets(curl, a->cfg->server, headers);
		sleep_seconds(a->cfg->sync_seconds);
	}
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	return NULL;
}
