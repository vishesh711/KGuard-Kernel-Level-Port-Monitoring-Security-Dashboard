// SPDX-License-Identifier: GPL-2.0
/*
 * eBPF engine: load bpf/kguard.bpf.c through its libbpf skeleton, attach
 * XDP (ingress) and TC clsact egress to the chosen interfaces and the
 * tracing programs for process ownership, then read the BPF ring buffer.
 *
 * The blocklist map is pinned in bpffs so `kguard-agent block` can change
 * it while the agent runs, and so blocks survive agent restarts.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "agent.h"
#include "kguard.skel.h"

#define BPFFS			"/sys/fs/bpf"
#define BLOCKLIST_PIN		BPFFS "/kguard_blocklist"
#define BPF_FS_MAGIC_NUMBER	0xcafe4a11
#define MAX_IFACES		64

/* Same layouts as in kguard.bpf.c */
struct lpm_key {
	uint32_t prefixlen;
	uint8_t addr[16];
};

struct block_value {
	uint64_t expires_ns;
	uint64_t drops;
};

struct counters {
	uint64_t packets;
	uint64_t events;
	uint64_t ringbuf_full;
	uint64_t blocked;
};

/* Same as struct port_key / struct owner in kguard.bpf.c */
struct port_key {
	uint16_t port;
	uint8_t protocol;
	uint8_t pad;
};

struct owner {
	uint32_t pid;
	uint32_t uid;
	char comm[16];
};

struct attached {
	int ifindex;
	bool xdp;
	bool tc;
	bool tc_hook_created;
};

static struct kguard_bpf *skel;
static struct ring_buffer *rb;
static struct attached ifaces[MAX_IFACES];
static int nr_ifaces;
static uint32_t xdp_flags;
static int64_t mono_to_real;	/* realtime - monotonic, ns */
static double last_offset_update;

static event_cb current_cb;
static void *current_ctx;

static int64_t clock_ns(clockid_t id)
{
	struct timespec ts;

	clock_gettime(id, &ts);
	return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void update_clock_offset(void)
{
	mono_to_real = clock_ns(CLOCK_REALTIME) - clock_ns(CLOCK_MONOTONIC);
	last_offset_update = clock_ns(CLOCK_MONOTONIC) / 1e9;
}

static int ensure_bpffs(void)
{
	struct statfs st;

	if (!statfs(BPFFS, &st) && st.f_type == BPF_FS_MAGIC_NUMBER)
		return 0;
	if (mount("bpf", BPFFS, "bpf", 0, NULL)) {
		log_warn("cannot mount bpffs at %s: %s (blocklist will not be pinned)",
			 BPFFS, strerror(errno));
		return -1;
	}
	return 0;
}

static int attach_iface(int ifindex, const char *name)
{
	struct attached *a = &ifaces[nr_ifaces];
	LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_EGRESS);
	LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1,
		    .prog_fd = bpf_program__fd(skel->progs.kguard_tc_egress));
	int err;

	if (nr_ifaces == MAX_IFACES)
		return -1;
	memset(a, 0, sizeof(*a));
	a->ifindex = ifindex;

	err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.kguard_xdp), xdp_flags, NULL);
	if (err) {
		log_warn("%s: XDP attach failed: %s", name, strerror(-err));
	} else {
		a->xdp = true;
	}

	err = bpf_tc_hook_create(&hook);
	if (err && err != -EEXIST) {
		log_warn("%s: tc hook failed: %s", name, strerror(-err));
	} else {
		a->tc_hook_created = !err;
		err = bpf_tc_attach(&hook, &opts);
		if (err)
			log_warn("%s: tc attach failed: %s", name, strerror(-err));
		else
			a->tc = true;
	}

	if (a->xdp || a->tc) {
		nr_ifaces++;
		log_info("ebpf engine: attached to %s (XDP %s, TC egress %s)", name,
			 a->xdp ? (xdp_flags & XDP_FLAGS_DRV_MODE ? "native" : "generic") : "no",
			 a->tc ? "yes" : "no");
	}
	return 0;
}

static void detach_all(void)
{
	int i;

	for (i = 0; i < nr_ifaces; i++) {
		struct attached *a = &ifaces[i];
		LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = a->ifindex, .attach_point = BPF_TC_EGRESS);
		LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1);

		if (a->xdp)
			bpf_xdp_detach(a->ifindex, xdp_flags, NULL);
		if (a->tc) {
			bpf_tc_detach(&hook, &opts);
			if (a->tc_hook_created)
				bpf_tc_hook_destroy(&hook);
		}
	}
	nr_ifaces = 0;
}

static int on_event(void *ctx, void *data, size_t size)
{
	struct kguard_event ev;

	(void)ctx;
	if (size < sizeof(ev))
		return 0;
	memcpy(&ev, data, sizeof(ev));
	ev.timestamp_ns += mono_to_real;
	current_cb(&ev, current_ctx);
	return 0;
}

/*
 * Services that were already listening (or had UDP ports bound) before the
 * agent started never pass through the listen/bind hooks. Seed their
 * owners from /proc/net/{tcp,tcp6,udp,udp6}, resolving each socket inode to
 * its process.
 */
static void seed_port_owners(void)
{
	static const struct {
		const char *path;
		uint8_t protocol;
	} tables[] = {
		{ "/proc/net/tcp", 6 }, { "/proc/net/tcp6", 6 },
		{ "/proc/net/udp", 17 }, { "/proc/net/udp6", 17 },
	};
	int fd = bpf_map__fd(skel->maps.port_owner);
	unsigned int seeded = 0;
	size_t t;

	for (t = 0; t < sizeof(tables) / sizeof(tables[0]); t++) {
		FILE *f = fopen(tables[t].path, "r");
		char line[512];

		if (!f)
			continue;
		if (!fgets(line, sizeof(line), f)) {	/* header */
			fclose(f);
			continue;
		}
		while (fgets(line, sizeof(line), f)) {
			unsigned int port, state, uid;
			unsigned long long inode;
			struct port_key key = { .protocol = tables[t].protocol };
			struct owner owner = {};

			if (sscanf(line, "%*d: %*[0-9A-Fa-f]:%x %*[0-9A-Fa-f]:%*x %x %*s %*s %*s %u %*d %llu",
				   &port, &state, &uid, &inode) != 4)
				continue;
			/* TCP: listeners only (state 0A); UDP: any bound port */
			if (!port || !inode || (tables[t].protocol == 6 && state != 0x0A))
				continue;
			if (!procres_lookup(inode, &owner.pid, owner.comm))
				continue;
			owner.uid = uid;
			key.port = port;
			if (!bpf_map_update_elem(fd, &key, &owner, BPF_NOEXIST))
				seeded++;
		}
		fclose(f);
	}
	log_info("ebpf engine: found owners of %u existing listening/bound ports", seeded);
}

static int ebpf_open(const struct agent_config *cfg)
{
	struct if_nameindex *all, *it;
	struct stat ns;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	xdp_flags = cfg->xdp_native ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;

	skel = kguard_bpf__open();
	if (!skel) {
		log_err("cannot open eBPF object");
		return -1;
	}
	if (!stat("/proc/self/ns/net", &ns))
		skel->rodata->kguard_netns = (uint32_t)ns.st_ino;
	bpf_map__set_max_entries(skel->maps.events, cfg->ringbuf_mb << 20);
	if (!ensure_bpffs())
		bpf_map__set_pin_path(skel->maps.blocklist, BLOCKLIST_PIN);

	err = kguard_bpf__load(skel);
	if (err) {
		log_err("loading eBPF programs failed: %s (needs root, BTF and kernel >= 5.17)",
			strerror(-err));
		return -1;
	}
	/* fentry/fexit/tp_btf; XDP and TC are attached per interface below */
	err = kguard_bpf__attach(skel);
	if (err) {
		log_err("attaching tracing programs failed: %s", strerror(-err));
		return -1;
	}
	/* After the hooks are live, so nothing slips between scan and hooks */
	seed_port_owners();

	if (cfg->ifaces) {
		char *list = strdup(cfg->ifaces), *save = NULL, *name;

		for (name = strtok_r(list, ",", &save); name; name = strtok_r(NULL, ",", &save)) {
			int ifindex = if_nametoindex(name);

			if (!ifindex)
				log_warn("no such interface: %s", name);
			else
				attach_iface(ifindex, name);
		}
		free(list);
	} else {
		all = if_nameindex();
		for (it = all; it && it->if_index; it++)
			attach_iface(it->if_index, it->if_name);
		if_freenameindex(all);
	}
	if (!nr_ifaces) {
		log_err("could not attach to any interface");
		return -1;
	}

	update_clock_offset();
	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), on_event, NULL, NULL);
	if (!rb) {
		log_err("ring buffer setup failed");
		return -1;
	}
	return 0;
}

/* Remove blocks whose time is up (XDP already ignores them) */
static void sweep_expired_blocks(void)
{
	int fd = bpf_map__fd(skel->maps.blocklist);
	int64_t now = clock_ns(CLOCK_MONOTONIC);
	struct lpm_key key, next, expired[64];
	struct block_value value;
	void *prev = NULL;
	int n = 0, i;

	while (n < 64 && !bpf_map_get_next_key(fd, prev, &next)) {
		if (!bpf_map_lookup_elem(fd, &next, &value) && value.expires_ns &&
		    (int64_t)value.expires_ns <= now)
			expired[n++] = next;
		key = next;
		prev = &key;
	}
	for (i = 0; i < n; i++)
		bpf_map_delete_elem(fd, &expired[i]);
}

static int ebpf_poll(int timeout_ms, event_cb cb, void *ctx)
{
	static double last_sweep;
	double now_s = clock_ns(CLOCK_MONOTONIC) / 1e9;
	int n;

	if (now_s - last_sweep > 5) {
		sweep_expired_blocks();
		last_sweep = now_s;
	}

	current_cb = cb;
	current_ctx = ctx;
	/* Re-sync the clock offset every 10 s (NTP adjustments) */
	if (clock_ns(CLOCK_MONOTONIC) / 1e9 - last_offset_update > 10)
		update_clock_offset();
	n = ring_buffer__poll(rb, timeout_ms);
	return n < 0 && n != -EINTR ? n : 0;
}

static uint64_t ebpf_dropped(void)
{
	int ncpus = libbpf_num_possible_cpus();
	struct counters *per_cpu;
	uint64_t total = 0;
	uint32_t zero = 0;
	int i;

	if (ncpus <= 0)
		return 0;
	per_cpu = calloc(ncpus, sizeof(*per_cpu));
	if (!per_cpu)
		return 0;
	if (!bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &zero, per_cpu))
		for (i = 0; i < ncpus; i++)
			total += per_cpu[i].ringbuf_full;
	free(per_cpu);
	return total;
}

static void ebpf_close(void)
{
	ring_buffer__free(rb);
	rb = NULL;
	if (skel)
		detach_all();
	kguard_bpf__destroy(skel);	/* the pinned blocklist stays */
	skel = NULL;
}

const struct engine ebpf_engine = {
	.name		= "ebpf",
	.open		= ebpf_open,
	.poll		= ebpf_poll,
	.kernel_dropped	= ebpf_dropped,
	.close		= ebpf_close,
};

/* ---- blocklist commands (work on the pinned map) ---- */

static int parse_prefix(const char *text, struct lpm_key *key)
{
	char addr[INET6_ADDRSTRLEN + 4];
	char *slash;
	int len = -1;

	snprintf(addr, sizeof(addr), "%s", text);
	slash = strchr(addr, '/');
	if (slash) {
		*slash = '\0';
		len = atoi(slash + 1);
	}
	memset(key, 0, sizeof(*key));
	if (inet_pton(AF_INET, addr, &key->addr[12]) == 1) {
		key->addr[10] = key->addr[11] = 0xff;
		if (len < 0)
			len = 32;
		if (len > 32)
			return -1;
		key->prefixlen = 96 + len;
	} else if (inet_pton(AF_INET6, addr, key->addr) == 1) {
		if (len < 0)
			len = 128;
		if (len > 128)
			return -1;
		key->prefixlen = len;
	} else {
		return -1;
	}
	/* Clear host bits so lookups and deletes match */
	for (int i = 0; i < 16; i++) {
		int start = i * 8;

		if ((int)key->prefixlen <= start)
			key->addr[i] = 0;
		else if ((int)key->prefixlen < start + 8)
			key->addr[i] &= 0xff << (8 - (key->prefixlen - start));
	}
	return 0;
}

static void format_prefix(const struct lpm_key *key, char *out, size_t size)
{
	char addr[INET6_ADDRSTRLEN];
	static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

	if (key->prefixlen >= 96 && !memcmp(key->addr, mapped, 12)) {
		inet_ntop(AF_INET, &key->addr[12], addr, sizeof(addr));
		snprintf(out, size, "%s/%u", addr, key->prefixlen - 96);
	} else {
		inet_ntop(AF_INET6, key->addr, addr, sizeof(addr));
		snprintf(out, size, "%s/%u", addr, key->prefixlen);
	}
}

static int open_pinned(void)
{
	int fd = bpf_obj_get(BLOCKLIST_PIN);

	if (fd < 0)
		fprintf(stderr, "cannot open %s: %s (start the agent with --engine=ebpf first)\n",
			BLOCKLIST_PIN, strerror(errno));
	return fd;
}

int ebpf_block(const char *prefix, unsigned int timeout_s)
{
	struct block_value value = {};
	struct lpm_key key;
	int fd, err;

	if (parse_prefix(prefix, &key)) {
		fprintf(stderr, "not an address or prefix: %s\n", prefix);
		return 2;
	}
	fd = open_pinned();
	if (fd < 0)
		return 1;
	if (timeout_s)
		value.expires_ns = clock_ns(CLOCK_MONOTONIC) + (int64_t)timeout_s * 1000000000LL;
	err = bpf_map_update_elem(fd, &key, &value, BPF_ANY);
	close(fd);
	if (err) {
		fprintf(stderr, "block failed: %s\n", strerror(errno));
		return 1;
	}
	return 0;
}

int ebpf_unblock(const char *prefix)
{
	struct lpm_key key;
	int fd, err;

	if (parse_prefix(prefix, &key)) {
		fprintf(stderr, "not an address or prefix: %s\n", prefix);
		return 2;
	}
	fd = open_pinned();
	if (fd < 0)
		return 1;
	err = bpf_map_delete_elem(fd, &key);
	close(fd);
	if (err) {
		fprintf(stderr, "unblock failed: %s\n", strerror(errno));
		return 1;
	}
	return 0;
}

int ebpf_list_blocks(void)
{
	struct lpm_key key, next;
	struct block_value value;
	int64_t now = clock_ns(CLOCK_MONOTONIC);
	void *prev = NULL;
	char text[64];
	int fd;

	fd = open_pinned();
	if (fd < 0)
		return 1;
	while (!bpf_map_get_next_key(fd, prev, &next)) {
		if (!bpf_map_lookup_elem(fd, &next, &value)) {
			format_prefix(&next, text, sizeof(text));
			if (!value.expires_ns)
				printf("%-44s permanent  drops=%llu\n", text,
				       (unsigned long long)value.drops);
			else if ((int64_t)value.expires_ns > now)
				printf("%-44s %llds left  drops=%llu\n", text,
				       (long long)((int64_t)value.expires_ns - now) / 1000000000LL,
				       (unsigned long long)value.drops);
		}
		key = next;
		prev = &key;
	}
	close(fd);
	return 0;
}
