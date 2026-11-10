// SPDX-License-Identifier: GPL-2.0
/*
 * kselftest-style tests for the KGuard module (roadmap P8.6), TAP output.
 *
 *   device    /dev/kguard: one reader at a time, the mmap layout, refused
 *             mappings, poll, events written for our own traffic, tail
 *   netlink   GET_STATS / GET_CONFIG for anyone; BLOCK_* and SET_CONFIG
 *             only with CAP_NET_ADMIN; block add / list / delete; local and
 *             allowlisted addresses refused; bad attributes rejected
 *   blocking  a client in another network namespace is cut off by a block
 *             when enforce=1, not with enforce=0, and let back in on delete
 *
 * Run as root with the module loaded:  ./kguard_test   (exit 0 = all passed,
 * 4 = skipped). Built by "make -C kernel selftest".
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/genetlink.h>
#include <linux/kguard.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define KSFT_PASS 0
#define KSFT_FAIL 1
#define KSFT_SKIP 4

static int tests_run, tests_failed;

static void result(bool ok, const char *fmt, ...)
{
	va_list ap;

	printf("%sok %d - ", ok ? "" : "not ", ++tests_run);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	fflush(stdout);
	if (!ok)
		tests_failed++;
}

/* ---- Generic Netlink ------------------------------------------------- */

#define ALIGN4(n) (((n) + 3) & ~3U)

struct msg {
	struct nlmsghdr nlh;
	struct genlmsghdr genl;
	char attrs[512];
};

static uint16_t family;
static uint32_t seq;

static void start(struct msg *m, uint16_t type, uint8_t cmd, uint16_t flags)
{
	memset(m, 0, sizeof(*m));
	m->nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	m->nlh.nlmsg_type = type;
	m->nlh.nlmsg_flags = NLM_F_REQUEST | flags;
	m->nlh.nlmsg_seq = ++seq;
	m->genl.cmd = cmd;
	m->genl.version = 1;
}

static void put(struct msg *m, uint16_t type, const void *data, uint16_t len)
{
	struct nlattr *a = (void *)((char *)m + ALIGN4(m->nlh.nlmsg_len));

	a->nla_type = type;
	a->nla_len = NLA_HDRLEN + len;
	memcpy((char *)a + NLA_HDRLEN, data, len);
	m->nlh.nlmsg_len = ALIGN4(m->nlh.nlmsg_len) + ALIGN4(a->nla_len);
}

static const struct nlattr *find(const void *data, int len, uint16_t type)
{
	const char *p = data;

	while (len >= NLA_HDRLEN) {
		const struct nlattr *a = (const void *)p;

		if (a->nla_len < NLA_HDRLEN || a->nla_len > len)
			return NULL;
		if ((a->nla_type & NLA_TYPE_MASK) == type)
			return a;
		len -= ALIGN4(a->nla_len);
		p += ALIGN4(a->nla_len);
	}
	return NULL;
}

typedef void (*reply_cb)(const void *attrs, int len, void *ctx);

/* Send, then read replies (calling cb for each) until the ACK or DONE; 0 or -errno */
static int transact(int fd, struct msg *m, reply_cb cb, void *ctx)
{
	char buf[16384];
	bool dump = m->nlh.nlmsg_flags & NLM_F_DUMP;

	if (!dump)
		m->nlh.nlmsg_flags |= NLM_F_ACK;
	if (send(fd, m, m->nlh.nlmsg_len, 0) < 0)
		return -errno;
	for (;;) {
		ssize_t n = recv(fd, buf, sizeof(buf), 0);
		struct nlmsghdr *h;

		if (n < 0)
			return -errno;
		for (h = (void *)buf; NLMSG_OK(h, (size_t)n); h = NLMSG_NEXT(h, n)) {
			if (h->nlmsg_seq != m->nlh.nlmsg_seq)
				continue;
			if (h->nlmsg_type == NLMSG_DONE)
				return 0;
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = NLMSG_DATA(h);

				return e->error;
			}
			if (cb)
				cb((char *)NLMSG_DATA(h) + GENL_HDRLEN,
				   h->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN, ctx);
		}
	}
}

static void family_cb(const void *attrs, int len, void *ctx)
{
	const struct nlattr *a = find(attrs, len, CTRL_ATTR_FAMILY_ID);

	if (a)
		*(uint16_t *)ctx = *(uint16_t *)((char *)a + NLA_HDRLEN);
}

static int genl_socket(void)
{
	struct timeval tv = { .tv_sec = 3 };
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);

	if (fd >= 0)
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

static int resolve_family(int fd)
{
	struct msg m;

	start(&m, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0);
	put(&m, CTRL_ATTR_FAMILY_NAME, KGUARD_GENL_NAME, sizeof(KGUARD_GENL_NAME));
	return transact(fd, &m, family_cb, &family);
}

static uint64_t attr_u64(const void *attrs, int len, uint16_t type)
{
	const struct nlattr *a = find(attrs, len, type);
	uint64_t v = 0;

	if (a)
		memcpy(&v, (char *)a + NLA_HDRLEN, a->nla_len - NLA_HDRLEN >= 8 ? 8 : 4);
	return v;
}

struct stats_ctx {
	uint64_t packets, events;
	bool seen;
};

static void stats_cb(const void *attrs, int len, void *ctx)
{
	struct stats_ctx *s = ctx;

	s->packets = attr_u64(attrs, len, KGUARD_ATTR_STAT_PACKETS);
	s->events = attr_u64(attrs, len, KGUARD_ATTR_STAT_EVENTS);
	s->seen = true;
}

static void enforce_cb(const void *attrs, int len, void *ctx)
{
	const struct nlattr *a = find(attrs, len, KGUARD_ATTR_CFG_ENFORCE);

	if (a)
		*(int *)ctx = *((uint8_t *)a + NLA_HDRLEN);
}

static int set_enforce(int fd, uint8_t on)
{
	struct msg m;

	start(&m, family, KGUARD_CMD_SET_CONFIG, 0);
	put(&m, KGUARD_ATTR_CFG_ENFORCE, &on, 1);
	return transact(fd, &m, NULL, NULL);
}

static int block_cmd(int fd, uint8_t cmd, const char *ip, uint32_t timeout)
{
	struct msg m;
	uint8_t addr[16];
	int len = 4;

	if (inet_pton(AF_INET, ip, addr) != 1) {
		inet_pton(AF_INET6, ip, addr);
		len = 16;
	}
	start(&m, family, cmd, 0);
	put(&m, KGUARD_ATTR_ADDR, addr, len);
	if (cmd == KGUARD_CMD_BLOCK_ADD)
		put(&m, KGUARD_ATTR_TIMEOUT, &timeout, 4);
	return transact(fd, &m, NULL, NULL);
}

static int allow_cmd(int fd, uint8_t cmd, const char *ip, uint8_t prefix)
{
	struct msg m;
	uint8_t addr[4];

	inet_pton(AF_INET, ip, addr);
	start(&m, family, cmd, 0);
	put(&m, KGUARD_ATTR_ADDR, addr, 4);
	put(&m, KGUARD_ATTR_PREFIX_LEN, &prefix, 1);
	return transact(fd, &m, NULL, NULL);
}

struct list_ctx {
	uint8_t want[4];
	bool found;
	uint64_t expires_ms;
};

static void list_cb(const void *attrs, int len, void *ctx)
{
	struct list_ctx *l = ctx;
	const struct nlattr *a = find(attrs, len, KGUARD_ATTR_ADDR);

	if (a && a->nla_len - NLA_HDRLEN == 4 && !memcmp((char *)a + NLA_HDRLEN, l->want, 4)) {
		l->found = true;
		l->expires_ms = attr_u64(attrs, len, KGUARD_ATTR_EXPIRES_MS);
	}
}

static bool listed(int fd, const char *ip, uint64_t *expires_ms)
{
	struct list_ctx l = { 0 };
	struct msg m;

	inet_pton(AF_INET, ip, l.want);
	start(&m, family, KGUARD_CMD_BLOCK_LIST, NLM_F_DUMP);
	if (transact(fd, &m, list_cb, &l))
		return false;
	if (expires_ms)
		*expires_ms = l.expires_ms;
	return l.found;
}

/* ---- traffic helpers ------------------------------------------------- */

static void udp_burst(uint16_t port, int count)
{
	struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(port),
				  .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	for (int i = 0; i < count; i++)
		sendto(fd, "kguard", 6, 0, (void *)&to, sizeof(to));
	close(fd);
}

/* Run fn in network namespace ns (a child process); returns its exit code */
static int in_netns(const char *ns, int (*fn)(void *), void *arg)
{
	char path[128];
	pid_t pid;
	int status;

	snprintf(path, sizeof(path), "/run/netns/%s", ns);
	pid = fork();
	if (pid == 0) {
		int fd = open(path, O_RDONLY);

		if (fd < 0 || setns(fd, CLONE_NEWNET))
			_exit(99);
		_exit(fn(arg));
	}
	waitpid(pid, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : 98;
}

static int try_connect(void *arg)
{
	struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(8081) };
	struct pollfd p;
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

	inet_pton(AF_INET, arg, &to.sin_addr);
	connect(fd, (void *)&to, sizeof(to));
	p.fd = fd;
	p.events = POLLOUT;
	if (poll(&p, 1, 1500) == 1) {
		int err = 0;
		socklen_t len = sizeof(err);

		getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
		return err == 0 ? 0 : 1;
	}
	return 1;	/* no answer: dropped */
}

static int run(const char *cmd)
{
	return system(cmd);
}

/* ---- tests ----------------------------------------------------------- */

static void test_device(void)
{
	struct kguard_mmap_info info;
	struct stat st;
	void *first, *area;
	int fd, fd2;

	result(stat("/dev/kguard", &st) == 0 && S_ISCHR(st.st_mode), "device: /dev/kguard is a character device");
	fd = open("/dev/kguard", O_RDWR | O_CLOEXEC);
	result(fd >= 0, "device: opens read-write as root");
	if (fd < 0)
		return;
	fd2 = open("/dev/kguard", O_RDWR | O_CLOEXEC);
	result(fd2 < 0 && errno == EBUSY, "device: a second reader gets EBUSY");
	if (fd2 >= 0)
		close(fd2);

	first = mmap(NULL, sizeof(info), PROT_READ, MAP_SHARED, fd, 0);
	result(first != MAP_FAILED, "device: info page maps");
	memcpy(&info, first, sizeof(info));
	munmap(first, sizeof(info));
	result(info.magic == KGUARD_MMAP_MAGIC && info.abi_version == KGUARD_ABI_VERSION &&
	       info.event_size == sizeof(struct kguard_event),
	       "device: magic, ABI version and event size match the header (abi %u)", info.abi_version);
	result(info.nr_rings > 0 && info.ring_slots >= 64 && !(info.ring_slots & (info.ring_slots - 1)),
	       "device: %u rings of %u slots (a power of two)", info.nr_rings, info.ring_slots);

	result(mmap(NULL, info.mmap_size, PROT_READ, MAP_PRIVATE, fd, 0) == MAP_FAILED,
	       "device: private mappings are refused");
	result(mmap(NULL, info.mmap_size, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0) == MAP_FAILED,
	       "device: executable mappings are refused");

	area = mmap(NULL, info.mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	result(area != MAP_FAILED, "device: all %llu bytes of rings map", (unsigned long long)info.mmap_size);
	if (area != MAP_FAILED) {
		/* Drain what is there, send traffic, and find it */
		uint16_t port = 40000 + (getpid() % 20000);
		struct pollfd p = { .fd = fd, .events = POLLIN };
		bool seen = false;
		unsigned int consumed = 0;

		for (uint32_t r = 0; r < info.nr_rings; r++) {
			struct kguard_ring_header *h = (void *)((char *)area + info.rings_offset + r * info.ring_stride);

			h->tail = __atomic_load_n(&h->head, __ATOMIC_ACQUIRE);
		}
		udp_burst(port, 20);
		result(poll(&p, 1, 2000) == 1 && (p.revents & POLLIN), "device: poll() wakes up for new events");
		usleep(200000);
		for (uint32_t r = 0; r < info.nr_rings; r++) {
			struct kguard_ring_header *h = (void *)((char *)area + info.rings_offset + r * info.ring_stride);
			struct kguard_event *slots = (void *)((char *)h + info.ring_header_size);
			uint64_t head = __atomic_load_n(&h->head, __ATOMIC_ACQUIRE);

			for (uint64_t t = h->tail; t != head; t++, consumed++) {
				struct kguard_event *e = &slots[t & (info.ring_slots - 1)];

				/* Ports are in host byte order (see the UAPI header) */
				if (e->protocol == IPPROTO_UDP && e->dst_port == port)
					seen = true;
			}
			__atomic_store_n(&h->tail, head, __ATOMIC_RELEASE);
		}
		result(seen, "device: our UDP packets to port %u are in the rings (%u events read)", port,
		       consumed);
		munmap(area, info.mmap_size);
	}
	close(fd);
	fd = open("/dev/kguard", O_RDWR | O_CLOEXEC);
	result(fd >= 0, "device: closing releases it for the next reader");
	if (fd >= 0)
		close(fd);
}

static int unprivileged_block(void *arg)
{
	int fd = genl_socket();

	(void)arg;
	if (setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534))
		return 90;
	return block_cmd(fd, KGUARD_CMD_BLOCK_ADD, "192.0.2.77", 10) == -EPERM ? 0 : 1;
}

static int unprivileged_stats(void *arg)
{
	struct stats_ctx s = { 0 };
	struct msg m;
	int fd = genl_socket();

	(void)arg;
	if (setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534))
		return 90;
	start(&m, family, KGUARD_CMD_GET_STATS, 0);
	return transact(fd, &m, stats_cb, &s) == 0 && s.seen ? 0 : 1;
}

static int as_child(int (*fn)(void *))
{
	pid_t pid = fork();
	int status;

	if (pid == 0)
		_exit(fn(NULL));
	waitpid(pid, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : 98;
}

static void test_netlink(int fd)
{
	struct stats_ctx before = { 0 }, after = { 0 };
	struct msg m;
	uint64_t expires = 0;
	int enforce = -1, ret;
	bool found;
	uint8_t bad[3] = { 1, 2, 3 };

	start(&m, family, KGUARD_CMD_GET_STATS, 0);
	result(transact(fd, &m, stats_cb, &before) == 0 && before.seen, "netlink: GET_STATS answers");
	udp_burst(9, 50);
	usleep(100000);
	start(&m, family, KGUARD_CMD_GET_STATS, 0);
	transact(fd, &m, stats_cb, &after);
	result(after.packets >= before.packets + 50, "netlink: packet counter grows with traffic (%llu -> %llu)",
	       (unsigned long long)before.packets, (unsigned long long)after.packets);
	start(&m, family, KGUARD_CMD_GET_CONFIG, 0);
	ret = transact(fd, &m, enforce_cb, &enforce);
	result(ret == 0 && (enforce == 0 || enforce == 1), "netlink: GET_CONFIG reports enforce=%d", enforce);

	result(as_child(unprivileged_stats) == 0, "netlink: an unprivileged user may read stats");
	result(as_child(unprivileged_block) == 0, "netlink: an unprivileged user gets EPERM for BLOCK_ADD");

	result(block_cmd(fd, KGUARD_CMD_BLOCK_ADD, "192.0.2.10", 30) == 0, "netlink: BLOCK_ADD with a timeout");
	found = listed(fd, "192.0.2.10", &expires);
	result(found && expires > 0 && expires <= 30000,
	       "netlink: BLOCK_LIST shows it, expiring in %llu ms", (unsigned long long)expires);
	result(block_cmd(fd, KGUARD_CMD_BLOCK_ADD, "192.0.2.10", 0) == 0 && listed(fd, "192.0.2.10", &expires) &&
	       expires == 0, "netlink: adding it again updates the timeout (now none)");
	result(block_cmd(fd, KGUARD_CMD_BLOCK_DEL, "192.0.2.10", 0) == 0 && !listed(fd, "192.0.2.10", NULL),
	       "netlink: BLOCK_DEL removes it");
	ret = block_cmd(fd, KGUARD_CMD_BLOCK_DEL, "192.0.2.10", 0);
	result(ret == -ENOENT, "netlink: deleting it again gives ENOENT (%d)", ret);

	ret = block_cmd(fd, KGUARD_CMD_BLOCK_ADD, "127.0.0.1", 10);
	result(ret == -EADDRNOTAVAIL, "netlink: a local address cannot be blocked (%d)", ret);
	result(allow_cmd(fd, KGUARD_CMD_ALLOW_ADD, "192.0.2.0", 24) == 0, "netlink: ALLOW_ADD 192.0.2.0/24");
	ret = block_cmd(fd, KGUARD_CMD_BLOCK_ADD, "192.0.2.10", 10);
	result(ret == -EADDRNOTAVAIL, "netlink: an allowlisted address cannot be blocked (%d)", ret);
	result(allow_cmd(fd, KGUARD_CMD_ALLOW_DEL, "192.0.2.0", 24) == 0, "netlink: ALLOW_DEL");

	start(&m, family, KGUARD_CMD_BLOCK_ADD, 0);
	put(&m, KGUARD_ATTR_ADDR, bad, sizeof(bad));
	ret = transact(fd, &m, NULL, NULL);
	result(ret == -EINVAL, "netlink: a 3-byte address is rejected with EINVAL (%d)", ret);
	start(&m, family, KGUARD_CMD_BLOCK_ADD, 0);
	ret = transact(fd, &m, NULL, NULL);
	result(ret == -EINVAL, "netlink: a missing address is rejected with EINVAL (%d)", ret);
}

static void test_blocking(int fd)
{
	const char *setup =
		"ip netns add kgst && ip link add kgst0 type veth peer name kgst1 && "
		"ip link set kgst1 netns kgst && ip addr add 10.211.0.1/24 dev kgst0 && ip link set kgst0 up && "
		"ip -n kgst addr add 10.211.0.2/24 dev kgst1 && ip -n kgst link set kgst1 up && "
		"ip -n kgst link set lo up";
	int listener, original = 0, one = 1;
	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(8081) };
	struct msg m;

	if (run(setup)) {
		result(false, "blocking: set up a client network namespace");
		return;
	}
	listener = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	inet_pton(AF_INET, "10.211.0.1", &addr.sin_addr);
	bind(listener, (void *)&addr, sizeof(addr));
	listen(listener, 64);

	start(&m, family, KGUARD_CMD_GET_CONFIG, 0);
	transact(fd, &m, enforce_cb, &original);

	result(in_netns("kgst", try_connect, "10.211.0.1") == 0, "blocking: the client connects before any block");
	set_enforce(fd, 1);
	block_cmd(fd, KGUARD_CMD_BLOCK_ADD, "10.211.0.2", 60);
	result(in_netns("kgst", try_connect, "10.211.0.1") != 0, "blocking: with enforce=1 a block cuts it off");
	set_enforce(fd, 0);
	result(in_netns("kgst", try_connect, "10.211.0.1") == 0,
	       "blocking: with enforce=0 (monitor only) the same block lets it through");
	set_enforce(fd, 1);
	block_cmd(fd, KGUARD_CMD_BLOCK_DEL, "10.211.0.2", 0);
	result(in_netns("kgst", try_connect, "10.211.0.1") == 0, "blocking: deleting the block lets it back in");
	block_cmd(fd, KGUARD_CMD_BLOCK_ADD, "10.211.0.2", 2);
	result(in_netns("kgst", try_connect, "10.211.0.1") != 0, "blocking: a 2-second block holds...");
	sleep(3);
	result(in_netns("kgst", try_connect, "10.211.0.1") == 0, "blocking: ...and expires by itself");

	set_enforce(fd, original);
	close(listener);
	run("ip netns del kgst; ip link del kgst0 2>/dev/null");
}

int main(void)
{
	bool ok;
	int fd;

	printf("TAP version 13\n");
	if (geteuid()) {
		printf("1..0 # SKIP needs root\n");
		return KSFT_SKIP;
	}
	if (access("/sys/module/kguard", F_OK)) {
		printf("1..0 # SKIP the kguard module is not loaded\n");
		return KSFT_SKIP;
	}
	test_device();
	fd = genl_socket();
	ok = fd >= 0 && resolve_family(fd) == 0 && family;
	result(ok, "netlink: the \"kguard\" family resolves (id %u)", family);
	test_netlink(fd);
	test_blocking(fd);
	close(fd);
	/* TAP allows the plan at the end: the count depends on early exits */
	printf("1..%d\n# %d tests, %d failed\n", tests_run, tests_run, tests_failed);
	return tests_failed ? KSFT_FAIL : KSFT_PASS;
}
