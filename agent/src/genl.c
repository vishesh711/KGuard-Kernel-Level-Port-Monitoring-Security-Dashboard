// SPDX-License-Identifier: GPL-2.0
/*
 * Minimal Generic Netlink client for the kernel module's control commands
 * (roadmap S6.4): add and remove blocks, read whether it enforces them.
 *
 * Each call opens a socket, resolves the "kguard" family, sends one request
 * with NLM_F_ACK and reads replies until the ACK. Block commands need
 * CAP_NET_ADMIN (the agent runs as root); the kernel answers -EPERM without it.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include "agent.h"

#define NLA_ALIGN4(len)	(((len) + 3) & ~3U)

struct request {
	struct nlmsghdr nlh;
	struct genlmsghdr genl;
	char attrs[256];
};

static void put_attr(struct request *r, uint16_t type, const void *data, uint16_t len)
{
	struct nlattr *nla = (struct nlattr *)((char *)r + NLA_ALIGN4(r->nlh.nlmsg_len));

	nla->nla_type = type;
	nla->nla_len = NLA_HDRLEN + len;
	memcpy((char *)nla + NLA_HDRLEN, data, len);
	r->nlh.nlmsg_len = NLA_ALIGN4(r->nlh.nlmsg_len) + NLA_ALIGN4(nla->nla_len);
}

/* Find attribute `type` in a run of attributes */
static const struct nlattr *find_attr(const char *data, int len, uint16_t type)
{
	while (len >= NLA_HDRLEN) {
		const struct nlattr *nla = (const void *)data;

		if (nla->nla_len < NLA_HDRLEN || nla->nla_len > len)
			return NULL;
		if ((nla->nla_type & NLA_TYPE_MASK) == type)
			return nla;
		len -= NLA_ALIGN4(nla->nla_len);
		data += NLA_ALIGN4(nla->nla_len);
	}
	return NULL;
}

/*
 * Send `req` and read until the ACK. With `want_attr`, copy that attribute's
 * payload (from the reply) into out/out_len. Returns 0 or -errno.
 */
static int transact(int fd, struct request *req, uint16_t want_attr, void *out, size_t out_len)
{
	static uint32_t seq = 1;
	char buf[8192];
	bool found = false;

	req->nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req->nlh.nlmsg_seq = __atomic_add_fetch(&seq, 1, __ATOMIC_RELAXED);
	if (send(fd, req, req->nlh.nlmsg_len, 0) < 0)
		return -errno;
	for (;;) {
		ssize_t n = recv(fd, buf, sizeof(buf), 0);
		struct nlmsghdr *nlh;

		if (n < 0)
			return -errno;
		for (nlh = (void *)buf; NLMSG_OK(nlh, (size_t)n); nlh = NLMSG_NEXT(nlh, n)) {
			if (nlh->nlmsg_seq != req->nlh.nlmsg_seq)
				continue;
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = NLMSG_DATA(nlh);

				if (err->error)
					return err->error;
				return (want_attr && !found) ? -ENODATA : 0;
			}
			if (want_attr) {
				const char *attrs = (char *)NLMSG_DATA(nlh) + GENL_HDRLEN;
				int len = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
				const struct nlattr *nla = find_attr(attrs, len, want_attr);

				if (nla) {
					size_t plen = nla->nla_len - NLA_HDRLEN;

					memcpy(out, (char *)nla + NLA_HDRLEN, plen < out_len ? plen : out_len);
					found = true;
				}
			}
		}
	}
}

static void start(struct request *r, uint16_t type, uint8_t cmd)
{
	memset(r, 0, sizeof(*r));
	r->nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	r->nlh.nlmsg_type = type;
	r->genl.cmd = cmd;
	r->genl.version = 1;
}

/* A socket and the kguard family id; <0 (-errno) if the module is not loaded */
static int open_family(int *fd_out)
{
	struct timeval tv = { .tv_sec = 2 };
	struct request r;
	uint16_t family = 0;
	int fd, ret;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
	if (fd < 0)
		return -errno;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	start(&r, GENL_ID_CTRL, CTRL_CMD_GETFAMILY);
	put_attr(&r, CTRL_ATTR_FAMILY_NAME, KGUARD_GENL_NAME, sizeof(KGUARD_GENL_NAME));
	ret = transact(fd, &r, CTRL_ATTR_FAMILY_ID, &family, sizeof(family));
	if (ret) {
		close(fd);
		return ret;
	}
	*fd_out = fd;
	return family;
}

/* "a.b.c.d[/32]" or "x::y[/128]" into 4 or 16 bytes; -EINVAL for real prefixes */
static int single_address(const char *prefix, unsigned char addr[16])
{
	char text[INET6_ADDRSTRLEN + 5];
	char *slash;

	snprintf(text, sizeof(text), "%s", prefix);
	slash = strchr(text, '/');
	if (slash)
		*slash++ = '\0';
	if (inet_pton(AF_INET, text, addr) == 1)
		return (!slash || !strcmp(slash, "32")) ? 4 : -EINVAL;
	if (inet_pton(AF_INET6, text, addr) == 1)
		return (!slash || !strcmp(slash, "128")) ? 16 : -EINVAL;
	return -EINVAL;
}

static int block_cmd(uint8_t cmd, const char *prefix, unsigned int timeout_s)
{
	unsigned char addr[16];
	struct request r;
	int len = single_address(prefix, addr);
	int fd, family, ret;

	if (len < 0)
		return len;	/* the module blocks single addresses only */
	family = open_family(&fd);
	if (family < 0)
		return family;
	start(&r, family, cmd);
	put_attr(&r, KGUARD_ATTR_ADDR, addr, len);
	if (cmd == KGUARD_CMD_BLOCK_ADD)
		put_attr(&r, KGUARD_ATTR_TIMEOUT, &timeout_s, sizeof(timeout_s));
	ret = transact(fd, &r, 0, NULL, 0);
	close(fd);
	return ret;
}

int genl_block(const char *prefix, unsigned int timeout_s)
{
	return block_cmd(KGUARD_CMD_BLOCK_ADD, prefix, timeout_s);
}

int genl_unblock(const char *prefix)
{
	return block_cmd(KGUARD_CMD_BLOCK_DEL, prefix, 0);
}

int genl_enforcing(void)
{
	struct request r;
	uint8_t enforce = 0;
	int fd, family, ret;

	family = open_family(&fd);
	if (family < 0)
		return family;
	start(&r, family, KGUARD_CMD_GET_CONFIG);
	ret = transact(fd, &r, KGUARD_ATTR_CFG_ENFORCE, &enforce, sizeof(enforce));
	close(fd);
	return ret ? ret : enforce;
}
