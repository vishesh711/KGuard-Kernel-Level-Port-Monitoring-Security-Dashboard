// SPDX-License-Identifier: GPL-2.0
/*
 * This host's listening sockets and connections (roadmap U7.2), read from
 * /proc/net/{tcp,tcp6,udp,udp6} like ss -tunap, with the owning process
 * (procres.c) and user. Sent to POST /api/agents/sockets by the sync thread.
 */

#include <arpa/inet.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "agent.h"

#define MAX_CONNECTIONS 2000

static const char *tcp_state(unsigned int st)
{
	static const char *const names[] = {
		[1] = "ESTABLISHED", [2] = "SYN_SENT", [3] = "SYN_RECV", [4] = "FIN_WAIT1",
		[5] = "FIN_WAIT2", [6] = "TIME_WAIT", [7] = "CLOSE", [8] = "CLOSE_WAIT",
		[9] = "LAST_ACK", [10] = "LISTEN", [11] = "CLOSING",
	};

	return st < sizeof(names) / sizeof(names[0]) && names[st] ? names[st] : "UNKNOWN";
}

/* "0100007F:1F90" -> text address and port; IPv6 is four little-endian words */
static int decode(const char *hex, char *out, size_t out_len, unsigned int *port)
{
	unsigned char raw[16];
	char addr_hex[33];
	const char *colon = strchr(hex, ':');
	size_t n;

	if (!colon)
		return -1;
	n = colon - hex;
	if ((n != 8 && n != 32) || n >= sizeof(addr_hex))
		return -1;
	memcpy(addr_hex, hex, n);
	addr_hex[n] = '\0';
	for (size_t i = 0; i < n / 8; i++) {
		unsigned int word;

		if (sscanf(addr_hex + i * 8, "%8x", &word) != 1)
			return -1;
		/* /proc prints each 32-bit word in host (little-endian) order */
		memcpy(raw + i * 4, &word, 4);
	}
	*port = strtoul(colon + 1, NULL, 16);
	if (n == 8)
		return inet_ntop(AF_INET, raw, out, out_len) ? 4 : -1;
	if (!memcmp(raw, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12))	/* v4-mapped */
		return inet_ntop(AF_INET, raw + 12, out, out_len) ? 4 : -1;
	return inet_ntop(AF_INET6, raw, out, out_len) ? 6 : -1;
}

static void safe_text(char *dst, const char *src, size_t size)
{
	size_t i;

	for (i = 0; i + 1 < size && src[i]; i++)
		dst[i] = (src[i] >= 0x20 && src[i] < 0x7f && src[i] != '"' && src[i] != '\\') ? src[i] : '?';
	dst[i] = '\0';
}

static void item(struct buf *b, bool *first, const char *proto, int family, const char *local,
		 unsigned int lport, const char *remote, unsigned int rport, const char *state,
		 unsigned int uid, unsigned long long inode)
{
	char comm[16] = "", safe_comm[17] = "", user[33] = "";
	struct passwd *pw = getpwuid(uid);
	uint32_t pid = 0;
	bool owned = inode && procres_lookup(inode, &pid, comm);

	if (owned)
		safe_text(safe_comm, comm, sizeof(safe_comm));
	if (pw)
		safe_text(user, pw->pw_name, sizeof(user));
	else
		snprintf(user, sizeof(user), "%u", uid);
	buf_printf(b, "%s{\"proto\":\"%s\",\"family\":%d,\"local\":\"%s\",\"lport\":%u,\"remote\":\"%s\","
		   "\"rport\":%u,\"state\":\"%s\",\"uid\":%u,\"inode\":%llu,\"user\":\"%s\"",
		   *first ? "" : ",", proto, family, local, lport, remote, rport, state, uid, inode, user);
	if (owned)
		buf_printf(b, ",\"pid\":%u,\"process\":\"%s\"", pid, safe_comm);
	buf_printf(b, "}");
	*first = false;
}

/* Append {"listeners":[...],"connections":[...]} to b */
void sockets_json(struct buf *b)
{
	static const char *const files[] = { "tcp", "tcp6", "udp", "udp6" };
	struct buf conns;
	bool first_listener = true, first_conn = true;
	unsigned int nr_conns = 0;

	buf_init(&conns);
	buf_printf(b, "{\"listeners\":[");
	for (size_t f = 0; f < 4; f++) {
		char path[32], line[512];
		bool udp = files[f][0] == 'u';
		const char *proto = udp ? "UDP" : "TCP";
		FILE *fp;

		snprintf(path, sizeof(path), "/proc/net/%s", files[f]);
		fp = fopen(path, "r");
		if (!fp)
			continue;
		if (!fgets(line, sizeof(line), fp)) {	/* header */
			fclose(fp);
			continue;
		}
		while (fgets(line, sizeof(line), fp)) {
			char lhex[64], rhex[64], local[INET6_ADDRSTRLEN], remote[INET6_ADDRSTRLEN];
			unsigned int st, lport, rport, uid;
			unsigned long long inode;
			const char *state;
			int family;

			if (sscanf(line, " %*d: %63s %63s %x %*s %*s %*s %u %*d %llu",
				   lhex, rhex, &st, &uid, &inode) != 5)
				continue;
			family = decode(lhex, local, sizeof(local), &lport);
			if (family < 0 || decode(rhex, remote, sizeof(remote), &rport) < 0)
				continue;
			state = udp ? (rport == 0 ? "LISTEN" : "CONNECTED") : tcp_state(st);
			if (!strcmp(state, "LISTEN"))
				item(b, &first_listener, proto, family, local, lport, remote, rport, state, uid, inode);
			else if (strcmp(state, "CLOSE") && strcmp(state, "TIME_WAIT") && nr_conns++ < MAX_CONNECTIONS)
				item(&conns, &first_conn, proto, family, local, lport, remote, rport, state, uid, inode);
		}
		fclose(fp);
	}
	buf_printf(b, "],\"connections\":[%s]}", conns.data ? conns.data : "");
	buf_free(&conns);
}
