// SPDX-License-Identifier: GPL-2.0
/*
 * Socket inode -> owning process, the way ss -p does it: scan
 * /proc/<pid>/fd for links named "socket:[<inode>]". The index is rebuilt
 * at most once a second, and only when an unknown inode is asked for.
 */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "agent.h"

struct owner_entry {
	uint64_t inode;
	uint32_t pid;
	char comm[16];
};

static struct owner_entry *owners;
static size_t nr_owners;
static double last_scan = -10;

static double now_s(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int cmp_inode(const void *a, const void *b)
{
	const struct owner_entry *x = a, *y = b;

	return x->inode < y->inode ? -1 : x->inode > y->inode;
}

static void read_comm(const char *pid, char comm[16])
{
	char path[300];
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%s/comm", pid);
	memset(comm, 0, 16);
	f = fopen(path, "r");
	if (!f)
		return;
	if (fgets(comm, 16, f))
		comm[strcspn(comm, "\n")] = '\0';
	fclose(f);
}

static void scan(void)
{
	struct owner_entry *list = NULL;
	size_t n = 0, cap = 0;
	struct dirent *p, *f;
	DIR *proc, *fds;

	proc = opendir("/proc");
	if (!proc)
		return;
	while ((p = readdir(proc))) {
		char dir[300], link[600], target[64];
		char comm[16] = "";
		bool have_comm = false;

		if (p->d_name[0] < '0' || p->d_name[0] > '9')
			continue;
		snprintf(dir, sizeof(dir), "/proc/%s/fd", p->d_name);
		fds = opendir(dir);
		if (!fds)
			continue;
		while ((f = readdir(fds))) {
			ssize_t len;
			unsigned long long ino;

			snprintf(link, sizeof(link), "%s/%s", dir, f->d_name);
			len = readlink(link, target, sizeof(target) - 1);
			if (len <= 0)
				continue;
			target[len] = '\0';
			if (sscanf(target, "socket:[%llu]", &ino) != 1)
				continue;
			if (!have_comm) {
				read_comm(p->d_name, comm);
				have_comm = true;
			}
			if (n == cap) {
				cap = cap ? cap * 2 : 256;
				list = realloc(list, cap * sizeof(*list));
				if (!list)
					abort();
			}
			list[n].inode = ino;
			list[n].pid = (uint32_t)strtoul(p->d_name, NULL, 10);
			memcpy(list[n].comm, comm, 16);
			n++;
		}
		closedir(fds);
	}
	closedir(proc);

	qsort(list, n, sizeof(*list), cmp_inode);
	free(owners);
	owners = list;
	nr_owners = n;
	last_scan = now_s();
}

static const struct owner_entry *find(uint64_t inode)
{
	struct owner_entry key = { .inode = inode };

	return nr_owners ? bsearch(&key, owners, nr_owners, sizeof(*owners), cmp_inode) : NULL;
}

bool procres_lookup(uint64_t inode, uint32_t *pid, char comm[16])
{
	const struct owner_entry *e = find(inode);

	if (!e && now_s() - last_scan >= 1.0) {
		scan();
		e = find(inode);
	}
	if (!e)
		return false;
	*pid = e->pid;
	memcpy(comm, e->comm, 16);
	return true;
}
