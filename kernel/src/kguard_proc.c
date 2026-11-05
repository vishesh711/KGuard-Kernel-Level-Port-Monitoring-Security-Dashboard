// SPDX-License-Identifier: GPL-2.0
/*
 * KGuard Kernel Module - /proc/kguard JSON view
 *
 * A text view of the event rings for debugging and simple readers. Reading
 * removes the events it returns, so it cannot be used while a reader holds
 * /dev/kguard (open() fails with -EBUSY).
 *
 * Each open() moves every queued event into a private snapshot, sorted by
 * time, and seq_file walks that snapshot by position. seq_file may call
 * show() for the same position more than once (when its buffer grows or a
 * read ends mid-record), so events are never removed inside show().
 *
 * Output:
 *   {"dropped": N, "events": [
 *   {"timestamp": ..., "family": 4, "src_ip": "...", ...},
 *   ...
 *   ]}
 */

#include "kguard.h"

#include <linux/cred.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sort.h>
#include <linux/socket.h>
#include <linux/uidgid.h>

struct kguard_snapshot {
	u64 dropped;
	unsigned int count;
	struct kguard_event events[];
};

static struct proc_dir_entry *kguard_proc_entry;

const char *kguard_protocol_name(u8 protocol)
{
	switch (protocol) {
	case IPPROTO_TCP:
		return "TCP";
	case IPPROTO_UDP:
		return "UDP";
	case IPPROTO_ICMP:
		return "ICMP";
	case IPPROTO_ICMPV6:
		return "ICMPv6";
	default:
		return "OTHER";
	}
}

const char *kguard_direction_name(u8 direction)
{
	switch (direction) {
	case KGUARD_DIR_IN:
		return "in";
	case KGUARD_DIR_OUT:
		return "out";
	case KGUARD_DIR_FWD:
		return "fwd";
	default:
		return "unknown";
	}
}

const char *kguard_ct_name(u8 state)
{
	switch (state) {
	case KGUARD_CT_NEW:
		return "new";
	case KGUARD_CT_ESTABLISHED:
		return "established";
	case KGUARD_CT_RELATED:
		return "related";
	case KGUARD_CT_INVALID:
		return "invalid";
	case KGUARD_CT_UNTRACKED:
		return "untracked";
	default:
		return "none";
	}
}

/* Copy a process name, replacing anything that is not safe inside a JSON string */
static void kguard_safe_comm(char *dst, const char *src)
{
	int i;

	for (i = 0; i < TASK_COMM_LEN - 1 && src[i]; i++)
		dst[i] = (src[i] >= 0x20 && src[i] < 0x7f &&
			  src[i] != '"' && src[i] != '\\') ? src[i] : '?';
	dst[i] = '\0';
}

static int kguard_cmp_time(const void *a, const void *b)
{
	const struct kguard_event *x = a, *y = b;

	if (x->timestamp_ns < y->timestamp_ns)
		return -1;
	return x->timestamp_ns > y->timestamp_ns;
}

/*
 * Positions: 0 is the header, 1..count are events, count + 1 is the footer.
 * The iterator token is position + 1 so that it is never NULL.
 */
static void *kguard_seq_token(struct seq_file *m, loff_t pos)
{
	struct kguard_snapshot *snap = m->private;

	if (pos < 0 || pos > (loff_t)snap->count + 1)
		return NULL;
	return (void *)(uintptr_t)(pos + 1);
}

static void *kguard_seq_start(struct seq_file *m, loff_t *pos)
{
	return kguard_seq_token(m, *pos);
}

static void *kguard_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return kguard_seq_token(m, *pos);
}

static void kguard_seq_stop(struct seq_file *m, void *v)
{
}

static void kguard_show_addr(struct seq_file *m, const char *key,
			     const struct kguard_event *e, const u8 *addr)
{
	if (e->family == AF_INET6)
		seq_printf(m, "\"%s\": \"%pI6c\", ", key, addr);
	else
		seq_printf(m, "\"%s\": \"%pI4\", ", key, addr);
}

static int kguard_seq_show(struct seq_file *m, void *v)
{
	struct kguard_snapshot *snap = m->private;
	unsigned int pos = (unsigned int)((uintptr_t)v - 1);
	const struct kguard_event *e;
	char comm[TASK_COMM_LEN];
	bool proc, sock;

	if (pos == 0) {
		seq_printf(m, "{\"dropped\": %llu, \"events\": [\n", snap->dropped);
		return 0;
	}

	if (pos > snap->count) {
		seq_puts(m, "\n]}\n");
		return 0;
	}

	e = &snap->events[pos - 1];
	proc = e->info & KGUARD_EVF_PROC;
	sock = e->info & KGUARD_EVF_SOCK;
	kguard_safe_comm(comm, proc ? e->comm : "");

	if (pos > 1)
		seq_puts(m, ",\n");
	seq_printf(m, "{\"timestamp\": %llu, \"family\": %u, ",
		   e->timestamp_ns, e->family == AF_INET6 ? 6 : 4);
	kguard_show_addr(m, "src_ip", e, e->src_addr);
	kguard_show_addr(m, "dst_ip", e, e->dst_addr);
	seq_printf(m, "\"src_port\": %u, \"dst_port\": %u, \"protocol\": \"%s\", \"flags\": %u, ",
		   e->src_port, e->dst_port, kguard_protocol_name(e->protocol),
		   e->tcp_flags);
	seq_printf(m, "\"direction\": \"%s\", \"ct_state\": \"%s\", \"netns\": %u, \"ifindex\": %u, ",
		   kguard_direction_name(e->direction), kguard_ct_name(e->ct_state),
		   e->netns, e->ifindex);
	seq_printf(m, "\"pid\": %d, \"comm\": \"%s\", \"uid\": %lld, \"sock_ino\": %llu}",
		   proc ? (int)e->pid : -1, comm,
		   sock ? (long long)e->uid : -1LL, sock ? e->sock_ino : 0);
	return 0;
}

static const struct seq_operations kguard_seq_ops = {
	.start = kguard_seq_start,
	.next  = kguard_seq_next,
	.stop  = kguard_seq_stop,
	.show  = kguard_seq_show,
};

static int kguard_proc_open(struct inode *inode, struct file *file)
{
	struct kguard_snapshot *snap;
	unsigned int capacity = kguard_ring_capacity();
	int ret;

	snap = kvmalloc(struct_size(snap, events, capacity), GFP_KERNEL);
	if (!snap)
		return -ENOMEM;

	/* Only one consumer at a time: /dev/kguard or this file */
	if (!kguard_reader_claim()) {
		kvfree(snap);
		return -EBUSY;
	}
	snap->count = kguard_ring_drain(snap->events, capacity, &snap->dropped);
	kguard_reader_release();

	/* Events come from per-CPU rings; put them back in time order */
	sort(snap->events, snap->count, sizeof(struct kguard_event),
	     kguard_cmp_time, NULL);

	ret = seq_open(file, &kguard_seq_ops);
	if (ret) {
		kguard_warn("Lost %u events: seq_open failed (%d)", snap->count, ret);
		kvfree(snap);
		return ret;
	}

	((struct seq_file *)file->private_data)->private = snap;
	return 0;
}

static int kguard_proc_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;

	kvfree(m->private);
	return seq_release(inode, file);
}

static const struct proc_ops kguard_proc_ops = {
	.proc_open    = kguard_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = kguard_proc_release,
};

/*
 * Create /proc/kguard. Reading consumes events, so it is root-only unless
 * reader_gid names a group that may read it too.
 */
int kguard_proc_init(void)
{
	umode_t mode = kguard_reader_gid >= 0 ? 0440 : 0400;
	kgid_t gid = GLOBAL_ROOT_GID;

	if (kguard_reader_gid >= 0) {
		gid = make_kgid(&init_user_ns, kguard_reader_gid);
		if (!gid_valid(gid)) {
			kguard_err("Invalid reader_gid %d", kguard_reader_gid);
			return -EINVAL;
		}
	}

	kguard_proc_entry = proc_create(KGUARD_PROC_NAME, mode, NULL,
					&kguard_proc_ops);
	if (!kguard_proc_entry) {
		kguard_err("Failed to create proc entry");
		return -ENOMEM;
	}
	proc_set_user(kguard_proc_entry, GLOBAL_ROOT_UID, gid);
	return 0;
}

void kguard_proc_cleanup(void)
{
	proc_remove(kguard_proc_entry);
	kguard_proc_entry = NULL;
}
