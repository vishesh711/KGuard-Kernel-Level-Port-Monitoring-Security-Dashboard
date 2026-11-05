// SPDX-License-Identifier: GPL-2.0
/*
 * KGuard Kernel Module - Proc Filesystem Interface
 *
 * Reading /proc/kguard returns the queued network events as one JSON
 * document and removes them from the buffer.
 *
 * Each open() moves every queued event into a private snapshot, and the
 * seq_file iterator then walks that snapshot by position. seq_file may call
 * show() for the same position more than once (when its output buffer has to
 * grow, or when a read ends mid-record), so events must never be removed
 * inside show(). Taking them out once at open() keeps every event intact for
 * as long as the reader keeps the file open.
 *
 * Output:
 *   {"dropped": N, "events": [
 *   {"timestamp": ..., "src_ip": "...", ...},
 *   ...
 *   ]}
 * "dropped" is the total number of events overwritten because the buffer
 * was full since the module was loaded.
 */

#include "kguard.h"

static int reader_gid = -1;
module_param(reader_gid, int, 0444);
MODULE_PARM_DESC(reader_gid,
		 "Group ID allowed to read /proc/kguard (default -1: root only)");

struct kguard_snapshot {
	u64 dropped;
	unsigned int count;
	struct kguard_event events[];
};

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

static int kguard_seq_show(struct seq_file *m, void *v)
{
	struct kguard_snapshot *snap = m->private;
	unsigned int pos = (unsigned int)((uintptr_t)v - 1);
	const struct kguard_event *e;
	__be32 src, dst;

	if (pos == 0) {
		seq_printf(m, "{\"dropped\": %llu, \"events\": [\n", snap->dropped);
		return 0;
	}

	if (pos > snap->count) {
		seq_puts(m, "\n]}\n");
		return 0;
	}

	e = &snap->events[pos - 1];
	src = htonl(e->src_ip);
	dst = htonl(e->dst_ip);

	if (pos > 1)
		seq_puts(m, ",\n");
	seq_printf(m, "{\"timestamp\": %llu, \"src_ip\": \"%pI4\", \"dst_ip\": \"%pI4\", ",
		   e->timestamp, &src, &dst);
	seq_printf(m, "\"src_port\": %u, \"dst_port\": %u, \"protocol\": \"%s\", \"flags\": %u}",
		   e->src_port, e->dst_port, kguard_protocol_name(e->protocol), e->flags);
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
	unsigned int capacity = kguard_buffer_capacity();
	int ret;

	snap = kvmalloc(struct_size(snap, events, capacity), GFP_KERNEL);
	if (!snap)
		return -ENOMEM;

	ret = kguard_buffer_drain(snap->events, capacity, &snap->dropped);
	if (ret < 0) {
		kvfree(snap);
		return ret;
	}
	snap->count = ret;

	ret = seq_open(file, &kguard_seq_ops);
	if (ret) {
		/* Events already left the ring buffer; count them as dropped */
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
 * Create /proc/kguard
 */
int kguard_proc_init(void)
{
	umode_t mode = reader_gid >= 0 ? 0440 : 0400;
	kgid_t gid = GLOBAL_ROOT_GID;

	/* Reading consumes events, so never let every user read the file */
	if (reader_gid >= 0) {
		gid = make_kgid(&init_user_ns, reader_gid);
		if (!gid_valid(gid)) {
			kguard_err("Invalid reader_gid %d", reader_gid);
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

/*
 * Remove /proc/kguard
 */
void kguard_proc_cleanup(void)
{
	if (kguard_proc_entry) {
		proc_remove(kguard_proc_entry);
		kguard_proc_entry = NULL;
	}
}
