// SPDX-License-Identifier: GPL-2.0
/*
 * KGuard Kernel Module - statistics and debugfs
 *
 * Counters are per CPU and updated without locks; readers sum them.
 *
 * debugfs (usually /sys/kernel/debug/kguard/):
 *   stats   totals: packets, events, drops, hook cost, ring fill
 *   rings   events waiting and dropped, per ring
 *   config  current runtime configuration
 *   blocks  blocklist: address, seconds left (0 = permanent), reason
 *   allow   allowlist prefixes
 */

#include "kguard.h"

#include <linux/debugfs.h>
#include <linux/seq_file.h>

DEFINE_PER_CPU(struct kguard_stats, kguard_pcpu_stats);

static struct dentry *kguard_debugfs_dir;

void kguard_stats_read(struct kguard_stats_total *total)
{
	u64 ns_total = 0, ns_samples = 0;
	int cpu;

	memset(total, 0, sizeof(*total));
	for_each_possible_cpu(cpu) {
		const struct kguard_stats *s = per_cpu_ptr(&kguard_pcpu_stats, cpu);

		total->packets += READ_ONCE(s->packets);
		total->events += READ_ONCE(s->events);
		total->dropped += READ_ONCE(s->dropped);
		total->filtered += READ_ONCE(s->filtered);
		ns_total += READ_ONCE(s->ns_total);
		ns_samples += READ_ONCE(s->ns_samples);
		total->alerts += READ_ONCE(s->alerts);
		total->block_drops += READ_ONCE(s->block_drops);
		total->rate_drops += READ_ONCE(s->rate_drops);
		total->would_drop += READ_ONCE(s->would_drop);
	}
	total->ns_per_packet = ns_samples ? div64_u64(ns_total, ns_samples) : 0;
	total->ring_fill = kguard_ring_fill();
	total->netns = kguard_netns_count();
	total->sources = kguard_track_count();
	total->track_full = kguard_track_full();
	total->blocks = kguard_block_count();
}

static int kguard_stats_show(struct seq_file *m, void *v)
{
	struct kguard_stats_total t;

	kguard_stats_read(&t);
	seq_printf(m, "packets        %llu\n", t.packets);
	seq_printf(m, "events         %llu\n", t.events);
	seq_printf(m, "dropped        %llu\n", t.dropped);
	seq_printf(m, "filtered       %llu\n", t.filtered);
	seq_printf(m, "ns_per_packet  %llu\n", t.ns_per_packet);
	seq_printf(m, "ring_fill      %llu\n", t.ring_fill);
	seq_printf(m, "ring_capacity  %u\n", kguard_ring_capacity());
	seq_printf(m, "netns_hooked   %llu\n", t.netns);
	seq_printf(m, "sources        %llu\n", t.sources);
	seq_printf(m, "track_full     %llu\n", t.track_full);
	seq_printf(m, "alerts         %llu\n", t.alerts);
	seq_printf(m, "block_drops    %llu\n", t.block_drops);
	seq_printf(m, "rate_drops     %llu\n", t.rate_drops);
	seq_printf(m, "would_drop     %llu\n", t.would_drop);
	seq_printf(m, "blocks         %llu\n", t.blocks);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(kguard_stats);

static int kguard_rings_show(struct seq_file *m, void *v)
{
	kguard_ring_show(m);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(kguard_rings);

static int kguard_config_show(struct seq_file *m, void *v)
{
	seq_printf(m, "capture_in     %d\n", READ_ONCE(kguard_cfg.capture_in));
	seq_printf(m, "capture_out    %d\n", READ_ONCE(kguard_cfg.capture_out));
	seq_printf(m, "capture_fwd    %d\n", READ_ONCE(kguard_cfg.capture_fwd));
	seq_printf(m, "capture_ipv6   %d\n", READ_ONCE(kguard_cfg.capture_ipv6));
	seq_printf(m, "socket_lookup  %d\n", READ_ONCE(kguard_cfg.socket_lookup));
	seq_printf(m, "wakeup_events  %u\n", READ_ONCE(kguard_cfg.wakeup_events));
	seq_printf(m, "enforce        %d\n", READ_ONCE(kguard_cfg.enforce));
	seq_printf(m, "auto_block     %d\n", READ_ONCE(kguard_cfg.auto_block));
	seq_printf(m, "scan_threshold %u\n", READ_ONCE(kguard_cfg.scan_threshold));
	seq_printf(m, "scan_window_ms %u\n", READ_ONCE(kguard_cfg.scan_window_ms));
	seq_printf(m, "syn_rate       %u\n", READ_ONCE(kguard_cfg.syn_rate));
	seq_printf(m, "syn_burst      %u\n", READ_ONCE(kguard_cfg.syn_burst));
	seq_printf(m, "block_timeout  %u\n", READ_ONCE(kguard_cfg.block_timeout));
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(kguard_config);

static void kguard_show_addr(struct seq_file *m, const struct kguard_addr *a)
{
	if (a->family == AF_INET6)
		seq_printf(m, "%pI6c", a->bytes);
	else
		seq_printf(m, "%pI4", a->bytes);
}

static int kguard_show_block(void *ctx, const struct kguard_addr *a, u64 expires_ms, u8 reason)
{
	static const char * const reasons[] = { "?", "manual", "scan", "syn_rate" };
	struct seq_file *m = ctx;

	kguard_show_addr(m, a);
	seq_printf(m, " %llu %s\n", div_u64(expires_ms + 999, 1000),
		   reason < ARRAY_SIZE(reasons) ? reasons[reason] : "?");
	return 0;
}

static int kguard_blocks_show(struct seq_file *m, void *v)
{
	kguard_block_walk(kguard_show_block, m, 0);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(kguard_blocks);

static int kguard_show_allow(void *ctx, const struct kguard_addr *a, u8 prefix_len)
{
	struct seq_file *m = ctx;

	kguard_show_addr(m, a);
	seq_printf(m, "/%u\n", prefix_len);
	return 0;
}

static int kguard_allow_show(struct seq_file *m, void *v)
{
	kguard_allow_walk(kguard_show_allow, m);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(kguard_allow);

/* debugfs is optional: failures are ignored, as the debugfs API intends */
int kguard_debugfs_init(void)
{
	kguard_debugfs_dir = debugfs_create_dir(KGUARD_MODULE_NAME, NULL);
	debugfs_create_file("stats", 0400, kguard_debugfs_dir, NULL, &kguard_stats_fops);
	debugfs_create_file("rings", 0400, kguard_debugfs_dir, NULL, &kguard_rings_fops);
	debugfs_create_file("config", 0400, kguard_debugfs_dir, NULL, &kguard_config_fops);
	debugfs_create_file("blocks", 0400, kguard_debugfs_dir, NULL, &kguard_blocks_fops);
	debugfs_create_file("allow", 0400, kguard_debugfs_dir, NULL, &kguard_allow_fops);
	return 0;
}

void kguard_debugfs_cleanup(void)
{
	debugfs_remove_recursive(kguard_debugfs_dir);
	kguard_debugfs_dir = NULL;
}
