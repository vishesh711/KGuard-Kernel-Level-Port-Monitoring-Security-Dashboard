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
	}
	total->ns_per_packet = ns_samples ? div64_u64(ns_total, ns_samples) : 0;
	total->ring_fill = kguard_ring_fill();
	total->netns = kguard_netns_count();
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
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(kguard_config);

/* debugfs is optional: failures are ignored, as the debugfs API intends */
int kguard_debugfs_init(void)
{
	kguard_debugfs_dir = debugfs_create_dir(KGUARD_MODULE_NAME, NULL);
	debugfs_create_file("stats", 0400, kguard_debugfs_dir, NULL, &kguard_stats_fops);
	debugfs_create_file("rings", 0400, kguard_debugfs_dir, NULL, &kguard_rings_fops);
	debugfs_create_file("config", 0400, kguard_debugfs_dir, NULL, &kguard_config_fops);
	return 0;
}

void kguard_debugfs_cleanup(void)
{
	debugfs_remove_recursive(kguard_debugfs_dir);
	kguard_debugfs_dir = NULL;
}
