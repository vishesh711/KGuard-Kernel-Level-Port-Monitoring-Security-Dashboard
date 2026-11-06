// SPDX-License-Identifier: GPL-2.0
/*
 * KGuard Kernel Module - entry point and module parameters
 *
 * Start-up order: rings, /dev/kguard, /proc/kguard, Generic Netlink,
 * debugfs, and last the Netfilter hooks (so nothing produces events before
 * there is somewhere to put them). Shutdown runs in reverse.
 */

#include "kguard.h"

#define CREATE_TRACE_POINTS
#include "kguard_trace.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(KGUARD_MODULE_DESC);
MODULE_AUTHOR(KGUARD_MODULE_AUTHOR);
MODULE_VERSION(KGUARD_MODULE_VERSION);
/* For process attribution and connection state */
MODULE_SOFTDEP("pre: nf_conntrack nf_socket_ipv4 nf_socket_ipv6");

static unsigned int buffer_size = KGUARD_RING_DEFAULT;
module_param(buffer_size, uint, 0444);
MODULE_PARM_DESC(buffer_size,
		 "Events each per-CPU ring holds, rounded up to a power of two (64 to 262144, default 16384)");

int kguard_reader_gid = -1;
module_param_named(reader_gid, kguard_reader_gid, int, 0444);
MODULE_PARM_DESC(reader_gid,
		 "Group allowed to read /dev/kguard and /proc/kguard (default -1: root only)");

static bool capture_in = true;
module_param(capture_in, bool, 0444);
MODULE_PARM_DESC(capture_in, "Capture packets delivered to this host (default on)");

static bool capture_out = true;
module_param(capture_out, bool, 0444);
MODULE_PARM_DESC(capture_out, "Capture packets sent by this host (default on)");

static bool capture_fwd = true;
module_param(capture_fwd, bool, 0444);
MODULE_PARM_DESC(capture_fwd, "Capture packets routed through this host (default on)");

static bool capture_ipv6 = true;
module_param(capture_ipv6, bool, 0444);
MODULE_PARM_DESC(capture_ipv6, "Capture IPv6 as well as IPv4 (default on)");

static bool socket_lookup = true;
module_param(socket_lookup, bool, 0444);
MODULE_PARM_DESC(socket_lookup, "Find the local socket of incoming TCP/UDP packets (default on)");

static unsigned int wakeup_events = 64;
module_param(wakeup_events, uint, 0444);
MODULE_PARM_DESC(wakeup_events, "Wake a waiting reader every N events (default 64)");

/* Guard: in-kernel detection and enforcement */
static bool enforce;
module_param(enforce, bool, 0444);
MODULE_PARM_DESC(enforce, "Drop traffic from blocked sources and excess SYNs (default off: monitor only)");

static bool auto_block;
module_param(auto_block, bool, 0444);
MODULE_PARM_DESC(auto_block, "Block detected scanners automatically when enforcing (default off)");

static unsigned int scan_threshold = 20;
module_param(scan_threshold, uint, 0444);
MODULE_PARM_DESC(scan_threshold, "Distinct ports from one source within the window that count as a scan (default 20)");

static unsigned int scan_window_ms = 5000;
module_param(scan_window_ms, uint, 0444);
MODULE_PARM_DESC(scan_window_ms, "Window for counting distinct ports, in ms (default 5000)");

static unsigned int syn_rate = 200;
module_param(syn_rate, uint, 0444);
MODULE_PARM_DESC(syn_rate, "New TCP connections per second allowed per source (default 200)");

static unsigned int syn_burst = 400;
module_param(syn_burst, uint, 0444);
MODULE_PARM_DESC(syn_burst, "Burst of new TCP connections allowed per source (default 400)");

static unsigned int block_timeout = 600;
module_param(block_timeout, uint, 0444);
MODULE_PARM_DESC(block_timeout, "Seconds an automatic block lasts (default 600, 0 = until removed)");

static unsigned int max_sources = 65536;
module_param(max_sources, uint, 0444);
MODULE_PARM_DESC(max_sources, "Most sources tracked at once; caps memory (default 65536)");

static unsigned int idle_timeout = 60;
module_param(idle_timeout, uint, 0444);
MODULE_PARM_DESC(idle_timeout, "Seconds of silence before a source's state is freed (default 60)");

static char *allow = "";
module_param(allow, charp, 0444);
MODULE_PARM_DESC(allow, "Comma-separated addresses/prefixes never blocked, e.g. 10.0.0.0/8,2001:db8::/32");

/* Load-time values; Generic Netlink can change them later */
struct kguard_config kguard_cfg;

static int __init kguard_init(void)
{
	int ret;

	kguard_cfg.capture_in = capture_in;
	kguard_cfg.capture_out = capture_out;
	kguard_cfg.capture_fwd = capture_fwd;
	kguard_cfg.capture_ipv6 = capture_ipv6;
	kguard_cfg.socket_lookup = socket_lookup;
	kguard_cfg.wakeup_events = clamp_t(unsigned int, wakeup_events, 1, 1U << 20);
	kguard_cfg.enforce = enforce;
	kguard_cfg.auto_block = auto_block;
	kguard_cfg.scan_threshold = clamp_t(unsigned int, scan_threshold, 2, 65536);
	kguard_cfg.scan_window_ms = clamp_t(unsigned int, scan_window_ms, 100, 3600 * 1000);
	kguard_cfg.syn_rate = clamp_t(unsigned int, syn_rate, 1, 1000000);
	kguard_cfg.syn_burst = clamp_t(unsigned int, syn_burst, 1, 1000000);
	kguard_cfg.block_timeout = block_timeout;

	ret = kguard_ring_init(buffer_size);
	if (ret)
		goto err;
	ret = kguard_dev_init();
	if (ret)
		goto err_ring;
	ret = kguard_proc_init();
	if (ret)
		goto err_dev;
	ret = kguard_track_init(max_sources, idle_timeout, allow);
	if (ret)
		goto err_proc;
	ret = kguard_genl_init();
	if (ret)
		goto err_track;
	kguard_debugfs_init();
	ret = kguard_netfilter_init();
	if (ret)
		goto err_genl;

	kguard_info("v%s loaded: /dev/kguard, /proc/kguard, %u netns hooked, guard %s",
		    KGUARD_MODULE_VERSION, kguard_netns_count(),
		    enforce ? "enforcing" : "monitoring only");
	return 0;

err_genl:
	kguard_debugfs_cleanup();
	kguard_genl_cleanup();
err_track:
	kguard_track_cleanup();
err_proc:
	kguard_proc_cleanup();
err_dev:
	kguard_dev_cleanup();
err_ring:
	kguard_ring_cleanup();
err:
	kguard_err("Failed to load: %d", ret);
	return ret;
}

static void __exit kguard_exit(void)
{
	/* Stop producers first; unregistering waits for running hooks */
	kguard_netfilter_cleanup();
	kguard_debugfs_cleanup();
	kguard_genl_cleanup();
	kguard_track_cleanup();
	kguard_proc_cleanup();
	kguard_dev_cleanup();
	kguard_ring_cleanup();
	kguard_info("unloaded");
}

module_init(kguard_init);
module_exit(kguard_exit);
