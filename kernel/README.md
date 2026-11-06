# KGuard Kernel Module

A Linux kernel module that records every IPv4 and IPv6 packet entering,
leaving or passing through the machine, with the context a security tool
needs: connection-tracking state, network namespace, and the process or
socket owner behind the connection. Events reach user space through
per-CPU lock-free ring buffers mapped straight into the reader's memory.

It also guards the machine from inside the kernel: it detects port scans
and SYN floods per source, and can drop traffic from blocked or flooding
sources before connection tracking ever sees it. It ships in monitor-only
mode and never drops anything until you turn enforcement on.

Tested on Linux 6.8 (Ubuntu 24.04 kernel), in a VM, with real traffic.

## How it works

```
 packet ─► guard hook (PRE_ROUTING, first): allowlist ─► blocklist ─►
           per-source scan + SYN-rate tracking ─► alerts (Netlink multicast),
           drops only when enforcing
      │
      ▼
           Netfilter hooks (LOCAL_IN / LOCAL_OUT / FORWARD, IPv4 + IPv6,
           every network namespace, just after conntrack)
              │  parse headers safely, add conntrack state, find the
              │  socket owner (UID, socket inode, sending process)
              ▼
           per-CPU ring buffers (one writer per ring, no shared lock)
              │
              ├─► /dev/kguard   mmap() + poll(): zero-copy, one reader
              └─► /proc/kguard  JSON text view, for debugging

 control:  Generic Netlink family "kguard" (stats, live configuration,
           change notifications)        tools/kguardctl.py
 insight:  debugfs counters, tracepoints kguard:kguard_event and
           kguard:kguard_ring_full
```

| File | What it does |
|---|---|
| `include/uapi/linux/kguard.h` | The ABI shared with user space: event record, ring layout, Netlink commands |
| `src/kguard_netfilter.c` | Hooks registered per network namespace; IPv4/IPv6 parsing; conntrack state; socket and process attribution |
| `src/kguard_guard.c` | Guard hook: allowlist, blocklist, scan and SYN-rate detection, enforcement, alerts |
| `src/kguard_track.c` | Per-source state table (RCU hash table, capped, garbage-collected), blocklist, allowlist |
| `src/kguard_ring.c` | Per-CPU single-producer rings with acquire/release ordering |
| `src/kguard_dev.c` | `/dev/kguard`: exclusive open, `mmap`, `poll` |
| `src/kguard_proc.c` | `/proc/kguard` JSON view |
| `src/kguard_genl.c` | Generic Netlink control interface |
| `src/kguard_stats.c` | Per-CPU counters and debugfs files |
| `src/kguard_trace.h` | Tracepoints |
| `tools/kguard_reader.c` | Example zero-copy reader in C |
| `tools/kguardctl.py` | Netlink control tool (standard-library Python) |
| `tests/` | Test suite that runs against a real kernel (`vm_tests.py`, `guard_tests.py`), plus a VM runner |

### Design notes

- **Lock-free rings.** Each CPU writes only to its own ring. Interrupts are
  disabled for the few instructions of a write, so a hook running in process
  context cannot interleave with one in softirq context on the same CPU.
  The kernel publishes `head` with release semantics and reads the reader's
  `tail` with acquire semantics; the reader does the reverse.
- **Untrusted tail.** The reader's `tail` lives in memory the reader can
  write, so the kernel never relies on it for memory safety: slot indexes
  are always masked, and a bogus tail only makes a ring look full.
- **Full rings drop new events** and count them per ring, in debugfs, and
  through the `kguard_ring_full` tracepoint. Older events are never
  overwritten while a reader may be copying them.
- **Wakeups.** A sleeping reader is woken when a ring goes from empty to
  non-empty, and then every `wakeup_events` events. An idle reader uses no
  CPU.
- **Process attribution.** Packets sent from a process's own context
  (`connect()`, `sendmsg()`) record its PID and name. For incoming TCP/UDP,
  the module looks up the local socket (listener or connection) and records
  its owner UID and inode; user space maps the inode to processes through
  `/proc/<pid>/fd`, as `ss -p` does. Kernel-internal sockets are skipped.
- **Namespaces.** Hooks are registered through `pernet_operations`, so
  every new network namespace (for example a container) is covered
  automatically and its events carry its namespace inode number.
- **Per-source state.** An `rhashtable` keyed by (address, namespace),
  looked up under RCU on the packet path, with one spinlock per source so
  sources never contend. Each source has a 1024-bit bitmap of ports tried
  in the current window (distinct-port count) and a SYN token bucket. The
  table is capped by `max_sources`; a worker frees idle sources every
  second (sooner when nearly full), so a flood of spoofed addresses cannot
  exhaust memory. Sources come from their own slab cache (`kguard_src` in
  `/proc/slabinfo`).
- **Fail-safe.** `enforce` is off by default. Allowlisted prefixes skip the
  guard entirely, and the machine's own addresses (loopback and every
  local address) are tracked and alerted on but can never be blocked or
  rate-limited.

## Building

```bash
sudo apt install linux-headers-$(uname -r) build-essential
make              # build kguard.ko (warnings are errors)
make tools        # build tools/kguard_reader
make checkpatch   # kernel coding style, strict
make KDIR=/path/to/kernel/build   # build for another kernel
```

## Loading

The module uses connection tracking and socket lookup, which `insmod` does
not load by itself:

```bash
sudo modprobe -a nf_conntrack nf_socket_ipv4 nf_socket_ipv6
sudo insmod kguard.ko
# or simply: sudo make install
```

### Module parameters

| Parameter | Default | Meaning |
|---|---|---|
| `buffer_size` | 16384 | Events per CPU ring (rounded up to a power of two, 64 to 262144) |
| `reader_gid` | -1 | Group allowed to read `/dev/kguard` and `/proc/kguard`; -1 means root only |
| `capture_in` / `capture_out` / `capture_fwd` | 1 | Which directions to record |
| `capture_ipv6` | 1 | Record IPv6 as well as IPv4 |
| `socket_lookup` | 1 | Find the local socket of incoming TCP/UDP packets |
| `conntrack` | 1 | Enable connection tracking to report packet state |
| `wakeup_events` | 64 | Wake a waiting reader every N events |
| `enforce` | 0 | 0: monitor only, never drop. 1: drop blocked sources and excess SYNs |
| `auto_block` | 0 | Block detected scanners automatically (only when enforcing) |
| `scan_threshold` | 20 | Distinct ports from one source within the window that count as a scan |
| `scan_window_ms` | 5000 | Window for counting distinct ports |
| `syn_rate` / `syn_burst` | 200 / 400 | New TCP connections per second (and burst) allowed per source |
| `block_timeout` | 600 | Seconds an automatic block lasts (0 = until removed) |
| `allow` | "" | Prefixes never blocked, e.g. `allow=10.0.0.0/8,2001:db8::/32` |
| `max_sources` | 65536 | Most sources tracked at once (caps memory) |
| `idle_timeout` | 60 | Seconds of silence before a source's state is freed |

`buffer_size`, `reader_gid`, `conntrack`, `allow`, `max_sources` and
`idle_timeout` are fixed at load time; everything else can be changed while
running with `kguardctl set`, and the allowlist with `kguardctl allow`.

## Reading events

Only one reader at a time: while a program holds `/dev/kguard`,
`/proc/kguard` returns `EBUSY`. Reading removes events from the rings.

**Zero-copy device** (what the backend uses):

```bash
sudo tools/kguard_reader            # print events as they arrive
sudo tools/kguard_reader -q -t 10   # count for 10 seconds
```

The ring layout and reader protocol are documented at the top of
`include/uapi/linux/kguard.h`.

**JSON view** (handy for debugging):

```bash
sudo cat /proc/kguard
```

```json
{"dropped": 0, "events": [
{"timestamp": 1762380000123456789, "family": 4, "src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "src_port": 50916, "dst_port": 4444, "protocol": "TCP", "flags": 2, "direction": "out", "ct_state": "new", "netns": 4026531840, "ifindex": 1, "pid": 120, "comm": "curl", "uid": 1000, "sock_ino": 1177}
]}
```

| Field | Meaning |
|---|---|
| `dropped` | Events lost to full rings since the module loaded |
| `timestamp` | Wall-clock time, nanoseconds since the Unix epoch |
| `family` | 4 or 6 |
| `direction` | `in` (to this host), `out` (from it), `fwd` (routed through it) |
| `flags` | TCP flags: FIN 0x01, SYN 0x02, RST 0x04, PSH 0x08, ACK 0x10, URG 0x20 |
| `ct_state` | `new`, `established`, `related`, `invalid`, `untracked`, or `none` without conntrack |
| `netns` | Network namespace inode number |
| `pid`, `comm` | Sending process, when sent from its own context; otherwise -1 and "" |
| `uid`, `sock_ino` | Owner and inode of the local socket; otherwise -1 and 0 |

Ports are 0 for protocols without ports and for non-first IP fragments.

### Permissions

`/dev/kguard` opens for `CAP_NET_ADMIN` or members of `reader_gid`.
`/proc/kguard` is mode 0400, or 0440 owned by `reader_gid`. To let the
backend's Docker container (an unprivileged user) read events:

```bash
sudo insmod kguard.ko reader_gid=1500
```

The Compose files add group 1500 to the backend (override with
`KGUARD_READER_GID`); uncomment the `devices:` entry to pass
`/dev/kguard` through.

## Guard: detection and blocking

```bash
python3 tools/kguardctl.py watch                      # live alerts
sudo python3 tools/kguardctl.py allow 192.168.1.0/24  # your management network first
sudo python3 tools/kguardctl.py set enforce=1         # start dropping
sudo python3 tools/kguardctl.py set auto_block=1 block_timeout=600
sudo python3 tools/kguardctl.py block 203.0.113.9 --timeout 3600
python3 tools/kguardctl.py blocks
sudo python3 tools/kguardctl.py unblock 203.0.113.9
```

What happens to a packet from a source that is not allowlisted:

| Situation | Monitor only (default) | `enforce=1` |
|---|---|---|
| Source is blocked | counted as `would_drop` | dropped (`block_drops`) |
| `scan_threshold` distinct ports in the window | `scan` alert | `scan` alert; blocked if `auto_block=1` |
| SYNs beyond `syn_rate`/`syn_burst` | `syn_rate` alert, counted as `would_drop` | excess SYNs dropped (`rate_drops`), alert |

Alerts are sent at most once per source and kind every 10 seconds, and at
most 100 per second overall. They go to the Netlink `events` group (the
backend stores them as dashboard alerts) and to the `kguard:kguard_alert`
tracepoint. Trying to block a local or allowlisted address is refused.

## Control and statistics

```bash
python3 tools/kguardctl.py stats                 # counters, hook cost
python3 tools/kguardctl.py config
sudo python3 tools/kguardctl.py set capture_out=0 wakeup_events=128
python3 tools/kguardctl.py watch                 # print configuration changes

sudo mount -t debugfs none /sys/kernel/debug     # if not mounted
sudo cat /sys/kernel/debug/kguard/{stats,rings,config,blocks,allow}

sudo perf record -e 'kguard:*' -a sleep 5        # or tracefs:
echo 1 | sudo tee /sys/kernel/tracing/events/kguard/enable
```

## Testing

`tests/vm_tests.py` loads the module and checks every feature with real
traffic (61 checks): lossless zero-copy reads at 5,000 packets/s, idle CPU
use, exclusive access, process attribution (curl, an `nc` listener),
conntrack states including invalid packets, IPv6, network namespaces, live
reconfiguration over Netlink, tracepoints, ring overflow and permissions.

`tests/guard_tests.py` (run by `vm_tests.py`) builds an attacker network
namespace joined by a veth pair and checks: an nmap SYN scan is reported
within a second, monitor-only mode drops nothing, blocks are enforced and
expire, IPv6 blocks, the allowlist always wins, local addresses cannot be
blocked, a SYN flood is cut to the configured rate, auto-blocking, and that
20,000 spoofed sources keep the state table at its cap with no leaks.

Run it in a throwaway VM so a kernel bug cannot take down your machine:

```bash
pip install virtme-ng
kernel/tests/run_in_vm.sh                     # boot the running kernel
kernel/tests/run_in_vm.sh /boot/vmlinuz-X     # or a specific one
```

`tests/load_test.py` is a standalone throughput check for `/proc/kguard`.

## Troubleshooting

| Problem | Fix |
|---|---|
| `insmod: Unknown symbol nf_ct_netns_get` | Load dependencies first: `sudo modprobe -a nf_conntrack nf_socket_ipv4 nf_socket_ipv6` |
| `open /dev/kguard: Device or resource busy` | Another reader (often the backend) holds it |
| `/proc/kguard: Device or resource busy` | Same: a reader holds `/dev/kguard` |
| `dropped` keeps rising | The reader is too slow: raise `buffer_size` or read more often |
| `refused: that address is local or allowlisted` | By design: local and allowlisted addresses are never blocked |
| `track_full` rising in stats | More active sources than `max_sources`; raise it, or lower `idle_timeout` |
| Kernel log | `dmesg \| grep kguard` |
