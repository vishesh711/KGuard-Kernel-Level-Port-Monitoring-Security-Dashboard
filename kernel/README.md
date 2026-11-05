# KGuard Kernel Module

A Linux kernel module that records every IPv4 and IPv6 packet entering,
leaving or passing through the machine, with the context a security tool
needs: connection-tracking state, network namespace, and the process or
socket owner behind the connection. Events reach user space through
per-CPU lock-free ring buffers mapped straight into the reader's memory.

Tested on Linux 6.8 (Ubuntu 24.04 kernel).

## How it works

```
 packet ─► Netfilter hooks (LOCAL_IN / LOCAL_OUT / FORWARD, IPv4 + IPv6,
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
| `src/kguard_ring.c` | Per-CPU single-producer rings with acquire/release ordering |
| `src/kguard_dev.c` | `/dev/kguard`: exclusive open, `mmap`, `poll` |
| `src/kguard_proc.c` | `/proc/kguard` JSON view |
| `src/kguard_genl.c` | Generic Netlink control interface |
| `src/kguard_stats.c` | Per-CPU counters and debugfs files |
| `src/kguard_trace.h` | Tracepoints |
| `tools/kguard_reader.c` | Example zero-copy reader in C |
| `tools/kguardctl.py` | Netlink control tool (standard-library Python) |
| `tests/` | Test suite that runs against a real kernel, plus a VM runner |

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

All but `buffer_size`, `reader_gid` and `conntrack` can be changed while
running with `kguardctl set`.

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

## Control and statistics

```bash
python3 tools/kguardctl.py stats                 # counters, hook cost
python3 tools/kguardctl.py config
sudo python3 tools/kguardctl.py set capture_out=0 wakeup_events=128
python3 tools/kguardctl.py watch                 # print configuration changes

sudo mount -t debugfs none /sys/kernel/debug     # if not mounted
sudo cat /sys/kernel/debug/kguard/{stats,rings,config}

sudo perf record -e 'kguard:*' -a sleep 5        # or tracefs:
echo 1 | sudo tee /sys/kernel/tracing/events/kguard/enable
```

## Testing

`tests/vm_tests.py` loads the module and checks every feature with real
traffic: lossless zero-copy reads at 5,000 packets/s, idle CPU use,
exclusive access, process attribution (curl, an `nc` listener), conntrack
states including invalid packets, IPv6, network namespaces, live
reconfiguration over Netlink, tracepoints, ring overflow and permissions.

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
| Kernel log | `dmesg \| grep kguard` |
