# KGuard design

How KGuard is built, why each part is built that way, what else was
considered, and what was measured. Numbers link to where they were
measured; "VM" means a QEMU guest and, unless it says KVM, an emulated one
(see [BENCHMARKS.md](BENCHMARKS.md) for what that does to timings).

## Goals and constraints

1. **See every connection attempt on a host**, in and out, IPv4 and IPv6,
   in every network namespace (containers), with the process behind it.
2. **Never be the reason a host is slow or down.** The packet path must not
   take a shared lock, allocate per packet, or wait on user space. A slow or
   dead reader may lose events but must not slow the network.
3. **Detect the attacks that matter at line rate in the kernel** (scans, SYN
   floods, spoofed sources) and leave everything that needs history or
   context (brute force, DNS tunnels, TLS fingerprints, baselines) to user
   space.
4. **Fail safe.** Out of the box nothing is dropped; when blocking is on, the
   host's own addresses and an allowlist can never be blocked.
5. **Run on stock kernels** (5.15 onwards) without patches, and, where a
   kernel module is not acceptable, without a module at all.

## The packet path, end to end

A TCP SYN arriving from the network on a host with the module loaded:

1. **Guard hook** (`NF_INET_PRE_ROUTING`, priority `NF_IP_PRI_FIRST`, before
   connection tracking). `kguard_guard.c` checks, in order: a source address
   that cannot arrive on a real interface (loopback, one of this host's own
   addresses, multicast, broadcast, zero) → spoof alert; the allowlist (CIDR) → skip everything; the
   blocklist (exact address with expiry) → `NF_DROP` if enforcing; the
   per-source table: one RCU lookup in an `rhashtable` keyed by (address,
   network namespace), then the source's own spinlock to set its bit in the
   distinct-port bitmap and take a token from its SYN bucket. Crossing a
   threshold sends an alert (at most one per source and kind every 10 s,
   100/s overall) over Generic Netlink multicast and the
   `kguard:kguard_alert` tracepoint.
2. **Conntrack** runs (and defragments).
3. **Capture hook** (`NF_INET_LOCAL_IN`, priority `NF_IP_PRI_CONNTRACK + 1`;
   `LOCAL_OUT` and `FORWARD` for the other directions). `kguard_netfilter.c`
   reads headers with `skb_header_pointer()` (safe on non-linear and short
   packets), skips IP options and IPv6 extension headers, records TTL, IP
   length, TCP window and, for a SYN, the order and values of its TCP options
   (OS fingerprint); adds the conntrack state; finds the owning socket (the
   sending process in `connect()`/`sendmsg()` context, or the listener for
   incoming packets via `nf_sk_lookup_slow_v4/6`) and records UID, socket
   inode and process name. The result is a fixed 128-byte `struct
   kguard_event` built on the stack.
4. **Ring write** (`kguard_ring.c`). With interrupts off for a handful of
   instructions: read this CPU's ring `head`, `smp_load_acquire()` the
   reader's `tail`, and either drop (ring full: count it) or `memcpy` the
   event into slot `head & (slots - 1)` and `smp_store_release(head + 1)`.
   If the ring was empty, or every `wakeup_events` (64) events, wake the
   reader. The hook returns `NF_ACCEPT`.
5. **Reader** (`backend/app/services/kguard_device.py`, or
   `agent/src/engine_module.c`). It has `/dev/kguard` mapped, sleeps in
   `poll()`, and on wake-up walks each ring from `tail` to an acquired
   `head`, then releases the new `tail`. No system call per event and no
   copy beyond the read itself.
6. **Backend** (`data_collector.py`). Up to 20,000 events per cycle are
   stored in one batch insert, the process behind each socket inode is
   resolved through `/proc/<pid>/fd` (cached), detectors run on the batch,
   and new events and alerts go to dashboards over the WebSocket.
7. **Dashboard.** WebSocket messages are written straight into the React
   Query cache, so open pages update without polling; the measured delay
   from packet to table row is under a second ([U7.1](../ROADMAP.md)).

With the eBPF engine, steps 1 to 4 are replaced by an XDP program (ingress)
and a TC egress program writing the same 128-byte event into a BPF ring
buffer, and the agent ships batches to the backend over HTTPS.

## Design decisions

### 1. A Netfilter module *and* an eBPF engine

**Chosen:** both, producing the same event format, selected per host
(`kguard-agent --engine module|ebpf`).

**Why:** Netfilter hooks see packets after routing and conntrack, in the
right network namespace, with the socket owner at hand; that is what makes
process attribution, conntrack state and per-namespace hooks
straightforward, and in-kernel enforcement simple (`NF_DROP`). But a module
must be built for each kernel, and many hosts refuse out-of-tree modules.
The eBPF engine (CO-RE, BTF) runs one binary on any 5.17+ kernel and drops
blocked sources in XDP before an `sk_buff` exists.

**Alternative considered:** eBPF only. Rejected because process attribution
from XDP (no socket yet) needs extra tracing programs and heuristics
(`agent/README.md` explains the connect/accept/bind tracking the agent
does), the guard's per-source state would have to live in BPF maps with
their size limits, and the module was the project's starting point.
Module only: rejected for the deployability reason above.

**Measured:** both engines deliver 10,000/10,000 packets each way on 6.8
([X4.1](../ROADMAP.md)); the eBPF XDP drop works against an attacker
namespace ([X4.3](../ROADMAP.md)). Cost comparison: [BENCHMARKS.md](BENCHMARKS.md)
(emulated VM only so far).

### 2. Where to hook

**Chosen:** a guard hook first in `PRE_ROUTING`, and capture hooks right
after conntrack in `LOCAL_IN`, `LOCAL_OUT` and `FORWARD`.

**Why:** blocking must happen before the host spends anything on the
packet (conntrack entry, routing), so the guard runs first. Capture wants
reassembled fragments and conntrack state, so it runs after conntrack; and
`LOCAL_IN`/`LOCAL_OUT` tell direction and owner unambiguously, where
`PRE_ROUTING` cannot yet know whether a packet is for this host.

**Alternative considered:** one hook in `PRE_ROUTING` for everything (no
direction, no outgoing traffic, no owner), or `POST_ROUTING` for egress
(misses locally generated packets that are dropped earlier). nftables or
iptables rules for blocking: rejected so that enforcement and detection
share one per-source table and need no user-space round trip.

**Measured:** fragments, IP options, IPv6 extension headers and truncated
TCP headers parsed correctly ([K2.1](../ROADMAP.md)); IPv4 and IPv6 in all
three directions ([K2.2](../ROADMAP.md)).

### 3. Per-CPU single-producer rings

**Chosen:** one ring per CPU, written only by that CPU with interrupts off
for the write, free-running 64-bit `head`/`tail` counters with
release/acquire ordering.

**Why:** Netfilter hooks run concurrently on every CPU. A per-CPU ring
needs no lock and no atomic read-modify-write in the packet path: the only
cross-CPU traffic is the reader's `tail` cache line. Interrupts off (not
just preemption off) because a hook in process context (`LOCAL_OUT` from
`sendmsg()`) and one in softirq on the same CPU must not interleave in the
same ring. `head`, `tail` and `dropped` sit on separate cache lines so the
kernel and the reader do not false-share.

**Alternatives considered:**
- *One shared ring with a spinlock:* every CPU contends on every packet.
- *`kfifo`:* single-producer too, but no shared mapping for user space and
  no per-ring drop accounting.
- *perf ring buffer / `BPF_MAP_TYPE_RINGBUF` from the module:* these need
  BPF or perf plumbing for a module, and the BPF ring buffer is one buffer
  shared by all CPUs (fine for the eBPF engine, which uses it).
- *Netlink unicast per event:* an allocation and a socket queue per event,
  and user-space backpressure turns into kernel memory.

**Full ring policy:** drop the *new* event and count it. Overwriting old
events would race with a reader copying them.

**Measured:** 40,000 events at 5,000/s with zero drops; the full suite on
kernels with lockdep and KCSAN reports no lock-order problem or data race
involving kguard ([K2.3](../ROADMAP.md), [P8.3](../ROADMAP.md)). That run
found and fixed one real deadlock risk (`get_task_comm()` under a
softirq-safe lock).

### 4. `mmap` on a character device

**Chosen:** `/dev/kguard`, exclusive open, the rings mapped `MAP_SHARED`
with `remap_vmalloc_range()`, `poll()` on a wait queue, and the reader
moving its own `tail`. `/proc/kguard` stays as a JSON text view for
debugging.

**Why:** zero copies and no system call per event: the reader reads
events where the kernel wrote them. `poll()` lets an idle reader sleep.

**Trust boundary:** the mapping is writable (the reader writes `tail`), so
the kernel never trusts `tail` for memory safety: slot indexes are always
masked, and a bogus `tail` only makes a ring look full or empty. Private
and executable mappings are refused.

**Alternatives considered:** `read()` copying events (a system call and a
copy per batch: kept as `/proc/kguard`); relayfs (per-CPU channels too,
but file-based and less suited to an exclusive consumer moving its own
position); Netlink (see above).

**Measured:** an idle reader uses about 0.05 s of CPU over 3 s with no
wake-ups ([K2.4](../ROADMAP.md)); the device and its mapping rules are
covered by the selftests run in CI ([P8.6](../ROADMAP.md)).

### 5. A fixed, versioned binary event

**Chosen:** `struct kguard_event`, 128 bytes (two cache lines), in a UAPI
header shared by the module, the eBPF programs, the agent and the Python
readers. The mapping starts with a header carrying a magic number, the ABI
version (2) and the event size.

**Why:** fixed size means slot arithmetic is a mask and a reader can skip
what it does not understand; one header file is the single definition of
the format. Version 2 grew the event from 96 to 128 bytes to carry TTL, IP
length, TCP window, MSS, window scale and option order.

**Alternative considered:** variable-length TLV or text (JSON per event):
flexible, but parsing in the packet path and variable slot sizes in the
ring. Text survives as the `/proc/kguard` debug view.

**Measured:** the Python decoder is checked against the header's layout
([K2.5](../ROADMAP.md), `backend/tests/test_kernel_abi.py`).

### 6. Per-source state: RCU `rhashtable`, bitmap and token bucket

**Chosen:** an `rhashtable` keyed by (address, namespace), looked up under
RCU, one spinlock per source, entries from their own slab cache, a hard cap
(`max_sources`, 65,536) and a worker freeing idle entries every second
(sooner when nearly full). Per source: a 1024-bit bitmap of destination
ports in the current window and a SYN token bucket in thousandths of a
token.

**Why:**
- *RCU lookups:* readers on every CPU take no lock; sources never contend
  with each other because each has its own lock.
- *Cap and GC:* a spoofed flood creates a new source per packet; without a
  cap that is unbounded kernel memory. Beyond the cap, new sources are
  counted (`track_full`) but not tracked.
- *Bitmap for distinct ports:* exact at the counts that matter (a scan
  threshold of 20) in 128 bytes, with a test-and-set per packet.
  HyperLogLog was considered and rejected: approximate at small counts,
  which is exactly where the threshold is. Each port's bit is a keyed hash
  (siphash, key drawn at load) so that ports cannot be chosen to collide; a
  plain `port % 1024` let a scan of ports 1024 apart go uncounted (found
  while writing the [threat model](THREAT_MODEL.md), fixed and tested).
- *Token bucket:* allows bursts (`syn_burst`) and a sustained rate
  (`syn_rate`) per source; thousandths avoid floating point.

**Alternatives considered:** a global hash with one lock (contention under
exactly the floods it must survive); a BPF LRU map (a module has no BPF
maps); evicting least-recently-used sources instead of capping (a flood
would evict the real attacker's state).

**Measured:** 1,000,000 spoofed sources keep the table under 65,536
entries; 20,000 sources against a cap of 1,000 stay at 1,000 slab objects;
idle state is freed; no kmemleak report ([K3.1](../ROADMAP.md)). An nmap
scan is reported 21 ms after its first SYN ([K3.2](../ROADMAP.md)); 1,000
SYNs at 50/s + 50 burst: 948 dropped, one alert ([K3.3](../ROADMAP.md)).

### 7. Splitting detection between kernel and user space

**Chosen:** the kernel detects port scans, SYN floods (per-source rate) and
impossible source addresses; everything else runs in the backend: brute
force, distributed SYN floods (half-open counts per target), OS
fingerprinting, TTL-based spoofing, amplification, DNS tunnelling, TLS
fingerprints, traffic baselines, threat lists.

**Why:** the kernel rules need only per-source counters and must act at
line rate (to drop); the user-space rules need history, payloads, external
data or tuning that has no place in the kernel. While the module's alerts
arrive, the backend switches off its own copies of the scan and rate rules
so an attack is reported once; if the module goes away they come back
(`kernel_alerts.py`).

**Alternative considered:** all detection in user space (simpler, but
blocking would wait on the reader and on a full ring); all in the kernel
(unreviewable complexity in the most dangerous place).

### 8. Fail-safe enforcement

**Chosen:** `enforce=0` by default: alerts say what would have been done
(`would_drop` counter) and nothing is dropped. With enforcement on, the
allowlist is checked first, and the host's own addresses (loopback and
every local address) are tracked but can never be blocked or rate-limited;
trying to block them is refused.

**Why:** a security tool that cuts off its own administrator, or a
monitoring rollout that drops production traffic on day one, does more
damage than most attacks it stops.

**Measured:** monitor mode drops nothing; local and allowlisted addresses
cannot be blocked ([K3.5](../ROADMAP.md)).

### 9. Generic Netlink for control

**Chosen:** a Generic Netlink family `kguard`: statistics, live
configuration with change notifications, block and allow list commands,
alert multicast. Changes need `CAP_NET_ADMIN`; reading statistics does not.

**Why:** typed attributes, per-command permissions, multicast for alerts
and namespace awareness come with the interface; `kguardctl.py` uses only
the Python standard library.

**Alternatives considered:** `ioctl` on `/dev/kguard` (the device is
exclusive to one reader, and ioctls have no multicast); sysfs files (one
value per file, no atomic multi-field changes, no events).

**Measured:** the selftests exercise every command and the permission
checks, in CI ([P8.6](../ROADMAP.md)).

### 10. The agent: C with libbpf, HTTPS with JSON

**Chosen:** one C binary (libbpf, libcurl) with both engines, a bounded
queue (200,000 events, drops counted), and batches of up to 5,000 events
posted as JSON over HTTPS with retry and backoff.

**Why:** C shares the UAPI header and the BPF skeleton directly and has a
small footprint; HTTPS and JSON go through any proxy and need no extra
service on the backend.

**Alternative considered:** Go with cilium/ebpf and gRPC (the roadmap's
first suggestion). Rejected to avoid a second toolchain for a component
that mostly moves bytes; gRPC would need its own port and TLS setup.

**Measured:** 1,000/1,000 events delivered across a backend restart
([X4.4](../ROADMAP.md)).

### 11. Blocking from the backend: leases

**Chosen:** a block is a record in the backend; enforcers (agents, and the
local module when the backend has `CAP_NET_ADMIN`) poll the list and hold
each entry as a lease of 300 s that they renew.

**Why:** a removal that never reaches an enforcer (a host offline at the
time) still ends within one lease; there is no state that can only be
cleaned up by a message that was lost.

**Alternative considered:** pushing add/remove commands (a lost "remove"
leaves a host blocked forever).

### 12. Backend state: PostgreSQL and Redis

**Chosen:** events, alerts, blocks, users and audit records in PostgreSQL
(SQLite for development and tests) with Alembic migrations; the detectors'
sliding windows and cooldowns in Redis.

**Why:** detection state that lives only in process memory is lost on
every restart and deploy, so an attack in progress would start counting
from zero (and alerts already sent would fire again). Redis keeps windows
as sorted sets and cooldowns as keys with expiry.

**Measured:** the backend suite runs against PostgreSQL 16 and Redis 7 in
CI, with migrations built from empty and checked against the models.

## Trade-offs and known limits

- **One reader.** `/dev/kguard` admits a single consumer; reading events
  removes them. Fan-out happens in the backend.
- **Drops under overload are by design.** A full ring loses new events
  (counted per ring, in debugfs and on the Hosts page) rather than slowing
  the network. The guard still sees every packet, because it runs before
  and independently of the rings.
- **Per-source state is capped.** Past `max_sources`, new sources are not
  tracked: a very wide spoofed flood can hide one real scanner among them
  until idle state is freed. See the [threat model](THREAT_MODEL.md).
- **Distinct ports are counted modulo collisions:** about n²/2048 ports are
  lost after n distinct ones (under 0.2 at a threshold of 20).
- **Payload inspection is eBPF-only.** DNS and TLS ClientHello sampling is
  done by the eBPF engine; the module carries headers only.
- **Benchmarks are from emulated VMs so far.** Per-packet costs on real
  hardware are not yet measured ([BENCHMARKS.md](BENCHMARKS.md)).

## What was measured, and where

| Claim | Evidence |
|---|---|
| No event lost at 5,000 events/s | [K2.3](../ROADMAP.md); kernel suite in CI |
| Scan alert 21 ms after the first SYN | [K3.2](../ROADMAP.md) |
| SYN rate limit holds to the configured rate | [K3.3](../ROADMAP.md) |
| Memory bounded under 1,000,000 spoofed sources | [K3.1](../ROADMAP.md); kernel suite in CI |
| No lockdep, KCSAN, KASAN or UBSAN report involving kguard | [P8.3](../ROADMAP.md); "Debug kernels" workflow |
| Builds and passes 84/84 on 5.15, 6.1, 6.6, 6.12 and 7.3 | [P8.5](../ROADMAP.md); CI kernel matrix |
| Clean under sparse, smatch, checkpatch | [P8.4](../ROADMAP.md) |
| Each Phase 5 attack raises its alert | [P8.2](../ROADMAP.md); `make attack-demo` |
| Dashboard updates in under a second | [U7.1](../ROADMAP.md) |
| Cost per packet of each engine | [BENCHMARKS.md](BENCHMARKS.md) (emulated) |
