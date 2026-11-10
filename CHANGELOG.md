# Changelog

Release versions cover the backend, the dashboard and the agent. The kernel
module carries its own version (`KGUARD_MODULE_VERSION`) and event ABI
version (`KGUARD_ABI_VERSION`). How each item below was verified is in
[ROADMAP.md](ROADMAP.md), under the item's ID.

## 2.0.0 (unreleased)

A rewrite of nearly every part. 1.0.0 (2025) was a prototype: a kernel
module that printed events to `/proc/kguard` as text, simple backend rules,
and a dashboard; its "complete" claims had not been tested.

Kernel module 3.0.0, event ABI 2.

### Kernel module

- Safe parsing of IPv4 and IPv6 (`skb_header_pointer`, IP options, extension
  headers, fragments), in, out and forwarded traffic, every network
  namespace, conntrack state, and the process behind each connection
  (K2.1, K2.2, K2.7 to K2.9).
- Lock-free per-CPU rings read zero-copy through `/dev/kguard` (`mmap`,
  `poll`); a versioned 128-byte binary event shared through a UAPI header
  (K2.3 to K2.5).
- Generic Netlink control (`kguardctl`): statistics, live settings, block
  and allow lists, alerts; debugfs counters and tracepoints (K2.6, K2.10,
  K2.11).
- In-kernel guard: per-source tracking in an RCU hash table with a memory
  cap, port-scan detection, per-source SYN rate limiting, blocking with
  expiry, an allowlist, spoofed-source detection; monitor-only by default,
  and the host's own addresses can never be blocked (K3.1 to K3.5, N5.5).
- SYN TCP options recorded for OS fingerprinting (N5.4).
- Builds on Linux 5.15 to 7.3 (P8.5); DKMS install (`make -C kernel
  dkms-install`).
- Fixed: scan detection could be evaded by probing ports 1024 apart (they
  shared one bit of the port bitmap); ports are now hashed with a secret key.
- Fixed: a possible deadlock naming the sending process under a socket lock,
  found by lockdep.

### eBPF engine and agent

- XDP and TC programs producing the same events without a kernel module,
  connection-owner tracking, an XDP blocklist (X4.1 to X4.3).
- `kguard-agent` (C, libbpf, libcurl): either engine, batches over HTTPS,
  survives backend restarts, enforces the server's block list; systemd unit
  (`make -C agent install`) (X4.4, X4.5).
- DNS message and TLS ClientHello sampling (N5.7, N5.8).

### Backend

- Reads the zero-copy device; agents enroll and send events from many hosts
  (X4.5).
- Detection: scan types from TCP flags, SYN floods per destination, brute
  force, TTL-based spoofing and bogons, amplification (victim and
  reflector), DNS tunnelling, JA3/JA4 TLS fingerprints with a blocklist, OS
  fingerprints, EWMA traffic baselines; kernel alerts take over the rules the
  kernel runs (N5.0 to N5.9).
- IPFIX flow export and a pcap of the packets around each serious alert
  (N5.10, N5.11).
- PostgreSQL with Alembic migrations and daily retention; detection state in
  Redis (S6.1, S6.2).
- Response engine: manual and automatic blocks as leases, allowlist, safety
  rules, audit log; enrichment with MITRE ATT&CK, GeoIP and threat lists
  (S6.3, S6.4).
- Logins with viewer and admin roles, rate limits, hardened containers;
  Slack, Telegram and e-mail notifications; Prometheus metrics and a Grafana
  dashboard; JSON logs with request IDs (S6.5 to S6.9).
- Fixed: threat lists and the kernel-alert subscription were skipped for up
  to a minute after the machine booted.

### Dashboard

- Events, Alerts (with details and the evidence behind each), Analytics,
  Hosts (with the kernel's own counters), Blocked IPs, Processes and
  Settings pages; updates pushed over the WebSocket in well under a second
  (U7.0 to U7.7).
- Fixed: the production image could not be built, and called the API on the
  visitor's own machine; it now uses its own origin.

### Proof and documentation

- Attack demos (`make attack-demo`: 8/8), a two-VM lab (`make lab`),
  benchmarks (`make bench`), selftests, fuzzing, sparse/smatch/checkpatch,
  KASAN/KCSAN/lockdep/kmemleak runs and a kernel matrix in CI (P8.1 to
  P8.9).
- New documentation: [design](docs/DESIGN.md), [threat
  model](docs/THREAT_MODEL.md), [deployment](docs/DEPLOYMENT.md),
  [benchmarks](docs/BENCHMARKS.md), a generated [API reference](docs/API.md)
  (D9.1 to D9.4).

### Known limits

- Benchmarks so far come from an emulated VM only ([BENCHMARKS.md](docs/BENCHMARKS.md)).
- Fuzzing has run for 1.9 hours per parser, not yet the 24 the roadmap asks
  for; it continues nightly in CI.
- What KGuard does not detect: [THREAT_MODEL.md](docs/THREAT_MODEL.md).

## 1.0.0 (2025-09-18)

The original prototype.
