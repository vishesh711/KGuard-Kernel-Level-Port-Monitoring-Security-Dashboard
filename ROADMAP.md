# KGuard Roadmap

The task list for taking KGuard from v1.0 (designed, but not working end to end) to a
kernel- and networking-heavy security tool that is tested, benchmarked and documented.

Architecture diagrams (today vs. target): https://claude.ai/artifact/NwCrCkZLKCcDHX52pvRWhr

**How to use this file**
- Work through phases in order. Each phase leaves the project in a working state.
- Tick a box only when its **Done when** check passes.
- Task IDs (e.g. `K2.3`) are for commit messages and PR titles: `K2.3: per-CPU ring buffer`.

| Phase | Theme | Shows |
|---|---|---|
| 0 | Foundations: tests, CI, dependencies | Engineering discipline |
| 1 | Make v1.0 work | Debugging |
| 2 | Advanced kernel module | Kernel internals, concurrency, memory |
| 3 | In-kernel detection and firewall | RCU, Netfilter, stateful filtering |
| 4 | eBPF / XDP engine and agent | Modern kernel tooling |
| 5 | Deep network detection | TCP/IP, protocols, attack patterns |
| 6 | Backend upgrade | Distributed systems, security |
| 7 | Frontend upgrade | Product |
| 8 | Proof: benchmarks, attack demos, kernel testing | Evidence |
| 9 | Documentation and release | Communication |

---

## Phase 0 — Foundations

- [ ] **F0.1 Update Python dependencies.** Unpin versions that fail on Python 3.12/3.13; remove unused packages (Celery, pandas, numpy) unless a later task uses them.
  *Done when:* `pip install -r backend/requirements.txt` works on Python 3.12 and 3.13.
- [ ] **F0.2 Backend test setup.** Add `backend/tests/` with pytest, a temporary SQLite database fixture and a FastAPI test client.
  *Done when:* `pytest` runs and passes one smoke test.
- [ ] **F0.3 Fake kernel source.** Make the `/proc/kguard` path configurable in tests and add a fixture that writes sample event JSON, so the backend can be tested without the module.
  *Done when:* a test feeds 50 fake events through the collector into the database.
- [ ] **F0.4 Frontend checks.** Make `npm run lint` and `npm run build` pass; add Vitest with one component test.
  *Done when:* all three commands pass locally.
- [ ] **F0.5 Kernel build check.** Add `kernel/` build to CI against the runner's kernel headers, with `-Werror`.
  *Done when:* CI fails on any kernel compiler warning.
- [ ] **F0.6 CI pipeline.** GitHub Actions workflow running F0.2–F0.5 on every push and PR.
  *Done when:* the workflow is green on `main`.
- [ ] **F0.7 Code style.** Add ruff (Python), Prettier (frontend) and `checkpatch.pl --no-tree` (kernel) to CI.
  *Done when:* all three run in CI with no errors.

## Phase 1 — Make v1.0 work

- [ ] **B1.1 Fix backend startup.** `database.py`: use `conn.execute(text("SELECT 1"))`.
  *Done when:* the app starts and `GET /api/health/` returns 200 (test).
- [ ] **B1.2 Fix alert metadata.** Use `alert_metadata=` in `models/security_alert.py` and `services/anomaly_detector.py`; map it to `metadata` in `SecurityAlertResponse`.
  *Done when:* `GET /api/alerts/` returns 200 with alerts present, and metadata is stored (test).
- [ ] **B1.3 Run detection on every batch.** After `_store_events`, pass the saved events to `anomaly_detector.analyze_events()` and set `is_suspicious` / `event_type` on matching events.
  *Done when:* feeding 15 ports from one IP produces a `PORT_SCAN` alert (test).
- [ ] **B1.4 Live updates.** Call `broadcast_network_event` and `broadcast_security_alert` after storing; check that message shapes match `frontend/src/types`.
  *Done when:* a WebSocket test client receives an alert message, and the dashboard shows a pop-up.
- [ ] **B1.5 Fix startup hooks.** Move `periodic_tasks` into the `lifespan` handler (remove deprecated `on_event`) and cancel background tasks on shutdown.
  *Done when:* no deprecation warnings, and shutdown is clean.
- [ ] **B1.6 Make the stats endpoints faster.** Replace the per-hour loop and load-everything queries in `/stats/summary` and `/stats/traffic` with `GROUP BY` queries.
  *Done when:* each endpoint runs one or two queries; response time for 1M rows is recorded.
- [ ] **K1.1 Fix kernel compile.** Rename the `current` variable in `kguard_buffer.c`; remove or use `kguard_buffer_count`.
  *Done when:* builds with no warnings (F0.5).
- [ ] **K1.2 Fix event loss on read.** Rewrite `/proc/kguard` with `seq_operations` (start/next/stop/show) so events are removed only after they're written; move the event array off the stack.
  *Done when:* reading 1000 queued events returns all 1000, checked with a load test.
- [ ] **K1.3 Fix the collector's speed limit.** Read until the buffer is empty on each poll instead of 100 events per second.
  *Done when:* sustained 5,000 packets/s shows zero drops.
- [ ] **E1.1 End-to-end smoke test.** Script: load module → start backend → run `nmap` against localhost → check that a port-scan alert appears through the API.
  *Done when:* the script passes in a VM.

## Phase 2 — Advanced kernel module (C)

- [ ] **K2.1 Safe packet parsing.** Use `skb_header_pointer()` for IP/TCP/UDP headers; handle IP options (`ihl`), fragments and non-linear packets.
  *Done when:* fragmented and option-carrying packets are parsed correctly (test packets from scapy).
- [ ] **K2.2 Wider coverage.** Hook `LOCAL_IN`, `LOCAL_OUT` and `FORWARD`; add IPv6 (`NFPROTO_IPV6`, extension headers). Add a direction field to events.
  *Done when:* events show in/out/forward for IPv4 and IPv6.
- [ ] **K2.3 Per-CPU lock-free ring buffer.** One single-producer ring per CPU, `smp_store_release` / `smp_load_acquire` for indices, no spinlock in the packet path. Size set by module parameter.
  *Done when:* the packet path takes no locks; a stress test on all CPUs passes under lockdep and KCSAN.
- [ ] **K2.4 Character device with mmap.** `/dev/kguard`: userspace maps the rings read-only (`remap_vmalloc_range`), sleeps in `poll()` on a wait queue, and moves its own read index. Keep `/proc/kguard` as a text debug view.
  *Done when:* a small C reader gets events with no `read()` copies and no busy polling.
- [ ] **K2.5 Binary event format.** Fixed-size, versioned struct shared through a UAPI header (`include/uapi/kguard.h`), with real-time timestamps (`ktime_get_real_ns`).
  *Done when:* the Python collector parses the struct with `struct.unpack`, and timestamps match wall-clock time.
- [ ] **K2.6 Generic Netlink control channel.** Commands: get stats, set thresholds, add/remove block entries. Multicast group for alerts.
  *Done when:* a `kguardctl` CLI (or `pyroute2` script) can change thresholds live.
- [ ] **K2.7 Process attribution.** On outgoing traffic, map `skb->sk` to the owning process (PID, command name, UID); for incoming connections, record the listening socket's owner.
  *Done when:* a `curl` shows as `curl` with its PID, and an `nc -l 4444` listener shows as `nc`.
- [ ] **K2.8 Connection tracking.** Read conntrack state (NEW, ESTABLISHED, RELATED, INVALID) for each packet when `nf_conntrack` is loaded.
  *Done when:* events carry connection state, and INVALID packets are counted.
- [ ] **K2.9 Per-namespace support.** Register hooks with `pernet_operations` so each network namespace (container) gets its own hooks and counters; tag events with a namespace ID.
  *Done when:* traffic inside a Docker container is captured and labeled.
- [ ] **K2.10 Settings and stats.** Module parameters (buffer size, enabled hooks); `debugfs` or sysfs counters: packets seen, events dropped, buffer fill, nanoseconds per packet.
  *Done when:* counters are readable under `/sys/kernel/debug/kguard/`.
- [ ] **K2.11 Module tracepoints.** Add `TRACE_EVENT`s for drops and detections so `perf` and `trace-cmd` can observe the module.
  *Done when:* `perf record -e kguard:*` shows events.

## Phase 3 — In-kernel detection and firewall

- [ ] **K3.1 Per-source state table.** `rhashtable` keyed by source IP, with RCU-protected lookups in the packet path, timer- or LRU-based expiry and a memory cap.
  *Done when:* 1M distinct sources don't exceed the memory cap, checked with kmemleak.
- [ ] **K3.2 In-kernel scan detection.** Track distinct destination ports per source in a time window (bitmap or HyperLogLog); emit an alert event over Netlink.
  *Done when:* `nmap -sS` triggers an alert within 1 second.
- [ ] **K3.3 Rate limiting.** Per-source token bucket for new connections (SYN packets).
  *Done when:* a SYN flood from one source is limited to the configured rate.
- [ ] **K3.4 Blocking.** Blocklist with expiry checked first in the hook; return `NF_DROP` for listed sources. Always honor an allowlist.
  *Done when:* a blocked IP can't connect, and is allowed again after expiry.
- [ ] **K3.5 Fail-safe mode.** A module parameter for monitor-only mode (never drop). Add a check that blocking can't lock out the management IP.
  *Done when:* monitor-only mode is on by default and documented.

## Phase 4 — eBPF / XDP engine and agent

- [ ] **X4.1 eBPF capture.** XDP program for incoming packets and TC program for outgoing, written with libbpf and CO-RE (BTF); events go to a `BPF_MAP_TYPE_RINGBUF`.
  *Done when:* the same event format as K2.5 comes out of the eBPF path.
- [ ] **X4.2 eBPF process tracking.** Probes on `tcp_v4_connect`, `inet_csk_accept` and the `sock:inet_sock_set_state` tracepoint, mapping connections to PID and command.
  *Done when:* matches the K2.7 output for the same test.
- [ ] **X4.3 XDP blocklist.** `BPF_MAP_TYPE_LPM_TRIE` of blocked CIDRs; return `XDP_DROP`.
  *Done when:* blocked traffic is dropped before the kernel's network stack.
- [ ] **X4.4 Agent.** One user-space program (Go with cilium/ebpf, or C with libbpf) that loads either engine (C module or eBPF), reads events, batches them and streams them to the backend over gRPC or HTTPS. Handles reconnects and backpressure.
  *Done when:* `kguard-agent --engine=module|ebpf` both feed the same backend.
- [ ] **X4.5 Multi-server.** Agent identity (host ID plus token); backend stores which host each event came from.
  *Done when:* two VMs show up separately in the dashboard.

## Phase 5 — Deep network detection

- [ ] **N5.1 Scan types from TCP flags.** Classify SYN, FIN, NULL, Xmas, ACK and Maimon scans, and UDP scans (from ICMP port-unreachable replies).
  *Done when:* each `nmap` scan type (`-sS -sF -sN -sX -sA -sU`) produces the correctly labeled alert.
- [ ] **N5.2 SYN flood.** Track half-open connections per destination; note whether SYN cookies are on (`net.ipv4.tcp_syncookies`).
  *Done when:* `hping3 --flood -S` raises a SYN flood alert.
- [ ] **N5.3 Brute force.** Repeated short connections to SSH, RDP or database ports from one source in a window.
  *Done when:* a `hydra` run against SSH raises a `BRUTE_FORCE` alert.
- [ ] **N5.4 Passive OS fingerprinting.** Guess the sender's OS from initial TTL, window size, MSS and TCP option order on SYN packets (p0f-style signatures).
  *Done when:* Linux, Windows and macOS hosts are recognized in the test lab.
- [ ] **N5.5 Spoofed traffic.** Flag TTL jumps for the same source, bogon/martian sources, and packets arriving on an unexpected interface.
  *Done when:* scapy-spoofed packets are flagged.
- [ ] **N5.6 Amplification attacks.** Detect DNS (ANY), NTP (monlist), memcached and SSDP reflection: large responses to small requests, or unsolicited responses.
  *Done when:* replayed amplification captures raise alerts.
- [ ] **N5.7 DNS tunneling.** Parse DNS queries; score long, high-entropy subdomains and unusual record types (TXT, NULL).
  *Done when:* an `iodine` or `dnscat2` session is detected, with a measured false-positive rate on normal browsing.
- [ ] **N5.8 TLS fingerprinting.** Parse the TLS ClientHello; compute JA3/JA4 and record the requested server name (SNI). Match against a list of known malware fingerprints.
  *Done when:* fingerprints for `curl`, Chrome and Python `requests` are recorded correctly.
- [ ] **N5.9 Sliding-window baseline.** Learn normal per-hour traffic per host/port; alert on large deviations.
  *Done when:* a replayed traffic spike raises an `UNUSUAL_TRAFFIC` alert.
- [ ] **N5.10 Flow export.** Group packets into flows and export IPFIX (or NetFlow v9).
  *Done when:* `nfdump` or Wireshark decodes the exported flows.
- [ ] **N5.11 Packet capture on alert.** Keep a short rolling buffer; on a high-severity alert, save the surrounding packets as `.pcap`.
  *Done when:* the saved file opens in Wireshark and contains the attack.

## Phase 6 — Backend upgrade

- [ ] **S6.1 PostgreSQL and migrations.** Postgres in production (TimescaleDB optional), real Alembic migrations, automatic deletion of old data.
  *Done when:* `alembic upgrade head` builds the schema from empty; retention job runs daily.
- [ ] **S6.2 Redis state.** Sliding-window counters for detection in Redis, so restarts don't lose detection state and multiple backend workers agree.
  *Done when:* a scan spread across a backend restart is still detected.
- [ ] **S6.3 Enrichment.** GeoIP (MaxMind GeoLite2), public bad-IP lists, and MITRE ATT&CK technique IDs on each alert (e.g. port scan → T1046).
  *Done when:* alerts show country, list matches and technique ID.
- [ ] **S6.4 Response engine.** Rules for when to block automatically, with allowlist, expiry, manual unblock and an audit log; sends block commands to the agent or Netlink.
  *Done when:* blocking and unblocking from the API works end to end.
- [ ] **S6.5 Login and roles.** JWT login, admin and viewer roles; destructive endpoints (`/cleanup`, blocking) are admin-only; WebSocket requires a token.
  *Done when:* unauthenticated requests get 401 (tests for every endpoint).
- [ ] **S6.6 Hardening.** Rate limiting, no default secret key (refuse to start without one), strict CORS and trusted hosts, run as a non-root user, read-only access to the device.
  *Done when:* security tests pass, and the container runs as non-root.
- [ ] **S6.7 Notifications.** Slack, email and Telegram for alerts at or above a set severity, with per-channel rate limits.
  *Done when:* a test alert reaches a Slack channel.
- [ ] **S6.8 Metrics.** Prometheus `/metrics`: events/s, drops, detection time, alerts by type; include a sample Grafana dashboard.
  *Done when:* the Grafana dashboard loads from `docker compose up`.
- [ ] **S6.9 Structured logging.** JSON logs with request IDs; log rotation.
  *Done when:* each log line is valid JSON.

## Phase 7 — Frontend upgrade

- [ ] **U7.1 Live data.** Use WebSocket messages to update React Query caches instead of only polling.
  *Done when:* new events appear without refresh in under 1 second.
- [ ] **U7.2 Process view.** Table of listening ports and active connections with process, PID and user; highlight unexpected listeners.
  *Done when:* starting `nc -l 4444` on a host shows up within seconds.
- [ ] **U7.3 Blocked IPs page.** List, add, unblock, and show expiry and reason.
  *Done when:* blocking and unblocking work from the UI.
- [ ] **U7.4 Alert details.** Show scan type, OS guess, TLS fingerprint, country, MITRE technique, related events and a pcap download.
  *Done when:* each alert type shows its own detail panel.
- [ ] **U7.5 Hosts page.** One row per agent: status, version, engine (module or eBPF), events/s, drops.
  *Done when:* two agents show separately.
- [ ] **U7.6 Login screen and roles.** Viewer can't see admin actions.
  *Done when:* role checks are tested.
- [ ] **U7.7 Kernel health panel.** Show the module or eBPF counters (K2.10): buffer fill, drops, nanoseconds per packet.
  *Done when:* the numbers match `debugfs`.

## Phase 8 — Proof: benchmarks, attack demos, kernel testing

- [ ] **P8.1 Test lab.** Vagrant or `virtme-ng` setup: one victim VM running KGuard, one attacker VM with nmap, hping3, hydra, scapy, iodine.
  *Done when:* `make lab` brings both up.
- [ ] **P8.2 Attack demo scripts.** One script per attack in Phase 5, each checking that the expected alert appears.
  *Done when:* `make attack-demo` runs all of them and prints pass/fail.
- [ ] **P8.3 Kernel debug builds.** Run the module's stress tests on a kernel with KASAN, KCSAN, lockdep and kmemleak enabled.
  *Done when:* zero reports from each tool, recorded in CI logs.
- [ ] **P8.4 Kernel static checks.** `sparse` (`make C=1`), `checkpatch.pl --strict`, and `smatch` in CI.
  *Done when:* clean output.
- [ ] **P8.5 Multi-kernel CI.** Build and load-test the module on several kernel versions (e.g. 5.15, 6.1, 6.6, latest) inside VMs.
  *Done when:* a CI matrix is green for every version.
- [ ] **P8.6 Kernel self-tests.** kselftest-style tests for the device, Netlink commands and blocking.
  *Done when:* tests run in CI inside a VM.
- [ ] **P8.7 Benchmarks.** Use `pktgen` (and `trafgen` or TRex) to measure packets/s, nanoseconds per packet and CPU use for: no monitoring, C module, eBPF TC and eBPF XDP. Include `perf` flame graphs.
  *Done when:* `docs/BENCHMARKS.md` has the numbers, charts and hardware details.
- [ ] **P8.8 Fuzzing.** Fuzz the packet parser in user space (libFuzzer on shared parsing code) and the Netlink/ioctl interface (syzkaller description, optional).
  *Done when:* 24 hours of fuzzing with no crashes.
- [ ] **P8.9 Backend coverage.** At least 80% test coverage on backend services.
  *Done when:* the CI coverage report shows at least 80%.

## Phase 9 — Documentation and release

- [ ] **D9.1 Honest README.** Remove unverified claims ("100% complete", "10,000+ packets/sec"); show real benchmark numbers, a short demo GIF and the architecture diagram.
  *Done when:* every number in the README links to its source.
- [ ] **D9.2 Design write-up.** `docs/DESIGN.md`: why per-CPU rings, why RCU, Netfilter vs XDP, the mmap interface, packet path walkthrough, trade-offs and what was measured.
  *Done when:* each major design choice has a "why" and an alternative considered.
- [ ] **D9.3 Threat model.** What KGuard detects, what it doesn't, and how an attacker could evade it.
  *Done when:* `docs/THREAT_MODEL.md` covers every detection in Phase 5.
- [ ] **D9.4 Clean up docs.** Merge or remove overlapping docs (`DEPLOYMENT.md`, `docs/DEPLOYMENT_GUIDE.md`, `PROJECT_SUMMARY.md`, `COMMIT_NOTES.md`); update the `.kiro` specs or mark them historical.
  *Done when:* one clear source for each topic.
- [ ] **D9.5 Release v2.0.** Tag, changelog, release notes with benchmark results; publish agent binaries and container images.
  *Done when:* the GitHub release exists, and install from the README works on a fresh VM.

---

## Highest-value tasks

If time is short, do these first. Together they show the most kernel and networking skill:

1. **Phase 1** (all): it has to work.
2. **K2.3 + K2.4**: lock-free per-CPU rings with zero-copy mmap.
3. **K3.1–K3.4**: in-kernel stateful firewall with RCU.
4. **X4.1 + P8.7**: eBPF/XDP engine, benchmarked against the C module.
5. **N5.1 + N5.4 + N5.8**: scan classification, OS fingerprinting, TLS fingerprinting.
6. **P8.2 + P8.3**: attack demos, plus clean KASAN/lockdep runs.
7. **D9.2**: the design write-up that explains all of it.
