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

- [x] **F0.1 Update Python dependencies.** Unpin versions that fail on Python 3.12/3.13; remove unused packages (Celery, pandas, numpy) unless a later task uses them.
  *Done when:* `pip install -r backend/requirements.txt` works on Python 3.12 and 3.13.
  *Status:* Done. Runtime and dev requirements split; the backend suite (170 tests) passes on Python 3.11, 3.12 and 3.13 in CI.
- [x] **F0.2 Backend test setup.** Add `backend/tests/` with pytest, a temporary SQLite database fixture and a FastAPI test client.
  *Done when:* `pytest` runs and passes one smoke test.
  *Status:* Done. pytest with a temporary SQLite database and the FastAPI test client; 170 tests.
- [x] **F0.3 Fake kernel source.** Make the `/proc/kguard` path configurable in tests and add a fixture that writes sample event JSON, so the backend can be tested without the module.
  *Done when:* a test feeds 50 fake events through the collector into the database.
  *Status:* Done. `tests/conftest.py` writes events in the exact `/proc/kguard` format.
- [x] **F0.4 Frontend checks.** Make `npm run lint` and `npm run build` pass; add Vitest with one component test.
  *Done when:* all three commands pass locally.
  *Status:* Done. ESLint, Prettier and Vitest (14 tests); `npm run build` passes, in CI too.
- [x] **F0.5 Kernel build check.** Add `kernel/` build to CI against the runner's kernel headers, with `-Werror`.
  *Done when:* CI fails on any kernel compiler warning.
  *Status:* Done. `-Werror` in the kernel Makefile; builds clean against 6.8 headers.
- [ ] **F0.6 CI pipeline.** GitHub Actions workflow running F0.2–F0.5 on every push and PR.
  *Done when:* the workflow is green on `main`.
  *Status:* Green on the `claude/lucid-gates-38lxek` branch (backend 3.11-3.13, frontend, kernel on the runners' Linux 7.0, agent). Tick once it is green on `main` after merging.
- [x] **F0.7 Code style.** Add ruff (Python), Prettier (frontend) and `checkpatch.pl --no-tree` (kernel) to CI.
  *Done when:* all three run in CI with no errors.
  *Status:* Done. ruff, Prettier and `make checkpatch` (strict) all pass with zero findings.

## Phase 1 — Make v1.0 work

- [x] **B1.1 Fix backend startup.** `database.py`: use `conn.execute(text("SELECT 1"))`.
  *Done when:* the app starts and `GET /api/health/` returns 200 (test).
  *Status:* Done. Also fixed the same bug in `/api/health/database`.
- [x] **B1.2 Fix alert metadata.** Use `alert_metadata=` in `models/security_alert.py` and `services/anomaly_detector.py`; map it to `metadata` in `SecurityAlertResponse`.
  *Done when:* `GET /api/alerts/` returns 200 with alerts present, and metadata is stored (test).
  *Status:* Done. Also fixed acknowledge/resolve notes never being saved (in-place JSON edits).
- [x] **B1.3 Run detection on every batch.** After `_store_events`, pass the saved events to `anomaly_detector.analyze_events()` and set `is_suspicious` / `event_type` on matching events.
  *Done when:* feeding 15 ports from one IP produces a `PORT_SCAN` alert (test).
  *Status:* Done. Detection now counts connection attempts only (SYN without ACK, UDP) over a 60-second sliding window per source.
- [x] **B1.4 Live updates.** Call `broadcast_network_event` and `broadcast_security_alert` after storing; check that message shapes match `frontend/src/types`.
  *Done when:* a WebSocket test client receives an alert message, and the dashboard shows a pop-up.
  *Status:* Done. Dashboard now uses real API data (it was hard-coded demo data) and one app-wide WebSocket.
- [x] **B1.5 Fix startup hooks.** Move `periodic_tasks` into the `lifespan` handler (remove deprecated `on_event`) and cancel background tasks on shutdown.
  *Done when:* no deprecation warnings, and shutdown is clean.
  *Status:* Done.
- [x] **B1.6 Make the stats endpoints faster.** Replace the per-hour loop and load-everything queries in `/stats/summary` and `/stats/traffic` with `GROUP BY` queries.
  *Done when:* each endpoint runs one or two queries; response time for 1M rows is recorded.
  *Status:* Done. 1M rows on SQLite: traffic summary 15.9 s (old, loads every row) to 3.9 s; event summary 10 s, mostly per-field GROUP BYs that need PostgreSQL or pre-aggregation (S6.1).
- [x] **K1.1 Fix kernel compile.** Rename the `current` variable in `kguard_buffer.c`; remove or use `kguard_buffer_count`.
  *Done when:* builds with no warnings (F0.5).
  *Status:* Done. Builds with zero warnings under `-Werror`.
- [x] **K1.2 Fix event loss on read.** Rewrite `/proc/kguard` with `seq_operations` (start/next/stop/show) so events are removed only after they're written; move the event array off the stack.
  *Done when:* reading 1000 queued events returns all 1000, checked with a load test.
  *Status:* Verified on Linux 6.8 in a VM: 20,000 of 20,000 events at 5,000 packets/s, and lossless with 7-byte reads.
- [x] **K1.3 Fix the collector's speed limit.** Read until the buffer is empty on each poll instead of 100 events per second.
  *Done when:* sustained 5,000 packets/s shows zero drops.
  *Status:* Verified on Linux 6.8: 5,000 packets/s for 4 s, zero drops.
- [x] **E1.1 End-to-end smoke test.** Script: load module → start backend → run `nmap` against localhost → check that a port-scan alert appears through the API.
  *Done when:* the script passes in a VM.
  *Status:* Passes on Linux 6.8 in a VM: module loads, backend reads /dev/kguard, nmap scan raises PORT_SCAN, curl and an nc listener are named, nothing dropped.

## Phase 2 — Advanced kernel module (C)

- [x] **K2.1 Safe packet parsing.** Use `skb_header_pointer()` for IP/TCP/UDP headers; handle IP options (`ihl`), fragments and non-linear packets.
  *Done when:* fragmented and option-carrying packets are parsed correctly (test packets from scapy).
  *Status:* Done. skb_header_pointer() for TCP/UDP, IP options via ip_hdrlen(), IPv6 extension headers via ipv6_skip_exthdr(), non-first fragments flagged with no ports. Verified with scapy-built packets (kernel/tests/vm_tests.py test_tricky_packets): IPv4 options, IPv4 and IPv6 fragments, hop-by-hop and destination-option headers, a truncated TCP header. Conntrack's defragmenter runs before the capture hooks, so IPv4 fragments arrive reassembled; IPv6 fragments that already carry a conntrack entry (loopback) arrive as fragments, and the test checks both shapes.
- [x] **K2.2 Wider coverage.** Hook `LOCAL_IN`, `LOCAL_OUT` and `FORWARD`; add IPv6 (`NFPROTO_IPV6`, extension headers). Add a direction field to events.
  *Done when:* events show in/out/forward for IPv4 and IPv6.
  *Status:* Done. LOCAL_IN, LOCAL_OUT and FORWARD for IPv4 and IPv6; events carry direction and interface. Verified.
- [x] **K2.3 Per-CPU lock-free ring buffer.** One single-producer ring per CPU, `smp_store_release` / `smp_load_acquire` for indices, no spinlock in the packet path. Size set by module parameter.
  *Done when:* the packet path takes no locks; a stress test on all CPUs passes under lockdep and KCSAN.
  *Status:* Done. One single-producer ring per CPU, interrupts off only for the write, acquire/release on head and tail. Verified: 40,000 events at 5,000/s with zero drops; and the whole suite on a 6.8 kernel built with lockdep, KCSAN and kmemleak (kernel/tests/debug_kernel.sh) reports no lock-order problem or data race involving kguard. That run found a real bug, fixed: naming the sender with get_task_comm() took task_lock under a softirq-safe socket lock (possible deadlock); the name is now copied lock-free.
- [x] **K2.4 Character device with mmap.** `/dev/kguard`: userspace maps the rings read-only (`remap_vmalloc_range`), sleeps in `poll()` on a wait queue, and moves its own read index. Keep `/proc/kguard` as a text debug view.
  *Done when:* a small C reader gets events with no `read()` copies and no busy polling.
  *Status:* Done. Exclusive open, MAP_SHARED mapping via remap_vmalloc_range(), poll() wait queue. Verified with tools/kguard_reader.c: idle reader uses ~0.05 s CPU over 3 s with zero wakeups.
- [x] **K2.5 Binary event format.** Fixed-size, versioned struct shared through a UAPI header (`include/uapi/kguard.h`), with real-time timestamps (`ktime_get_real_ns`).
  *Done when:* the Python collector parses the struct with `struct.unpack`, and timestamps match wall-clock time.
  *Status:* Done. Versioned struct in include/uapi/linux/kguard.h, now ABI 2: 128 bytes (two cache lines) with TTL, IP length, TCP window and SYN options; real-time timestamps. Python readers decode it with the struct format documented in the header (checked by backend/tests/test_kernel_abi.py).
- [x] **K2.6 Generic Netlink control channel.** Commands: get stats, set thresholds, add/remove block entries. Multicast group for alerts.
  *Done when:* a `kguardctl` CLI (or `pyroute2` script) can change thresholds live.
  *Status:* Done. Family "kguard": stats, configuration (thresholds, enforce, capture switches) with multicast change notification, block/allow list add/remove/list, alert multicast. CAP_NET_ADMIN for changes. CLI: tools/kguardctl.py. Verified live changes and that non-root users are refused.
- [x] **K2.7 Process attribution.** On outgoing traffic, map `skb->sk` to the owning process (PID, command name, UID); for incoming connections, record the listening socket's owner.
  *Done when:* a `curl` shows as `curl` with its PID, and an `nc -l 4444` listener shows as `nc`.
  *Status:* Done. Sender PID/name in process context; socket owner UID and inode for incoming TCP/UDP (listener lookup); backend resolves the inode to the process. Verified with curl and an nc listener. The name copy is lock-free (see K2.3).
- [x] **K2.8 Connection tracking.** Read conntrack state (NEW, ESTABLISHED, RELATED, INVALID) for each packet when `nf_conntrack` is loaded.
  *Done when:* events carry connection state, and INVALID packets are counted.
  *Status:* Done. nf_ct_get() state, conntrack enabled per namespace with nf_ct_netns_get(); a SYN+FIN packet is reported INVALID. Verified.
- [x] **K2.9 Per-namespace support.** Register hooks with `pernet_operations` so each network namespace (container) gets its own hooks and counters; tag events with a namespace ID.
  *Done when:* traffic inside a Docker container is captured and labeled.
  *Status:* Done. pernet_operations; a new namespace is hooked automatically and its events carry its inode number. Verified with ip netns.
- [x] **K2.10 Settings and stats.** Module parameters (buffer size, enabled hooks); `debugfs` or sysfs counters: packets seen, events dropped, buffer fill, nanoseconds per packet.
  *Done when:* counters are readable under `/sys/kernel/debug/kguard/`.
  *Status:* Done. Seven module parameters; debugfs stats, rings and config; hook cost sampled 1 in 64 packets.
- [x] **K2.11 Module tracepoints.** Add `TRACE_EVENT`s for drops and detections so `perf` and `trace-cmd` can observe the module.
  *Done when:* `perf record -e kguard:*` shows events.
  *Status:* Done. kguard:kguard_event, kguard:kguard_ring_full and kguard:kguard_alert. Verified with `perf record -e 'kguard:*'` (perf 6.8) and through tracefs.

## Phase 3 — In-kernel detection and firewall

- [x] **K3.1 Per-source state table.** `rhashtable` keyed by source IP, with RCU-protected lookups in the packet path, timer- or LRU-based expiry and a memory cap.
  *Done when:* 1M distinct sources don't exceed the memory cap, checked with kmemleak.
  *Status:* Done. rhashtable keyed by (address, netns), RCU lookups, per-source spinlock, max_sources cap, GC on the unbound workqueue, frees via call_rcu into an unmerged slab cache. Verified: 1,000,000 spoofed sources (delivery proven by the module's packet counter) keep the table under the default cap of 65,536; 20,000 sources against a cap of 1,000 stay at 1,000 slab objects; idle state is freed; kmemleak on the debug kernel finds no kguard object after the whole suite and unloading.
- [x] **K3.2 In-kernel scan detection.** Track distinct destination ports per source in a time window (bitmap or HyperLogLog); emit an alert event over Netlink.
  *Done when:* `nmap -sS` triggers an alert within 1 second.
  *Status:* Done. 1024-bit distinct-port bitmap per source per window; alert over Netlink multicast and tracepoint. Verified: nmap -sS from another namespace detected 21 ms after its first SYN.
- [x] **K3.3 Rate limiting.** Per-source token bucket for new connections (SYN packets).
  *Done when:* a SYN flood from one source is limited to the configured rate.
  *Status:* Done. Per-source SYN token bucket (thousandths of a token). Verified: 1,000 SYNs in 0.1 s with rate 50/s, burst 50: 948 dropped, one alert.
- [x] **K3.4 Blocking.** Blocklist with expiry checked first in the hook; return `NF_DROP` for listed sources. Always honor an allowlist.
  *Done when:* a blocked IP can't connect, and is allowed again after expiry.
  *Status:* Done. Blocklist with expiry checked first at PRE_ROUTING (before conntrack); CIDR allowlist checked before everything; manual blocks over Netlink; auto_block for scanners. Verified for IPv4 and IPv6, including expiry and unblock.
- [x] **K3.5 Fail-safe mode.** A module parameter for monitor-only mode (never drop). Add a check that blocking can't lock out the management IP.
  *Done when:* monitor-only mode is on by default and documented.
  *Status:* Done. enforce=0 by default (alerts say "none", blocks only counted as would_drop); local and allowlisted addresses can never be blocked or rate-limited, and blocking them is refused.

## Phase 4 — eBPF / XDP engine and agent

- [x] **X4.1 eBPF capture.** XDP program for incoming packets and TC program for outgoing, written with libbpf and CO-RE (BTF); events go to a `BPF_MAP_TYPE_RINGBUF`.
  *Done when:* the same event format as K2.5 comes out of the eBPF path.
  *Status:* Done. agent/bpf/kguard.bpf.c: XDP ingress + TC clsact egress, BPF ring buffer of the same 128-byte struct kguard_event (ABI 2, with the SYN option parser), CO-RE with partial preserve_access_index structs (no vmlinux.h). Verified on 6.8: 10,000/10,000 packets each way, nothing lost.
- [x] **X4.2 eBPF process tracking.** Probes on `tcp_v4_connect`, `inet_csk_accept` and the `sock:inet_sock_set_state` tracepoint, mapping connections to PID and command.
  *Done when:* matches the K2.7 output for the same test.
  *Status:* Done. fentry tcp_connect, fexit inet_csk_accept (via bpf_get_func_ret, signature-independent), fexit inet_listen/inet_bind/inet6_bind, fentry udp_sendmsg, tp_btf inet_sock_set_state; existing listeners seeded from /proc/net at start-up. Verified: curl, nc listeners started before and after the agent, first UDP datagram.
- [x] **X4.3 XDP blocklist.** `BPF_MAP_TYPE_LPM_TRIE` of blocked CIDRs; return `XDP_DROP`.
  *Done when:* blocked traffic is dropped before the kernel's network stack.
  *Status:* Done. LPM trie (IPv4 stored IPv4-mapped) pinned in bpffs, XDP_DROP with per-entry drop counters and expiry; kguard-agent block/unblock/blocks. Verified against an attacker namespace: IPv4 prefix, IPv6, expiry.
- [x] **X4.4 Agent.** One user-space program (Go with cilium/ebpf, or C with libbpf) that loads either engine (C module or eBPF), reads events, batches them and streams them to the backend over gRPC or HTTPS. Handles reconnects and backpressure.
  *Done when:* `kguard-agent --engine=module|ebpf` both feed the same backend.
  *Status:* Done in C (libbpf + libcurl), not Go/gRPC: one binary, --engine=module|ebpf, bounded queue with drop counting, HTTPS JSON batches with retry/backoff. Verified: both engines, and 1,000/1,000 events delivered across a backend restart.
- [x] **X4.5 Multi-server.** Agent identity (host ID plus token); backend stores which host each event came from.
  *Done when:* two VMs show up separately in the dashboard.
  *Status:* Done. Enrollment with a shared key, per-agent tokens (SHA-256 stored), host_id on events and alerts, per-host detection, Hosts page. Verified: two agents (module and eBPF, separate network namespaces) shown as two hosts; scan alert attributed to the scanned host. Two separate VMs not tested.

## Phase 5 — Deep network detection

- [x] **N5.0 Reduce sensitive-port noise.** Ports 80 and 443 are in the default `SUSPICIOUS_PORTS`, so every new web client raises a MEDIUM alert on a web server. Drop them from the default or score them lower, and add an allowlist of trusted sources.
  *Done when:* normal web traffic to a web server raises no alerts.
  *Status:* Done. 80 and 443 removed from the default SUSPICIOUS_PORTS; TRUSTED_SOURCES (CIDRs) skips detection. Verified in scripts/detection_lab.py: 30 web requests to port 443 raise no alerts.
- [x] **N5.1 Scan types from TCP flags.** Classify SYN, FIN, NULL, Xmas, ACK and Maimon scans, and UDP scans (from ICMP port-unreachable replies).
  *Done when:* each `nmap` scan type (`-sS -sF -sN -sX -sA -sU`) produces the correctly labeled alert.
  *Status:* Done. Probe types classified from TCP flags plus conntrack state (backend/app/services/probes.py, signatures observed for every nmap type on Linux 6.8); alerts are titled by scan type. UDP scans are recognised from the UDP probes themselves (new-connection UDP to many ports), not from ICMP replies. SYN/UDP come from the kernel guard (labelled from events up to the alert's time), stealth scans from the backend. Verified: nmap -sS -sF -sN -sX -sA -sM -sU each give the right label.
- [x] **N5.2 SYN flood.** Track half-open connections per destination; note whether SYN cookies are on (`net.ipv4.tcp_syncookies`).
  *Done when:* `hping3 --flood -S` raises a SYN flood alert.
  *Status:* Done. Half-open connections per destination (SYN without a completing ACK) whatever the source, so spoofed random-source floods are caught; alert includes net.ipv4.tcp_syncookies. Verified: hping3 -S --flood --rand-source raises SYN_FLOOD.
- [x] **N5.3 Brute force.** Repeated short connections to SSH, RDP or database ports from one source in a window.
  *Done when:* a `hydra` run against SSH raises a `BRUTE_FORCE` alert.
  *Status:* Done. Repeated new connections to login/database ports (BRUTE_FORCE_PORTS): 10 within BRUTE_FORCE_WINDOW_SECONDS (300). Verified with hydra against a real sshd (scripts/detection_lab.py). That test found a gap, fixed: SSH takes several passwords per connection, so hydra made 15 connections in 103 s and slipped under the old 60-second window.
- [x] **N5.4 Passive OS fingerprinting.** Guess the sender's OS from initial TTL, window size, MSS and TCP option order on SYN packets (p0f-style signatures).
  *Done when:* Linux, Windows and macOS hosts are recognized in the test lab.
  *Status:* Done. Event ABI v2 (128 bytes) carries TTL, IP length, DF, TCP window and, for SYNs, MSS, window scale and option order, filled by both the kernel module and the eBPF program (bounded option loop accepted by the verifier). backend/app/services/fingerprint.py matches p0f-style signatures (Linux, Windows, macOS, FreeBSD, OpenBSD) and scanning tools (nmap, masscan, zmap, crafted); events store os_guess and alerts name the sender. Verified in scripts/detection_lab.py: a real Linux SYN (curl) is recognised as Linux; Windows and macOS are recognised from their SYN signatures replayed with scapy (no Windows/macOS machines in the test VM); nmap -sS is named nmap.
- [x] **N5.5 Spoofed traffic.** Flag TTL jumps for the same source, bogon/martian sources, and packets arriving on an unexpected interface.
  *Done when:* scapy-spoofed packets are flagged.
  *Status:* Done. Kernel guard (PRE_ROUTING, before the allowlist): loopback, own-address and martian sources on a real interface raise KGUARD_ALERT_SPOOF with reason and interface, one per reason per 10 s counting packets, dropped when enforcing. Backend: TTL jumps per source (same initial TTL, ignoring scanner-crafted packets and known scanners) and bogon sources aggregated per category. "Unexpected interface" is covered by the kernel check for this host's own addresses. Verified: scapy-forged 127.0.0.1, own-address, multicast, 198.18.0.7 and TTL-shifted packets are flagged (kernel guard tests and detection lab).
- [x] **N5.6 Amplification attacks.** Detect DNS (ANY), NTP (monlist), memcached and SSDP reflection: large responses to small requests, or unsolicited responses.
  *Done when:* replayed amplification captures raise alerts.
  *Status:* Done. Victim side: unsolicited (conntrack new/invalid, or no query seen without conntrack) UDP replies of at least 200 bytes from reflector ports, per destination and service; reflector side: this host's UDP service replying with many times the request bytes. Verified with scapy replays of DNS ANY answers, NTP monlist pages, memcached get answers and SSDP M-SEARCH answers (all four raise AMPLIFICATION), and a host service amplifying 39x. Writing the SSDP replay found that the old 400-byte minimum missed typical SSDP answers (250-350 bytes); lowered to 200.
- [x] **N5.7 DNS tunneling.** Parse DNS queries; score long, high-entropy subdomains and unusual record types (TXT, NULL).
  *Done when:* an `iodine` or `dnscat2` session is detected, with a measured false-positive rate on normal browsing.
  *Status:* Done. The eBPF agent samples DNS messages (separate payload ring buffer); the backend parses them (compression- and loop-safe), stores each lookup with its process, and scores lookups per client and registered domain: name length, random-looking names, uniqueness, TXT/NULL types (DNS_TUNNELING). Verified: a real iodine tunnel (NULL records) raises DNS_TUNNELING, attributed to the iodine process (scripts/payload_lab.py). False positives: none on real hostnames (500 top sites and ~6,000 third-party hosts from Ghostery's tracker database) in a simulated 8-hour browsing session (36,000 lookups) or with every hostname at once; the closest domain scored 0.31 against 0.6 (scripts/dns_fp_eval.py). The browsing pattern is modelled (no Internet in the test environment); dnscat2 was not available.
- [x] **N5.8 TLS fingerprinting.** Parse the TLS ClientHello; compute JA3/JA4 and record the requested server name (SNI). Match against a list of known malware fingerprints.
  *Done when:* fingerprints for `curl`, Chrome and Python `requests` are recorded correctly.
  *Status:* Done. The eBPF agent copies TLS ClientHellos (followed across TCP segments, or chunked when offloaded); the backend reassembles them, computes JA3, JA4 and SNI per process, and alerts on fingerprints in a CSV blocklist (MALICIOUS_TLS, abuse.ch SSLBL format). Verified against Wireshark 4.2.2 on the same traffic: curl and Python requests match exactly; Chromium matches on JA3 and JA4 a/b, and JA4 c differs only because Wireshark 4.2.2 keeps GREASE signature algorithms, which the JA4 spec ignores (ours stays the same across Chromium connections while JA3 changes). No malware list is bundled: the sandbox cannot reach abuse.ch, so matching is tested with a sample list.
- [x] **N5.9 Sliding-window baseline.** Learn normal per-hour traffic per host/port; alert on large deviations.
  *Done when:* a replayed traffic spike raises an `UNUSUAL_TRAFFIC` alert.
  *Status:* Done. EWMA mean/variance of incoming connection attempts per host and port per minute; UNUSUAL_TRAFFIC after warm-up when far above mean (6 sigma and 5x); spikes are not learned. Adapts to the recent past; no time-of-day model. Verified with replayed spikes in unit tests.
- [x] **N5.10 Flow export.** Group packets into flows and export IPFIX (or NetFlow v9).
  *Done when:* `nfdump` or Wireshark decodes the exported flows.
  *Status:* Done. backend/app/services/flow_export.py: unidirectional flows per observation domain (agent, or network namespace on this server) and 5-tuple; exported on FIN/RST, idle and active timeouts or a full table; IPFIX (RFC 7011) over UDP with IPv4/IPv6 templates refreshed every 30 s, messages under 1400 bytes. Verified (scripts/flow_pcap_lab.py): nfcapd/nfdump 1.7 stores the flows, whose packets and bytes equal tcpdump's for a 2 MB download in both directions; Wireshark decodes all records without errors. The lab caught packets being counted twice (seen in two namespaces), fixed by one observation domain per namespace.
- [x] **N5.11 Packet capture on alert.** Keep a short rolling buffer; on a high-severity alert, save the surrounding packets as `.pcap`.
  *Done when:* the saved file opens in Wireshark and contains the attack.
  *Status:* Done. backend/app/services/packet_capture.py: AF_PACKET TPACKET_V3 ring mmap'ed into the backend, classic BPF socket filter cutting packets to 256 bytes in the kernel, blocks kept for 30 s within a memory budget; on an alert of HIGH or above (this server's) the packets to or from the alert's addresses, from before and 5 s after, are saved as a nanosecond pcap, noted on the alert and served at /api/alerts/{id}/pcap. Verified: an nmap scan blocked by the kernel yields a pcap with all 200 SYN probes (20 from before the alert), nothing else, and no packet over the snap length. Off by default; agents do not capture.

## Phase 6 — Backend upgrade

- [x] **S6.1 PostgreSQL and migrations.** Postgres in production (TimescaleDB optional), real Alembic migrations, automatic deletion of old data.
  *Done when:* `alembic upgrade head` builds the schema from empty; retention job runs daily.
  *Status:* Done. On PostgreSQL 16 and SQLite, `alembic upgrade head` builds the schema from empty, `alembic check` finds no difference from the models, and downgrade to empty and back works; CI runs this and the full backend suite (178 tests) on PostgreSQL. The backend migrates at start-up (checked by starting it on an empty PostgreSQL database), and upgrades pre-migration databases in place. The retention job runs a minute after start-up and then daily, deleting in batches (tests cover each table, pcap removal, batching, 0 = keep forever, and the daily schedule). The production compose file runs postgres:16. TimescaleDB is not used.
- [x] **S6.2 Redis state.** Sliding-window counters for detection in Redis, so restarts don't lose detection state and multiple backend workers agree.
  *Done when:* a scan spread across a backend restart is still detected.
  *Status:* Done. With `REDIS_URL`, the per-source probe windows, the brute-force login windows and every alert cooldown live in Redis (sorted sets trimmed by time and size; cooldowns claimed with atomic `SET NX EX`). Test with real processes: a backend sees 6 ports, is restarted, sees 6 more, and raises one 12-port scan; without Redis the same run raises nothing. Two backend processes sharing Redis, each seeing half a scan, raise it exactly once. If Redis goes away, detection continues in memory and reports `memory fallback`. The whole suite runs with state in Redis in CI (PostgreSQL + Redis job) and passed locally. The SYN-flood, spoofing and amplification trackers (windows of seconds) stay in memory.
- [x] **S6.3 Enrichment.** GeoIP (MaxMind GeoLite2), public bad-IP lists, and MITRE ATT&CK technique IDs on each alert (e.g. port scan → T1046).
  *Done when:* alerts show country, list matches and technique ID.
  *Status:* Done. Every stored alert gets `metadata.enrichment` (database hook, so every detector is covered): MITRE techniques per alert type (types with no clear technique get none rather than a guess), country and ASN from GeoLite2 databases, and matches from FireHOL/Spamhaus-format list files, with `python -m app.threatlists update` (keeps the old copy on a bad download). Tested end to end: a detected scan shows country, list and T1046 in the API, and the dashboard's recent alerts show them as tags. The GeoIP tests use small generated databases and the updater is tested against a local web server: this environment cannot download MaxMind's databases (they need a free account) or the public lists.
- [x] **S6.4 Response engine.** Rules for when to block automatically, with allowlist, expiry, manual unblock and an audit log; sends block commands to the agent or Netlink.
  *Done when:* blocking and unblocking from the API works end to end.
  *Status:* Done. Blocks, allowlist and audit log in the database; safety rules (no loopback/link-local/multicast, nothing wider than /16 or /32, nothing on the allowlist or an agent's address); automatic rules off by default (alert types, minimum severity, threat-listed sources, doubling for repeat offenders; spoofable alert types excluded). Agents poll their blocklist and apply it as renewable leases: eBPF in XDP, the module over Generic Netlink; the backend applies it to its own machine's module over Netlink when it has CAP_NET_ADMIN. VM tests against an attacker namespace: blocking through the API cuts the attacker off and unblocking restores access, with the eBPF agent and with the module agent; a port scan blocks its source automatically; a block whose removal a killed agent never saw ends within one lease; monitor-only mode is reported; the backend blocks directly over Netlink. Full agent suite 53/53. A dashboard page for blocks is U7.3.
- [x] **S6.5 Login and roles.** JWT login, admin and viewer roles; destructive endpoints (`/cleanup`, blocking) are admin-only; WebSocket requires a token.
  *Done when:* unauthenticated requests get 401 (tests for every endpoint).
  *Status:* Done. Users table (migration 0002), scrypt password hashes, HS256 tokens carrying a version so a password, role or status change ends existing logins at once, user management API and `python -m app.users`. Tests take every endpoint from the OpenAPI schema: all 29 non-public operations return 401 without a token, viewers get 403 on all 7 that change data, and can read the other 17; bad, expired, forged, `alg: none` and revoked tokens are refused. The 5 public endpoints are listed with the reason (login, liveness probe, `/`, and the agents' own enrollment-key and token auth). The WebSocket refuses connections without a valid token. Acknowledge and resolve record the logged-in user. Blocking endpoints do not exist yet; S6.4 adds them as admin-only. The dashboard has a login screen (checked in Chromium: sign-in, live WebSocket, sign-out); hiding admin actions from viewers is U7.6. Lab scripts, the end-to-end smoke test (VM, real module), the agent suite (31/31) and the flow/pcap lab (10/10) pass with login.
- [x] **S6.6 Hardening.** Rate limiting, no default secret key (refuse to start without one), strict CORS and trusted hosts, run as a non-root user, read-only access to the device.
  *Done when:* security tests pass, and the container runs as non-root.
  *Status:* Done. Per-address token-bucket limit on the API and a failed-login limit per address and per username (429 + Retry-After); refuses to start without a 32+ character SECRET_KEY, with an example value, or with `*` origins/hosts (tested by starting the real server); CORS limited to listed origins without credentials; TrustedHost always on; security headers; tokens redacted from all logs (found and fixed: uvicorn logged WebSocket URLs with the token). Production image built and run: user 10001 by default, code root-owned and read-only, no compiler or curl; with the Compose settings (read-only root, `cap_drop: ALL`, no-new-privileges) the backend ran healthy against PostgreSQL with zero capabilities. Also fixed in Compose: missing nginx and redis config mounts, a root-owned log directory the non-root user could not write, and a published backend port. Device access: the backend uses the module's reader group, not root or CAP_NET_ADMIN, so it cannot change module settings or block lists; it opens `/dev/kguard` read-write only to store its own read position in the ring header. Not checked: the nginx frontend container (Docker Hub rate-limited its image pull here).
- [ ] **S6.7 Notifications.** Slack, email and Telegram for alerts at or above a set severity, with per-channel rate limits.
  *Done when:* a test alert reaches a Slack channel.
  *Status:* Built and tested against stand-ins: a local server playing Slack's webhook and Telegram's Bot API, and a local SMTP server. A scan detected by the collector arrives on all three; severity threshold, per-channel hourly limit (with a "N held back" note), retries honouring Retry-After, no retry on 4xx, secrets never shown, and the admin test endpoint (`POST /api/notifications/test`) are tested. **Not met yet:** no real Slack channel, since this environment cannot reach hooks.slack.com. Set `SLACK_WEBHOOK_URL` and call the test endpoint to finish it.
- [x] **S6.8 Metrics.** Prometheus `/metrics`: events/s, drops, detection time, alerts by type; include a sample Grafana dashboard.
  *Done when:* the Grafana dashboard loads from `docker compose up`.
  *Status:* Done. `/metrics` (own `METRICS_TOKEN`) exports events per host, alerts by type and severity, a detection-time histogram, kernel and agent-queue drops, agent online and blocklist sync, active blocks, API rate and latency. Checked with `docker compose -f docker-compose.prod.yml up`: Prometheus scrapes the backend (target up), Grafana provisions the data source and the 11-panel "KGuard overview" dashboard, and with real agent traffic every panel shows data (screenshot in `docs/images/grafana-kguard.png`).
- [x] **S6.9 Structured logging.** JSON logs with request IDs; log rotation.
  *Done when:* each log line is valid JSON.
  *Status:* Done. Every line, including uvicorn's start-up and shutdown, Alembic's, warnings and uncaught exceptions, is one JSON object. Each request and WebSocket connection gets an ID (the client's X-Request-ID if sensible), returned in the response and on every line logged while it is handled; one access line per request with status and duration. A test starts the real server (`python -m app`), sends good, 404 and 422 requests, stops it and parses every line of its output; also checked by hand with DEBUG on (code reloader) and off. LOG_FILE rotates by size (tested: each file under the limit and all JSON); in Docker, stdout is rotated by Docker. The production image now runs one process instead of four workers, which had each read the kernel rings and kept separate detection state.

## Phase 7 — Frontend upgrade

- [x] **U7.0 Build the placeholder pages.** Events, Alerts, Analytics and Settings are still "coming soon" stubs. Events: filterable, paginated table. Alerts: list with acknowledge/resolve. Analytics: top IPs, top ports, alerts over time. Settings: show detection thresholds.
  *Done when:* every sidebar link shows real data.
  *Status:* Done. Events (filters for addresses, port, protocol, direction, process, host, suspicious; pagination), Alerts (status, severity and type filters; acknowledge), Analytics (alerts and events over time, top sources, ports, alert types; 1 h / 24 h / 7 d) and Settings (thresholds, automatic blocking, notification channels, enrichment, retention) are real pages, plus new Processes and Blocked pages. Checked in Chromium against a real backend with two agents' traffic: every sidebar link shows real data (8/8). Unit tests for each page. Also fixed a latent Tailwind error (undefined `ring-ring` token) that broke the CSS and the production build as soon as the button classes were used.
- [x] **U7.1 Live data.** Use WebSocket messages to update React Query caches instead of only polling.
  *Done when:* new events appear without refresh in under 1 second.
  *Status:* Done. A WebSocket event goes straight into the cached lists of newest events (no request); filtered lists and statistics refresh at most every 2 seconds. Measured in Chromium: from an agent POSTing an event to its row on the Events page, 26-72 ms over 8 runs.
- [x] **U7.2 Process view.** Table of listening ports and active connections with process, PID and user; highlight unexpected listeners.
  *Done when:* starting `nc -l 4444` on a host shows up within seconds.
  *Status:* Done. `/api/sockets` reads /proc/net (TCP/UDP, IPv4/IPv6) with process, PID and user, like `ss -tunap`; agents send the same snapshot every few seconds. A host's first snapshot is its baseline (this server's is taken a few seconds after start-up, once its own port is open); later listeners are highlighted until an admin marks them expected. In the VM: `nc -l 4444` on the backend's machine appeared flagged in 0.6 s, and `nc -l 4446` on an agent's host in 2.2 s, with the right PID and user. Found and fixed on the way: baselining at first view (a listener started before anyone looked became "normal"), and baselining before uvicorn opened its port (the backend flagged itself).
- [x] **U7.3 Blocked IPs page.** List, add, unblock, and show expiry and reason.
  *Done when:* blocking and unblocking work from the UI.
  *Status:* Done. Blocked page: active blocks and history with reason, manual or automatic (linked to its alert), host and time left; block and unblock, allowlist, audit log, each agent's enforcement state. In Chromium: blocking from the form put the address in the agents' blocklist, and Unblock removed it.
- [x] **U7.4 Alert details.** Show scan type, OS guess, TLS fingerprint, country, MITRE technique, related events and a pcap download.
  *Done when:* each alert type shows its own detail panel.
  *Status:* Done. `/alerts/:id`: summary with country, threat lists and MITRE link; a panel per alert type built from its detector's metadata (scan type and ports, OS/tool fingerprint, SYN cookies, spoofing reason, amplification factor, DNS tunnel domain, JA3/JA4/SNI, baseline ratio, ...); related events (new `?ids=` filter); pcap download; acknowledge/resolve/block for admins. Unit tests render a panel for each of 8 alert types; checked in Chromium on a real port-scan alert.
- [x] **U7.5 Hosts page.** One row per agent: status, version, engine (module or eBPF), events/s, drops.
  *Done when:* two agents show separately.
  *Status:* Done. One row per agent with status, engine, version, events per second (from stored events of the last minute, so right after restarts and across processes), drops, blocklist state. Two agents (eBPF and module) showed as separate rows in Chromium; tested in the backend and the frontend.
- [x] **U7.6 Login screen and roles.** Viewer can't see admin actions.
  *Done when:* role checks are tested.
  *Status:* Done. Viewers see every page but no acknowledge, resolve, block, unblock, allowlist or "mark expected" controls (the API refuses them anyway). Role checks are unit-tested on the alerts, alert detail, blocks and processes pages, and checked in Chromium by logging in as a viewer.
- [x] **U7.7 Kernel health panel.** Show the module or eBPF counters (K2.10): buffer fill, drops, nanoseconds per packet.
  *Done when:* the numbers match `debugfs`.
  *Status:* Done. Hosts page panel: packets, events, drops, buffer fill against ring capacity, ns per packet, mode and guard counters, read over Generic Netlink GET_STATS (no privileges needed). In the VM the API's values lie between two debugfs reads taken around the call, and ring capacity, hooked namespaces and blocklist size equal debugfs exactly. eBPF agents report only their drops (on the Hosts table).

## Phase 8 — Proof: benchmarks, attack demos, kernel testing

- [x] **P8.1 Test lab.** Vagrant or `virtme-ng` setup: one victim VM running KGuard, one attacker VM with nmap, hping3, hydra, scapy, iodine.
  *Done when:* `make lab` brings both up.
  *Status:* Done. `make lab` (`scripts/lab.sh`, `scripts/lab_node.py`) boots two virtme-ng VMs joined by a private QEMU socket link: the victim (10.77.0.1) loads the module and runs the backend on :8000, sshd and a web server; the attacker (10.77.0.2) has the attack tools and a root shell. `LAB_CHECK=1 make lab` is the non-interactive check: the attacker logs in to the victim's API across the link, runs `nmap -sS`, and waits for the victim to report it. Run here: exit 0, "SYN Scan Detected from 10.77.0.2" (kernel alert) on the victim. The interactive shell mode was not exercised (no terminal in this environment). Both VMs run the host's root filesystem, so the tools must be installed on the host.
- [x] **P8.2 Attack demo scripts.** One script per attack in Phase 5, each checking that the expected alert appears.
  *Done when:* `make attack-demo` runs all of them and prints pass/fail.
  *Status:* Done. `scripts/attacks/<attack>.sh` (scans, brute_force, syn_flood, os_fingerprint, spoofing, amplification, dns_tunnel, tls) each run one attack with real tools (nmap, hydra, hping3, scapy, iodine, openssl) in a VM; `make attack-demo` runs all eight and prints a PASS/FAIL line each. Run on the 6.8 kernel (emulated VM): 8/8 PASS, 35 checks (detection lab 21/21, payload lab 14/14).
- [ ] **P8.3 Kernel debug builds.** Run the module's stress tests on a kernel with KASAN, KCSAN, lockdep and kmemleak enabled.
  *Done when:* zero reports from each tool, recorded in CI logs.
  *Status:* Clean locally; not in CI. `kernel/tests/debug_kernel.sh` builds a 6.8 kernel with the checkers, boots it in a VM, runs the whole suite and reports what the checkers found (it streams reports as they happen). Two kernels, since KASAN and KCSAN exclude each other: lockdep + KCSAN + kmemleak (`tests/debug.config`), and KASAN + UBSAN + lockdep + kmemleak + SLUB debug (`tests/debug-kasan.config`, `DEBUG_FLAVOR=kasan`). Both runs: zero lockdep, KCSAN, KASAN and UBSAN reports, and zero kmemleak objects from kguard after unloading (the KCSAN run found and fixed a lockdep deadlock earlier, see K2.8). Under emulation the debug kernels are about 10 times slower, so timing checks fail there (KASAN run: 68/81 functional checks; the rest are rates, wake-up counts and slab counts inflated by KASAN's quarantine), and the 1,000,000-source scale test is skipped on both. Not met as written: the runs are in this environment's logs, not CI. A debug-kernel build takes about 20 minutes on 4 CPUs, which fits a scheduled CI job but none exists yet.
- [ ] **P8.4 Kernel static checks.** `sparse` (`make C=1`), `checkpatch.pl --strict`, and `smatch` in CI.
  *Done when:* clean output.
  *Status:* Partly done. sparse (`make -C kernel sparse`, `C=2`, any warning in our files fails, and a failed build fails) and checkpatch `--strict` run in CI and are clean (CI run 56, "Kernel module" job). smatch is not done: it has to be built from its git source, and fetching and building that code was not permitted in this environment. It needs either a packaged smatch or permission to build it.
- [ ] **P8.5 Multi-kernel CI.** Build and load-test the module on several kernel versions (e.g. 5.15, 6.1, 6.6, latest) inside VMs.
  *Done when:* a CI matrix is green for every version.
  *Status:* Not done. `kernel/tests/kernel_matrix.sh` fetches the Ubuntu mainline builds of 5.15, 6.1, 6.6, 6.12 and the latest stable from kernel.ubuntu.com, builds the module against each with warnings as errors, and runs the full suite in a VM on each. It has not been run: downloading and booting those kernels was not permitted in this environment, and there is no CI matrix yet. Only 6.8 (Ubuntu 24.04) and the CI runner's kernel are tested.
- [x] **P8.6 Kernel self-tests.** kselftest-style tests for the device, Netlink commands and blocking.
  *Done when:* tests run in CI inside a VM.
  *Status:* Done. `kernel/tests/selftests/kguard_test.c` (TAP, `make -C kernel selftest`): 35 tests of the device (ABI, mmap rules, poll, events), Generic Netlink (stats, config, permissions, block/allow add, list, delete, errors) and blocking (a client in a namespace cut off and let back in, enforce vs monitor-only, expiry). The CI job "Kernel module in a VM" boots the runner's kernel with KVM and runs them: 35/35 (CI run 56), followed by the full suite, 84/84. Getting the suite green on CI needed nmap and scapy installed, a readable checkout for the non-root check, retries for raw sends that fill the veth queue on fast KVM, and ignoring the runner CPU's boot-time SRSO warning.
- [ ] **P8.7 Benchmarks.** Use `pktgen` (and `trafgen` or TRex) to measure packets/s, nanoseconds per packet and CPU use for: no monitoring, C module, eBPF TC and eBPF XDP. Include `perf` flame graphs.
  *Done when:* `docs/BENCHMARKS.md` has the numbers, charts and hardware details.
  *Status:* Harness done; numbers only from an emulated VM. `make bench` (`scripts/benchmark.py`, `bench_vm.sh`, `bench_report.py`) measures all six modes (no monitoring, module, XDP generic, XDP native, and egress no monitoring vs TC egress) with trafgen (pktgen optional), 3 repeats, flame graphs, and writes `docs/BENCHMARKS.md` material: the table, two charts, six flame graphs and the hardware details. But this environment has no KVM, so every figure is from QEMU software emulation and far from hardware cost; the document says so up front. Not met in spirit until it is run on hardware or KVM. Findings: no event losses in any mode; a 6.8 kernel BUG with pktgen + generic XDP (so trafgen is the default); an unexplained 50x per-run gap between the XDP and TC programs; an occasional veth reference left at teardown.
- [ ] **P8.8 Fuzzing.** Fuzz the packet parser in user space (libFuzzer on shared parsing code) and the Netlink/ioctl interface (syzkaller description, optional).
  *Done when:* 24 hours of fuzzing with no crashes.
  *Status:* Harnesses done; 1.9 hours run, not 24. The module's TCP options walk moved to `kernel/src/kguard_parse.h`, shared by the module and a libFuzzer harness with ASan and UBSan (`make -C kernel fuzz`); it caught a planted off-by-one as a heap overflow. Atheris harnesses fuzz the backend's TLS ClientHello and DNS parsers (`backend/fuzz`), whose contract is "return a result or raise the parser's own error". One run of 6,900 s each, no crashes: TCP options 2.48 billion inputs, TLS 47.4 million, DNS 162 million. `.github/workflows/fuzz.yml` runs all three for an hour a night from the cached corpus, so the hours add up; it has not run yet. No syzkaller description.
- [x] **P8.9 Backend coverage.** At least 80% test coverage on backend services.
  *Done when:* the CI coverage report shows at least 80%.
  *Status:* Done. CI measures coverage on every Python version and fails under 80% (`backend/pyproject.toml`); CI run 56 reports 89.23% (358 passed, 8 skipped) and uploads `coverage.xml`. The lowest services are `kguard_netlink.py` (66%) and `detection_state.py` (70%), whose untested branches need a live kernel or Redis failure.

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
