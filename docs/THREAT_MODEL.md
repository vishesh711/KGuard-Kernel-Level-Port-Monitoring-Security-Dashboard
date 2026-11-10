# KGuard threat model

What KGuard detects, what it does not, and how an attacker who knows how it
works could get past it. Thresholds are the defaults; every one is a setting
(`backend/README.md`, `kernel/README.md`). Where a detection was verified
against a real attack, the roadmap item says how.

## Who the attacker is

| Attacker | In scope | What they can do |
|---|---|---|
| **Remote, on the network** | Yes | Send any packet to the monitored hosts, with any source address they can route or spoof; scan, flood, guess passwords, reflect traffic at them. |
| **A compromised process on a monitored host, without root** | Yes | Open connections, resolve names, make TLS connections: exfiltrate or reach a command-and-control server. |
| **An unprivileged local user** | Yes | Try to read KGuard's events or change its settings. |
| **Root on a monitored host** | No | Can unload the module, stop the agent, detach eBPF programs or edit their maps. KGuard does not defend a host against its own administrator. It notices the agent going quiet (the Hosts page shows when each host was last seen) but nothing more. |
| **Someone with a dashboard login** | Partly | Viewers see everything; admins can block addresses. Logins are rate-limited and roles are enforced on every endpoint (`backend/tests/test_api_access.py`). |

## What KGuard cannot see

- **Payloads it is not given.** The kernel module records headers only. The
  eBPF engine samples DNS messages and TLS ClientHellos; everything else,
  including the content of any encrypted connection, is opaque.
- **DNS over HTTPS or TLS, and QUIC.** DNS tunnelling detection reads plain
  DNS on port 53; TLS fingerprinting reads TLS over TCP. DoH, DoT and HTTP/3
  ClientHellos (inside QUIC) are not parsed.
- **Packets that skip the hooks.** The module sees what passes Netfilter:
  packets sent through `AF_PACKET` sockets do not, and kernel-bypass
  networking (DPDK, AF_XDP) is invisible to both engines. With
  `PACKET_QDISC_BYPASS`, `AF_PACKET` sends also skip the eBPF engine's TC
  egress program (seen while benchmarking: trafgen's default).
- **What happens inside a connection.** Brute-force detection counts
  connections, not failed logins; it cannot tell a successful guess from a
  failed one.
- **Hosts without the module or an agent.**

## Detections

Each entry: what triggers it, what it misses, and how it can be evaded.

### Port scans (kernel guard, and backend probe types)

*Triggers:* the kernel counts distinct destination ports per source address:
20 within 5 s raises a scan alert in about 20 ms (nmap -sS: 21 ms after its
first SYN, [K3.2](../ROADMAP.md)). The backend classifies each probe (SYN,
FIN, NULL, Xmas, ACK, Maimon, UDP) and alerts on 10 ports of one probe type
within 60 s, so stealth scans are labelled ([N5.1](../ROADMAP.md)).

*Misses and evasion:*
- **Slow scans.** Fewer than 10 ports per minute per source passes both
  rules. A scan of all 65,535 ports at 9 per minute takes five days and is
  never reported.
- **Distributed scans.** Counting is per source address: 100 sources
  probing 5 ports each are not a scan to KGuard.
- **IPv6 address rotation.** A source is one 128-bit address. An attacker
  with a /64 can give every probe a new source address. Grouping sources by
  prefix is not implemented.
- **Hiding in a spoofed flood.** The kernel tracks at most 65,536 sources
  (`max_sources`); beyond that, new sources are counted but not tracked,
  until idle state is freed (60 s). Under a wide random-source flood a real
  scanner may go untracked by the kernel. The backend still sees its events
  unless the rings overflow (drops are counted on the Hosts page).
- **Choosing colliding ports** no longer works: ports are hashed into the
  1,024-bit bitmap with a secret key. (Before this was fixed, a scan of
  ports 1,024 apart set one bit and was never counted; a guard test now
  covers it.)

### SYN floods

*Triggers:* in the kernel, a per-source token bucket (200 SYN/s, burst 400)
alerts and, when enforcing, drops the excess ([K3.3](../ROADMAP.md)). In the
backend, 200 half-open connections to one destination within 10 s,
whatever their sources, so random-source floods are caught; the alert says
whether SYN cookies are on ([N5.2](../ROADMAP.md); hping3 `--flood
--rand-source` verified).

*Misses and evasion:* a flood below 200 half-open connections per 10 s per
destination; a single source under 200 SYN/s. The per-source limit cannot
stop a random-source flood: that needs SYN cookies (the alert reports
whether they are on) or upstream filtering. Under a very large flood the
rings may drop events (counted), so the backend undercounts, but the
threshold is low enough to fire long before that.

### Brute force

*Triggers:* 10 new connections from one source to one login or database
port (SSH, Telnet, RDP, SMB, FTP, SMTP, IMAP, POP3, VNC, MySQL, PostgreSQL,
MSSQL, Redis, MongoDB) within 300 s ([N5.3](../ROADMAP.md); hydra against sshd).

*Misses and evasion:*
- **Several guesses per connection.** SSH allows several passwords per
  connection (`MaxAuthTries`, 6 by default), so 9 connections in 5 minutes
  are about 54 guesses and pass unreported.
- **Slow or distributed guessing**, below 10 connections per 5 minutes per
  source.
- **Services on other ports** (SSH on 2222) unless added to
  `BRUTE_FORCE_PORTS`.
- It cannot tell success from failure: a correct password on the third try
  is three connections and no alert. Use the service's own logs for that.

### Suspicious ports and high connection rates

*Triggers:* any connection attempt to `SUSPICIOUS_PORTS` (22, 23, 3389,
5432, 3306); more than 100 connection attempts per minute from one source.

*Limits:* these are coarse indicators, easy to stay under, and noisy on
hosts that serve those ports. Use `TRUSTED_SOURCES` for known clients
([N5.0](../ROADMAP.md)).

### Passive OS fingerprinting

*What it does:* names the sender's operating system or scanning tool from a
SYN's initial TTL, window, MSS and TCP option order (p0f-style), and adds it
to alerts ([N5.4](../ROADMAP.md)).

*Limits and evasion:* it is a guess, not evidence. Only SYNs are
fingerprinted. Any attacker can make their SYNs look like another OS (raw
packets, or tuning their own TCP stack); scanning tools that craft packets
are labelled `crafted` or by tool name, but a careful attacker can copy a
Linux or Windows signature exactly. Middleboxes that rewrite MSS or options
change the result. Windows and macOS signatures were verified with replayed
SYNs, not real machines.

### Spoofed sources

*Triggers:* in the kernel, a packet arriving on a real interface that
claims to come from a loopback address, one of this host's own addresses,
or an address no host can have (multicast, broadcast, zero), aggregated to
one alert per reason per 10 s and dropped when enforcing. In the backend,
bogon sources (documentation, benchmarking, reserved ranges) and a source
whose hop count (from the TTL) suddenly changes by 5 or more, 3 or more
times ([N5.5](../ROADMAP.md)).

*Misses and evasion:* spoofing an ordinary routable address that this host
has never heard from is undetectable from packets alone; there is no
baseline TTL to compare with, and a careful attacker sets a plausible TTL.
Turn on reverse-path filtering (`rp_filter`) and ask upstream networks to
filter spoofed traffic (BCP 38).

### Amplification

*Triggers:* as a victim, 50 unsolicited UDP replies of 200 bytes or more
from reflector ports (DNS, NTP, memcached, SSDP, CLDAP, chargen, ...) to one
destination within 10 s. As a reflector, one of this host's UDP services
sending a client 10 times the bytes it received, and at least 100,000 bytes
in the window ([N5.6](../ROADMAP.md); DNS ANY, NTP monlist, memcached and
SSDP replays verified).

*Misses and evasion:* reflectors on non-standard ports, replies under 200
bytes, or a low enough rate. Detection on the victim does not stop the
traffic: by the time it arrives, the link may already be full; the defence
is upstream.

### DNS tunnelling (eBPF engine)

*Triggers:* per client and registered domain within 60 s, at least 20
lookups scored on name length, how random the names look, how many are
never repeated, and TXT/NULL record types; alert at a score of 0.6
([N5.7](../ROADMAP.md); a real iodine tunnel verified, and no false alert
on 36,000 lookups of real hostnames).

*Misses and evasion:*
- **DNS over HTTPS or TLS**: not seen at all.
- **Low and slow**: under 20 lookups per minute per domain (a tunnel at a
  few bytes per second).
- **Many domains**: splitting traffic across registered domains so none
  reaches the minimum.
- **Natural-looking names**: encoding data in dictionary words lowers the
  randomness score.
- **Allowlisted domains** (reverse lookups, DNS blocklists) are skipped,
  so a tunnel through a server that answers for them would be too.
- Hosts with only the kernel module: no DNS payloads.

### Malicious TLS clients (eBPF engine)

*Triggers:* a ClientHello whose JA3 or JA4 fingerprint is on a blocklist
(CSV, abuse.ch SSLBL format). Every ClientHello is also stored with its
server name (SNI) and process ([N5.8](../ROADMAP.md); fingerprints match
Wireshark on curl, Python and Chromium).

*Misses and evasion:*
- **No list, no alerts.** No malware list is bundled; matching works only
  once `TLS_FINGERPRINT_BLOCKLIST` points at one.
- **Fingerprint changes.** Malware that uses a browser-like TLS library
  (uTLS, or the system's) or changes its cipher list gets a new
  fingerprint. JA4 is robust to extension reordering, JA3 is not.
- **Encrypted ClientHello** hides the real server name; **QUIC** (HTTP/3)
  is not parsed.

### Traffic baseline

*Triggers:* connection attempts to a port far above its learned average
(EWMA): 6 standard deviations and 5 times the mean, after a warm-up
([N5.9](../ROADMAP.md)).

*Misses and evasion:* the baseline adapts. A slow ramp ("boiling frog") is
learned as normal; spikes are not learned, but a plateau is. There is no
time-of-day model, so a nightly job looks like an anomaly at first, and an
attack timed to busy hours hides better.

### Flow export and packet capture

These are evidence, not detections. IPFIX flow export records every flow
for an external collector ([N5.10](../ROADMAP.md)). Packet capture keeps
the last 30 s of packets on the server and saves those to and from the
addresses of a HIGH or CRITICAL alert as a pcap ([N5.11](../ROADMAP.md)).
It is off by default, cuts packets to 256 bytes, and agents do not capture.

## Attacks on KGuard itself

| Attack | Effect | Mitigation |
|---|---|---|
| **Flood to overflow the rings** | New events are dropped while a ring is full | Drops are counted per ring (debugfs, Hosts page, Prometheus). The kernel guard runs before the rings and still sees every packet, so blocking and kernel alerts keep working. |
| **Spoofed flood to fill the source table** | New sources are not tracked by the kernel | Capped memory (65,536 sources), idle state freed every second; `track_full` counter. The backend rules still see events. |
| **Alert flood to hide a real alert** | The kernel sends at most 100 alerts/s and one per source and kind every 10 s; the backend applies a cooldown per source (300 s) | Spoof alerts are aggregated per reason, so random-source floods produce few alerts. A real scanner among many spoofed scan sources may lose its multicast alert; its events still reach the backend's rules. |
| **Getting someone else blocked** | With automatic blocking on, a SYN scan with a forged source address (no handshake needed) blocks that address: an attacker can block your DNS resolver or a partner | Automatic blocking is **off** by default in the kernel and the backend. When on: allowlist critical addresses; the backend never blocks agents, the allowlist, wide prefixes or reserved addresses; blocks expire (backend: 60 minutes, doubling for repeats, at most a week; kernel `auto_block`: `block_timeout`, 600 s). |
| **Locking out the administrator** | Blocking the host's own or management addresses | Local addresses can never be blocked or rate-limited; the allowlist is checked first; monitor-only by default. |
| **Reading events as a local user** | Events reveal connections and process names | `/dev/kguard` and `/proc/kguard` are root-only, or one chosen group (`reader_gid`). |
| **Changing settings as a local user** | Turning off capture or enforcement | Every Netlink change needs `CAP_NET_ADMIN` (tested). The production backend container has no capabilities. |
| **Forging agent data** | A fake agent sending made-up events | Agents enroll with a shared key and get a per-agent token (stored hashed); enrollment is off while the key is empty. An enrolled host that is compromised can still send false data about itself. |
| **Attacking the dashboard** | Guessing passwords, stealing tokens | Login rate limits per address and username, scrypt password hashes, signed tokens that are revoked by password changes, `Host` header checks, viewer and admin roles (`backend/README.md`, "Login and security"). |
| **Malformed packets aimed at the parsers** | Crashes or out-of-bounds reads in the kernel or backend | Headers read with `skb_header_pointer()`; the TCP options walk is shared with a libFuzzer harness (2.48 billion inputs, no crash); the backend's TLS and DNS parsers are fuzzed with Atheris; KASAN and UBSAN runs in CI report nothing involving kguard ([P8.3](../ROADMAP.md), [P8.8](../ROADMAP.md)). |

## Out of scope

- A root user on a monitored host.
- Denial of service against the server's network link.
- Attacks inside encrypted traffic (application exploits, data theft over
  HTTPS), and detection that needs payloads the engines do not sample.
- Insider misuse of the dashboard by an admin (it is audited: every block
  and allowlist change records who made it).
