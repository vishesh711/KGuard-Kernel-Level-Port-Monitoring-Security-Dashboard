"""
KGuard guard tests (roadmap Phase 3): in-kernel scan detection, SYN rate
limiting, blocking, allowlist and monitor-only mode.

Traffic comes from an "attacker" network namespace joined to the host by a
veth pair, because local addresses are never blocked by design:

    host  kgv0 10.200.0.1 / 2001:db8:200::1  <-->  kgv1 10.200.0.2 / ::2  (netns kgatk)

A small HTTP server on the host answers on port 8080 so each test can check
whether the attacker still gets through.

Run through vm_tests.py (which loads the module and provides the helpers).
"""

import json
import os
import subprocess
import sys
import time

# Set by vm_tests.py to itself (the running __main__ module)
h = None

HOST4, ATK4 = "10.200.0.1", "10.200.0.2"
HOST6, ATK6 = "2001:db8:200::1", "2001:db8:200::2"
NS = "kgatk"


def ctl(*args, check_rc=True):
    r = subprocess.run(h.CTL + list(args), capture_output=True, text=True)
    if check_rc and r.returncode:
        raise RuntimeError(f"kguardctl {' '.join(args)} failed: {r.stderr.strip()}")
    return r


def stats():
    return {k: int(v) for k, v in json.loads(ctl("--json", "stats").stdout).items()}


def reset_guard():
    ctl("set", "enforce=0", "auto_block=0", "scan_threshold=20", "scan_window_ms=5000",
        "syn_rate=200", "syn_burst=400", "block_timeout=600")
    for b in json.loads(ctl("--json", "blocks").stdout):
        ctl("unblock", b["address"])
    for prefix in json.loads(ctl("--json", "allowlist").stdout):
        ctl("disallow", prefix)


def in_ns(cmd, **kw):
    return subprocess.run(["ip", "netns", "exec", NS] + cmd, capture_output=True, text=True, **kw)


def reach(v6=False):
    """True if the attacker can fetch a page from the host"""
    url = f"http://[{HOST6}]:8080/" if v6 else f"http://{HOST4}:8080/"
    r = in_ns(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "2", url])
    return r.stdout.strip() == "200"


class Lab:
    def __enter__(self):
        h.sh(f"ip netns add {NS}")
        h.sh("ip link add kgv0 type veth peer name kgv1")
        h.sh(f"ip link set kgv1 netns {NS}")
        h.sh(f"ip addr add {HOST4}/24 dev kgv0")
        h.sh(f"ip -6 addr add {HOST6}/64 dev kgv0 nodad")
        h.sh("ip link set kgv0 up")
        h.sh(f"ip netns exec {NS} ip addr add {ATK4}/24 dev kgv1")
        h.sh(f"ip netns exec {NS} ip -6 addr add {ATK6}/64 dev kgv1 nodad")
        h.sh(f"ip netns exec {NS} ip link set kgv1 up")
        h.sh(f"ip netns exec {NS} ip link set lo up")
        root = "/tmp/kguard-www"
        os.makedirs(root, exist_ok=True)
        self.servers = [
            subprocess.Popen([sys.executable, "-m", "http.server", "8080", "--bind", addr, "-d", root],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for addr in (HOST4, HOST6)
        ]
        time.sleep(1.5)
        return self

    def __exit__(self, *exc):
        for s in self.servers:
            s.kill()
        h.sh(f"ip netns del {NS}", check_rc=False)
        h.sh("ip link del kgv0", check_rc=False)


class AlertWatch:
    def __enter__(self):
        self.proc = subprocess.Popen(h.CTL + ["--json", "watch"], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
        # kguardctl says "watching ..." once it has joined the multicast group;
        # a fixed sleep misses alerts when Python starts slowly (emulated VMs)
        self.proc.stderr.readline()
        return self

    def __exit__(self, *exc):
        self.proc.terminate()

    def alerts(self, wait=1.0):
        time.sleep(wait)
        self.proc.terminate()
        out = self.proc.communicate(timeout=10)[0]
        return [a for a in map(json.loads, out.splitlines()) if a.get("event") == "alert"]


def nmap_attacker(ports="1-200"):
    in_ns(["nmap", "-sS", "-Pn", "-n", "-p", ports, "--max-retries", "0", HOST4])


def test_scan_alert_monitor_only():
    """K3.2 + K3.5: a SYN scan is reported within a second; monitor mode drops nothing"""
    reset_guard()
    h.check("guard starts in monitor-only mode", json.loads(ctl("--json", "config").stdout)["enforce"] == 0)
    with h.KGuardDevice() as dev, AlertWatch() as watch:
        dev.read()
        nmap_attacker()
        alerts = watch.alerts()
        events = dev.read()
    syns = [e["timestamp"] for e in events
            if e["src_ip"] == ATK4 and e["direction"] == "in" and e["flags"] == 0x02]
    scans = [a for a in alerts if a["type"] == "scan" and a["src_ip"] == ATK4]
    delay_ms = (scans[0]["timestamp"] - min(syns)) / 1e6 if scans and syns else None
    h.check("nmap -sS from another host raises a scan alert within 1 s of its first SYN",
            delay_ms is not None and delay_ms < 1000,
            f"{delay_ms:.0f} ms after the first SYN" if delay_ms is not None else alerts)
    h.check("monitor mode: alert says no action taken", scans and scans[0]["action"] == "none")
    h.check("monitor mode: scanner can still connect", reach())


def test_scan_with_colliding_ports():
    """K3.2: ports chosen 1024 apart are still distinct ports (they shared one bitmap bit
    when the bit was port % 1024, so such a scan was never counted)"""
    reset_guard()
    ports = ",".join(str(22 + 1024 * k) for k in range(40))
    with AlertWatch() as watch:
        nmap_attacker(ports)
        alerts = watch.alerts()
    scans = [a for a in alerts if a["type"] == "scan" and a["src_ip"] == ATK4]
    h.check("a scan of 40 ports 1024 apart (22, 1046, 2070, ...) raises a scan alert", scans,
            scans[0] if scans else alerts)


def test_block_needs_enforce():
    """K3.5: a block in monitor mode is only counted, never enforced"""
    reset_guard()
    ctl("block", ATK4)
    before = stats()["would_drop"]
    ok = reach()
    h.check("monitor mode: blocked source still gets through", ok)
    h.check("monitor mode: would-be drops are counted", stats()["would_drop"] > before)
    reset_guard()


def test_block_and_expiry():
    """K3.4: blocked sources are dropped; blocks expire"""
    reset_guard()
    ctl("set", "enforce=1")
    # Each kguardctl run takes a second or two in an emulated VM, so the
    # timeout leaves room and the listing comes right after the block
    timeout = 20
    blocked_at = time.monotonic()
    ctl("block", ATK4, "--timeout", str(timeout))
    listed = json.loads(ctl("--json", "blocks").stdout)
    entry = listed[0] if listed else {}
    h.check("block is listed with its timeout and reason",
            entry.get("address") == ATK4 and entry.get("reason") == "manual"
            and 0 < entry.get("expires_in", 0) <= timeout, repr(listed))
    before = stats()["block_drops"]
    h.check("enforce: blocked source cannot connect", not reach())
    h.check("enforce: drops are counted", stats()["block_drops"] > before)
    # Wait out the timeout, plus a second for garbage collection
    time.sleep(max(0.0, blocked_at + timeout + 1 - time.monotonic()))
    gone = not json.loads(ctl("--json", "blocks").stdout)
    h.check("block expires and the source gets through again", reach() and gone)
    reset_guard()


def test_ipv6_block():
    reset_guard()
    ctl("set", "enforce=1")
    h.check("IPv6 attacker can connect before the block", reach(v6=True))
    ctl("block", ATK6)
    h.check("enforce: blocked IPv6 source cannot connect", not reach(v6=True))
    h.check("IPv4 address of the same attacker is unaffected", reach())
    reset_guard()


def test_allowlist_wins():
    """K3.4: the allowlist always wins; it cannot be blocked over"""
    reset_guard()
    ctl("set", "enforce=1")
    ctl("block", ATK4)
    ctl("allow", "10.200.0.0/24")
    h.check("allowlisted source gets through despite an existing block", reach())
    r = ctl("block", "10.200.0.77", check_rc=False)
    h.check("new blocks inside the allowlist are refused", r.returncode != 0 and "allowlisted" in r.stderr,
            r.stderr.strip())
    reset_guard()


def test_local_never_blocked():
    """K3.5: the machine's own addresses can never be blocked"""
    reset_guard()
    refused = []
    for addr in ("127.0.0.1", HOST4, "::1", HOST6):
        r = ctl("block", addr, check_rc=False)
        refused.append(r.returncode != 0 and "local" in r.stderr)
    h.check("blocking loopback or this host's own addresses is refused", all(refused), refused)


def syn_flood(count, port=8081):
    """Send count TCP SYNs from the attacker as fast as possible (raw socket)"""
    code = f"""
import socket, struct
def csum(data):
    data += b"\\0" * (len(data) % 2)
    s = sum(struct.unpack(f"!{{len(data) // 2}}H", data))
    s = (s >> 16) + (s & 0xFFFF); s += s >> 16
    return ~s & 0xFFFF
raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
src, dst = socket.inet_aton("{ATK4}"), socket.inet_aton("{HOST4}")
packets = []
for i in range({count}):
    seg = struct.pack("!HHIIBBHHH", 20000 + i % 40000, {port}, i, 0, 5 << 4, 0x02, 1024, 0, 0)
    c = csum(src + dst + struct.pack("!BBH", 0, 6, len(seg)) + seg)
    packets.append(seg[:16] + struct.pack("!H", c) + seg[18:])
import time
start = time.monotonic()
for p in packets:
    raw.sendto(p, ("{HOST4}", 0))
print(time.monotonic() - start)
"""
    r = in_ns([sys.executable, "-c", code], check=True)
    return float(r.stdout.strip())


def test_syn_rate_limit():
    """K3.3: a SYN flood from one source is cut to the configured rate"""
    reset_guard()
    ctl("set", "enforce=1", "syn_rate=50", "syn_burst=50")
    before = stats()["rate_drops"]
    with AlertWatch() as watch:
        sent = 1000
        elapsed = syn_flood(sent)
        alerts = watch.alerts()
    dropped = stats()["rate_drops"] - before
    allowed = 50 + 50 * elapsed
    h.check(f"SYN flood limited to ~50/s (+50 burst) over {elapsed:.1f}s",
            sent - allowed * 1.2 <= dropped <= sent - allowed * 0.8,
            f"sent={sent} dropped={dropped} allowed~{allowed:.0f}")
    rate = [a for a in alerts if a["type"] == "syn_rate" and a["src_ip"] == ATK4]
    h.check("SYN rate alert says excess was dropped", rate and rate[0]["action"] == "dropped", rate)
    h.check("one alert per source per 10 s, not one per packet", len(rate) == 1, f"{len(rate)} alerts")
    reset_guard()


def test_auto_block():
    """K3.4: with auto_block, a scanner is blocked by the kernel itself"""
    reset_guard()
    ctl("set", "enforce=1", "auto_block=1", "block_timeout=30")
    h.sh(f"echo 1 > {h.TRACEFS}/events/kguard/kguard_alert/enable")
    h.sh(f"echo > {h.TRACEFS}/trace")
    with AlertWatch() as watch:
        nmap_attacker()
        alerts = watch.alerts()
    h.sh(f"echo 0 > {h.TRACEFS}/events/kguard/kguard_alert/enable")
    scans = [a for a in alerts if a["type"] == "scan" and a["src_ip"] == ATK4]
    h.check("auto-block: scan alert reports the source was blocked", scans and scans[0]["action"] == "blocked", scans)
    blocks = json.loads(ctl("--json", "blocks").stdout)
    h.check("auto-block: scanner is in the blocklist with reason 'scan'",
            any(b["address"] == ATK4 and b["reason"] == "scan" for b in blocks), blocks)
    h.check("auto-block: scanner can no longer connect", not reach())
    h.check("kguard_alert tracepoint fires", "kguard_alert" in open(f"{h.TRACEFS}/trace").read())
    ctl("unblock", ATK4)
    h.check("unblock restores access", reach())
    reset_guard()


def spoofed_udp(count, pace=0):
    """Send UDP from count different spoofed sources (10.64.0.1 upwards, avoiding the lab's 10.200/16).
    With pace, pause 20 ms after every pace packets so the receive queue never overflows."""
    code = f"""
import socket, struct, time
raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
dst = socket.inet_aton("{HOST4}")
for i in range({count}):
    if {pace} and i and i % {pace or 1} == 0:
        time.sleep(0.02)
    src = struct.pack("!I", (10 << 24) + (64 << 16) + i + 1)
    udp = struct.pack("!HHHH", 30000, 9999, 9, 0) + b"x"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, src, dst)
    while True:
        try:
            raw.sendto(ip + udp, ("{HOST4}", 0))
            break
        except OSError as e:  # ENOBUFS: the queue is full (fast, KVM-backed VMs); wait for room
            if e.errno != 105:
                raise
            time.sleep(0.001)
"""
    in_ns([sys.executable, "-c", code], check=True)


def forge(packets):
    """Send scapy packets from the attacker's interface at layer 2, so no source address is refused"""
    mac = open("/sys/class/net/kgv0/address").read().strip()
    code = ("from scapy.all import Ether, IP, TCP, UDP, sendp\n"
            f"sendp([Ether(dst='{mac}') / p for p in [{', '.join(packets)}]], iface='kgv1', verbose=0)\n")
    in_ns([sys.executable, "-c", code], check=True)


def test_spoofed_sources():
    """N5.5: packets from a real interface claiming impossible sources raise SPOOF alerts"""
    reset_guard()
    ctl("allow", "127.0.0.0/8")  # a forged allowlisted address must not slip past
    before = stats()["spoofed"]
    with AlertWatch() as watch:
        forge([f"IP(src='127.0.0.1', dst='{HOST4}') / TCP(dport=8080, flags='S')",
               f"IP(src='{HOST4}', dst='{HOST4}') / TCP(sport=8080, dport=8080, flags='S')",
               f"IP(src='224.0.0.9', dst='{HOST4}') / UDP(dport=520)",
               f"IP(src='{ATK4}', dst='{HOST4}') / TCP(dport=8080, flags='S')"])
        alerts = watch.alerts()
    ctl("disallow", "127.0.0.0/8")
    spoofs = {a["src_ip"]: a for a in alerts if a["type"] == "spoof"}
    reasons = {ip: a["spoof_reason"] for ip, a in spoofs.items()}
    h.check("loopback, own-address and multicast sources each raise a spoof alert",
            reasons == {"127.0.0.1": "loopback", HOST4: "local", "224.0.0.9": "martian"}, reasons)
    ifindex = int(open("/sys/class/net/kgv0/ifindex").read())
    h.check("spoof alert names the arrival interface",
            all(a["ifindex"] == ifindex for a in spoofs.values()), [a["ifindex"] for a in spoofs.values()])
    h.check("the real attacker address is not reported as spoofed", ATK4 not in spoofs)
    h.check("spoofed counter counts them", stats()["spoofed"] - before == 3, stats()["spoofed"] - before)
    h.check("each spoof alert counts one packet", all(a["attempts"] == 1 for a in spoofs.values()))

    # Random spoofed sources: one alert per reason every 10 s, counting the packets
    with AlertWatch() as watch:
        forge([f"IP(src='224.{i // 250}.{i % 250}.1', dst='{HOST4}') / UDP(dport=520)" for i in range(500)])
        flood = [a for a in watch.alerts() if a["type"] == "spoof"]
    h.check("500 random martian sources raise at most one alert, not one per source", len(flood) <= 1, flood)
    time.sleep(10.5)
    with AlertWatch() as watch:
        forge([f"IP(src='239.1.1.1', dst='{HOST4}') / UDP(dport=520)"])
        after = [a for a in watch.alerts() if a["type"] == "spoof"]
    counted = sum(a["attempts"] for a in flood + after)
    h.check("alerts count every spoofed packet they stand for (500 + 1)",
            len(after) == 1 and counted == 501, f"{counted} counted in {len(flood + after)} alerts")

    ctl("set", "enforce=1")
    with h.KGuardDevice() as dev, AlertWatch() as watch:
        dev.read()
        forge([f"IP(src='127.0.0.2', dst='{HOST4}') / TCP(dport=8080, flags='S')"])
        alerts = watch.alerts()
        events = dev.read()
    ctl("set", "enforce=0")
    dropped = [a for a in alerts if a["type"] == "spoof" and a["src_ip"] == "127.0.0.2"]
    h.check("enforce mode: spoofed packet is dropped before it is processed",
            dropped and dropped[0]["action"] == "dropped"
            and not [e for e in events if e["src_ip"] == "127.0.0.2"], dropped)


def slab_objects(name="kguard_src"):
    for line in open("/proc/slabinfo"):
        if line.startswith(name + " "):
            return int(line.split()[1])
    return 0


def test_source_table_cap():
    """K3.1: the per-source table never grows past max_sources, and frees idle state"""
    h.load("max_sources=1000", "idle_timeout=5")
    with Lab():
        spoofed_udp(20000)
        st = h.debugfs_stats()  # read at once: idle sources are freed after 5 s
        objects = slab_objects()
        h.check("20,000 spoofed sources: table stays at the cap",
                st["sources"] <= 1000 and st["track_full"] >= 18000,
                f"sources={st['sources']} not_tracked={st['track_full']}")
        h.check("memory follows the cap (kguard_src slab objects)", objects <= 1100, f"objects={objects}")
        time.sleep(9)
        left = h.debugfs_stats()["sources"]
        h.check("idle sources are freed", left == 0, f"sources={left}")
    h.unload()
    log = h.sh("dmesg")
    h.check("no slab objects left behind at unload", "still has objects" not in log and "kguard_src" not in log)

    sanitizer = ("KCSAN" if os.path.exists("/sys/kernel/debug/kcsan") else
                 "KASAN" if "KernelAddressSanitizer initialized" in h.sh("dmesg") else None)
    if sanitizer:
        print(f"SKIP  1,000,000-source scale test on a {sanitizer} kernel (hours under emulation)", flush=True)
        return

    # One million distinct sources with the default cap (65,536). Paced, and with a long receive
    # backlog, so every packet really reaches the guard (an emulated VM drops bursts at the veth)
    h.load()
    h.sh("sysctl -qw net.core.netdev_max_backlog=100000")
    with Lab():
        before = stats()["packets"]
        start = time.monotonic()
        spoofed_udp(1_000_000, pace=2000)
        seconds = time.monotonic() - start
        time.sleep(2)
        delivered = stats()["packets"] - before
        st = h.debugfs_stats()
        objects = slab_objects()
        size = next((int(line.split()[3]) for line in open("/proc/slabinfo")
                     if line.startswith("kguard_src ")), 0)
        h.check("1,000,000 spoofed sources reach the host (module packet counter)",
                delivered >= 990_000, f"{delivered} packets seen in {seconds:.0f} s")
        # Near the cap the GC evicts sources idle for 5 s, so a paced flood may never fill the table;
        # the hard limit itself is shown above (20,000 sources against a cap of 1,000)
        h.check("table stays under the default cap of 65,536 sources",
                st["sources"] <= 65536, f"sources={st['sources']} not_tracked={st['track_full']}")
        h.check("memory stays bounded (kguard_src slab)", objects <= 65536 * 1.05,
                f"{objects} objects x {size} bytes = {objects * size / 2**20:.1f} MiB")
    h.unload()


def run_all():
    h.load()
    with Lab():
        for test in (test_scan_alert_monitor_only, test_scan_with_colliding_ports,
                     test_block_needs_enforce, test_block_and_expiry,
                     test_ipv6_block, test_allowlist_wins, test_local_never_blocked, test_syn_rate_limit,
                     test_auto_block, test_spoofed_sources):
            try:
                test()
            except Exception as e:
                h.check(f"{test.__name__} ran without errors", False, repr(e)[:200])
    try:
        test_source_table_cap()
    except Exception as e:
        h.check("test_source_table_cap ran without errors", False, repr(e)[:200])


if __name__ == "__main__":
    run_all()
