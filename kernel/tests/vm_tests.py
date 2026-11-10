#!/usr/bin/env python3
"""
KGuard kernel module test suite (roadmap Phase 2).

Loads the module and checks each feature against real traffic. Run as root
on a disposable machine or VM whose kernel matches the build, from the
kernel/ directory:

    make && make tools && sudo python3 tests/vm_tests.py [--guard]

--guard runs only the Phase 3 guard tests (tests/guard_tests.py).

Needs: python3, curl, nc (OpenBSD netcat), ip (iproute2), nmap.
"""

import errno
import glob
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kguard_dev import KGuardDevice  # noqa: E402

KO = os.path.abspath("kguard.ko")
CTL = [sys.executable, os.path.abspath("tools/kguardctl.py")]
READER = os.path.abspath("tools/kguard_reader")
DEBUGFS = "/sys/kernel/debug/kguard"
TRACEFS = "/sys/kernel/tracing"

results = []
DMESG_START = 0  # kernel log lines before the suite started


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


def sh(cmd, check_rc=True, **kw):
    r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)
    if check_rc and r.returncode:
        raise RuntimeError(f"{cmd} failed: {r.stderr.strip()}")
    return r.stdout


def load(*params):
    unload()
    # Loadable modules on distribution kernels, built in on test kernels
    sh("modprobe -a nf_conntrack nf_socket_ipv4 nf_socket_ipv6", check_rc=False)
    if not os.path.isdir("/sys/module/nf_conntrack"):
        raise RuntimeError("nf_conntrack is neither loaded nor built in")
    sh(["insmod", KO, *params])


def unload():
    if re.search(r"^kguard ", open("/proc/modules").read(), re.M):
        sh("rmmod kguard")


def debugfs_stats():
    out = {}
    for line in open(f"{DEBUGFS}/stats"):
        key, value = line.split()
        out[key] = int(value)
    return out


def udp_sink(family=socket.AF_INET, addr="127.0.0.1"):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.bind((addr, 0))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
    return s, s.getsockname()[1]


def send_udp(port, count, rate=0, family=socket.AF_INET, addr="127.0.0.1"):
    tx = socket.socket(family, socket.SOCK_DGRAM)
    start = time.monotonic()
    for i in range(count):
        tx.sendto(b"k", (addr, port))
        if rate:
            ahead = (i + 1) / rate - (time.monotonic() - start)
            if ahead > 0.001:
                time.sleep(ahead)
    tx.close()
    return time.monotonic() - start


def collect(dev, seconds):
    """Read events from the device for a while, counting poll wakeups"""
    events, wakeups = [], 0
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if dev.wait(200):
            wakeups += 1
            events.extend(dev.read())
    events.extend(dev.read())
    return events, wakeups


def test_load():
    load()
    st = os.stat("/dev/kguard")
    check("module loads and creates /dev/kguard", (st.st_mode & 0o170000) == 0o020000)
    proc_mode = os.stat("/proc/kguard").st_mode & 0o777
    check("/proc/kguard is root-only by default", proc_mode == 0o400, oct(proc_mode))
    check("init network namespace is hooked", debugfs_stats()["netns_hooked"] == 1)


def test_mmap_python_reader():
    """K2.4 / K2.5: the Python mmap reader decodes every event"""
    sink, port = udp_sink()
    total, rate = 3000, 1000
    with KGuardDevice() as dev:
        dev.read()
        before = dev.dropped()
        out = {}

        def reader():
            out["events"], _ = collect(dev, total / rate + 1.5)

        t = threading.Thread(target=reader)
        t.start()
        send_udp(port, total, rate)
        t.join()
        dropped = dev.dropped() - before

    ev = [e for e in out["events"] if e["protocol"] == "UDP" and e["dst_port"] == port]
    ins = sum(1 for e in ev if e["direction"] == "in")
    outs = sum(1 for e in ev if e["direction"] == "out")
    check("Python mmap reader gets every packet in and out", ins == total and outs == total,
          f"in={ins} out={outs} of {total}")
    check("Python mmap reader: nothing dropped", dropped == 0, f"dropped={dropped}")
    sink.close()


def test_exclusive_reader():
    with KGuardDevice():
        try:
            KGuardDevice()
            second = "opened"
        except OSError as e:
            second = errno.errorcode.get(e.errno, str(e.errno))
        try:
            open("/proc/kguard").read()
            proc = "opened"
        except OSError as e:
            proc = errno.errorcode.get(e.errno, str(e.errno))
    check("second /dev/kguard reader is refused", second == "EBUSY", second)
    check("/proc/kguard is refused while /dev/kguard is open", proc == "EBUSY", proc)
    check("/proc/kguard works again after the device is closed", "events" in open("/proc/kguard").read())


def run_c_reader(seconds, traffic=None):
    """Run the C mmap reader in its own process; return its summary and CPU time"""
    reader = subprocess.Popen([READER, "-q", "-t", str(seconds)], stdout=subprocess.PIPE, text=True)
    time.sleep(0.5)
    sent = traffic() if traffic else 0
    _, status, usage = os.wait4(reader.pid, 0)
    summary = reader.stdout.read().strip().splitlines()[-1]
    stats = {k: float(v) for k, v in (kv.split("=") for kv in summary.split())}
    return sent, stats, usage.ru_utime + usage.ru_stime, summary


def test_c_reader_throughput():
    """K2.3 / K2.4: zero-copy C reader keeps up with 5,000 packets/s, nothing lost"""
    load()
    sink, port = udp_sink()
    total, rate = 20000, 5000

    def traffic():
        # Send from a separate process so the sender is not slowed by this one
        sh([sys.executable, "-c",
            f"import socket,time\n"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); t=time.monotonic()\n"
            f"for i in range({total}):\n"
            f"    s.sendto(b'k',('127.0.0.1',{port}))\n"
            f"    a=(i+1)/{rate}-(time.monotonic()-t)\n"
            f"    a>0.001 and time.sleep(a)\n"
            f"print(time.monotonic()-t)"])
        return total

    sent, stats, _, summary = run_c_reader(total / rate + 3, traffic)
    check(f"C mmap reader gets every packet at {rate}/s (in + out)", stats["events"] >= 2 * sent, summary)
    check("C mmap reader: nothing dropped", stats["dropped"] == 0, summary)
    sink.close()


def test_no_busy_polling():
    """K2.4: an idle reader sleeps in poll() and uses almost no CPU"""
    _, stats, cpu, summary = run_c_reader(3)
    check("idle reader sleeps (few wakeups, near-zero CPU)", stats["wakeups"] <= 5 and cpu < 0.1,
          f"{summary} cpu={cpu:.3f}s")


def owner_of_inode(ino):
    """Find the process holding socket inode ino, as ss -p does"""
    target = f"socket:[{ino}]"
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            for fd in os.listdir(f"/proc/{pid}/fd"):
                if os.readlink(f"/proc/{pid}/fd/{fd}") == target:
                    return int(pid), open(f"/proc/{pid}/comm").read().strip()
        except OSError:
            continue
    return None, None


def test_process_attribution():
    """K2.7: curl shows as curl; an nc listener is found from its socket"""
    nc = subprocess.Popen(["nc", "-l", "127.0.0.1", "4444"], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    # nc closes its listening socket once it accepts, so note the inode now
    listener_inodes = {
        int(m.group(1))
        for fd in os.listdir(f"/proc/{nc.pid}/fd")
        if (m := re.match(r"socket:\[(\d+)\]", os.readlink(f"/proc/{nc.pid}/fd/{fd}")))
    }
    pid, comm = owner_of_inode(next(iter(listener_inodes))) if listener_inodes else (None, None)
    with KGuardDevice() as dev:
        dev.read()
        curl = subprocess.Popen(["curl", "-s", "--max-time", "1", "http://127.0.0.1:4444/"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        curl.wait()
        events, _ = collect(dev, 0.5)

    syn_out = [e for e in events if e["direction"] == "out" and e["dst_port"] == 4444 and e["flags"] == 0x02]
    syn_in = [e for e in events if e["direction"] == "in" and e["dst_port"] == 4444 and e["flags"] == 0x02]
    check("outgoing SYN attributed to curl",
          syn_out and syn_out[0]["comm"] == "curl" and syn_out[0]["pid"] == curl.pid,
          f"{syn_out[0]['comm']}/{syn_out[0]['pid']} vs curl/{curl.pid}" if syn_out else "no SYN")

    ino = syn_in[0]["sock_ino"] if syn_in else 0
    nc.kill()
    check("incoming SYN carries the nc listener's socket inode", ino in listener_inodes,
          f"event ino={ino}, nc sockets={listener_inodes}")
    check("that inode resolves to the nc process (as ss -p does)", pid == nc.pid and comm == "nc",
          f"{comm}/{pid}")
    check("conntrack: first SYN is NEW", syn_out and syn_out[0]["ct_state"] == "new")
    established = [e for e in events if e["dst_port"] == 4444 and e["ct_state"] == "established"]
    check("conntrack: later packets are ESTABLISHED", len(established) > 0)


def test_packet_headers():
    """Event v2: TTL, length, DF, and the SYN's window and option order (OS fingerprinting)"""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 4446))
    srv.listen()
    with KGuardDevice() as dev:
        dev.read()
        socket.create_connection(("127.0.0.1", 4446), timeout=2).close()
        events, _ = collect(dev, 0.5)
    srv.close()
    syn = [e for e in events if e["dst_port"] == 4446 and e["flags"] == 0x02 and e["direction"] == "out"]
    e = syn[0] if syn else {}
    check("SYN carries TTL 64, DF and its length (20 + 20 + 20 options)",
          (e.get("ttl"), e.get("df"), e.get("ip_len")) == (64, True, 60),
          (e.get("ttl"), e.get("df"), e.get("ip_len")))
    check("SYN carries Linux's TCP option order, MSS and window scale",
          e.get("tcp_options") == "M,S,T,N,W" and e.get("tcp_mss") == 65495 and e.get("tcp_wscale", -1) >= 0,
          f"options={e.get('tcp_options')} mss={e.get('tcp_mss')} wscale={e.get('tcp_wscale')}")
    acks = [e for e in events if e["dst_port"] == 4446 and e["flags"] == 0x10]
    check("non-SYN packets carry no options",
          acks and all(a["tcp_options"] == "" and a["tcp_wscale"] == -1 for a in acks))

    sink, port = udp_sink()
    send_udp(port, 1)  # one byte of payload
    proc = json.loads(open("/proc/kguard").read())
    sink.close()
    udp = [e for e in proc["events"] if e["dst_port"] == port]
    check("/proc/kguard shows the v2 header fields",
          udp and udp[0]["ttl"] == 64 and udp[0]["ip_len"] == 29 and udp[0]["tcp_options"] == "",
          udp[0] if udp else "no event")


def tcp_checksum(src, dst, segment):
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(segment))
    data = pseudo + segment + (b"\0" if len(segment) % 2 else b"")
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def test_invalid_packets():
    """K2.8: a SYN+FIN packet is invalid to conntrack"""
    raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    seg = struct.pack("!HHIIBBHHH", 40001, 4445, 1, 0, 5 << 4, 0x03, 1024, 0, 0)
    seg = seg[:16] + struct.pack("!H", tcp_checksum("127.0.0.1", "127.0.0.1", seg)) + seg[18:]
    with KGuardDevice() as dev:
        dev.read()
        raw.sendto(seg, ("127.0.0.1", 0))
        events, _ = collect(dev, 0.5)
    bad = [e for e in events if e["dst_port"] == 4445]
    check("SYN+FIN packet reported as conntrack INVALID",
          bad and all(e["ct_state"] == "invalid" for e in bad), [e["ct_state"] for e in bad])


RAW_SENDER = """
import socket, sys
from scapy.all import IP, IPv6, IPOption, UDP, TCP, Raw, IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, fragment, fragment6
from scapy.all import IPv6ExtHdrFragment
v4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
v6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
def send4(p): v4.sendto(bytes(p), ("127.0.0.1", 0))
def send6(p): v6.sendto(bytes(p), ("::1", 0))
# IPv4 with 8 bytes of options (ihl 7): ports must come from after the options
send4(IP(dst="127.0.0.1", options=[IPOption(b"\\x01" * 8)]) / UDP(sport=41001, dport=5101) / b"opts")
# A 3000-byte datagram in 1000-byte fragments
for f in fragment(IP(dst="127.0.0.1", id=4242) / UDP(sport=41002, dport=5102) / (b"x" * 3000), fragsize=1000):
    send4(f)
# IPv6 with hop-by-hop and destination-options headers before UDP
send6(IPv6(dst="::1") / IPv6ExtHdrHopByHop() / IPv6ExtHdrDestOpt() / UDP(sport=41003, dport=5103) / b"ext")
# IPv6 fragments
for f in fragment6(IPv6(dst="::1") / IPv6ExtHdrFragment(id=77) / UDP(sport=41004, dport=5104) / (b"y" * 3000), 1200):
    send6(f)
# Says TCP, but the header is cut short: must not be read past the packet
send4(IP(dst="127.0.0.1", proto=6) / Raw(b"\\x9f\\x0f"))
"""


def test_tricky_packets():
    """K2.1: IP options, fragments, IPv6 extension headers and truncated headers are parsed safely"""
    with KGuardDevice() as dev:
        dev.read()
        r = subprocess.run([sys.executable, "-W", "ignore", "-c", RAW_SENDER], capture_output=True, text=True)
        events, _ = collect(dev, 1.0)
    if r.returncode:
        check("raw test packets sent (scapy)", False, r.stderr.strip()[-200:])
        return

    def find(**want):
        return [e for e in events if all(e.get(k) == v for k, v in want.items())]

    opts = find(dst_port=5101, direction="out")
    check("IPv4 with options: ports read after the options",
          opts and opts[0]["src_port"] == 41001 and opts[0]["ip_len"] == 20 + 8 + 8 + 4, opts[:1])

    # Whether the capture hooks see a datagram reassembled or as fragments depends on the kernel path:
    # conntrack's defragmenter (before the hooks) reassembles IPv4, but skips IPv6 packets that already
    # carry a conntrack entry, as loopback ones do. Either way the parse must be right: one datagram
    # with its ports and full length, or fragments where only the first has the ports.
    def datagram(family, port, sport, payload_len, direction):
        frags = [e for e in events if e["family"] == family and e["direction"] == direction
                 and (e["dst_port"] == port or (e["fragment"] and e["src_port"] == e["dst_port"] == 0))]
        whole = [e for e in frags if not e["fragment"] and e["ip_len"] == payload_len]
        if len(frags) == 1 and whole:
            return whole[0]["src_port"] == sport, "reassembled"
        first = [e for e in frags if not e["fragment"]]
        return (len(first) == 1 and first[0]["src_port"] == sport and len(frags) >= 3,
                f"{len(frags)} fragments, first with ports {first[0]['src_port'] if first else None}")

    for label, family, port, sport, length in (("IPv4", 4, 5102, 41002, 20 + 8 + 3000),
                                               ("IPv6", 6, 5104, 41004, 40 + 8 + 3000)):
        for direction in ("out", "in"):
            ok, how = datagram(family, port, sport, length, direction)
            check(f"{label} fragmented datagram ({direction}): parsed correctly", ok, how)

    ext = find(dst_port=5103, direction="out")
    check("IPv6 extension headers (hop-by-hop, destination options) are skipped to reach UDP",
          ext and ext[0]["src_port"] == 41003 and ext[0]["protocol"] == "UDP", ext[:1])
    short = [e for e in events if e["protocol"] == "TCP" and e["family"] == 4 and e["ip_len"] == 22]
    check("a truncated TCP header is not read past the packet (no ports, no crash)",
          short and all(e["src_port"] == e["dst_port"] == 0 for e in short), short[:1])


def test_perf():
    """K2.11: perf record -e 'kguard:*' sees the module's tracepoints"""
    perf = shutil.which("perf")
    # Ubuntu's /usr/bin/perf is a wrapper that only runs the perf built for the
    # running kernel version; any perf binary works for tracepoints, so fall back
    # to one of the installed builds when booting another kernel (kernel matrix)
    if perf and subprocess.run([perf, "--version"], capture_output=True).returncode != 0:
        builds = sorted(glob.glob("/usr/lib/linux-tools*/*/perf") + glob.glob("/usr/lib/linux-tools/*/perf"))
        perf = builds[-1] if builds else perf
    if not perf:
        check("perf available", False, "perf not installed")
        return
    sink, port = udp_sink()
    # The traffic is the command perf runs, so it is recorded from the first packet
    sender = f"import socket; s = socket.socket(2, 2); [s.sendto(b'k', ('127.0.0.1', {port})) for _ in range(200)]"
    rec = subprocess.run([perf, "record", "-q", "-o", "/tmp/kguard-perf.data", "-e", "kguard:*", "-a", "--",
                          sys.executable, "-c", sender], capture_output=True, text=True, timeout=120)
    sink.close()
    out = subprocess.run([perf, "script", "-i", "/tmp/kguard-perf.data"], capture_output=True, text=True)
    hits = [line for line in out.stdout.splitlines() if "kguard:kguard_event" in line and f":{port}" in line]
    check("perf record -e 'kguard:*' captures kguard_event tracepoints (200 sent, seen out and in)",
          len(hits) >= 400, f"{len(hits)} events; " + (hits[0].strip()[-90:] if hits
                                                         else (rec.stderr + out.stderr).strip()[-150:]))


def test_ipv6():
    """K2.2: IPv6 with ports, in both directions"""
    sink, port = udp_sink(socket.AF_INET6, "::1")
    with KGuardDevice() as dev:
        dev.read()
        send_udp(port, 10, family=socket.AF_INET6, addr="::1")
        events, _ = collect(dev, 0.5)
    v6 = [e for e in events if e["family"] == 6 and e["dst_port"] == port]
    dirs = sorted({e["direction"] for e in v6})
    check("IPv6 packets captured with ports", len(v6) == 20 and v6[0]["dst_ip"] == "::1", f"{len(v6)} events")
    check("IPv6 captured in both directions", dirs == ["in", "out"], dirs)
    sink.close()


def test_network_namespaces():
    """K2.9: a new namespace (like a container) is hooked and labelled"""
    host_ns = os.stat("/proc/self/ns/net").st_ino
    sh("ip netns add kgtest")
    try:
        sh("ip netns exec kgtest ip link set lo up")
        check("new namespace is hooked automatically", debugfs_stats()["netns_hooked"] == 2)
        with KGuardDevice() as dev:
            dev.read()
            sh(["ip", "netns", "exec", "kgtest", sys.executable, "-c",
                "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
                "[s.sendto(b'x', ('127.0.0.1', 7777)) for _ in range(3)]"])
            events, _ = collect(dev, 0.5)
        ns_events = [e for e in events if e["dst_port"] == 7777]
        netns = {e["netns"] for e in ns_events}
        check("namespace traffic tagged with its own netns id",
              ns_events and host_ns not in netns, f"netns={netns} host={host_ns}")
    finally:
        sh("ip netns del kgtest")
    time.sleep(1)
    check("namespace unhooked when deleted", debugfs_stats()["netns_hooked"] == 1)


def test_netlink_control():
    """K2.6: change configuration live and see the notification"""
    watch = subprocess.Popen(CTL + ["--json", "watch"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    time.sleep(0.5)
    sink, port = udp_sink()
    try:
        sh(CTL + ["set", "capture_out=0"])
        with KGuardDevice() as dev:
            dev.read()
            send_udp(port, 50)
            events, _ = collect(dev, 0.5)
        dirs = {e["direction"] for e in events if e["dst_port"] == port}
        check("capture_out=0 stops outgoing events at once", dirs == {"in"}, dirs)
    finally:
        sh(CTL + ["set", "capture_out=1"])
        sink.close()
    time.sleep(0.5)
    watch.terminate()
    notes = watch.communicate(timeout=10)[0]
    both = '"capture_out": 0' in notes and '"capture_out": 1' in notes
    check("configuration changes are multicast to watchers", both, notes.strip().replace("\n", " | ")[:120])

    send_udp(udp_sink()[1], 500)
    stats = dict(line.split() for line in sh(CTL + ["stats"]).splitlines())
    check("netlink stats report packets and hook cost",
          int(stats["packets"]) > 0 and int(stats["ns_per_packet"]) > 0,
          f"packets={stats['packets']} ns_per_packet={stats['ns_per_packet']}")

    as_nobody = subprocess.run(CTL + ["set", "capture_in=0"], capture_output=True, text=True,
                               user=65534, group=65534, extra_groups=[])
    check("non-root users cannot change configuration", as_nobody.returncode != 0 and "permission" in as_nobody.stderr,
          as_nobody.stderr.strip()[:80])


def test_tracepoints():
    """K2.11: the module's tracepoints fire"""
    if not os.path.exists(f"{TRACEFS}/events"):
        sh(f"mount -t tracefs nodev {TRACEFS}")
    with open(f"{TRACEFS}/trace", "w") as f:
        f.write("")
    with open(f"{TRACEFS}/events/kguard/kguard_event/enable", "w") as f:
        f.write("1")
    sink, port = udp_sink()
    send_udp(port, 5)
    with open(f"{TRACEFS}/events/kguard/kguard_event/enable", "w") as f:
        f.write("0")
    trace = open(f"{TRACEFS}/trace").read()
    hits = [line for line in trace.splitlines() if "kguard_event" in line and f":{port}" in line]
    check("kguard_event tracepoint fires for captured packets", len(hits) >= 10, hits[0].strip()[-90:] if hits else "")
    sink.close()


def test_ring_full():
    """Full rings drop new events and count them (debugfs, header, tracepoint)"""
    load("buffer_size=64")
    with open(f"{TRACEFS}/trace", "w") as f:
        f.write("")
    with open(f"{TRACEFS}/events/kguard/kguard_ring_full/enable", "w") as f:
        f.write("1")
    sink, port = udp_sink()
    send_udp(port, 2000)
    with open(f"{TRACEFS}/events/kguard/kguard_ring_full/enable", "w") as f:
        f.write("0")
    dropped = debugfs_stats()["dropped"]
    traced = "kguard_ring_full" in open(f"{TRACEFS}/trace").read()
    proc = open("/proc/kguard").read()
    reported = int(re.search(r'"dropped": (\d+)', proc).group(1))
    check("full rings drop and count new events", dropped > 0 and reported == dropped,
          f"debugfs={dropped} proc={reported}")
    check("kguard_ring_full tracepoint fires", traced)
    sink.close()


def test_reader_group():
    """Only root and the reader_gid group may read events"""
    load("reader_gid=1500")
    st = os.stat("/proc/kguard")
    check("reader_gid makes /proc/kguard 0440 for that group", (st.st_mode & 0o777) == 0o440 and st.st_gid == 1500)
    probe = [sys.executable, "-c", "import os; os.close(os.open('/dev/kguard', os.O_RDWR))"]
    member = subprocess.run(probe, user=65534, group=65534, extra_groups=[1500], capture_output=True, text=True)
    stranger = subprocess.run(probe, user=65534, group=65534, extra_groups=[], capture_output=True, text=True)
    check("reader group member can open /dev/kguard", member.returncode == 0, member.stderr.strip()[-60:])
    check("other users are refused", stranger.returncode != 0 and "Operation not permitted" in stranger.stderr)


def test_clean_unload():
    unload()
    # Only what the kernel logged during the suite: boot messages (e.g. a CPU
    # vulnerability "WARNING" on some hosts) are not the module's doing
    log = "\n".join(sh("dmesg").splitlines()[DMESG_START:])
    pattern = re.compile(r"WARNING|BUG|Oops|general protection|lockdep|refcount")
    bad = [line for line in log.splitlines() if pattern.search(line)]
    check("module unloads with no kernel warnings", not bad, bad[0] if bad else "")


def main():
    global DMESG_START
    if os.geteuid():
        raise SystemExit("run as root")
    DMESG_START = len(sh("dmesg").splitlines())
    if not os.path.exists("/sys/kernel/debug/kguard") and not os.path.ismount("/sys/kernel/debug"):
        sh("mount -t debugfs none /sys/kernel/debug", check_rc=False)
    if not os.path.exists(f"{TRACEFS}/events"):
        sh(f"mount -t tracefs nodev {TRACEFS}", check_rc=False)
    tests = [test_load, test_mmap_python_reader, test_exclusive_reader, test_c_reader_throughput,
             test_no_busy_polling, test_process_attribution, test_packet_headers, test_tricky_packets,
             test_invalid_packets, test_ipv6, test_network_namespaces, test_netlink_control, test_tracepoints,
             test_perf, test_ring_full, test_reader_group, test_clean_unload]
    guard_only = "--guard" in sys.argv
    try:
        for test in tests[:-1] if not guard_only else []:
            try:
                test()
            except Exception as e:  # report and keep going
                check(f"{test.__name__} ran without errors", False, repr(e)[:200])

        # Phase 3: in-kernel detection and enforcement
        import guard_tests
        guard_tests.h = sys.modules[__name__]
        guard_tests.run_all()
        test_clean_unload()
    finally:
        unload()
    failed = [name for name, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
