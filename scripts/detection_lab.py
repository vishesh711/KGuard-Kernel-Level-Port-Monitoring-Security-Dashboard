#!/usr/bin/env python3
"""
KGuard detection lab (roadmap Phase 5): real attack tools against a real
kernel, checked through the backend's API.

An "attacker" network namespace is joined to the host by a veth pair:

    host  kgv0 10.200.0.1  <-->  kgv1 10.200.0.2  (netns kgatk)

The KGuard module is loaded and the backend reads /dev/kguard and the
module's alerts, as in production. Then, from the attacker:

  - ordinary web browsing to port 443          -> no alerts (N5.0)
  - nmap -sS -sF -sN -sX -sA -sM -sU           -> one alert per scan type,
                                                  correctly labelled (N5.1)
  - hydra against a real sshd on port 22       -> BRUTE_FORCE (N5.3)
  - hping3 -S --flood --rand-source            -> SYN_FLOOD (N5.2)
  - SYNs from Linux (curl), and Windows and macOS
    SYN signatures replayed with scapy         -> each OS named (N5.4)
  - scapy-forged loopback, bogon and TTL-shifted
    sources                                    -> SPOOFED_TRAFFIC (N5.5)
  - replayed DNS ANY and NTP monlist replies,
    and this host's UDP service amplifying     -> AMPLIFICATION (N5.6)

Run as root in a disposable VM, from the repository root:

    make -C kernel && sudo python3 scripts/detection_lab.py /path/to/backend/python

Needs: nmap, hping3, hydra, sshd (openssh-server), curl, ip (iproute2), scapy
(for the system python3).
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND_PY = sys.argv[1] if len(sys.argv) > 1 else "python3"
HOST, ATTACKER, NS = "10.200.0.1", "10.200.0.2", "kgatk"
# A second, well-behaved host in the attacker's network (its address gets spoofed)
NEIGHBOUR = "10.200.0.3"
PORT = 8790
API = f"http://127.0.0.1:{PORT}"

results = []
BACKEND_LOG = None


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


def sh(cmd, check_rc=True, **kw):
    r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)
    if check_rc and r.returncode:
        raise RuntimeError(f"{cmd} failed: {r.stderr.strip()}")
    return r.stdout


def in_ns(cmd, **kw):
    return subprocess.run(["ip", "netns", "exec", NS] + cmd, capture_output=True, text=True, **kw)


def api(path):
    with urllib.request.urlopen(API + path, timeout=10) as r:
        return json.loads(r.read())


def alerts():
    return api("/api/alerts/?size=100")["items"]


def wait_for(predicate, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        found = predicate()
        if found:
            return found
        time.sleep(1)
    return None


def listener(port):
    """Accept and close connections, like a login service rejecting a password"""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, port))
    s.listen(128)

    def serve():
        while True:
            try:
                conn, _ = s.accept()
                conn.close()
            except OSError:
                return

    threading.Thread(target=serve, daemon=True).start()
    return s


def setup():
    sh("modprobe -a nf_conntrack nf_socket_ipv4 nf_socket_ipv6")
    if "kguard " not in open("/proc/modules").read():
        sh(["insmod", os.path.join(ROOT, "kernel", "kguard.ko")])
    sh(f"ip netns add {NS}")
    sh("ip link add kgv0 type veth peer name kgv1")
    sh(f"ip link set kgv1 netns {NS}")
    sh(f"ip addr add {HOST}/24 dev kgv0")
    sh("ip link set kgv0 up")
    sh(f"ip netns exec {NS} ip addr add {ATTACKER}/24 dev kgv1")
    sh(f"ip netns exec {NS} ip addr add {NEIGHBOUR}/24 dev kgv1")
    # Let forged sources reach the hooks after routing (reverse-path filtering would drop them)
    for conf in ("all", "default", "kgv0"):
        sh(f"sysctl -qw net.ipv4.conf.{conf}.rp_filter=0")
    sh(f"ip netns exec {NS} ip link set kgv1 up")
    sh(f"ip netns exec {NS} ip link set lo up")


def teardown(procs):
    for p in procs:
        p.kill()
    sh(f"ip netns del {NS}", check_rc=False)
    sh("ip link del kgv0", check_rc=False)
    sh("rmmod kguard", check_rc=False)


def start_backend():
    work = tempfile.mkdtemp(prefix="kguard-lab-")
    env = dict(os.environ, DATABASE_URL=f"sqlite:///{work}/kguard.db", DEBUG="true",
               DATA_COLLECTION_INTERVAL="0.5")
    global BACKEND_LOG
    BACKEND_LOG = f"{work}/backend.log"
    proc = subprocess.Popen([BACKEND_PY, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
                             "--port", str(PORT)],
                            cwd=os.path.join(ROOT, "backend"), env=env,
                            stdout=open(f"{work}/backend.log", "w"), stderr=subprocess.STDOUT)
    ok = wait_for(lambda: api("/api/health/kernel")["details"]["kernel_detection"]
                  if _reachable() else None, timeout=60)
    if not ok:
        raise RuntimeError("backend did not start or did not subscribe to kernel alerts")
    return proc


def _reachable():
    try:
        api("/api/health/")
        return True
    except OSError:
        return False


def test_web_traffic_is_quiet():
    for _ in range(30):
        in_ns(["curl", "-s", "-o", "/dev/null", "--max-time", "2", f"http://{HOST}:443/"])
    time.sleep(4)
    found = alerts()
    check("30 web requests to port 443 raise no alerts", not found, [a["title"] for a in found])


SCANS = [("sS", "syn", "SYN"), ("sF", "fin", "FIN"), ("sN", "null", "NULL"), ("sX", "xmas", "Xmas"),
         ("sA", "ack", "ACK"), ("sM", "maimon", "Maimon"), ("sU", "udp", "UDP")]


def test_scan_types():
    for flag, kind, label in SCANS:
        in_ns(["nmap", f"-{flag}", "-Pn", "-n", "-p", "1-100", "--max-retries", "0", "--min-rate", "500", HOST])

        def labelled():
            return [a for a in alerts() if a["alert_type"] == "PORT_SCAN"
                    and (a.get("metadata") or {}).get("scan_type") == kind]

        found = wait_for(labelled, timeout=30)
        source = (found[0]["metadata"] or {}).get("source", "backend") if found else None
        check(f"nmap -{flag} raises a '{label} Scan' alert", found and found[0]["title"].startswith(f"{label} Scan"),
              f"{found[0]['title']} (detected by {source})" if found
              else f"no alert; alerts so far: {[a['title'] for a in alerts()]}")
        if flag == "sS":
            meta = (found[0].get("metadata") or {}) if found else {}
            check("the SYN scan alert names nmap from its TCP fingerprint",
                  meta.get("sender_fingerprint") == "nmap", meta.get("fingerprints"))
        time.sleep(16)  # let the next scan start a fresh detection window


def start_sshd():
    """A real OpenSSH server on HOST:22 with a throwaway host key; no account can log in"""
    work = tempfile.mkdtemp(prefix="kguard-sshd-")
    sh(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"{work}/host_key"])
    os.makedirs("/run/sshd", exist_ok=True)
    proc = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", "/dev/null", "-o", f"HostKey={work}/host_key",
                             "-o", f"ListenAddress={HOST}", "-o", "Port=22", "-o", f"PidFile={work}/pid",
                             "-o", "UsePAM=no", "-o", "PasswordAuthentication=yes", "-o", "MaxStartups=100"],
                            stdout=subprocess.DEVNULL, stderr=open(f"{work}/sshd.log", "w"))
    # Wait for its log line, not a test connection: KGuard would rightly report that one
    if not wait_for(lambda: "Server listening" in open(f"{work}/sshd.log").read(), timeout=15):
        raise RuntimeError("sshd did not start: " + open(f"{work}/sshd.log").read()[-300:])
    return proc


def test_brute_force():
    words = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    words.write("\n".join(f"guess{i}" for i in range(60)))
    words.close()
    started = time.time()
    r = in_ns(["hydra", "-l", "nosuchuser", "-P", words.name, "-t", "4", "-I", "-f", f"ssh://{HOST}"],
              timeout=300)
    took = time.time() - started
    summary = [line for line in (r.stdout + r.stderr).splitlines()
               if any(k in line for k in ("login tries", "[ERROR]", "valid password", "finished"))]
    found = wait_for(lambda: [a for a in alerts() if a["alert_type"] == "BRUTE_FORCE"])
    syns, page = [], 1
    while True:  # every connection attempt to port 22 KGuard stored, across pages
        reply = api(f"/api/events/?src_ip={ATTACKER}&dst_port=22&size=100&page={page}")
        syns += [e for e in reply["items"] if e["flags"] == 2 and e.get("direction") == "in"]
        if page >= reply.get("pages", 1):
            break
        page += 1
    meta = (found[0].get("metadata") or {}) if found else {}
    check("hydra against sshd raises BRUTE_FORCE on port 22", found and found[0]["dst_port"] == 22,
          f"{found[0]['title']}: {meta.get('connections')} connections" if found
          else f"no alert; hydra took {took:.0f} s and KGuard saw {len(syns)} connection attempts to "
               f"port 22; hydra: {summary[-2:]}")


def test_syn_flood():
    in_ns(["timeout", "4", "hping3", "-S", "--flood", "--rand-source", "-p", "8080", HOST])
    start = time.time()
    try:
        api("/api/health/")
        print(f"      (API answered {time.time() - start:.1f} s after the flood)", flush=True)
    except OSError as e:
        print(f"      (API did not answer within 10 s after the flood: {e})", flush=True)
    found = wait_for(lambda: [a for a in alerts() if a["alert_type"] == "SYN_FLOOD"], timeout=60)
    meta = (found[0].get("metadata") or {}) if found else {}
    check("hping3 SYN flood from random sources raises SYN_FLOOD", found,
          f"{found[0]['title']}: {meta.get('half_open')} half-open from {meta.get('distinct_sources')} "
          f"sources, syn_cookies={meta.get('syn_cookies')}" if found else "no alert")


def forge(packets, count=1):
    """Send scapy packets (Python expressions) from the attacker's interface, at layer 2"""
    mac = open("/sys/class/net/kgv0/address").read().strip()
    code = ("from scapy.all import *\n"
            f"pkts = [Ether(dst='{mac}') / p for i in range({count}) for p in [{', '.join(packets)}]]\n"
            "sendp(pkts, iface='kgv1', verbose=0)\n")
    r = in_ns([sys.executable, "-c", code])
    if r.returncode:
        raise RuntimeError(r.stderr.strip()[-300:])


def events_from(ip):
    return api(f"/api/events/?src_ip={ip}&size=100")["items"]


LINUX_OPTS = "[('MSS', 1460), ('SAckOK', b''), ('Timestamp', (1, 0)), ('NOP', None), ('WScale', 7)]"
SIGNATURES = {
    "Windows": ("10.200.0.11", "IP(src='10.200.0.11', dst='{h}', ttl=128, flags='DF') / TCP(sport=50001, dport=443, "
                "flags='S', window=64240, options=[('MSS', 1460), ('NOP', None), ('WScale', 8), ('NOP', None), "
                "('NOP', None), ('SAckOK', b'')])"),
    "macOS": ("10.200.0.12", "IP(src='10.200.0.12', dst='{h}', ttl=64, flags='DF') / TCP(sport=50002, dport=443, "
              "flags='S', window=65535, options=[('MSS', 1460), ('NOP', None), ('WScale', 6), ('NOP', None), "
              "('NOP', None), ('Timestamp', (123456, 0)), ('SAckOK', b''), ('EOL', None)])"),
}


def test_os_fingerprints():
    in_ns(["curl", "-s", "-o", "/dev/null", "--max-time", "2", "--interface", NEIGHBOUR, f"http://{HOST}:443/"])
    for _ip, packet in SIGNATURES.values():
        forge([packet.format(h=HOST)])
    for name, ip in (("Linux", NEIGHBOUR), ("Windows", SIGNATURES["Windows"][0]), ("macOS", SIGNATURES["macOS"][0])):
        found = wait_for(lambda: [e for e in events_from(ip) if e["flags"] == 2 and e.get("os_guess")], timeout=60)
        e = found[0] if found else {}
        check(f"{name} SYN recognised as {name}", e.get("os_guess") == name,
              f"{e.get('os_guess')}: ttl={e.get('ttl')} win={e.get('tcp_window')} opts={e.get('tcp_options')}")


def spoof_alerts(**meta):
    def match():
        return [a for a in alerts() if a["alert_type"] == "SPOOFED_TRAFFIC"
                and all((a.get("metadata") or {}).get(k) == v for k, v in meta.items())]
    return wait_for(match, timeout=20)


def test_spoofing():
    forge([f"IP(src='127.0.0.1', dst='{HOST}') / TCP(dport=443, flags='S')"])
    found = spoof_alerts(source="kernel", spoof_reason="loopback")
    check("forged 127.0.0.1 source raises the kernel's spoof alert", found, found[0]["title"] if found else "none")

    forge([f"IP(src='198.18.0.7', dst='{HOST}') / TCP(dport=443, flags='S')"])
    found = spoof_alerts(bogon_category="benchmarking")
    check("forged bogon source (198.18.0.7) raises SPOOFED_TRAFFIC", found, found[0]["title"] if found else "none")

    # The neighbour talks normally (0 hops), then someone 19 hops away forges its address
    for _ in range(5):
        in_ns(["curl", "-s", "-o", "/dev/null", "--max-time", "2", "--interface", NEIGHBOUR, f"http://{HOST}:443/"])
    forge([f"IP(src='{NEIGHBOUR}', dst='{HOST}', ttl=45) / TCP(sport=40000 + i, dport=443, flags='S', "
           f"window=64240, options={LINUX_OPTS})"], count=5)
    found = spoof_alerts(spoof_reason="ttl_jump")
    meta = (found[0].get("metadata") or {}) if found else {}
    check(f"TTL-shifted packets claiming {NEIGHBOUR} raise SPOOFED_TRAFFIC",
          found and found[0]["src_ip"] == NEIGHBOUR and meta.get("odd_hops") == [19],
          f"usual {meta.get('usual_hops')} hops, odd {meta.get('odd_hops')}" if found else "none")


# Replies as reflectors send them: a DNS ANY answer and NTP monlist (mode 7) pages
DNS_ANY = ("IP(src=['8.8.8.8', '1.1.1.1'][i % 2], dst='{h}') / UDP(sport=53, dport=40000 + i) / "
           "DNS(id=i, qr=1, qd=DNSQR(qname='example.com', qtype='ANY'), "
           "an=" + " / ".join(["DNSRR(rrname='example.com', type='TXT', rdata='v=spf1 ' + 'x' * 240)"] * 5) + ")")
NTP_MONLIST = ("IP(src='129.6.15.%d' % (28 + i % 3), dst='{h}') / UDP(sport=123, dport=41000 + i) / "
               "Raw(b'\\x97\\x00\\x03\\x2a\\x00\\x06\\x00\\x48' + bytes(432))")
# memcached over UDP: 8-byte frame header, then a "get" answer with a large stored value
MEMCACHED = ("IP(src='45.33.%d.7' % (i % 4), dst='{h}') / UDP(sport=11211, dport=42000 + i) / "
             "Raw(bytes([0, i % 256, 0, 0, 0, 1, 0, 0]) + b'VALUE a 0 1300\\r\\n' + b'A' * 1300 + b'\\r\\nEND\\r\\n')")
# SSDP: an M-SEARCH answer from a home router (UPnP), a typical ~310 bytes
SSDP = ("IP(src='198.199.%d.10' % (i % 5), dst='{h}') / UDP(sport=1900, dport=43000 + i) / "
        "Raw(b'HTTP/1.1 200 OK\\r\\nCACHE-CONTROL: max-age=1800\\r\\nEXT:\\r\\n"
        "LOCATION: http://192.168.1.1:49152/rootDesc.xml\\r\\n"
        "SERVER: Linux/3.14 UPnP/1.0 MiniUPnPd/2.1\\r\\nST: upnp:rootdevice\\r\\n"
        "USN: uuid:12345678-90ab-cdef-1234-567890abcdef::upnp:rootdevice\\r\\n"
        "BOOTID.UPNP.ORG: 1604936417\\r\\nCONFIGID.UPNP.ORG: 1337\\r\\n\\r\\n')")


def test_amplification():
    for service, packet in (("DNS", DNS_ANY), ("NTP", NTP_MONLIST), ("memcached", MEMCACHED), ("SSDP", SSDP)):
        forge([packet.format(h=HOST)], count=60)

        def found(service=service):
            return [a for a in alerts() if a["alert_type"] == "AMPLIFICATION"
                    and a["title"] == f"{service} Amplification Attack Against {HOST}"]
        hit = wait_for(found, timeout=20)
        meta = (hit[0].get("metadata") or {}) if hit else {}
        check(f"replayed {service} reflection replies raise AMPLIFICATION", hit,
              f"{meta.get('replies')} replies, {meta.get('bytes')} bytes from {meta.get('reflectors')} reflectors"
              if hit else [a["title"] for a in alerts()][-5:])

    # This host's own "NTP" service answers 36-byte requests with 1428-byte packets
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind((HOST, 123))

    def serve():
        while True:
            try:
                _data, addr = srv.recvfrom(2048)
                srv.sendto(bytes(1400), addr)
            except OSError:
                return

    threading.Thread(target=serve, daemon=True).start()
    code = ("import socket, time\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            f"for i in range(100):\n    s.sendto(b'\\x17\\x00\\x03\\x2a' + bytes(4), ('{HOST}', 123))\n"
            "    time.sleep(0.01)\n")
    in_ns([sys.executable, "-c", code], check=True)
    hit = wait_for(lambda: [a for a in alerts() if a["alert_type"] == "AMPLIFICATION"
                            and (a.get("metadata") or {}).get("role") == "reflector"], timeout=20)
    srv.close()
    meta = (hit[0].get("metadata") or {}) if hit else {}
    check("this host amplifying a client's requests raises AMPLIFICATION (reflector)",
          hit and hit[0]["src_ip"] == ATTACKER,
          f"{hit[0]['title']}: {meta.get('amplification')}x" if hit else "none")


def main():
    if os.geteuid():
        raise SystemExit("run as root")
    procs = []
    try:
        setup()
        os.makedirs("/tmp/kguard-www", exist_ok=True)
        procs.append(subprocess.Popen([sys.executable, "-m", "http.server", "443", "--bind", HOST,
                                       "-d", "/tmp/kguard-www"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        procs.append(start_sshd())
        listener(8080)
        procs.append(start_backend())
        tests = (test_web_traffic_is_quiet, test_scan_types, test_brute_force, test_syn_flood,
                 test_os_fingerprints, test_spoofing, test_amplification)
        only = os.environ.get("LAB_TESTS", "").split(",")  # e.g. LAB_TESTS=syn_flood,spoofing
        for test in tests:
            if only != [""] and test.__name__.removeprefix("test_") not in only:
                continue
            try:
                test()
            except Exception as e:
                check(f"{test.__name__} ran without errors", False, repr(e)[:200])
        if any(not ok for _n, ok in results) and BACKEND_LOG:
            print("--- backend log (last lines) ---")
            print("".join(open(BACKEND_LOG).readlines()[-25:]))
    finally:
        teardown(procs)
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
