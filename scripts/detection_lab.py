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
  - repeated logins to port 22                 -> BRUTE_FORCE (N5.3)
  - hping3 -S --flood --rand-source            -> SYN_FLOOD (N5.2)

Run as root in a disposable VM, from the repository root:

    make -C kernel && sudo python3 scripts/detection_lab.py /path/to/backend/python

Needs: nmap, hping3, curl, ip (iproute2).
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
PORT = 8790
API = f"http://127.0.0.1:{PORT}"

results = []


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
        time.sleep(16)  # let the next scan start a fresh detection window


def test_brute_force():
    code = ("import socket\n"
            "for i in range(15):\n"
            f"    s = socket.create_connection(('{HOST}', 22), timeout=2); s.close()\n")
    in_ns([sys.executable, "-c", code], check=True)
    found = wait_for(lambda: [a for a in alerts() if a["alert_type"] == "BRUTE_FORCE"])
    check("15 rapid logins to port 22 raise BRUTE_FORCE", found and found[0]["dst_port"] == 22,
          found[0]["title"] if found else "no alert")


def test_syn_flood():
    in_ns(["timeout", "4", "hping3", "-S", "--flood", "--rand-source", "-p", "8080", HOST])
    found = wait_for(lambda: [a for a in alerts() if a["alert_type"] == "SYN_FLOOD"], timeout=60)
    meta = (found[0].get("metadata") or {}) if found else {}
    check("hping3 SYN flood from random sources raises SYN_FLOOD", found,
          f"{found[0]['title']}: {meta.get('half_open')} half-open from {meta.get('distinct_sources')} "
          f"sources, syn_cookies={meta.get('syn_cookies')}" if found else "no alert")


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
        listener(22)
        listener(8080)
        procs.append(start_backend())
        for test in (test_web_traffic_is_quiet, test_scan_types, test_brute_force, test_syn_flood):
            try:
                test()
            except Exception as e:
                check(f"{test.__name__} ran without errors", False, repr(e)[:200])
    finally:
        teardown(procs)
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
