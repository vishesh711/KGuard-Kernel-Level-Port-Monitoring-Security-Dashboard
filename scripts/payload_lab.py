#!/usr/bin/env python3
"""
KGuard payload lab (roadmap N5.7, N5.8): real TLS clients and a real DNS
tunnel, seen by the eBPF agent and analysed by the backend.

    host  kgv0 10.200.0.1  <-->  kgv1 10.200.0.2  (netns kgsrv: TLS server, iodined)

The agent (eBPF engine, on kgv0) reports to the backend. On the host:

  - curl, Python requests and headless Chromium (twice) connect over TLS
    -> each ClientHello is recorded with SNI, JA3, JA4 and the client
       process; JA3/JA4 are compared with Wireshark's on a tcpdump capture
  - iodine opens a DNS tunnel to iodined and pings through it
    -> DNS_TUNNELING; ordinary lookups raise nothing

Run as root in a disposable VM, from the repository root:

    make -C agent && sudo python3 scripts/payload_lab.py /path/to/backend/python

Needs: curl, tcpdump, tshark, openssl, iodine, ethtool, Python requests (system
python3), Chromium (Playwright's, or set CHROMIUM=...).
"""

import glob
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND_PY = sys.argv[1] if len(sys.argv) > 1 else "python3"
AGENT = os.path.join(ROOT, "agent", "build", "kguard-agent")
HOST, SERVER, NS = "10.200.0.1", "10.200.0.2", "kgsrv"
PORT = 8791
API = f"http://127.0.0.1:{PORT}"
WORK = tempfile.mkdtemp(prefix="kguard-payload-lab-")
CHROMIUM = os.environ.get("CHROMIUM") or next(
    iter(sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux*/chrome"))), "")

results = []
procs = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


def sh(cmd, check_rc=True, **kw):
    r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)
    if check_rc and r.returncode:
        raise RuntimeError(f"{cmd} failed: {r.stderr.strip()[-300:]}")
    return r.stdout


def bg(cmd, log, **kw):
    p = subprocess.Popen(cmd, stdout=open(os.path.join(WORK, log), "w"), stderr=subprocess.STDOUT, **kw)
    procs.append(p)
    return p


def api(path):
    with urllib.request.urlopen(API + path, timeout=10) as r:
        return json.loads(r.read())


def wait_for(predicate, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        try:
            found = predicate()
        except OSError:
            found = None
        if found:
            return found
        time.sleep(1)
    return None


TLS_SERVER = """
import socket, ssl, threading
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("{work}/cert.pem", "{work}/key.pem")
ctx.set_alpn_protocols(["http/1.1"])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("{server}", 443)); s.listen(64)
def handle(c):
    try:
        t = ctx.wrap_socket(c, server_side=True); t.recv(65536)
        t.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok"); t.close()
    except Exception:
        c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
"""


def setup():
    sh(f"ip netns add {NS}")
    sh("ip link add kgv0 type veth peer name kgv1")
    sh(f"ip link set kgv1 netns {NS}")
    sh(f"ip addr add {HOST}/24 dev kgv0")
    sh("ip link set kgv0 up")
    sh(f"ip netns exec {NS} ip addr add {SERVER}/24 dev kgv1")
    sh(f"ip netns exec {NS} ip link set kgv1 up")
    sh(f"ip netns exec {NS} ip link set lo up")
    sh(f"openssl req -x509 -newkey rsa:2048 -nodes -keyout {WORK}/key.pem -out {WORK}/cert.pem "
       f"-days 1 -subj /CN=test.lab")
    with open(f"{WORK}/tls_server.py", "w") as f:
        f.write(TLS_SERVER.format(work=WORK, server=SERVER))
    bg(["ip", "netns", "exec", NS, sys.executable, f"{WORK}/tls_server.py"], "tls_server.log")
    bg(["ip", "netns", "exec", NS, "iodined", "-f", "-c", "-l", SERVER, "-P", "lab-secret", "10.53.0.1",
        "t.lab"], "iodined.log")

    def tls_listening():
        try:
            socket.create_connection((SERVER, 443), timeout=1).close()
            return True
        except OSError:
            return False
    if not wait_for(tls_listening, timeout=30):
        raise RuntimeError("TLS server did not start: " + open(f"{WORK}/tls_server.log").read()[-300:])


def start_backend():
    env = dict(os.environ, DATABASE_URL=f"sqlite:///{WORK}/kguard.db", AGENT_ENROLLMENT_KEY="lab-key",
               DEBUG="true", KGUARD_SOURCE="proc", PROC_KGUARD_PATH="/nonexistent", KERNEL_DETECTION="off")
    bg([BACKEND_PY, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(PORT)],
       "backend.log", cwd=os.path.join(ROOT, "backend"), env=env)
    if not wait_for(lambda: api("/api/health/"), timeout=60):
        raise RuntimeError("backend did not start")


def start_agent():
    state = f"{WORK}/agent"
    sh([AGENT, "enroll", "--server", API, "--key", "lab-key", "--name", "lab-host", "--state-dir", state])
    bg([AGENT, "run", "--engine", "ebpf", "--iface", "kgv0", "--server", API, "--state-dir", state,
        "--flush-ms", "200"], "agent.log")
    if not wait_for(lambda: "running:" in open(f"{WORK}/agent.log").read(), timeout=30):
        raise RuntimeError("agent did not start: " + open(f"{WORK}/agent.log").read()[-300:])


def run_clients():
    url = "https://test.lab/"
    sh(["curl", "-sSk", "--resolve", f"test.lab:443:{SERVER}", url, "-o", "/dev/null"])
    sh([sys.executable, "-W", "ignore", "-c",
        "import socket, requests, urllib3; urllib3.disable_warnings()\n"
        "real = socket.getaddrinfo\n"
        f"socket.getaddrinfo = lambda h, *a, **k: real('{SERVER}' if h == 'test.lab' else h, *a, **k)\n"
        f"requests.get('{url}', verify=False)\n"])
    run_chromium(2)


def run_chromium(times):
    # Chromium's default profile, in a writable home (an explicit fresh --user-data-dir loads
    # nothing in the test VM)
    url = "https://test.lab/"
    home = os.path.join(WORK, "home")
    os.makedirs(home, exist_ok=True)
    for _ in range(times):
        sh([CHROMIUM, "--headless=new", "--no-sandbox", "--disable-gpu", "--ignore-certificate-errors",
            f"--host-resolver-rules=MAP test.lab {SERVER}", "--dump-dom", url],
           timeout=300, env=dict(os.environ, HOME=home))


def wireshark_fingerprints(pcap):
    out = sh(["tshark", "-r", pcap, "-Y", "tls.handshake.type==1", "-T", "fields", "-e", "tcp.srcport",
              "-e", "tls.handshake.ja3", "-e", "tls.handshake.ja4"])
    return {int(p): (ja3, ja4) for p, ja3, ja4 in (line.split("\t") for line in out.strip().splitlines())}


def test_tls_fingerprints():
    pcap = f"{WORK}/tls.pcap"
    dump = bg(["tcpdump", "-Z", "root", "-i", "kgv0", "-U", "-w", pcap, "tcp port 443"], "tcpdump.log")
    time.sleep(2)
    run_clients()
    # Once more without segmentation offload, so the ~1.7 KB ClientHello leaves as two TCP
    # segments and the eBPF program has to follow the flow
    sh("ethtool -K kgv0 tso off gso off")
    run_chromium(1)
    sh("ethtool -K kgv0 tso on gso on")
    time.sleep(3)
    dump.terminate()
    dump.wait()
    shark = wireshark_fingerprints(pcap)

    rows = wait_for(lambda: (lambda r: r if len(r) >= len(shark) else None)(
        api("/api/tls/handshakes?size=100")["items"]), timeout=20) or []
    by_port = {r["client_port"]: r for r in rows}
    check("every ClientHello Wireshark saw is recorded", shark and set(shark) <= set(by_port),
          f"wireshark {len(shark)}, kguard {len(by_port)}")

    def rows_of(process):
        return [r for r in rows if r["process_name"] == process]

    for process, label in (("curl", "curl"), ("python3", "Python requests")):
        found = rows_of(process)
        r = found[0] if found else {}
        ws = shark.get(r.get("client_port"), (None, None))
        check(f"{label}: SNI, JA3 and JA4 recorded and equal to Wireshark's",
              r and r["sni"] == "test.lab" and (r["ja3"], r["ja4"]) == ws,
              f"JA4 {r.get('ja4')} JA3 {r.get('ja3')}" if r else f"no handshake from {process}")

    chrome = rows_of("chrome")
    fresh = [r for r in chrome if "0029" not in (r["ja4_r"] or "")]  # not session resumption
    check("Chromium: handshakes recorded and named after the process (not its IO thread)",
          len(chrome) >= 2, f"{len(chrome)} handshakes, processes {sorted({r['process_name'] for r in rows})}")
    check("Chromium: JA3 equals Wireshark's for every connection",
          chrome and all(r["ja3"] == shark.get(r["client_port"], (None,))[0] for r in chrome))
    check("Chromium: JA4 (a, b) equal Wireshark's; c differs only by GREASE, which Wireshark 4.2 keeps",
          chrome and all(r["ja4"].rsplit("_", 1)[0] == shark.get(r["client_port"], ("", ""))[1].rsplit("_", 1)[0]
                         for r in chrome))
    ja3s, ja4s = {r["ja3"] for r in fresh}, {r["ja4"] for r in fresh}
    check("Chromium: one JA4 across runs although JA3 changes (extension shuffling)",
          len(fresh) >= 2 and len(ja4s) == 1, f"{len(fresh)} fresh handshakes: {len(ja3s)} JA3s, JA4 {ja4s}")
    # How Chromium's ~1.7 KB ClientHello crossed kgv0: several TCP segments (eBPF follows the flow) or
    # one offloaded super-packet (eBPF copies it in chunks); either way it must be recorded whole
    sizes = sh(["tshark", "-r", pcap, "-Y", "tls.handshake.type==1 && tls.record.length > 1400", "-T", "fields",
                "-e", "tcp.srcport", "-e", "tcp.len", "-e", "tls.record.length"]).split("\n")
    split = [line for line in sizes if line and int(line.split("\t")[1]) < int(line.split("\t")[2]) + 5]
    split_ports = {int(line.split("\t")[0]) for line in split}
    check("Chromium's ClientHello split across TCP segments is reassembled (eBPF follows the flow)",
          split_ports and split_ports <= set(by_port) and all(by_port[p]["ja4"].startswith("t13d15")
                                                              for p in split_ports),
          f"{len(split)} of {len([x for x in sizes if x])} large ClientHellos were split")
    check("Chromium's ClientHello sent as one offloaded super-packet is recorded whole (eBPF chunks it)",
          any(int(line.split("\t")[0]) in by_port for line in sizes if line and line not in split))


def dns_query(name, msg_id):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return msg_id.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x01\x00\x01"


def test_dns():
    # Ordinary lookups first (the server answers REFUSED or nothing; only the queries matter)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = ["www.google.com", "fonts.gstatic.com", "www.youtube.com", "i.ytimg.com", "github.com",
             "api.github.com", "www.wikipedia.org", "upload.wikimedia.org", "cdn.jsdelivr.net", "www.bbc.co.uk"]
    for i, name in enumerate(names * 4):
        s.sendto(dns_query(name, i), (SERVER, 53))
        time.sleep(0.05)
    seen = wait_for(lambda: api("/api/dns/queries?domain=google.com")["total"], timeout=15)
    check("ordinary DNS lookups are recorded", seen, f"{seen} lookups of google.com")

    iodine = bg(["iodine", "-f", "-r", "-P", "lab-secret", SERVER, "t.lab"], "iodine.log")
    up = wait_for(lambda: "10.53.0." in sh("ip -4 addr show", check_rc=False), timeout=60)
    check("iodine tunnel comes up over DNS", up, open(f"{WORK}/iodine.log").read()[-200:] if not up else "")
    if up:
        # Traffic through the tunnel (to the far end, 10.53.0.1): each packet becomes DNS lookups
        tunnel = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(40):
            tunnel.sendto(os.urandom(200), ("10.53.0.1", 9))
            time.sleep(0.2)
    alert = wait_for(lambda: [a for a in api("/api/alerts/?size=100")["items"]
                              if a["alert_type"] == "DNS_TUNNELING"], timeout=30)
    meta = (alert[0].get("metadata") or {}) if alert else {}
    check("iodine session raises DNS_TUNNELING for t.lab",
          alert and meta.get("domain") == "t.lab",
          f"{alert[0]['title']}: score {meta.get('score')}, {meta.get('queries')} queries, "
          f"types {meta.get('record_types')}" if alert else "no alert")
    rows = api("/api/dns/queries?domain=t.lab&size=5")["items"]
    check("tunnel lookups are attributed to the iodine process",
          rows and all(r["process_name"] == "iodine" for r in rows), [r["process_name"] for r in rows])
    others = [a for a in api("/api/alerts/?size=100")["items"]
              if a["alert_type"] == "DNS_TUNNELING" and (a.get("metadata") or {}).get("domain") != "t.lab"]
    check("ordinary lookups raise no DNS_TUNNELING alert", not others, [a["title"] for a in others])
    iodine.terminate()


def teardown():
    for p in procs:
        p.kill()
    sh(f"ip netns del {NS}", check_rc=False)
    sh("ip link del kgv0", check_rc=False)


def main():
    if os.geteuid():
        raise SystemExit("run as root")
    for tool in ("tcpdump", "tshark", "iodine", "iodined", "openssl", "curl", "ethtool"):
        if not shutil.which(tool):
            raise SystemExit(f"{tool} is required")
    try:
        setup()
        start_backend()
        start_agent()
        for test in (test_tls_fingerprints, test_dns):
            try:
                test()
            except Exception as e:
                check(f"{test.__name__} ran without errors", False, repr(e)[:300])
    finally:
        teardown()
        if any(not ok for _n, ok in results):
            for log in ("agent.log", "backend.log"):
                print(f"--- {log} (last lines) ---")
                print("".join(open(os.path.join(WORK, log)).readlines()[-15:]))
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
