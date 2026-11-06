#!/usr/bin/env python3
"""
KGuard flow export and packet capture lab (roadmap N5.10, N5.11).

    host  kgv0 10.200.0.1  <-->  kgv1 10.200.0.2  (netns kgatk)

The kernel module captures; the backend exports flows over IPFIX to a real
collector (nfcapd, from nfdump) and keeps a packet ring for alerts.

  - the namespace downloads a 2 MB file from the host over HTTP
    -> nfdump shows the connection's flows, and their packet and byte
       counts equal what tcpdump captured on kgv0; Wireshark decodes the
       raw IPFIX messages
  - nmap -sS of 200 ports, with the kernel enforcing (auto-block), raises a
    HIGH scan alert
    -> a .pcap of the scanner's packets, from before and after the alert,
       is saved and can be downloaded from the alert

Run as root in a disposable VM, from the repository root:

    make -C kernel && sudo python3 scripts/flow_pcap_lab.py /path/to/backend/python

Needs: nmap, curl, tcpdump, tshark, nfdump (nfcapd), ip (iproute2).
"""

import csv
import glob
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND_PY = sys.argv[1] if len(sys.argv) > 1 else "python3"
HOST, ATTACKER, NS = "10.200.0.1", "10.200.0.2", "kgatk"
PORT, COLLECTOR_PORT = 8792, 4739
API = f"http://127.0.0.1:{PORT}"
WORK = tempfile.mkdtemp(prefix="kguard-flow-lab-")

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
    os.makedirs(f"{WORK}/www", exist_ok=True)
    with open(f"{WORK}/www/file.bin", "wb") as f:
        f.write(os.urandom(2 * 1024 * 1024))
    bg([sys.executable, "-m", "http.server", "8080", "--bind", HOST, "-d", f"{WORK}/www"], "http.log")
    os.makedirs(f"{WORK}/flows", exist_ok=True)
    bg(["nfcapd", "-w", f"{WORK}/flows", "-p", str(COLLECTOR_PORT), "-t", "3600"], "nfcapd.log")
    # The raw IPFIX messages too, for Wireshark
    bg(["tcpdump", "-Z", "root", "-i", "lo", "-U", "-w", f"{WORK}/ipfix.pcap", f"udp port {COLLECTOR_PORT}"],
       "tcpdump-ipfix.log")


def start_backend():
    env = dict(os.environ, DATABASE_URL=f"sqlite:///{WORK}/kguard.db", DEBUG="true",
               DATA_COLLECTION_INTERVAL="0.5", IPFIX_COLLECTORS=f'["127.0.0.1:{COLLECTOR_PORT}"]',
               IPFIX_IDLE_TIMEOUT="5", PCAP_ON_ALERT="true", PCAP_DIR=f"{WORK}/pcaps", PCAP_SECONDS="30")
    bg([BACKEND_PY, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(PORT)],
       "backend.log", cwd=os.path.join(ROOT, "backend"), env=env)
    if not wait_for(lambda: api("/api/health/kernel")["details"]["kernel_detection"], timeout=60):
        raise RuntimeError("backend did not start or did not subscribe to kernel alerts")
    services = api("/api/health/detailed")["services"]
    check("backend exports flows and keeps a packet ring",
          services["flow_export"]["enabled"] and services["packet_capture"]["running"],
          f"flow export {services['flow_export']['collectors']}, capture {services['packet_capture']}")


def tshark_rows(pcap, display_filter, fields):
    out = sh(["tshark", "-r", pcap, "-Y", display_filter, "-T", "fields"] +
             [arg for f in fields for arg in ("-e", f)])
    return [line.split("\t") for line in out.splitlines() if line]


def test_flow_export():
    truth_pcap = f"{WORK}/download.pcap"
    dump = bg(["tcpdump", "-Z", "root", "-i", "kgv0", "-U", "-w", truth_pcap, "tcp port 8080"], "tcpdump.log")
    time.sleep(2)
    sh(["ip", "netns", "exec", NS, "curl", "-s", "-o", "/dev/null", f"http://{HOST}:8080/file.bin"])
    time.sleep(2)
    dump.terminate()
    dump.wait()

    # What actually crossed kgv0, per direction (the hooks see the same packets: veth does not segment)
    truth = {}
    for src, sport, length in tshark_rows(truth_pcap, "tcp", ["ip.src", "tcp.srcport", "ip.len"]):
        key = (src, int(sport))
        packets, octets = truth.get(key, (0, 0))
        truth[key] = (packets + 1, octets + int(length))
    client_port = next(p for (src, p) in truth if src == ATTACKER)

    # FIN, then 2 s grace and a collection cycle; then stop nfcapd so it writes its file
    time.sleep(6)
    for p in procs:
        if p.args[0] in ("nfcapd", "tcpdump"):
            p.terminate()
            p.wait()
    files = [f for f in glob.glob(f"{WORK}/flows/**/nfcapd.*", recursive=True) if not f.endswith("current")]
    out = sh(["nfdump", "-r", files[0], "-o", "csv", f"port {client_port}"]) if files else ""
    # One row per observation domain: the host's namespace and the attacker's both see each packet
    flows = {}
    for row in csv.DictReader(io.StringIO(out)):
        if row.get("sa") and row["sa"] not in ("", "Summary"):
            try:
                flows.setdefault((row["sa"], int(row["sp"])), []).append((int(row["ipkt"]), int(row["ibyt"])))
            except (KeyError, ValueError, TypeError):
                continue
    check("nfcapd (nfdump) receives and stores KGuard's IPFIX flows", flows,
          f"{len(files)} file(s); flows for the download: {flows}" if files else "no nfcapd file")
    for (src, sport), (packets, octets) in truth.items():
        label = "download" if src == HOST else "request"
        got = flows.get((src, sport))
        check(f"{label} flow {src}:{sport}: packets and bytes equal tcpdump's, in each namespace",
              got and len(got) == 2 and all(g == (packets, octets) for g in got),
              f"nfdump {got}, tcpdump {(packets, octets)}")

    messages = tshark_rows(f"{WORK}/ipfix.pcap", "cflow", ["cflow.srcport", "cflow.flow_end_reason"])
    records = [rec for ports, reasons in (m for m in messages if len(m) == 2)
               for rec in zip(ports.split(","), reasons.split(","))]
    malformed = tshark_rows(f"{WORK}/ipfix.pcap", "_ws.malformed || _ws.expert.severity >= error", ["frame.number"])
    download = {reason for port, reason in records if port == "8080"}
    check("Wireshark decodes the IPFIX messages without errors; the download ended by FIN",
          records and not malformed and download == {"3"},
          f"{len(messages)} messages, {len(records)} flow records, {len(malformed)} malformed, "
          f"download end reasons {download}")


def test_pcap_on_alert():
    # Scan alerts are HIGH when the kernel blocks the scanner. The ring still sees the
    # probes dropped after the block: AF_PACKET taps packets before netfilter.
    sh([sys.executable, os.path.join(ROOT, "kernel", "tools", "kguardctl.py"), "set", "enforce=1", "auto_block=1"])
    started = time.time()
    sh(["ip", "netns", "exec", NS, "nmap", "-sS", "-Pn", "-n", "-p", "1-200", "--max-retries", "0", HOST],
       check_rc=False)

    def captured():
        for a in api("/api/alerts/?size=100")["items"]:
            if a["alert_type"] == "PORT_SCAN" and (a.get("metadata") or {}).get("pcap"):
                return a
        return None
    alert = wait_for(captured, timeout=40)
    check("a HIGH scan alert gets a packet capture", alert,
          f"{alert['title']} ({alert['severity']}): {alert['metadata']['pcap']}" if alert
          else [(a["title"], a["severity"]) for a in api("/api/alerts/?size=100")["items"]])
    if not alert:
        return
    path = f"{WORK}/download-alert.pcap"
    with urllib.request.urlopen(f"{API}/api/alerts/{alert['id']}/pcap", timeout=10) as r, open(path, "wb") as f:
        f.write(r.read())
    rows = tshark_rows(path, "ip", ["ip.src", "ip.dst", "tcp.flags.syn", "tcp.flags.ack", "tcp.dstport",
                                    "frame.time_epoch"])
    def flag(value):  # tshark prints True/False (4.x) or 1/0
        return value in ("1", "True")
    probes = [r for r in rows if r[0] == ATTACKER and flag(r[2]) and not flag(r[3])]
    ports = {int(r[4]) for r in probes if r[4]}
    others = [r for r in rows if ATTACKER not in (r[0], r[1])]
    alert_time = alert["metadata"].get("kernel_timestamp", 0) / 1e9
    before = [r for r in probes if float(r[5]) < alert_time]
    check("the capture holds the scan: SYN probes to most of the 200 ports, replies included",
          len(ports) >= 150 and any(r[1] == ATTACKER for r in rows),
          f"{len(rows)} packets, {len(probes)} SYNs to {len(ports)} ports")
    check("only the scanner's packets are in it", not others, others[:3])
    check("packets from before the alert are included (rolling buffer)", before,
          f"{len(before)} probes before the alert, {time.time() - started:.0f} s after the scan began")
    snap = sh(["tshark", "-r", path, "-T", "fields", "-e", "frame.cap_len", "-c", "200"]).split()
    check("packets are cut to the snap length in the kernel (BPF socket filter)",
          snap and max(int(x) for x in snap) <= 256, f"largest captured packet {max(map(int, snap))} bytes")


def teardown():
    for p in procs:
        p.kill()
    sh(f"ip netns del {NS}", check_rc=False)
    sh("ip link del kgv0", check_rc=False)
    sh("rmmod kguard", check_rc=False)


def main():
    if os.geteuid():
        raise SystemExit("run as root")
    for tool in ("nmap", "curl", "tcpdump", "tshark", "nfcapd", "nfdump"):
        if not shutil.which(tool):
            raise SystemExit(f"{tool} is required")
    try:
        setup()
        start_backend()
        for test in (test_flow_export, test_pcap_on_alert):
            try:
                test()
            except Exception as e:
                check(f"{test.__name__} ran without errors", False, repr(e)[:300])
    finally:
        teardown()
        if any(not ok for _n, ok in results):
            print("--- backend.log (last lines) ---")
            print("".join(open(os.path.join(WORK, "backend.log")).readlines()[-15:]))
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
