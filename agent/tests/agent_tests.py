#!/usr/bin/env python3
"""
kguard-agent test suite (roadmap Phase 4). Run as root on a disposable
machine or VM with BTF (/sys/kernel/btf/vmlinux), from the repository root:

    make -C kernel && make -C agent && sudo python3 agent/tests/agent_tests.py [PYTHON]

PYTHON is an interpreter with the backend's requirements (default: python3).
Needs: curl, nc, nmap, ip (iproute2).

Checks:
  - eBPF engine (XDP + TC): every packet in and out, process attribution,
    IPv6
  - XDP blocklist (LPM trie): drops a remote attacker, IPv6, expiry
  - kernel module engine through the agent
  - two agents (module and eBPF engines, one inside a network namespace)
    reporting to one backend as separate hosts, with per-host detection
  - the agent survives a backend restart without losing events
"""

import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
AGENT = os.path.join(ROOT, "agent", "build", "kguard-agent")
MODULE = os.path.join(ROOT, "kernel", "kguard.ko")
BACKEND_PY = sys.argv[1] if len(sys.argv) > 1 else "python3"

HOST4, ATK4 = "10.200.0.1", "10.200.0.2"
HOST6, ATK6 = "2001:db8:200::1", "2001:db8:200::2"
NS = "kgatk"
PORT = 8770
API = f"http://{HOST4}:{PORT}"

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


def module_loaded():
    return re.search(r"^kguard ", open("/proc/modules").read(), re.M) is not None


class Agent:
    """Run kguard-agent in the background; stop it with SIGINT"""

    def __init__(self, *args, netns=None, out=None):
        cmd = [AGENT, "run", *args]
        if netns:
            cmd = ["ip", "netns", "exec", netns] + cmd
        self.out = out or tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False)
        self.log = tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False)
        self.proc = subprocess.Popen(cmd, stdout=self.out, stderr=self.log)

    def started(self, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            if "running:" in open(self.log.name).read():
                return True
            if self.proc.poll() is not None:
                return False
            time.sleep(0.2)
        return False

    def stop(self):
        self.proc.send_signal(signal.SIGINT)
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        return open(self.log.name).read()

    def records(self):
        return [json.loads(line) for line in open(self.out.name) if line.startswith("{")]

    def events(self):
        return [r for r in self.records() if r.get("type") != "payload"]

    def payloads(self):
        return [r for r in self.records() if r.get("type") == "payload"]


def udp_burst(port, count, rate, family=socket.AF_INET, addr="127.0.0.1"):
    """Send from a separate process so the sender is not slowed by this one"""
    sh([sys.executable, "-c",
        "import socket,time\n"
        f"s=socket.socket({int(family)},socket.SOCK_DGRAM); t=time.monotonic()\n"
        f"for i in range({count}):\n"
        f"    s.sendto(b'k',('{addr}',{port}))\n"
        f"    a=(i+1)/{rate}-(time.monotonic()-t)\n"
        "    a>0.001 and time.sleep(a)\n"])


def udp_sink(family=socket.AF_INET, addr="127.0.0.1"):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.bind((addr, 0))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
    return s, s.getsockname()[1]


# ---------------------------------------------------------------- eBPF engine

def test_ebpf_capture():
    """X4.1: XDP + TC see every packet in and out, in the shared event format"""
    sink, port = udp_sink()
    agent = Agent("--engine", "ebpf", "--stdout", "--iface", "lo")
    check("eBPF engine loads and attaches (verifier accepts all programs)", agent.started(),
          open(agent.log.name).read().strip().splitlines()[-1:])
    total = 10000
    udp_burst(port, total, 2000)
    time.sleep(1)
    log = agent.stop()
    ev = [e for e in agent.events() if e["dst_port"] == port and e["protocol"] == "UDP"]
    ins = sum(1 for e in ev if e["direction"] == "in")
    outs = sum(1 for e in ev if e["direction"] == "out")
    dropped = re.search(r"kernel dropped (\d+)", log)
    check("eBPF: every packet captured in and out", ins == total and outs == total,
          f"in={ins} out={outs} of {total}")
    check("eBPF: nothing lost in the ring buffer", dropped and dropped.group(1) == "0",
          dropped.group(0) if dropped else log[-200:])
    stamps = [e["timestamp"] for e in ev]
    check("eBPF timestamps are wall-clock time", stamps and abs(stamps[0] / 1e9 - time.time()) < 120)
    sink.close()


def test_ebpf_attribution():
    """X4.2: curl and an nc listener are named without any /proc scanning"""
    nc = subprocess.Popen(["nc", "-l", "127.0.0.1", "4444"], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
    agent = Agent("--engine", "ebpf", "--stdout", "--iface", "lo")
    agent.started()
    late = subprocess.Popen(["nc", "-l", "127.0.0.1", "4447"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)  # starts listening after the agent
    time.sleep(0.5)
    for p in (4444, 4447):
        subprocess.run(["curl", "-s", "--max-time", "1", f"http://127.0.0.1:{p}/"], capture_output=True)
    sink, port = udp_sink()
    udp_burst(port, 3, 100)
    time.sleep(1)
    agent.stop()
    nc.kill()
    late.kill()
    ev = agent.events()
    syn_out = [e for e in ev if e["dst_port"] == 4444 and e["flags"] == 2 and e["direction"] == "out"]
    syn_in = [e for e in ev if e["dst_port"] == 4444 and e["flags"] == 2 and e["direction"] == "in"]
    check("eBPF: outgoing SYN attributed to curl (fentry tcp_connect)",
          syn_out and syn_out[0]["comm"] == "curl", syn_out[:1])
    check("eBPF: listener started before the agent is named (start-up scan of /proc/net)",
          syn_in and syn_in[0]["comm"] == "nc" and syn_in[0]["pid"] == nc.pid, syn_in[:1])
    late_in = [e for e in ev if e["dst_port"] == 4447 and e["flags"] == 2 and e["direction"] == "in"]
    check("eBPF: listener started after the agent is named (fexit inet_listen)",
          late_in and late_in[0]["comm"] == "nc" and late_in[0]["pid"] == late.pid, late_in[:1])
    s = syn_out[0] if syn_out else {}
    check("eBPF: SYN carries TTL, length and Linux's TCP option order (XDP/TC option parser)",
          (s.get("ttl"), s.get("ip_len"), s.get("tcp_options"), s.get("tcp_mss")) == (64, 60, "M,S,T,N,W", 65495)
          and s.get("tcp_wscale", -1) >= 0 and s.get("df") is True,
          {k: s.get(k) for k in ("ttl", "ip_len", "df", "tcp_window", "tcp_mss", "tcp_wscale", "tcp_options")})
    udp_out = [e for e in ev if e["dst_port"] == port and e["direction"] == "out"]
    check("eBPF: first UDP datagram already attributed (fentry udp_sendmsg)",
          len(udp_out) == 3 and all(e["comm"] == "python3" for e in udp_out),
          [e["comm"] for e in udp_out])
    sink.close()


def test_ebpf_ipv6():
    sink, port = udp_sink(socket.AF_INET6, "::1")
    agent = Agent("--engine", "ebpf", "--stdout", "--iface", "lo")
    agent.started()
    udp_burst(port, 10, 100, socket.AF_INET6, "::1")
    time.sleep(1)
    agent.stop()
    v6 = [e for e in agent.events() if e["family"] == 6 and e["dst_port"] == port]
    check("eBPF: IPv6 captured in both directions", len(v6) == 20, f"{len(v6)} events")
    sink.close()


# ---------------------------------------------------------------- lab network

class Lab:
    """Attacker namespace joined to the host by a veth pair, plus a web server"""

    def __enter__(self):
        sh(f"ip netns add {NS}")
        sh("ip link add kgv0 type veth peer name kgv1")
        sh(f"ip link set kgv1 netns {NS}")
        sh(f"ip addr add {HOST4}/24 dev kgv0")
        sh(f"ip -6 addr add {HOST6}/64 dev kgv0 nodad")
        sh("ip link set kgv0 up")
        for cmd in (f"ip addr add {ATK4}/24 dev kgv1", f"ip -6 addr add {ATK6}/64 dev kgv1 nodad",
                    "ip link set kgv1 up", "ip link set lo up"):
            sh(f"ip netns exec {NS} {cmd}")
        os.makedirs("/tmp/kguard-www", exist_ok=True)
        self.servers = [
            subprocess.Popen([sys.executable, "-m", "http.server", "8080", "--bind", a, "-d", "/tmp/kguard-www"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for a in (HOST4, HOST6)
        ]
        time.sleep(1.5)
        return self

    def __exit__(self, *exc):
        for s in self.servers:
            s.kill()
        sh(f"ip netns del {NS}", check_rc=False)
        sh("ip link del kgv0", check_rc=False)


def reach(v6=False):
    url = f"http://[{HOST6}]:8080/" if v6 else f"http://{HOST4}:8080/"
    r = in_ns(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "2", url])
    return r.stdout.strip() == "200"


def test_xdp_blocklist():
    """X4.3: blocked prefixes are dropped in XDP, before the network stack"""
    agent = Agent("--engine", "ebpf", "--stdout", "--iface", "kgv0")
    agent.started()
    try:
        check("attacker reaches the host before any block", reach())
        sh([AGENT, "block", "10.200.0.0/24"])
        check("XDP drops a blocked IPv4 prefix", not reach())
        listing = sh([AGENT, "blocks"])
        drops = re.search(r"10\.200\.0\.0/24\s+permanent\s+drops=(\d+)", listing)
        check("blocklist shows the prefix and counts drops", drops and int(drops.group(1)) > 0, listing.strip())
        check("IPv6 traffic from the same attacker is unaffected", reach(v6=True))
        sh([AGENT, "block", ATK6])
        check("XDP drops a blocked IPv6 address", not reach(v6=True))
        sh([AGENT, "unblock", "10.200.0.0/24"])
        sh([AGENT, "unblock", ATK6])
        check("unblock restores access", reach() and reach(v6=True))
        sh([AGENT, "block", ATK4, "--timeout", "3"])
        blocked_now = not reach()
        time.sleep(4)
        check("timed blocks expire", blocked_now and reach())
    finally:
        agent.stop()
        for prefix in ("10.200.0.0/24", ATK6, ATK4):
            sh([AGENT, "unblock", prefix], check_rc=False)


# ---------------------------------------------------------------- module engine

def load_module():
    if not module_loaded():
        sh("modprobe -a nf_conntrack nf_socket_ipv4 nf_socket_ipv6")
        sh(["insmod", MODULE])


def test_module_engine():
    """X4.4: the same agent reads the kernel module's rings"""
    load_module()
    nc = subprocess.Popen(["nc", "-l", "127.0.0.1", "4445"], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
    sink, port = udp_sink()
    agent = Agent("--engine", "module", "--stdout")
    check("module engine opens /dev/kguard", agent.started())
    udp_burst(port, 2000, 1000)
    subprocess.run(["curl", "-s", "--max-time", "1", "http://127.0.0.1:4445/"], capture_output=True)
    time.sleep(1)
    agent.stop()
    nc.kill()
    ev = agent.events()
    udp = [e for e in ev if e["dst_port"] == port]
    check("module engine: every packet in and out", len(udp) == 4000, f"{len(udp)} of 4000")
    syn_in = [e for e in ev if e["dst_port"] == 4445 and e["flags"] == 2 and e["direction"] == "in"]
    check("module engine: listener named from its socket inode (agent's /proc scan)",
          syn_in and syn_in[0]["comm"] == "nc", syn_in[:1])
    check("module engine: conntrack state included", syn_in and syn_in[0]["ct_state"] == "new")
    check("module engine: SYN option order forwarded", syn_in and syn_in[0]["tcp_options"] == "M,S,T,N,W",
          syn_in[0].get("tcp_options") if syn_in else None)
    sink.close()


# ---------------------------------------------------------------- backend

def api(path):
    with urllib.request.urlopen(API + path, timeout=5) as r:
        return json.loads(r.read())


class Backend:
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="kguard-backend-")
        self.env = dict(os.environ,
                        DATABASE_URL=f"sqlite:///{self.dir}/kguard.db",
                        KGUARD_SOURCE="device", KGUARD_DEVICE_PATH="/nonexistent",
                        PROC_KGUARD_PATH="/nonexistent", KERNEL_DETECTION="off",
                        AGENT_ENROLLMENT_KEY="lab-key", DEBUG="true")
        self.proc = None

    def start(self):
        self.proc = subprocess.Popen(
            [BACKEND_PY, "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", str(PORT)],
            cwd=os.path.join(ROOT, "backend"), env=self.env,
            stdout=open(f"{self.dir}/backend.log", "a"), stderr=subprocess.STDOUT)
        for _ in range(60):
            try:
                api("/api/health/")
                return
            except OSError:
                time.sleep(0.5)
        raise RuntimeError("backend did not start: " + open(f"{self.dir}/backend.log").read()[-500:])

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=20)
            self.proc = None


def enroll(name, state, netns=None):
    cmd = [AGENT, "enroll", "--server", API, "--key", "lab-key", "--name", name, "--state-dir", state]
    if netns:
        cmd = ["ip", "netns", "exec", netns] + cmd
    return subprocess.run(cmd, capture_output=True, text=True)


def wait_for(predicate, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if predicate():
                return True
        except OSError:
            pass
        time.sleep(0.5)
    return False


def test_two_hosts():
    """X4.5: two agents, two engines, two network namespaces -> two hosts"""
    load_module()
    backend = Backend()
    backend.start()
    agents = []
    try:
        r1 = enroll("host-a", "/tmp/kguard-agent-a")
        r2 = enroll("host-b", "/tmp/kguard-agent-b", netns=NS)
        check("agents enroll with the shared key", r1.returncode == 0 and r2.returncode == 0,
              (r1.stderr + r2.stderr).strip()[:200])
        bad = subprocess.run([AGENT, "enroll", "--server", API, "--key", "wrong", "--name", "x",
                              "--state-dir", "/tmp/kguard-agent-x"], capture_output=True, text=True)
        check("a wrong enrollment key is refused", bad.returncode != 0 and "403" in bad.stderr)

        agents.append(Agent("--engine", "module", "--server", API, "--state-dir", "/tmp/kguard-agent-a",
                            "--flush-ms", "200"))
        agents.append(Agent("--engine", "ebpf", "--iface", "kgv1,lo", "--server", API,
                            "--state-dir", "/tmp/kguard-agent-b", "--flush-ms", "200", netns=NS))
        check("both agents start", all(a.started() for a in agents))

        in_ns(["nmap", "-sS", "-Pn", "-n", "-p", "1-100", "--max-retries", "0", HOST4])
        reach()

        def both_online():
            listed = {a["name"]: a for a in api("/api/agents/")}
            return (set(listed) == {"host-a", "host-b"} and all(a["online"] for a in listed.values())
                    and all(a["events_received"] > 0 for a in listed.values()))

        ok = wait_for(both_online)
        listed = {a["name"]: a for a in api("/api/agents/")}
        check("dashboard lists two online hosts, each sending events", ok,
              {n: (a["engine"], a["events_received"]) for n, a in listed.items()})
        check("each host reports its own engine",
              listed.get("host-a", {}).get("engine") == "module" and listed.get("host-b", {}).get("engine") == "ebpf")

        a_id, b_id = listed["host-a"]["id"], listed["host-b"]["id"]
        a_events = api(f"/api/events/?host_id={a_id}&size=100")["items"]
        b_events = api(f"/api/events/?host_id={b_id}&size=100")["items"]
        check("host A saw the scan arriving, host B saw it leaving",
              any(e["src_ip"] == ATK4 and e["direction"] == "in" for e in a_events)
              and any(e["src_ip"] == ATK4 and e["direction"] == "out" for e in b_events))
        scans = wait_for(lambda: any(a["host_id"] == a_id for a in api("/api/alerts/?alert_type=PORT_SCAN")["items"]))
        check("port scan alert attributed to the scanned host", scans)
    finally:
        for a in agents:
            a.stop()
        backend.stop()


def test_backend_restart():
    """X4.4: the agent keeps its batch and retries until the backend is back"""
    load_module()
    backend = Backend()
    backend.start()
    sink, port = udp_sink()
    agent = None
    try:
        enroll("host-r", "/tmp/kguard-agent-r")
        agent = Agent("--engine", "module", "--server", API, "--state-dir", "/tmp/kguard-agent-r",
                      "--flush-ms", "200")
        agent.started()
        backend.stop()
        udp_burst(port, 500, 500)  # sent while the backend is down
        time.sleep(3)
        backend.start()

        def arrived():
            return api(f"/api/events/?dst_port={port}&size=1")["total"] >= 1000

        ok = wait_for(arrived, timeout=60)
        total = api(f"/api/events/?dst_port={port}&size=1")["total"]
        log = open(agent.log.name).read()
        check("events sent while the backend was down arrive after it restarts", ok, f"{total} of 1000")
        check("agent logged the outage and the recovery",
              "backend unavailable" in log and "reachable again" in log)
    finally:
        if agent:
            agent.stop()
        backend.stop()
        sink.close()


def main():
    if os.geteuid():
        raise SystemExit("run as root")
    if module_loaded():
        sh("rmmod kguard")
    tests = [test_ebpf_capture, test_ebpf_attribution, test_ebpf_ipv6]
    for test in tests:
        try:
            test()
        except Exception as e:
            check(f"{test.__name__} ran without errors", False, repr(e)[:200])
    with Lab():
        for test in (test_xdp_blocklist, test_module_engine, test_two_hosts, test_backend_restart):
            try:
                test()
            except Exception as e:
                check(f"{test.__name__} ran without errors", False, repr(e)[:200])
    if module_loaded():
        sh("rmmod kguard")
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
