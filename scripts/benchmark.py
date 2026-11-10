#!/usr/bin/env python3
"""
KGuard benchmarks (roadmap P8.7). Run as root, in a VM or on a test box:

    sudo python3 scripts/benchmark.py [--seconds 10] [--out docs/bench]

pktgen floods 64-byte UDP packets from one end of a veth pair into a
network namespace ("dut") where the monitoring runs, in each mode:

    none          nothing loaded
    module        the KGuard kernel module (Netfilter hooks), a reader
                  draining /dev/kguard (kernel/tools/kguard_reader)
    ebpf-generic  the agent's eBPF engine, XDP in generic (skb) mode
    ebpf-native   the agent's eBPF engine, XDP in native (driver) mode

and, the other way, pktgen sending out of "dut" through the qdisc layer
(xmit_mode queue_xmit), so the agent's TC egress program sees every packet:

    none-egress   nothing loaded
    ebpf-tc       the agent's eBPF engine (its TC clsact egress program)

For each mode it records:
    pps           packets per second reaching IP in "dut" (Ip InReceives)
    cpu_ns/pkt    all CPU time spent (kernel + softirq, every CPU) per packet
    extra ns/pkt  cpu_ns/pkt minus the baseline run in the same direction
    own ns/pkt    the component's own measure: the module's ns_per_packet
                  counter, or the BPF programs' run_time_ns / run_cnt
    lost          events dropped (module rings / eBPF ring buffer)

and, with --flame, a perf profile of each mode as a flame graph SVG.
Results go to <out>/results.json and <out>/*.svg.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "kernel" / "kguard.ko"
READER = ROOT / "kernel" / "tools" / "kguard_reader"
AGENT = ROOT / "agent" / "build" / "kguard-agent"
NS = "dut"
SEND, RECV = "bsend", "brecv"
SRC_IP, DST_IP = "10.250.0.1", "10.250.0.2"


def sh(cmd, check=True, **kw):
    r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)
    if check and r.returncode:
        raise RuntimeError(f"{cmd}: {r.stderr.strip()}")
    return r.stdout


def setup():
    sh(f"ip netns add {NS}")
    sh(f"ip link add {SEND} type veth peer name {RECV}")
    sh(f"ip link set {RECV} netns {NS}")
    sh(f"ip addr add {SRC_IP}/24 dev {SEND}; ip link set {SEND} up")
    sh(f"ip -n {NS} addr add {DST_IP}/24 dev {RECV}; ip -n {NS} link set {RECV} up; ip -n {NS} link set lo up")
    # Native XDP on a veth needs an XDP program (or GRO) on the peer too
    sh(f"ethtool -K {SEND} gro on", check=False)
    sh("modprobe pktgen")
    sh("sysctl -qw kernel.bpf_stats_enabled=1", check=False)


def teardown():
    sh(f"ip netns del {NS}", check=False)
    sh(f"ip link del {SEND}", check=False)
    if os.path.exists("/sys/module/kguard"):
        sh("rmmod kguard", check=False)


def pgset(path, line, netns=None):
    if netns:
        sh(["ip", "netns", "exec", netns, "sh", "-c", f"echo '{line}' > {path}"])
        return
    with open(path, "w") as f:
        f.write(line + "\n")


def is_egress(mode):
    return mode in ("none-egress", "ebpf-tc")


def pktgen(seconds, egress=False):
    """Flood for `seconds`: into "dut" (ingress), or out of it through the qdisc layer"""
    netns, dev_name, dst_ip = (NS, RECV, SRC_IP) if egress else (None, SEND, DST_IP)
    peer = sh(["ip", "-j", "link", "show", SEND] if egress else ["ip", "-n", NS, "-j", "link", "show", RECV])
    mac = json.loads(peer)[0]["address"]
    thread_file = "/proc/net/pktgen/kpktgend_0"
    pgset(thread_file, "rem_device_all", netns)
    pgset(thread_file, f"add_device {dev_name}", netns)
    dev = f"/proc/net/pktgen/{dev_name}"
    lines = ["count 0", "pkt_size 64", "delay 0", f"dst {dst_ip}", f"dst_mac {mac}",
             "udp_src_min 9", "udp_src_max 9", "udp_dst_min 5001", "udp_dst_max 5001",
             "flag NO_TIMESTAMP"]
    if egress:
        lines.append("xmit_mode queue_xmit")
    for line in lines:
        pgset(dev, line, netns)
    if egress:
        runner = subprocess.Popen(["ip", "netns", "exec", NS, "sh", "-c", "echo start > /proc/net/pktgen/pgctrl"])
        time.sleep(seconds)
        pgset("/proc/net/pktgen/pgctrl", "stop", netns)
        runner.wait()
        return
    runner = threading.Thread(target=lambda: pgset("/proc/net/pktgen/pgctrl", "start"))
    runner.start()
    time.sleep(seconds)
    pgset("/proc/net/pktgen/pgctrl", "stop")
    runner.join()


def in_receives(egress=False):
    """Ip InReceives at the receiving end"""
    text = sh("cat /proc/net/snmp" if egress else f"ip netns exec {NS} cat /proc/net/snmp")
    head, values = [line.split() for line in text.splitlines() if line.startswith("Ip:")][:2]
    return int(values[head.index("InReceives")])


def cpu_busy_ns():
    """Kernel + irq + softirq time of every CPU, in ns"""
    tick_ns = 1e9 / os.sysconf("SC_CLK_TCK")
    fields = open("/proc/stat").readline().split()[1:]
    user, nice, system, idle, iowait, irq, softirq = map(int, fields[:7])
    return (system + irq + softirq) * tick_ns


def module_stats():
    out = sh([sys.executable, str(ROOT / "kernel" / "tools" / "kguardctl.py"), "--json", "stats"], check=False)
    try:
        return json.loads(out)
    except ValueError:
        return {}


def bpf_run_stats():
    """Sum of run_time_ns and run_cnt over KGuard's BPF programs"""
    total_ns = total_cnt = 0
    try:
        progs = json.loads(sh("bpftool -j prog show"))
    except (RuntimeError, ValueError):
        return 0, 0
    for p in progs:
        if "kguard" in p.get("name", "") or p.get("type") in ("xdp", "sched_cls"):
            total_ns += p.get("run_time_ns", 0)
            total_cnt += p.get("run_cnt", 0)
    return total_ns, total_cnt


def start_mode(mode):
    procs = []
    if mode == "module":
        sh("modprobe -a nf_conntrack nf_socket_ipv4 nf_socket_ipv6")
        sh(["insmod", str(MODULE)])
        procs.append(subprocess.Popen([str(READER)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    elif mode.startswith("ebpf"):
        # The agent attaches XDP (ingress) and TC egress to the interface
        args = ["ip", "netns", "exec", NS, str(AGENT), "run", "--engine", "ebpf", "--stdout",
                "--iface", RECV, "--no-payloads"]
        if mode == "ebpf-native":
            args.append("--xdp-native")
        agent = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        procs.append(agent)
        deadline = time.time() + 30
        while time.time() < deadline and agent.poll() is None:
            time.sleep(0.5)
            if os.path.exists("/sys/fs/bpf/kguard_blocklist"):
                break
        time.sleep(2)
    return procs


def stop_mode(mode, procs):
    lost = None
    for p in procs:
        p.terminate()
        try:
            out = p.communicate(timeout=20)[1] or ""
        except subprocess.TimeoutExpired:
            p.kill()
            out = ""
        m = re.search(r"kernel dropped (\d+)", out)
        if m:
            lost = int(m.group(1))
    if mode == "module":
        sh("rmmod kguard", check=False)
    return lost


def fold_perf(perf_data):
    """perf script -> folded stacks {"a;b;c": samples}"""
    text = sh(["perf", "script", "-i", perf_data, "-F", "comm,ip,sym"], check=False)
    stacks, cur = defaultdict(int), []
    for line in text.splitlines() + [""]:
        if not line.strip():
            if cur:
                stacks[";".join(reversed(cur))] += 1
            cur = []
        elif line[0].isspace():
            parts = line.split()
            if len(parts) >= 2:
                cur.append(re.sub(r"\+0x[0-9a-f]+$", "", parts[1]))
        else:
            cur = [line.split()[0]]
    return stacks


def flame_svg(stacks, title, path, width=1200):
    """A minimal flame graph (like Brendan Gregg's) from folded stacks"""
    total = sum(stacks.values()) or 1
    tree = {}
    for stack, n in stacks.items():
        node = tree
        for frame in stack.split(";"):
            node = node.setdefault(frame, {"_n": 0})
            node["_n"] += n
    rows, row_h = [], 16
    depth_max = [0]

    def walk(node, x, depth):
        for name, child in sorted((k, v) for k, v in node.items() if k != "_n"):
            w = child["_n"] / total * width
            if w >= 0.5:
                rows.append((x, depth, w, name, child["_n"]))
                depth_max[0] = max(depth_max[0], depth)
                walk(child, x, depth + 1)
            x += w
    walk(tree, 0.0, 0)
    height = (depth_max[0] + 3) * row_h
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" font-family="monospace" '
           f'font-size="11"><rect width="100%" height="100%" fill="#fff"/>'
           f'<text x="4" y="12" font-size="13">{title} ({total} samples)</text>']
    for x, depth, w, name, n in rows:
        y = height - (depth + 1) * row_h
        hue = 20 + (hash(name) % 40)
        label = name if len(name) * 6.5 < w else name[: max(0, int(w / 6.5) - 2)] + ".." if w > 20 else ""
        safe = name.replace("&", "&amp;").replace("<", "&lt;")
        out.append(f'<g><title>{safe} ({n} samples, {n / total:.1%})</title>'
                   f'<rect x="{x:.1f}" y="{y}" width="{max(w - 0.5, 0.5):.1f}" height="{row_h - 1}" '
                   f'fill="hsl({hue},90%,60%)"/><text x="{x + 2:.1f}" y="{y + 11}">'
                   f'{label.replace("&", "&amp;").replace("<", "&lt;")}</text></g>')
    out.append("</svg>")
    Path(path).write_text("\n".join(out))


def run_mode(mode, seconds, flame, out_dir):
    procs = start_mode(mode)
    try:
        time.sleep(1)
        stats_before, bpf_before = module_stats(), bpf_run_stats()
        egress = is_egress(mode)
        recv0, cpu0, t0 = in_receives(egress), cpu_busy_ns(), time.monotonic()
        perf = None
        if flame:
            perf = subprocess.Popen(["perf", "record", "-a", "-g", "-F", "499", "-o",
                                     f"/tmp/perf-{mode}.data", "--", "sleep", str(seconds)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pktgen(seconds, egress)
        elapsed = time.monotonic() - t0
        recv, cpu = in_receives(egress) - recv0, cpu_busy_ns() - cpu0
        stats_after, bpf_after = module_stats(), bpf_run_stats()
        if perf:
            perf.wait()
            flame_svg(fold_perf(f"/tmp/perf-{mode}.data"), f"KGuard benchmark: {mode}", out_dir / f"flame-{mode}.svg")
    finally:
        lost = stop_mode(mode, procs)
    result = {"mode": mode, "direction": "egress" if is_egress(mode) else "ingress",
              "seconds": round(elapsed, 2), "packets": recv, "pps": round(recv / elapsed),
              "cpu_ns_per_packet": round(cpu / recv, 1) if recv else None}
    if mode == "module":
        result["own_ns_per_packet"] = stats_after.get("ns_per_packet")
        result["lost"] = stats_after.get("dropped", 0) - stats_before.get("dropped", 0)
        result["events"] = stats_after.get("events", 0) - stats_before.get("events", 0)
    elif mode.startswith("ebpf"):
        ns = bpf_after[0] - bpf_before[0]
        cnt = bpf_after[1] - bpf_before[1]
        result["own_ns_per_packet"] = round(ns / cnt, 1) if cnt else None
        result["bpf_runs"] = cnt
        result["lost"] = lost
    return result


def machine():
    cpu = next((line.split(":", 1)[1].strip() for line in open("/proc/cpuinfo") if line.startswith("model name")), "?")
    virt = sh("systemd-detect-virt", check=False).strip() or "unknown"
    return {"kernel": os.uname().release, "cpu": cpu, "cpus": os.cpu_count(), "virtualization": virt,
            "kvm": "hypervisor" in open("/proc/cpuinfo").read()}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seconds", type=int, default=10)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--modes", default="none,module,ebpf-generic,ebpf-native,none-egress,ebpf-tc")
    parser.add_argument("--flame", action="store_true")
    parser.add_argument("--out", default=str(ROOT / "docs" / "bench"))
    args = parser.parse_args()
    if os.geteuid():
        raise SystemExit("run as root")
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    teardown()
    setup()
    runs = []
    try:
        for rep in range(args.repeat):
            for mode in args.modes.split(","):
                r = run_mode(mode, args.seconds, args.flame and rep == 0, out_dir)
                r["repeat"] = rep
                runs.append(r)
                print(json.dumps(r), flush=True)
    finally:
        teardown()
    json.dump({"machine": machine(), "seconds": args.seconds, "runs": runs},
              open(out_dir / "results.json", "w"), indent=2)
    print(f"wrote {out_dir / 'results.json'}")


if __name__ == "__main__":
    main()
