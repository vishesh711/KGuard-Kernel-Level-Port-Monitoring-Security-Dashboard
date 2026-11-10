#!/usr/bin/env python3
"""
KGuard benchmarks (roadmap P8.7). Run as root, in a VM or on a test box:

    sudo python3 scripts/benchmark.py [--seconds 10] [--out docs/bench]

A generator (trafgen by default, or the kernel's pktgen) floods 60-byte
UDP frames from one end of a veth pair into a network namespace ("dut")
where the monitoring runs, in each mode:

    none          nothing loaded
    module        the KGuard kernel module (Netfilter hooks), a reader
                  draining /dev/kguard (kernel/tools/kguard_reader)
    ebpf-generic  the agent's eBPF engine, XDP in generic (skb) mode
    ebpf-native   the agent's eBPF engine, XDP in native (driver) mode

and, the other way, the generator sending out of "dut" through the qdisc
layer, so the agent's TC egress program sees every packet:

    none-egress   nothing loaded
    ebpf-tc       the agent's eBPF engine (its TC clsact egress program)

For each mode it records:
    pps           packets per second reaching IP in "dut" (Ip InReceives)
    device_rx     frames the receiving veth took in during the window; with
                  backlog_drops (full per-CPU queues) it shows where the
                  frames that never reached IP went
    cpu_ns/pkt    all CPU time spent (kernel + softirq, every CPU) per packet
    extra ns/pkt  cpu_ns/pkt minus the baseline run in the same direction
    own ns/pkt    the component's own measure: the module's ns_per_packet
                  counter, or the BPF programs' run_time_ns / run_cnt
    lost          events dropped (module rings / eBPF ring buffer)

and, with --flame, a perf profile of each mode as a flame graph SVG.
Results go to <out>/results.json and <out>/*.svg.

Why trafgen: pktgen keeps extra references on the skb it resends, and
generic (skb) XDP on a veth then calls pskb_expand_head() on that shared
skb, which is a kernel BUG() (seen on 6.8: "kernel BUG at
net/core/skbuff.c:2138" from netif_receive_generic_xdp). trafgen sends
from a PF_PACKET ring, one fresh skb per frame, so every mode can run.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "kernel" / "kguard.ko"
READER = ROOT / "kernel" / "tools" / "kguard_reader"
AGENT = ROOT / "agent" / "build" / "kguard-agent"
NS = "dut"
SEND, RECV = "bsend", "brecv"
SRC_IP, DST_IP = "10.250.0.1", "10.250.0.2"
# Seconds of flooding before the measurement window opens
WARMUP = 1
# trafgen maps a scratch file in its working directory: keep that on tmpfs
SCRATCH = "/run/kguard-bench"


def sh(cmd, check=True, **kw):
    r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)
    if check and r.returncode:
        raise RuntimeError(f"{cmd}: {r.stderr.strip()}")
    return r.stdout


NS_ANCHOR = None  # a process inside "dut": its /proc/<pid>/net shows that namespace


def setup():
    global NS_ANCHOR
    sh(f"ip netns add {NS}")
    sh(f"ip link add {SEND} type veth peer name {RECV}")
    sh(f"ip link set {RECV} netns {NS}")
    sh(f"ip addr add {SRC_IP}/24 dev {SEND}; ip link set {SEND} up")
    sh(f"ip -n {NS} addr add {DST_IP}/24 dev {RECV}; ip -n {NS} link set {RECV} up; ip -n {NS} link set lo up")
    NS_ANCHOR = subprocess.Popen(["ip", "netns", "exec", NS, "sleep", "infinity"])
    # Native XDP on a veth needs an XDP program (or GRO) on the peer too
    sh(f"ethtool -K {SEND} gro on", check=False)
    sh("modprobe pktgen")
    os.makedirs(SCRATCH, exist_ok=True)
    if not os.path.ismount(SCRATCH):
        sh(f"mount -t tmpfs none {SCRATCH}")
    sh("sysctl -qw kernel.bpf_stats_enabled=1", check=False)


def teardown():
    if NS_ANCHOR:
        NS_ANCHOR.kill()
        NS_ANCHOR.wait()
    # Deleting one end of the veth pair deletes both; give up rather than
    # hang if the kernel still holds a reference to the device
    for cmd in (f"ip link del {SEND}", f"ip netns del {NS}"):
        try:
            sh(cmd, check=False, timeout=30)
        except subprocess.TimeoutExpired:
            print(f"teardown: '{cmd}' did not finish in 30 s", file=sys.stderr, flush=True)
    if os.path.exists("/sys/module/kguard"):
        sh("rmmod kguard", check=False)
    if os.path.ismount(SCRATCH):
        sh(f"umount {SCRATCH}", check=False)


def pgset(path, line, netns=None):
    if netns:
        sh(["ip", "netns", "exec", netns, "sh", "-c", f"echo '{line}' > {path}"])
        return
    with open(path, "w") as f:
        f.write(line + "\n")


def is_egress(mode):
    return mode in ("none-egress", "ebpf-tc")


def pktgen(egress, measure):
    """Flood into "dut" (ingress) or out of it through the qdisc layer while measure() runs"""
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
    else:
        runner = threading.Thread(target=lambda: pgset("/proc/net/pktgen/pgctrl", "start"))
        runner.start()
    try:
        time.sleep(WARMUP)
        return measure()
    finally:
        pgset("/proc/net/pktgen/pgctrl", "stop", netns)
        runner.wait() if egress else runner.join()


def trafgen(egress, measure):
    """Flood with trafgen (one CPU), the same frames as pktgen(), while measure() runs"""
    netns, dev_name, src, dst = (NS, RECV, DST_IP, SRC_IP) if egress else (None, SEND, SRC_IP, DST_IP)
    peer = sh(["ip", "-j", "link", "show", SEND] if egress else ["ip", "-n", NS, "-j", "link", "show", RECV])
    mac = json.loads(peer)[0]["address"]
    conf = tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False, dir=SCRATCH)
    conf.write(f"{{ eth(da={mac}), ipv4(saddr={src}, daddr={dst}, ttl=64), udp(sp=9, dp=5001), fill(0, 18) }}\n")
    conf.close()
    cmd = ["trafgen", "--dev", dev_name, "--conf", conf.name, "--cpus", "1"]
    if egress:
        cmd = ["ip", "netns", "exec", netns] + cmd + ["--qdisc-path"]  # through TC egress
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, cwd=SCRATCH)
    try:
        time.sleep(WARMUP)
        if proc.poll() is not None:
            raise RuntimeError(f"trafgen: {proc.communicate()[1].strip()[-300:]}")
        return measure()
    finally:
        # trafgen takes many seconds to honour SIGINT under emulation; the
        # numbers are already taken, so stop it outright
        proc.kill()
        proc.wait()
        os.unlink(conf.name)


def proc_net(egress, name):
    """/proc/net/<name> of the receiving side, read directly (no subprocess)"""
    return open(f"/proc/net/{name}" if egress else f"/proc/{NS_ANCHOR.pid}/net/{name}").read()


def in_receives(egress=False):
    """Ip InReceives at the receiving end"""
    head, values = [line.split() for line in proc_net(egress, "snmp").splitlines() if line.startswith("Ip:")][:2]
    return int(values[head.index("InReceives")])


def device_rx(egress=False):
    """Frames the receiving veth took in (counted before the stack sees them)"""
    dev = SEND if egress else RECV
    for line in proc_net(egress, "dev").splitlines():
        name, _, rest = line.partition(":")
        if name.strip() == dev:
            return int(rest.split()[1])
    return 0


def softnet_dropped():
    """Packets dropped because a CPU's backlog queue was full (all CPUs)"""
    return sum(int(line.split()[1], 16) for line in open("/proc/net/softnet_stat"))


def cpu_busy_ns():
    """Kernel + irq + softirq time of every CPU, in ns"""
    tick_ns = 1e9 / os.sysconf("SC_CLK_TCK")
    fields = open("/proc/stat").readline().split()[1:]
    user, nice, system, idle, iowait, irq, softirq = map(int, fields[:7])
    return (system + irq + softirq) * tick_ns


def snapshot(egress):
    """Every counter of the window, read back to back from /proc"""
    return (time.monotonic(), in_receives(egress), device_rx(egress), softnet_dropped(), cpu_busy_ns())


def module_stats():
    out = sh([sys.executable, str(ROOT / "kernel" / "tools" / "kguardctl.py"), "--json", "stats"], check=False)
    try:
        return json.loads(out)
    except ValueError:
        return {}


def bpf_run_stats():
    """run_time_ns and run_cnt of each XDP and TC program (needs kernel.bpf_stats_enabled)"""
    try:
        progs = json.loads(sh("bpftool -j prog show"))
    except (RuntimeError, ValueError):
        return {}
    return {f"{p.get('name', '?')}#{p['id']}": (p.get("run_time_ns", 0), p.get("run_cnt", 0))
            for p in progs if p.get("type") in ("xdp", "sched_cls")}


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
        log = open(f"/tmp/kguard-bench-agent-{mode}.log", "w+")
        agent = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=log, text=True)
        agent.log = log
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
            p.wait(timeout=20)
        except subprocess.TimeoutExpired:
            p.kill()
        out = ""
        if hasattr(p, "log"):
            p.log.seek(0)
            out = p.log.read()
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


def run_mode(mode, seconds, flame, out_dir, generator="trafgen"):
    procs = start_mode(mode)
    egress = is_egress(mode)
    extra = {}

    def measure():
        """One window of `seconds` while the generator floods, then (--flame) a
        separate profiling window, so perf's own cost stays out of the numbers"""
        stats_before, bpf_before = module_stats(), bpf_run_stats()
        t0, recv0, rx0, drop0, cpu0 = snapshot(egress)
        time.sleep(seconds)
        t1, recv1, rx1, drop1, cpu1 = snapshot(egress)
        extra["device_rx"] = rx1 - rx0
        extra["backlog_drops"] = drop1 - drop0
        numbers = (recv1 - recv0, cpu1 - cpu0, t1 - t0, stats_before, module_stats(), bpf_before, bpf_run_stats())
        if flame:
            subprocess.run(["perf", "record", "-a", "-g", "-F", "499", "-o", f"/tmp/perf-{mode}.data",
                            "--", "sleep", str(seconds)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return numbers

    try:
        time.sleep(1)
        recv, cpu, elapsed, stats_before, stats_after, bpf_before, bpf_after = \
            (trafgen if generator == "trafgen" else pktgen)(egress, measure)
        if flame:
            flame_svg(fold_perf(f"/tmp/perf-{mode}.data"), f"KGuard benchmark: {mode}", out_dir / f"flame-{mode}.svg")
    finally:
        lost = stop_mode(mode, procs)
    result = {"mode": mode, "direction": "egress" if is_egress(mode) else "ingress",
              "seconds": round(elapsed, 2), "packets": recv, "pps": round(recv / elapsed),
              "cpu_ns_per_packet": round(cpu / recv, 1) if recv else None, **extra}
    if mode == "module":
        result["own_ns_per_packet"] = stats_after.get("ns_per_packet")
        result["lost"] = stats_after.get("dropped", 0) - stats_before.get("dropped", 0)
    elif mode.startswith("ebpf"):
        programs = {}
        for name, (ns, cnt) in bpf_after.items():
            ns0, cnt0 = bpf_before.get(name, (0, 0))
            if cnt - cnt0:
                programs[name] = {"runs": cnt - cnt0, "ns_per_run": round((ns - ns0) / (cnt - cnt0), 1)}
        # Each packet runs the direction's program once: XDP in, TC egress out.
        # (The bpftool snapshots straddle the window, so run counts cover a
        # few seconds more than it; the time per run does not depend on that.)
        main = "kguard_tc_egress" if egress else "kguard_xdp"
        runs = [p for name, p in programs.items() if name.startswith(main + "#")]
        result["own_ns_per_packet"] = runs[0]["ns_per_run"] if runs else None
        result["bpf_programs"] = programs
        result["lost"] = lost
    return result


def machine():
    cpu = next((line.split(":", 1)[1].strip() for line in open("/proc/cpuinfo") if line.startswith("model name")), "?")
    virt = sh("systemd-detect-virt", check=False).strip() or "unknown"
    # The "hypervisor" CPU flag is set under emulation too; QEMU names its TCG CPU model
    accel = "tcg (emulated, no KVM)" if "TCG" in cpu else ("none" if virt == "none" else "hardware-assisted")
    return {"kernel": os.uname().release, "cpu": cpu, "cpus": os.cpu_count(), "virtualization": virt,
            "accelerator": accel}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seconds", type=int, default=10)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--modes", default="none,module,ebpf-generic,ebpf-native,none-egress,ebpf-tc")
    parser.add_argument("--flame", action="store_true")
    parser.add_argument("--generator", choices=["trafgen", "pktgen"], default="trafgen")
    parser.add_argument("--out", default=str(ROOT / "docs" / "bench"))
    args = parser.parse_args()
    if os.geteuid():
        raise SystemExit("run as root")
    if args.generator == "pktgen" and "ebpf-generic" in args.modes.split(","):
        raise SystemExit("pktgen with generic XDP hits a kernel BUG() (shared skb); use --generator trafgen")
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    teardown()
    setup()
    runs = []
    try:
        for rep in range(args.repeat):
            for mode in args.modes.split(","):
                try:
                    r = run_mode(mode, args.seconds, args.flame and rep == 0, out_dir, args.generator)
                except Exception:
                    traceback.print_exc()
                    sys.stdout.flush()
                    raise
                r["repeat"] = rep
                runs.append(r)
                print(json.dumps(r), flush=True)
    finally:
        teardown()
    json.dump({"machine": machine(), "seconds": args.seconds, "generator": args.generator, "runs": runs},
              open(out_dir / "results.json", "w"), indent=2)
    print(f"wrote {out_dir / 'results.json'}")


if __name__ == "__main__":
    main()
