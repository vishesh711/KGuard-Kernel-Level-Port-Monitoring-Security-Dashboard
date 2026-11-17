#!/usr/bin/env python3
"""
Fill a KGuard backend with sample traffic and attacks, so the dashboard has
something to show where no kernel module runs (Docker Desktop on a Mac, for
example).

Two demo hosts enroll as agents and send events over the normal agent API;
the backend's real detectors then raise the alerts. The named attackers use
documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so no
real host is accused; KGuard flags those as impossible sources too, as it should.

    AGENT_ENROLLMENT_KEY=<key> python3 scripts/demo/seed.py [--url http://localhost:8000]

The backend needs the same AGENT_ENROLLMENT_KEY (put it in .env and restart).
Only the Python standard library is used.
"""

import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request

SYN, ACK, PSH_ACK, XMAS = 0x02, 0x10, 0x18, 0x29  # FIN|PSH|URG
NS = 1_000_000_000


def call(url, path, body, headers):
    request = urllib.request.Request(
        url.rstrip("/") + path, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as e:
        sys.exit(f"{path}: HTTP {e.code}: {e.read().decode(errors='replace')[:300]}")
    except urllib.error.URLError as e:
        sys.exit(f"Cannot reach the backend at {url}: {e.reason}")


def event(ts, src, dst, sport, dport, flags=ACK, proto="TCP", ttl=56):
    return {"timestamp": ts, "src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
            "protocol": proto, "flags": flags, "ttl": ttl, "direction": "in"}


def background(dst, now, hours=12):
    """Ordinary traffic over the last hours: web, SSH from the office, DNS"""
    rng = random.Random(dst)
    events = []
    for _ in range(hours * 120):
        ts = now - rng.randint(60, hours * 3600) * NS
        kind = rng.random()
        if kind < 0.7:
            src = f"100.64.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            events.append(event(ts, src, dst, rng.randint(32768, 60999), 443, rng.choice([SYN, ACK, PSH_ACK])))
        elif kind < 0.85:
            events.append(event(ts, "10.20.0.15", dst, rng.randint(32768, 60999), 22, ACK, ttl=63))
        else:
            events.append(event(ts, dst, "10.20.0.2", rng.randint(32768, 60999), 53, 0, "UDP", 64))
    return events


def attacks(dst, now):
    """A SYN scan, an Xmas scan, SSH password guessing and a SYN flood, all in the last minutes"""
    rng = random.Random(1)
    out = []
    t = now - 300 * NS
    out += [event(t + i * 2_000_000, "198.51.100.23", dst, 51515, port, SYN, ttl=49)
            for i, port in enumerate(range(1, 201))]
    t = now - 200 * NS
    out += [event(t + i * 3_000_000, "203.0.113.50", dst, 40404, port, XMAS, ttl=52)
            for i, port in enumerate(range(1, 101))]
    t = now - 120 * NS
    out += [event(t + i * 4 * NS, "192.0.2.77", dst, 40000 + i, 22, SYN, ttl=47) for i in range(25)]
    t = now - 30 * NS
    public = [o for o in range(11, 224) if o not in (100, 127, 169, 172, 192, 198, 203)]  # no special ranges
    for i in range(2000):
        src = f"{rng.choice(public)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        out.append(event(t + i * 1_500_000, src, dst, rng.randint(1024, 65535), 80, SYN, ttl=rng.randint(30, 250)))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default=os.environ.get("KGUARD_URL", "http://localhost:8000"),
                        help="backend address (default http://localhost:8000)")
    parser.add_argument("--key", default=os.environ.get("AGENT_ENROLLMENT_KEY", ""),
                        help="agent enrollment key (default: $AGENT_ENROLLMENT_KEY)")
    args = parser.parse_args()
    if not args.key:
        sys.exit("Set AGENT_ENROLLMENT_KEY (the same value the backend has) or pass --key")

    now = time.time_ns()
    hosts = [("demo-web-1", "10.20.0.10", True), ("demo-db-1", "10.20.0.11", False)]
    for name, address, attacked in hosts:
        agent = call(args.url, "/api/agents/enroll", {"name": name, "hostname": f"{name}.demo"},
                     {"X-Enrollment-Key": args.key})
        events = background(address, now) + (attacks(address, now) if attacked else [])
        events.sort(key=lambda e: e["timestamp"])
        result = call(args.url, "/api/agents/ingest",
                      {"agent": {"engine": "ebpf", "version": "2.0.0", "hostname": f"{name}.demo"}, "events": events},
                      {"Authorization": f"Bearer {agent['token']}"})
        print(f"{name}: {result['accepted']} events sent")
    print("Done. Open the dashboard: the attacks show up under Alerts.")


if __name__ == "__main__":
    main()
