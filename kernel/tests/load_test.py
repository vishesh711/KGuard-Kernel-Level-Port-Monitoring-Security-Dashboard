#!/usr/bin/env python3
"""
KGuard kernel load test (roadmap K1.2 / K1.3).

Sends UDP packets to 127.0.0.1 at a fixed rate while reading /proc/kguard,
then checks that the number of incoming events equals the number of packets
the loopback interface received, that every packet was also seen leaving,
and that the kernel dropped none.

Run as root with the module loaded, on an otherwise idle machine or VM.

Usage: load_test.py [--rate 5000] [--seconds 4] [--chunk 0]
  --chunk N  read /proc/kguard N bytes at a time (forces seq_file to stop and
             resume mid-record many times); 0 reads it in one go.
"""

import argparse
import json
import os
import socket
import threading
import time

PROC = "/proc/kguard"


def lo_ipv4_rx_packets():
    """IPv4 packets received on lo (from /proc/net/snmp would include all
    interfaces, so count via the interface counter and ignore IPv6 traffic:
    the test sends only IPv4)."""
    with open("/sys/class/net/lo/statistics/rx_packets") as f:
        return int(f.read())


def read_kguard(chunk):
    fd = os.open(PROC, os.O_RDONLY)
    try:
        parts = []
        while True:
            data = os.read(fd, chunk if chunk else 1 << 20)
            if not data:
                break
            parts.append(data)
    finally:
        os.close(fd)
    doc = json.loads(b"".join(parts))
    return doc["events"], doc["dropped"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rate", type=int, default=5000, help="packets per second to send")
    parser.add_argument("--seconds", type=float, default=4.0)
    parser.add_argument("--chunk", type=int, default=0)
    args = parser.parse_args()

    read_kguard(args.chunk)  # empty the buffer first
    rx_before = lo_ipv4_rx_packets()

    events = []
    dropped = 0
    stop = threading.Event()

    def reader():
        nonlocal dropped
        while not stop.is_set():
            batch, dropped = read_kguard(args.chunk)
            events.extend(batch)
            time.sleep(0.25)

    t = threading.Thread(target=reader)
    t.start()

    # A bound socket on the target port, so no ICMP "port unreachable" replies
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind(("127.0.0.1", 0))
    sink.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
    port = sink.getsockname()[1]
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    total = int(args.rate * args.seconds)
    start = time.monotonic()
    for i in range(total):
        tx.sendto(b"k", ("127.0.0.1", port))
        # pace to the target rate
        ahead = (i + 1) / args.rate - (time.monotonic() - start)
        if ahead > 0.001:
            time.sleep(ahead)
    elapsed = time.monotonic() - start

    time.sleep(0.5)
    stop.set()
    t.join()
    batch, dropped = read_kguard(args.chunk)
    events.extend(batch)

    rx = lo_ipv4_rx_packets() - rx_before
    to_port = [e for e in events if e["protocol"] == "UDP" and e["dst_port"] == port]
    in_events = sum(1 for e in events if e.get("direction", "in") == "in")
    out_to_port = sum(1 for e in to_port if e.get("direction") == "out")
    in_to_port = len(to_port) - out_to_port

    print(f"sent            {total} packets in {elapsed:.2f}s ({total / elapsed:.0f}/s)")
    print(f"lo received     {rx} packets")
    print(f"events read     {len(events)} ({in_events} incoming)")
    print(f"test port       {in_to_port} in, {out_to_port} out")
    print(f"kernel dropped  {dropped}")

    ok = dropped == 0 and in_to_port == total and out_to_port == total and in_events == rx
    print("RESULT", "PASS" if ok else "FAIL")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
