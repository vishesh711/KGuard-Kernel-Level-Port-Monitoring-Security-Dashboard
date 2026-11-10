#!/usr/bin/env python3
"""
Turn docs/bench/results.json (scripts/benchmark.py) into a Markdown table
and SVG bar charts:

    python3 scripts/bench_report.py [docs/bench/results.json]

Writes docs/bench/pps.svg and docs/bench/cost.svg and prints the table
(median of the repeats, with the range) for docs/BENCHMARKS.md.
"""

import json
import statistics
import sys
from pathlib import Path

ORDER = ["none", "module", "ebpf-generic", "ebpf-native", "none-egress", "ebpf-tc"]
LABEL = {"none": "no monitoring", "module": "C module (Netfilter)", "ebpf-generic": "eBPF XDP, generic",
         "ebpf-native": "eBPF XDP, native", "none-egress": "no monitoring (egress)", "ebpf-tc": "eBPF TC egress"}
BASE = {"none": "none", "module": "none", "ebpf-generic": "none", "ebpf-native": "none",
        "none-egress": "none-egress", "ebpf-tc": "none-egress"}


def median_range(values):
    values = [v for v in values if v is not None]
    if not values:
        return None, None, None
    return statistics.median(values), min(values), max(values)


def bar_chart(rows, title, unit, path, color):
    """Horizontal bars: rows = [(label, value)]"""
    width, left, bar_h, gap = 720, 190, 22, 10
    top = 34
    height = top + len(rows) * (bar_h + gap) + 10
    peak = max((v for _, v in rows if v), default=1) or 1
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" font-family="sans-serif" '
           f'font-size="12"><rect width="100%" height="100%" fill="#fff"/>'
           f'<text x="8" y="20" font-size="14" font-weight="bold">{title}</text>']
    for i, (label, value) in enumerate(rows):
        y = top + i * (bar_h + gap)
        w = (value or 0) / peak * (width - left - 110)
        out.append(f'<text x="{left - 8}" y="{y + 15}" text-anchor="end">{label}</text>')
        out.append(f'<rect x="{left}" y="{y}" width="{w:.1f}" height="{bar_h}" fill="{color}"/>')
        text = "n/a" if value is None else f"{value:,.0f} {unit}"
        out.append(f'<text x="{left + w + 6:.1f}" y="{y + 15}">{text}</text>')
    out.append("</svg>")
    Path(path).write_text("\n".join(out))


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/bench/results.json")
    data = json.loads(path.read_text())
    by_mode = {}
    for r in data["runs"]:
        by_mode.setdefault(r["mode"], []).append(r)
    summary = {}
    for mode in ORDER:
        runs = by_mode.get(mode)
        if not runs:
            continue
        summary[mode] = {
            "pps": median_range([r["pps"] for r in runs]),
            "cpu": median_range([r["cpu_ns_per_packet"] for r in runs]),
            "own": median_range([r.get("own_ns_per_packet") for r in runs]),
            "lost": sum(r.get("lost") or 0 for r in runs),
            "n": len(runs),
        }
    m = data["machine"]
    print(f"Machine: {m['cpu']}, {m['cpus']} CPUs, kernel {m['kernel']}, virtualization: {m['virtualization']}; "
          f"{data['seconds']} s per run, median of {max(s['n'] for s in summary.values())} runs (range in brackets)\n")
    print("| Mode | Packets/s | CPU ns/packet | Added ns/packet | Own ns/packet | Events lost |")
    print("|---|---:|---:|---:|---:|---:|")
    for mode, s in summary.items():
        pps, cpu, own = s["pps"], s["cpu"], s["own"]
        base = summary.get(BASE[mode], {}).get("cpu", (None,))[0]
        extra = "–" if mode == BASE[mode] or base is None or cpu[0] is None else f"{cpu[0] - base:+,.0f}"
        own_text = "–" if own[0] is None else f"{own[0]:,.0f} [{own[1]:,.0f}–{own[2]:,.0f}]"
        lost = "–" if mode.startswith("none") else f"{s['lost']:,}"
        print(f"| {LABEL[mode]} | {pps[0]:,.0f} [{pps[1]:,.0f}–{pps[2]:,.0f}] | "
              f"{cpu[0]:,.0f} [{cpu[1]:,.0f}–{cpu[2]:,.0f}] | {extra} | {own_text} | {lost} |")
    out = path.parent
    bar_chart([(LABEL[k], v["pps"][0]) for k, v in summary.items()], "Packets per second (higher is better)",
              "pps", out / "pps.svg", "#3b82f6")
    bar_chart([(LABEL[k], v["cpu"][0]) for k, v in summary.items()], "CPU time per packet (lower is better)",
              "ns", out / "cost.svg", "#f97316")


if __name__ == "__main__":
    main()
