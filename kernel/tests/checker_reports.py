#!/usr/bin/env python3
"""
Sort the kernel checkers' reports in a debug-kernel run (debug_kernel.sh)
into those that involve kguard and those that do not.

    checker_reports.py LOG

LOG holds the guest's kernel log between "=== kernel log" and "=== end
kernel log". A report starts at a checker's headline (BUG: KCSAN/KASAN,
UBSAN, lockdep, WARNING, ...) and runs to the line that closes it ("====="
for KCSAN and KASAN, "</TASK>" or "---[ end trace" for the others), the
next headline, or 80 lines. It involves kguard when any of its lines
names kguard (a kguard function in a stack, or the module in a WARNING's
"Modules linked in" or RIP line). Prints both lists and exits 1 when a
report involves kguard.

A vanilla debug kernel under load reports some races of its own (e.g.
poll_schedule_timeout/pollwake in fs/select.c, virtqueue_kick_prepare in
virtio); those are listed but not counted against the module.
"""

import re
import sys

HEADLINE = re.compile(r"BUG: |WARNING: |UBSAN: |possible circular locking|possible recursive locking|"
                      r"inconsistent lock state|suspicious RCU usage|sleeping function called")
# KCSAN/KASAN close with a ===== line; WARNING, UBSAN and lockdep end their stack with </TASK>
CLOSING = re.compile(r"^(\[[ 0-9.]+\] )?(=+|\s*</TASK>|---\[ end trace.*)$")
STRIP = re.compile(r"^\[[ 0-9.]+\] ")
MAX_LINES = 80


def kernel_log(text):
    start, end = text.find("=== kernel log"), text.find("=== end kernel log")
    if start < 0:
        return []
    return text[start:end if end > 0 else None].splitlines()[1:]


def reports(lines):
    found, current = [], None
    for line in lines:
        if HEADLINE.search(line) and not line.lstrip().startswith("Modules linked in"):
            if current:
                found.append(current)
            current = [line]
            continue
        if current is None:
            continue
        if CLOSING.match(line.rstrip()) and len(current) > 1:
            if "TASK" in line or "end trace" in line:
                current.append(line)
            found.append(current)
            current = None
            continue
        current.append(line)
        if len(current) >= MAX_LINES:
            found.append(current)
            current = None
    if current:
        found.append(current)
    return found


def main():
    text = open(sys.argv[1], errors="replace").read()
    ours, others = [], []
    for report in reports(kernel_log(text)):
        (ours if any("kguard" in line for line in report) else others).append(report)
    for title, group in (("involving kguard", ours), ("elsewhere in the kernel (not counted)", others)):
        print(f"{len(group)} checker report(s) {title}")
        for report in group:
            print("  " + STRIP.sub("", report[0]).strip())
    if ours:
        print("\nFirst report involving kguard:")
        print("\n".join(ours[0]))
    return 1 if ours else 0


if __name__ == "__main__":
    sys.exit(main())
