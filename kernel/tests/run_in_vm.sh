#!/usr/bin/env bash
#
# Run the kernel module test suite inside a throwaway VM (virtme-ng).
#
# The VM shares this machine's files read-only, loads the freshly built
# module, runs tests/vm_tests.py as root, and is discarded afterwards, so a
# kernel bug cannot take down the host.
#
# Usage: kernel/tests/run_in_vm.sh [path/to/vmlinuz]
#   With no argument the VM boots the running kernel's image.
#   The module is built against KDIR (default: that kernel's headers).
#
# Needs: virtme-ng (pip install virtme-ng), qemu-system-x86, the kernel
# image and its modules under /lib/modules, curl, nc, iproute2.
# Uses KVM when /dev/kvm exists, otherwise software emulation (slower).

set -euo pipefail

cd "$(dirname "$0")/.."
KERNEL_IMAGE="${1:-}"
OUT="$PWD/tests/out"
mkdir -p "$OUT"
rm -f "$OUT/vm_results.txt" "$OUT/vm_exit"

command -v vng >/dev/null || { echo "virtme-ng not found: pip install virtme-ng" >&2; exit 2; }

if [[ -n "$KERNEL_IMAGE" ]]; then
    KVER=$(basename "$KERNEL_IMAGE" | sed 's/^vmlinuz-//')
    : "${KDIR:=/lib/modules/$KVER/build}"
fi
make ${KDIR:+KDIR="$KDIR"} >/dev/null
make tools >/dev/null

args=(--cpus 4 --memory 2G --rwdir "$OUT")
[[ -e /dev/kvm ]] || args+=(--disable-kvm)
[[ -n "$KERNEL_IMAGE" ]] && args+=(--run "$KERNEL_IMAGE")

vng "${args[@]}" --exec \
    "cd '$PWD' && python3 tests/vm_tests.py > '$OUT/vm_results.txt' 2>&1; echo \$? > '$OUT/vm_exit'" \
    >/dev/null 2>&1 || true

if [[ ! -f "$OUT/vm_exit" ]]; then
    echo "The VM did not finish the tests (boot failure or timeout)" >&2
    exit 2
fi
grep -E '^(PASS|FAIL)|checks passed' "$OUT/vm_results.txt"
exit "$(cat "$OUT/vm_exit")"
