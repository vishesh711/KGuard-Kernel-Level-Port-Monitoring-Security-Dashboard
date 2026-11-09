#!/usr/bin/env bash
#
# Run the kernel test suite on a kernel built with the kernel's own bug
# detectors, then report what they found:
#
#   lockdep (PROVE_LOCKING)  lock-order and IRQ-safety bugs, i.e. deadlocks
#                            that have not happened yet
#   KCSAN                    data races
#   kmemleak                 leaked allocations, scanned after unloading
#
# Usage: kernel/tests/debug_kernel.sh /path/to/linux-source
#   Builds the kernel there with virtme-ng (vng --build) and the config in
#   tests/debug.config, builds kguard.ko against it in a copy of kernel/,
#   boots it and runs tests/vm_tests.py.
#
# Timing checks fail under KCSAN in an emulated VM (10x slower); what
# matters is the report at the end: no lockdep or KCSAN report naming
# kguard, and no kmemleak object from kguard.

set -euo pipefail

SRC="${1:?usage: $0 /path/to/linux-source}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d /tmp/kguard-debug-XXXXXX)"

(cd "$SRC" && vng --build --config "$HERE/tests/debug.config" --jobs "$(nproc)")
cp -r "$HERE" "$WORK/kguard"
make -C "$WORK/kguard" clean >/dev/null
make -C "$WORK/kguard" KDIR="$SRC"
make -C "$WORK/kguard" tools >/dev/null

cat > "$WORK/run.sh" <<SCRIPT
mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
mount -t tracefs none /sys/kernel/tracing 2>/dev/null || true
cd "$WORK/kguard"
echo clear > /sys/kernel/debug/kmemleak
python3 -u tests/vm_tests.py 2>&1 | grep --line-buffered -E "^(PASS|FAIL|SKIP)|checks passed|Traceback"
echo "=== detector findings"
echo scan > /sys/kernel/debug/kmemleak; sleep 6; echo scan > /sys/kernel/debug/kmemleak
echo "kmemleak objects from kguard: \$(grep -c kguard /sys/kernel/debug/kmemleak || true)"
dmesg | grep -E "WARNING:|BUG:|possible circular|possible recursive|inconsistent lock|suspicious RCU|data-race|sleeping function" || true
SCRIPT

args=(--cpus 4 --memory 4G --exec "bash $WORK/run.sh")
[[ -e /dev/kvm ]] || args+=(--disable-kvm)
vng -r "$SRC/arch/x86/boot/bzImage" "${args[@]}" 2>&1 | tee "$WORK/log" | sed -n '/=== detector findings/,$p'
echo "Full log: $WORK/log"
