#!/usr/bin/env bash
#
# Run the kernel test suite on a kernel built with the kernel's own bug
# detectors, then report what they found:
#
#   lockdep (PROVE_LOCKING)  lock-order and IRQ-safety bugs, i.e. deadlocks
#                            that have not happened yet
#   KCSAN                    data races (default build)
#   KASAN + UBSAN            out-of-bounds and use-after-free accesses,
#                            undefined behaviour (DEBUG_FLAVOR=kasan)
#   kmemleak                 leaked allocations, scanned after unloading
#
# Usage: [DEBUG_FLAVOR=kcsan|kasan] kernel/tests/debug_kernel.sh /path/to/linux-source
#   Builds the kernel there with the config in tests/debug.config (KCSAN)
#   or tests/debug-kasan.config, builds kguard.ko against it in a copy of
#   kernel/, boots it and runs tests/vm_tests.py. KASAN and KCSAN cannot be
#   in one kernel, so P8.3 takes one run of each. SKIP_BUILD=1 reuses the
#   kernel already built there.
#
# Timing checks fail under KCSAN in an emulated VM (10x slower); what
# matters is the report at the end: no lockdep or KCSAN report naming
# kguard, and no kmemleak object from kguard.

set -euo pipefail

SRC="${1:?usage: $0 /path/to/linux-source}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d /tmp/kguard-debug-XXXXXX)"

CONFIG="$HERE/tests/debug.config"
[[ "${DEBUG_FLAVOR:-kcsan}" == kasan ]] && CONFIG="$HERE/tests/debug-kasan.config"
if [[ -z "${SKIP_BUILD:-}" ]]; then
    if [[ -f "$SRC/.config" ]]; then
        # vng --build keeps an existing .config, so merge the fragment ourselves
        (cd "$SRC" && scripts/kconfig/merge_config.sh -m .config "$CONFIG" >/dev/null &&
            make olddefconfig >/dev/null && make -j"$(nproc)" >/dev/null)  # all: also refreshes Module.symvers
    else
        (cd "$SRC" && vng --build --config "$CONFIG" --jobs "$(nproc)")
    fi
fi
cp -r "$HERE" "$WORK/kguard"
make -C "$WORK/kguard" KDIR="$SRC" clean >/dev/null
make -C "$WORK/kguard" KDIR="$SRC"
make -C "$WORK/kguard" tools >/dev/null

PATTERN="WARNING:|BUG:|KASAN|UBSAN|possible circular|possible recursive|inconsistent lock|suspicious RCU|data-race|sleeping function"
cat > "$WORK/run.sh" <<SCRIPT
mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
mount -t tracefs none /sys/kernel/tracing 2>/dev/null || true
cd "$WORK/kguard"
echo clear > /sys/kernel/debug/kmemleak
# Detector reports as they happen, so a run cut short still shows them
dmesg -w | grep --line-buffered -E "$PATTERN" | sed -u 's/^/live: /' &
python3 -u tests/vm_tests.py 2>&1 | grep --line-buffered -E "^(PASS|FAIL|SKIP)|checks passed|Traceback"
echo "=== detector findings"
echo scan > /sys/kernel/debug/kmemleak; sleep 6; echo scan > /sys/kernel/debug/kmemleak
echo "kmemleak objects from kguard: \$(grep -c kguard /sys/kernel/debug/kmemleak || true)"
dmesg | grep -E "$PATTERN" || true
SCRIPT

args=(--cpus 4 --memory 4G --exec "bash $WORK/run.sh")
[[ -e /dev/kvm ]] || args+=(--disable-kvm)
vng -r "$SRC/arch/x86/boot/bzImage" "${args[@]}" 2>&1 | tee "$WORK/log" | grep -E '^live: |=== detector|kmemleak objects|checks passed' || true
echo "Full log: $WORK/log"
