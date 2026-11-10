#!/usr/bin/env bash
#
# Run the kselftest-style tests (TAP) in a throwaway VM (virtme-ng):
# load the freshly built module, run tests/selftests/kguard_test, unload.
#
# Usage: kernel/tests/selftests/run_in_vm.sh [path/to/vmlinuz]
#   With no argument the VM boots the running kernel. KDIR as for make.

set -euo pipefail

cd "$(dirname "$0")/../.."
KERNEL_IMAGE="${1:-}"
OUT="$PWD/tests/out"
mkdir -p "$OUT"
rm -f "$OUT/selftest.tap" "$OUT/selftest_exit"

command -v vng >/dev/null || { echo "virtme-ng not found: pip install virtme-ng" >&2; exit 2; }
make ${KDIR:+KDIR="$KDIR"} >/dev/null
make selftest >/dev/null

args=(--cpus 2 --memory 1G --rwdir "$OUT")
[[ -e /dev/kvm ]] || args+=(--disable-kvm)
[[ -n "$KERNEL_IMAGE" ]] && args+=(--run "$KERNEL_IMAGE")

vng "${args[@]}" --exec \
    "cd '$PWD' && modprobe -a nf_conntrack nf_socket_ipv4 nf_socket_ipv6 && insmod kguard.ko && \
     tests/selftests/kguard_test > '$OUT/selftest.tap' 2>&1; echo \$? > '$OUT/selftest_exit'; rmmod kguard" \
    >/dev/null 2>&1 || true

if [[ ! -f "$OUT/selftest_exit" ]]; then
    echo "The VM did not finish the selftests (boot failure or timeout)" >&2
    exit 2
fi
cat "$OUT/selftest.tap"
exit "$(cat "$OUT/selftest_exit")"
