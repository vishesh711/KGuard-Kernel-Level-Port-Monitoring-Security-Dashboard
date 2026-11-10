#!/usr/bin/env bash
#
# Run scripts/benchmark.py in a throwaway VM (virtme-ng), roadmap P8.7.
#
#   scripts/bench_vm.sh [benchmark.py options]     e.g. --seconds 10 --flame
#   make bench
#
# Environment: KERNEL_IMAGE (default: the running kernel), KDIR (headers
# for the module build), VM_CPUS (default 4). Uses KVM when /dev/kvm exists;
# without it the VM is emulated (TCG) and every number is far below what
# real hardware does, so results.json records the virtualization in use.

set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
command -v vng >/dev/null || { echo "virtme-ng not found: pip install virtme-ng" >&2; exit 2; }
make -C kernel ${KDIR:+KDIR="$KDIR"} >/dev/null
make -C kernel tools >/dev/null
make -C agent >/dev/null

vm_args=(--cpus "${VM_CPUS:-4}" --memory 2G --rw)
[[ -e /dev/kvm ]] || vm_args+=(--disable-kvm)
[[ -n "${KERNEL_IMAGE:-}" ]] && vm_args+=(--run "$KERNEL_IMAGE")
args=$(printf '%q ' "$@")
mkdir -p docs/bench
timeout "${VM_TIMEOUT:-3600}" vng "${vm_args[@]}" --exec \
    "cd '$ROOT' && python3 scripts/benchmark.py $args > /tmp/kguard-bench-run.log 2>&1; cp /tmp/kguard-bench-*.log '$ROOT/docs/bench/' 2>/dev/null"
cat docs/bench/kguard-bench-run.log
