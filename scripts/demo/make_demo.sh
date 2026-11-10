#!/usr/bin/env bash
#
# Record docs/images/demo.gif: real attacks against KGuard in a throwaway VM,
# seen in the dashboard (capture.py, capture.js), then frames -> GIF.
#
# Environment: KERNEL_IMAGE, KDIR (as for scripts/attack_demo.sh),
# BACKEND_PY (python with the backend's packages). Needs virtme-ng, nmap,
# hping3, sshd, Node with Playwright, and Pillow (PYTHON=python with Pillow).
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD
BACKEND_PY="${BACKEND_PY:-$ROOT/backend/.venv/bin/python}"
DIST=/tmp/kguard-demo-dist
FRAMES="$ROOT/docs/images/demo-frames"

make -C kernel ${KDIR:+KDIR="$KDIR"} >/dev/null
(cd frontend && VITE_API_BASE_URL=http://127.0.0.1:8790 VITE_WS_URL=ws://127.0.0.1:8790/ws \
    npx vite build --outDir "$DIST" >/dev/null)
rm -rf "$FRAMES"; mkdir -p "$FRAMES"

args=(--cpus 4 --memory 3G --rw)
[[ -e /dev/kvm ]] || args+=(--disable-kvm)
[[ -n "${KERNEL_IMAGE:-}" ]] && args+=(--run "$KERNEL_IMAGE")
timeout "${VM_TIMEOUT:-3600}" vng "${args[@]}" --exec \
    "cd '$ROOT' && python3 scripts/demo/capture.py '$BACKEND_PY' '$DIST' '$FRAMES' > '$FRAMES/capture.log' 2>&1"
cat "$FRAMES/capture.log"
"${PYTHON:-python3}" scripts/demo/frames_to_gif.py "$FRAMES" docs/images/demo.gif
