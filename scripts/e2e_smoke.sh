#!/usr/bin/env bash
#
# KGuard end-to-end smoke test (roadmap task E1.1)
#
# Loads the kernel module, starts the backend against /proc/kguard, port-scans
# localhost and checks that a PORT_SCAN alert comes back through the API.
#
# Needs: root, kernel headers for the running kernel, python3 with the backend
# requirements installed, curl, and nmap (falls back to bash /dev/tcp if missing).
# Run it in a VM or a disposable machine: it loads a kernel module.
#
# Usage: sudo scripts/e2e_smoke.sh [python-binary]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${1:-python3}"
PORT="${KGUARD_E2E_PORT:-8765}"
API="http://127.0.0.1:${PORT}"
WORK="$(mktemp -d /tmp/kguard-e2e.XXXXXX)"
BACKEND_PID=""

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
    if [[ -n "$BACKEND_PID" ]]; then
        kill "$BACKEND_PID" 2>/dev/null || true
        wait "$BACKEND_PID" 2>/dev/null || true
    fi
    if lsmod | grep -q '^kguard '; then
        rmmod kguard || true
    fi
    if [[ -f "$WORK/backend.log" ]] && [[ "${KEEP_LOGS:-0}" == "1" ]]; then
        echo "Backend log kept at $WORK/backend.log"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

[[ $EUID -eq 0 ]] || fail "run as root (sudo $0)"
command -v curl >/dev/null || fail "curl is required"

echo "== Building kernel module"
make -C "$ROOT/kernel" >/dev/null
pass "module built"

echo "== Loading kernel module"
if lsmod | grep -q '^kguard '; then
    rmmod kguard
fi
insmod "$ROOT/kernel/kguard.ko" buffer_size=65536
[[ -r /proc/kguard ]] || fail "/proc/kguard missing after insmod"
pass "module loaded, /proc/kguard present"

echo "== Starting backend"
(
    cd "$ROOT/backend"
    DATABASE_URL="sqlite:///$WORK/kguard-e2e.db" \
    PROC_KGUARD_PATH=/proc/kguard \
    DATA_COLLECTION_INTERVAL=0.5 \
    DEBUG=true \
    exec "$PYTHON" -m uvicorn app.main:app --host 127.0.0.1 --port "$PORT"
) >"$WORK/backend.log" 2>&1 &
BACKEND_PID=$!

for _ in $(seq 1 30); do
    if curl -sf "$API/api/health/" >/dev/null; then break; fi
    sleep 0.5
done
curl -sf "$API/api/health/" >/dev/null || { cat "$WORK/backend.log" >&2; fail "backend did not start"; }

kernel_ok=$(curl -sf "$API/api/health/" | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["kernel_module"])')
[[ "$kernel_ok" == "True" ]] || fail "backend cannot see the kernel module"
pass "backend running and sees the kernel module"

echo "== Scanning 127.0.0.1"
if command -v nmap >/dev/null; then
    nmap -sS -Pn -n -p 1-200 --max-retries 0 127.0.0.1 >/dev/null
else
    echo "(nmap not found, using bash /dev/tcp)"
    for p in $(seq 1 60); do
        timeout 0.2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$p" 2>/dev/null || true
    done
fi

echo "== Waiting for the PORT_SCAN alert"
found=""
for _ in $(seq 1 30); do
    found=$(curl -sf "$API/api/alerts/?alert_type=PORT_SCAN" | "$PYTHON" -c '
import json, sys
items = json.load(sys.stdin)["items"]
print(items[0]["src_ip"] if items else "")')
    [[ -n "$found" ]] && break
    sleep 0.5
done
[[ -n "$found" ]] || { tail -50 "$WORK/backend.log" >&2; fail "no PORT_SCAN alert"; }
pass "PORT_SCAN alert raised for $found"

events=$(curl -sf "$API/api/events/stats/summary?hours=1" | "$PYTHON" -c 'import json,sys; d=json.load(sys.stdin); print(d["total_events"], d["suspicious_events"])')
pass "events stored / flagged suspicious: $events"

dropped=$(curl -sf "$API/api/health/kernel" | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["details"]["kernel_events_dropped"])')
[[ "$dropped" == "0" ]] || fail "kernel dropped $dropped events"
pass "no events dropped by the kernel buffer"

echo "All end-to-end checks passed."
