#!/usr/bin/env bash
#
# KGuard end-to-end smoke test (roadmap task E1.1)
#
# Loads the kernel module, starts the backend (reading /dev/kguard), port-scans
# localhost and checks that a PORT_SCAN alert comes back through the API, then
# checks that connections are attributed to the right processes.
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
# insmod does not load dependencies
modprobe -a nf_conntrack nf_socket_ipv4 nf_socket_ipv6
insmod "$ROOT/kernel/kguard.ko"
[[ -c /dev/kguard && -r /proc/kguard ]] || fail "/dev/kguard or /proc/kguard missing after insmod"
pass "module loaded, /dev/kguard and /proc/kguard present"

echo "== Starting backend"
(
    cd "$ROOT/backend"
    DATABASE_URL="sqlite:///$WORK/kguard-e2e.db" \
    PROC_KGUARD_PATH=/proc/kguard \
    DATA_COLLECTION_INTERVAL=0.5 \
    DEBUG=true \
    SECRET_KEY="e2e-signing-key-00000000000000000000000000" \
    ADMIN_USERNAME=e2e ADMIN_PASSWORD=e2e-admin-password \
    exec "$PYTHON" -m uvicorn app.main:app --host 127.0.0.1 --port "$PORT"
) >"$WORK/backend.log" 2>&1 &
BACKEND_PID=$!

for _ in $(seq 1 30); do
    if curl -sf "$API/api/health/" >/dev/null; then break; fi
    sleep 0.5
done
curl -sf "$API/api/health/" >/dev/null || { cat "$WORK/backend.log" >&2; fail "backend did not start"; }

# Every API call but the health probe needs a login (roadmap S6.5)
TOKEN=$(curl -sf -H 'Content-Type: application/json' \
    -d '{"username": "e2e", "password": "e2e-admin-password"}' "$API/api/auth/login" |
    "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["access_token"])') || fail "cannot log in"
api_get() { curl -sf -H "Authorization: Bearer $TOKEN" "$@"; }

kernel_ok=$(curl -sf "$API/api/health/" | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["kernel_module"])')
[[ "$kernel_ok" == "True" ]] || fail "backend cannot see the kernel module"
pass "backend running and sees the kernel module"

source=""
for _ in $(seq 1 20); do
    source=$(api_get "$API/api/health/kernel" | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["details"]["source"])')
    [[ "$source" == "device" ]] && break
    sleep 0.5
done
[[ "$source" == "device" ]] || fail "backend is not reading /dev/kguard (source: $source)"
pass "backend reads events through /dev/kguard (zero-copy)"

kdet=""
for _ in $(seq 1 30); do
    kdet=$(api_get "$API/api/health/kernel" | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["details"]["kernel_detection"])')
    [[ "$kdet" == "True" ]] && break
    sleep 0.5
done
[[ "$kdet" == "True" ]] || fail "backend is not receiving in-kernel alerts"
pass "backend subscribed to in-kernel scan and SYN-rate alerts"

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
    found=$(api_get "$API/api/alerts/?alert_type=PORT_SCAN" | "$PYTHON" -c '
import json, sys
items = json.load(sys.stdin)["items"]
print(items[0]["src_ip"] if items else "")')
    [[ -n "$found" ]] && break
    sleep 0.5
done
[[ -n "$found" ]] || { tail -50 "$WORK/backend.log" >&2; fail "no PORT_SCAN alert"; }
pass "PORT_SCAN alert raised for $found"

origin=$(api_get "$API/api/alerts/?alert_type=PORT_SCAN" | "$PYTHON" -c '
import json, sys
items = json.load(sys.stdin)["items"]
print(len(items), (items[0].get("metadata") or {}).get("source", "backend"))')
[[ "$origin" == "1 kernel" ]] || fail "expected one kernel-detected PORT_SCAN alert, got: $origin"
pass "scan detected in the kernel and reported once"

events=$(api_get "$API/api/events/stats/summary?hours=1" | "$PYTHON" -c 'import json,sys; d=json.load(sys.stdin); print(d["total_events"], d["suspicious_events"])')
[[ "${events#* }" -gt 0 ]] || fail "no events were marked suspicious after the scan ($events)"
pass "events stored / flagged suspicious: $events"

echo "== Checking process attribution"
nc -l 127.0.0.1 4446 >/dev/null 2>&1 &
NC_PID=$!
sleep 0.5
curl -s --max-time 1 http://127.0.0.1:4446/ >/dev/null || true
kill "$NC_PID" 2>/dev/null || true
names=""
for _ in $(seq 1 20); do
    names=$(api_get "$API/api/events/?dst_port=4446&size=100" | "$PYTHON" -c '
import json, sys
items = json.load(sys.stdin)["items"]
print(" ".join(sorted({e["direction"] + ":" + e["process_name"] for e in items if e["process_name"]})))')
    [[ "$names" == *"out:curl"* && "$names" == *"in:nc"* ]] && break
    sleep 0.5
done
[[ "$names" == *"out:curl"* ]] || fail "outgoing connection not attributed to curl (got: $names)"
[[ "$names" == *"in:nc"* ]] || fail "incoming connection not attributed to the nc listener (got: $names)"
pass "connections attributed: $names"

dropped=$(api_get "$API/api/health/kernel" | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["details"]["kernel_events_dropped"])')
[[ "$dropped" == "0" ]] || fail "kernel dropped $dropped events"
pass "no events dropped by the kernel buffer"

echo "All end-to-end checks passed."
