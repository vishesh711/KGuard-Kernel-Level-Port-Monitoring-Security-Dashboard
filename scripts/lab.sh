#!/usr/bin/env bash
#
# Test lab (roadmap P8.1): a victim VM running KGuard and an attacker VM
# with the attack tools, joined by a private link (QEMU socket network).
#
#   victim    10.77.0.1   kernel module, backend (API on :8000), sshd, web server
#   attacker  10.77.0.2   nmap, hping3, hydra, scapy, iodine, curl
#
#   make lab                  victim in the background, a root shell on the attacker;
#                             leaving the shell stops both
#   LAB_CHECK=1 make lab      no shell: the attacker scans the victim and checks
#                             that the victim's API reports the scan; exit 0 on PASS
#
# The API accepts the lab admin: user "lab", password "lab-admin-password".
# Both VMs run the host's root filesystem (virtme-ng), so the tools must be
# installed on the host. Environment: KERNEL_IMAGE, KDIR, BACKEND_PY as for
# scripts/attack_demo.sh; LAB_PORT (default 12470) for the link.

set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
BACKEND_PY="${BACKEND_PY:-$ROOT/backend/.venv/bin/python}"
[[ -x "$BACKEND_PY" ]] || BACKEND_PY=$(command -v python3)
command -v vng >/dev/null || { echo "virtme-ng not found: pip install virtme-ng" >&2; exit 2; }
PORT=${LAB_PORT:-12470}
OUT="$ROOT/kernel/tests/out"
mkdir -p "$OUT"

make -C kernel ${KDIR:+KDIR="$KDIR"} >/dev/null

base=(--cpus 2 --memory 2G --rw)
[[ -e /dev/kvm ]] || base+=(--disable-kvm)
[[ -n "${KERNEL_IMAGE:-}" ]] && base+=(--run "$KERNEL_IMAGE")
nic() { echo "-netdev socket,id=lab,$1 -device virtio-net-pci,netdev=lab,mac=$2"; }

rm -f "$OUT/lab-victim.log"
echo "== starting the victim VM (log: $OUT/lab-victim.log)"
vng "${base[@]}" --qemu-opts "$(nic "listen=127.0.0.1:$PORT" 52:54:00:77:00:01)" --exec \
    "cd '$ROOT' && python3 scripts/lab_node.py victim '$BACKEND_PY'" > "$OUT/lab-victim.log" 2>&1 &
victim=$!
trap 'kill $victim 2>/dev/null; pkill -f "listen=127.0.0.1:$PORT" 2>/dev/null; wait $victim 2>/dev/null' EXIT
for _ in $(seq 60); do
    ss -ltn | grep -q "127.0.0.1:$PORT " && break
    sleep 1
done

attacker=(vng "${base[@]}" --qemu-opts "$(nic "connect=127.0.0.1:$PORT" 52:54:00:77:00:02)")
if [[ -n "${LAB_CHECK:-}" ]]; then
    echo "== attacker VM: scanning the victim"
    "${attacker[@]}" --exec "cd '$ROOT' && python3 scripts/lab_node.py check" 2>&1 | tee "$OUT/lab-attacker.log"
    grep -q '^PASS' "$OUT/lab-attacker.log"
else
    echo "== attacker VM: run 'python3 scripts/lab_node.py attacker' first to bring up the link,"
    echo "   then attack 10.77.0.1 (e.g. nmap -sS 10.77.0.1). Exit the shell to stop the lab."
    "${attacker[@]}"
fi
