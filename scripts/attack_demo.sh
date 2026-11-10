#!/usr/bin/env bash
#
# Attack demos (roadmap P8.2): run real attacks against a KGuard host in a
# throwaway VM and check that each raises the expected alert.
#
#   scripts/attack_demo.sh                 every attack
#   scripts/attack_demo.sh syn_flood dns_tunnel
#   make attack-demo
#
# Attack          Tools                         Expected
# scans           nmap -sS/-sT/-sF/-sN/-sX/-sA/-sU  PORT_SCAN of each type
# brute_force     hydra against a real sshd      BRUTE_FORCE on port 22
# syn_flood       hping3 --flood --rand-source   SYN_FLOOD, no false scan alerts
# os_fingerprint  nmap, curl, Python sockets     sender fingerprints on alerts
# spoofing        hping3 with bogon/odd-TTL sources   SPOOFED_TRAFFIC
# amplification   DNS, NTP, memcached, SSDP replies   AMPLIFICATION (victim side)
# dns_tunnel      iodine                         DNS_TUNNELING
# tls             openssl/curl ClientHellos      MALICIOUS_TLS for a listed JA3/JA4
#
# Each attack runs from an attacker network namespace against the victim
# (the VM itself, with the kernel module, an eBPF agent and the backend).
#
# Environment: KERNEL_IMAGE (default: the running kernel), KDIR (headers
# for the module build), BACKEND_PY (python with the backend's packages,
# default backend/.venv/bin/python). Needs virtme-ng, qemu and the attack
# tools listed above inside the VM's root filesystem (the host's).

set -uo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

declare -A LAB=( [scans]=detection [brute_force]=detection [syn_flood]=detection
                 [os_fingerprint]=detection [spoofing]=detection [amplification]=detection
                 [dns_tunnel]=payload [tls]=payload )
declare -A TEST=( [scans]=scan_types [brute_force]=brute_force [syn_flood]=syn_flood
                  [os_fingerprint]=os_fingerprints [spoofing]=spoofing [amplification]=amplification
                  [dns_tunnel]=dns [tls]=tls_fingerprints )
ORDER=(scans brute_force syn_flood os_fingerprint spoofing amplification dns_tunnel tls)

attacks=("$@")
[[ ${#attacks[@]} -gt 0 ]] || attacks=("${ORDER[@]}")
for a in "${attacks[@]}"; do
    [[ -n "${LAB[$a]:-}" ]] || { echo "unknown attack '$a'; one of: ${ORDER[*]}" >&2; exit 2; }
done

BACKEND_PY="${BACKEND_PY:-$ROOT/backend/.venv/bin/python}"
[[ -x "$BACKEND_PY" ]] || BACKEND_PY=$(command -v python3)
command -v vng >/dev/null || { echo "virtme-ng not found: pip install virtme-ng" >&2; exit 2; }

make -C kernel ${KDIR:+KDIR="$KDIR"} >/dev/null || exit 1
make -C agent >/dev/null || exit 1
OUT="$ROOT/kernel/tests/out"
mkdir -p "$OUT"

vm_args=(--cpus 4 --memory 2G --rw)
[[ -e /dev/kvm ]] || vm_args+=(--disable-kvm)
[[ -n "${KERNEL_IMAGE:-}" ]] && vm_args+=(--run "$KERNEL_IMAGE")

for lab in detection payload; do
    tests=()
    for a in "${attacks[@]}"; do [[ ${LAB[$a]} == "$lab" ]] && tests+=("${TEST[$a]}"); done
    [[ ${#tests[@]} -gt 0 ]] || continue
    filter=$(IFS=,; echo "${tests[*]}")
    echo "== $lab lab: $filter (booting a VM)"
    rm -f "$OUT/$lab-lab.log"
    timeout "${VM_TIMEOUT:-2400}" vng "${vm_args[@]}" --exec \
        "cd '$ROOT' && LAB_TESTS=$filter python3 -W ignore scripts/${lab}_lab.py '$BACKEND_PY' > '$OUT/$lab-lab.log' 2>&1" \
        >/dev/null 2>&1
    grep -E '^(== |PASS|FAIL)' "$OUT/$lab-lab.log" | cut -c1-160
done

# One line per attack: PASS when its section ran and every check in it passed
echo
echo "Attack demo results:"
status=0
for a in "${attacks[@]}"; do
    log="$OUT/${LAB[$a]}-lab.log"
    section=$(awk -v t="== ${TEST[$a]}" '$0 == t {on=1; next} /^== / {on=0} on' "$log" 2>/dev/null)
    passed=$(grep -c '^PASS' <<<"$section")
    failed=$(grep -c '^FAIL' <<<"$section")
    if [[ $passed -gt 0 && $failed -eq 0 ]]; then
        printf '  PASS  %-15s %d checks\n' "$a" "$passed"
    else
        printf '  FAIL  %-15s %d passed, %d failed\n' "$a" "$passed" "$failed"
        status=1
    fi
done
exit $status
