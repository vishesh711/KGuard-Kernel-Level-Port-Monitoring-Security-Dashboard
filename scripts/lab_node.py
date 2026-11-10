#!/usr/bin/env python3
"""
One node of the test lab (scripts/lab.sh), run inside its VM as root:

    lab_node.py victim BACKEND_PY   KGuard module, backend on :8000, sshd on :22,
                                    a web server on :80; runs until the VM stops
    lab_node.py attacker            bring up the attacker's end of the link
    lab_node.py check               attacker: nmap -sS the victim and wait for the
                                    victim's API to report the scan
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VICTIM, ATTACKER = "10.77.0.1", "10.77.0.2"
MACS = {"victim": "52:54:00:77:00:01", "attacker": "52:54:00:77:00:02"}
API = f"http://{VICTIM}:8000"
AUTH = {"SECRET_KEY": "lab-signing-key-" + "0" * 32, "ADMIN_USERNAME": "lab",
        "ADMIN_PASSWORD": "lab-admin-password", "RATE_LIMIT_PER_MINUTE": "0",
        "ALLOWED_HOSTS": json.dumps(["127.0.0.1", "localhost", VICTIM])}


def sh(cmd):
    subprocess.run(cmd, shell=isinstance(cmd, str), check=True)


def link_up(role):
    """Give the lab NIC (found by its MAC) the node's address"""
    for name in os.listdir("/sys/class/net"):
        if open(f"/sys/class/net/{name}/address").read().strip() == MACS[role]:
            sh(f"ip addr add {VICTIM if role == 'victim' else ATTACKER}/24 dev {name}")
            sh(f"ip link set {name} up; ip link set lo up")
            print(f"{role}: {name} up", flush=True)
            return name
    raise SystemExit(f"no NIC with MAC {MACS[role]}")


def victim(backend_py):
    link_up("victim")
    sh("modprobe -a nf_conntrack nf_socket_ipv4 nf_socket_ipv6")
    sh(["insmod", os.path.join(ROOT, "kernel", "kguard.ko")])
    work = tempfile.mkdtemp(prefix="kguard-lab-")
    env = dict(os.environ, **AUTH, DATABASE_URL=f"sqlite:///{work}/kguard.db", DATA_COLLECTION_INTERVAL="0.5")
    procs = [subprocess.Popen([backend_py, "-m", "uvicorn", "app.main:app", "--host", VICTIM, "--port", "8000"],
                              cwd=os.path.join(ROOT, "backend"), env=env)]
    os.makedirs("/run/sshd", exist_ok=True)
    sh(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"{work}/host_key"])
    procs.append(subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", "/dev/null", "-o", f"HostKey={work}/host_key",
                                   "-o", f"ListenAddress={VICTIM}", "-o", "UsePAM=no",
                                   "-o", "PasswordAuthentication=yes", "-o", f"PidFile={work}/sshd.pid"]))
    procs.append(subprocess.Popen([sys.executable, "-m", "http.server", "80", "--bind", VICTIM],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    print("victim: KGuard module loaded; backend, sshd and web server starting", flush=True)
    try:
        while all(p.poll() is None for p in procs):
            time.sleep(1)
    finally:
        for p in procs:
            p.kill()
    raise SystemExit("victim: a service exited")


def api(path, token=None, data=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(API + path, data=json.dumps(data).encode() if data else None, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def check():
    link_up("attacker")
    token, deadline = None, time.time() + 300
    while token is None and time.time() < deadline:
        try:
            token = api("/api/auth/login", data={"username": "lab", "password": AUTH["ADMIN_PASSWORD"]})["access_token"]
        except OSError:
            time.sleep(2)
    if token is None:
        raise SystemExit("FAIL  victim API not reachable at " + API)
    print(f"attacker: victim API up at {API}", flush=True)
    health = api("/api/health/kernel", token)
    print("attacker: victim kernel module:", "loaded" if health.get("details", {}).get("kernel_detection") else health)
    subprocess.run(["nmap", "-sS", "-Pn", "-n", "-T4", "-p", "1-1000", VICTIM], check=True,
                   stdout=subprocess.DEVNULL)
    deadline = time.time() + 60
    while time.time() < deadline:
        found = [a for a in api("/api/alerts/?size=100", token)["items"]
                 if a.get("src_ip") == ATTACKER and a["alert_type"] == "PORT_SCAN"]
        if found:
            print(f"PASS  scan from the attacker VM raised '{found[0]['title']}' on the victim")
            return
        time.sleep(2)
    raise SystemExit("FAIL  no PORT_SCAN alert from the attacker VM within 60 s")


if __name__ == "__main__":
    role = sys.argv[1] if len(sys.argv) > 1 else ""
    if role == "victim":
        victim(sys.argv[2] if len(sys.argv) > 2 else "python3")
    elif role == "attacker":
        link_up("attacker")
    elif role == "check":
        check()
    else:
        raise SystemExit(__doc__)
