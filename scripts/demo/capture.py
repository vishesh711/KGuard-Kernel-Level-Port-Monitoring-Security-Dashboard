#!/usr/bin/env python3
"""
Record the README's demo: real attacks against a real KGuard host, seen in the
dashboard. Run inside a throwaway VM (scripts/demo/make_demo.sh does that):

    python3 scripts/demo/capture.py BACKEND_PY DIST_DIR FRAMES_DIR

It loads the kernel module, starts the backend and serves the built dashboard
(DIST_DIR), sets up the detection lab's attacker namespace, then runs
capture.js, which logs in and screenshots the dashboard while nmap and hping3
attack the host. The frames go to FRAMES_DIR.
"""

import glob
import http.server
import json
import os
import socketserver
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.argv, (BACKEND_PY, DIST, FRAMES) = sys.argv[:2], sys.argv[1:4]
os.environ["ALLOWED_ORIGINS"] = json.dumps(["http://127.0.0.1:4173"])

import detection_lab as lab  # noqa: E402  (reads BACKEND_PY from sys.argv)


class SPA(http.server.SimpleHTTPRequestHandler):
    """Static files, and index.html for client-side routes"""

    def __init__(self, *args, **kw):
        super().__init__(*args, directory=DIST, **kw)

    def send_head(self):
        if not os.path.exists(os.path.join(DIST, self.path.lstrip("/").split("?")[0])):
            self.path = "/index.html"
        return super().send_head()

    def log_message(self, *args):
        pass


def main():
    procs = []
    try:
        lab.setup()
        lab.listener(8080)
        procs.append(lab.start_sshd())
        procs.append(lab.start_backend())
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 4173), SPA)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        os.makedirs(FRAMES, exist_ok=True)
        # The VM's environment does not carry PLAYWRIGHT_BROWSERS_PATH: find Chromium
        chrome = next(iter(sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux*/chrome"))), "")
        env = dict(os.environ, CHROME=chrome, FRAMES=FRAMES, USERNAME=lab.LAB_AUTH["ADMIN_USERNAME"],
                   PASSWORD=lab.LAB_AUTH["ADMIN_PASSWORD"], ATTACKER_NS=lab.NS, TARGET=lab.HOST)
        node_path = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True).stdout.strip()
        env["NODE_PATH"] = node_path
        result = subprocess.run(["node", os.path.join(HERE, "capture.js")], env=env)
        print("capture.js exit", result.returncode, flush=True)
    finally:
        lab.teardown(procs)


if __name__ == "__main__":
    main()
