"""
Map socket inode numbers to the processes holding them.

The kernel module reports the inode of the socket a packet belongs to (for
example a listening server's socket). Like `ss -p`, we find the owner by
scanning /proc/<pid>/fd for links named "socket:[<inode>]".

The scan is cached and rebuilt at most once per `min_rescan_seconds`, and
only when an unknown inode shows up.
"""

import os
import time
from typing import Dict, Iterable, Optional, Tuple

Owner = Tuple[int, str]


class ProcessResolver:
    def __init__(self, proc_root: str = "/proc", min_rescan_seconds: float = 1.0):
        self.proc_root = proc_root
        self.min_rescan_seconds = min_rescan_seconds
        self._owners: Dict[int, Owner] = {}
        self._last_scan = 0.0
        self.scans = 0

    def lookup(self, inode: int) -> Optional[Owner]:
        return self.lookup_many([inode]).get(inode)

    def lookup_many(self, inodes: Iterable[int]) -> Dict[int, Owner]:
        wanted = {i for i in inodes if i}
        missing = wanted - self._owners.keys()
        if missing and time.monotonic() - self._last_scan >= self.min_rescan_seconds:
            self._scan()
        return {i: self._owners[i] for i in wanted if i in self._owners}

    def _scan(self) -> None:
        owners: Dict[int, Owner] = {}
        try:
            pids = [p for p in os.listdir(self.proc_root) if p.isdigit()]
        except OSError:
            pids = []
        for pid in pids:
            fd_dir = os.path.join(self.proc_root, pid, "fd")
            try:
                fds = os.listdir(fd_dir)
            except OSError:
                continue  # process exited, or not ours to inspect
            comm = None
            for fd in fds:
                try:
                    target = os.readlink(os.path.join(fd_dir, fd))
                except OSError:
                    continue
                if target.startswith("socket:["):
                    if comm is None:
                        comm = self._comm(pid)
                    owners[int(target[8:-1])] = (int(pid), comm)
        self._owners = owners
        self._last_scan = time.monotonic()
        self.scans += 1

    def _comm(self, pid: str) -> str:
        try:
            with open(os.path.join(self.proc_root, pid, "comm")) as f:
                return f.read().strip()
        except OSError:
            return "?"
