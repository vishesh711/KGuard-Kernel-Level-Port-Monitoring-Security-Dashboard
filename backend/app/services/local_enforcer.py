"""
Apply the blocklist to the kernel module on this machine (roadmap S6.4).

Blocks for every host (host_id empty) go to the module over Generic Netlink
(KGUARD_CMD_BLOCK_ADD / BLOCK_DEL), each as a lease the module ends by
itself unless it is renewed. The module blocks single addresses, so a
prefix is left to eBPF agents and counted as "skipped".

Changing the module's blocklist needs CAP_NET_ADMIN. The production
container drops every capability, so there this reports "not permitted"
and agents do the enforcing; run with LOCAL_ENFORCEMENT=off to say so.

Status: off, no module, not permitted, enforcing, monitor only (the module
records blocks but enforce=0 lets the traffic through), or an error.
"""

import errno
import ipaddress
import logging
import time
from datetime import timezone
from typing import Any, Callable, Dict, Optional, Tuple

from ..config import settings
from ..database import SessionLocal
from ..utils.time import utc_naive
from .kguard_netlink import KGuardControlSocket
from .response import response_engine

logger = logging.getLogger(__name__)


class LocalEnforcer:
    def __init__(self, socket_factory: Callable[[], Any] = KGuardControlSocket):
        self.socket_factory = socket_factory
        self.sock = None
        self.status = "not started"
        # address -> (expiry in Unix seconds or 0, when to renew the lease)
        self.managed: Dict[str, Tuple[int, float]] = {}
        self.stats = {"applied": 0, "failed": 0, "skipped_prefixes": 0, "removed": 0}
        self.last_error: Optional[str] = None

    def _socket(self):
        if self.sock is None:
            self.sock = self.socket_factory()
        return self.sock

    def _desired(self) -> Tuple[Dict[str, int], int]:
        db = SessionLocal()
        try:
            desired, skipped = {}, 0
            for block in response_engine.active(db, everywhere_only=True):
                net = ipaddress.ip_network(block.cidr)
                if net.prefixlen != net.max_prefixlen:
                    skipped += 1
                    continue
                expires = 0
                if block.expires_at:
                    expires = int(utc_naive(block.expires_at).replace(tzinfo=timezone.utc).timestamp())
                desired[str(net.network_address)] = expires
            return desired, skipped
        finally:
            db.close()

    def sync(self, now: float = None) -> str:
        if settings.local_enforcement != "auto":
            self.status = "off"
            return self.status
        now = time.time() if now is None else now
        try:
            sock = self._socket()
        except OSError:
            self.status = "no module"
            return self.status

        desired, self.stats["skipped_prefixes"] = self._desired()
        lease = settings.block_lease_seconds
        failed = 0
        try:
            for addr, expires in desired.items():
                known = self.managed.get(addr)
                if known and known[0] == expires and now < known[1]:
                    continue
                timeout = lease if not expires else min(lease, expires - now)
                if timeout <= 0:
                    continue
                try:
                    sock.block_add(addr, int(timeout))
                    self.managed[addr] = (expires, now + timeout / 2)
                    self.stats["applied"] += 1
                except PermissionError:
                    raise
                except OSError as e:
                    # EADDRNOTAVAIL: the module refuses its own or allowlisted addresses
                    failed += 1
                    self.last_error = f"{addr}: {e.strerror}"
            for addr in [a for a in self.managed if a not in desired]:
                try:
                    sock.block_del(addr)
                except PermissionError:
                    raise
                except OSError as e:
                    if e.errno != errno.ENOENT:
                        failed += 1
                        self.last_error = f"{addr}: {e.strerror}"
                        continue
                del self.managed[addr]
                self.stats["removed"] += 1
            enforcing = sock.enforcing()
        except PermissionError:
            self.status = "not permitted"  # no CAP_NET_ADMIN
            return self.status
        except OSError as e:
            # The module went away: start again next time
            self.close()
            self.status = f"error: {e.strerror or e}"
            return self.status
        self.stats["failed"] = failed
        self.status = "enforcing" if enforcing else "monitor only"
        return self.status

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None
        self.managed.clear()

    def get_stats(self) -> Dict[str, Any]:
        return dict(self.stats, status=self.status, managed=len(self.managed), last_error=self.last_error)


local_enforcer = LocalEnforcer()
