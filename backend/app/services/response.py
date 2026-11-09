"""
Response engine (roadmap S6.4): decide what to block, keep the record, and
hand the blocklist to whatever enforces it.

    admin (API) ---+                         +--> agents: GET /api/agents/blocklist every few
    alerts (auto) -+--> blocks table + audit |    seconds; eBPF agents drop in XDP, module
                   |    log + allowlist      |    agents over Netlink (BLOCK_ADD/DEL)
                   +-------------------------+--> this machine's kernel module over Netlink,
                                                  when the backend may (local_enforcer)

Safety rules, checked for manual and automatic blocks alike:
  - never loopback, link-local, multicast, unspecified or reserved addresses
  - never a prefix wider than /16 (IPv4) or /32 (IPv6)
  - never anything overlapping the allowlist or an enrolled agent's address
  - an allowlist entry added later unblocks what it covers

Enforcers hold each block as a lease of BLOCK_LEASE_SECONDS (or less, if the
block expires sooner) and renew it while the block stays in the list. So an
unblock that never reaches an enforcer (agent restarted, message lost) still
ends within one lease.
"""

import hashlib
import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..config import settings
from ..database import SessionLocal
from ..models.agent import Agent
from ..models.response import AllowEntry, AuditEntry, Block
from ..utils.time import utc_naive

logger = logging.getLogger(__name__)

AUTO_ACTOR = "auto-response"
EXPIRY_ACTOR = "expiry"
# Widest prefix that may be blocked, per IP version
MIN_PREFIX = {4: 16, 6: 32}
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
MAX_AUTO_MINUTES = 7 * 24 * 60


class BlockRefused(ValueError):
    """A block the safety rules do not allow (the message says why)"""


def network(text: str) -> ipaddress._BaseNetwork:
    try:
        return ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        raise BlockRefused(f"Not an IP address or prefix: {text!r}")


def _unsafe(net) -> Optional[str]:
    if net.prefixlen < MIN_PREFIX[net.version]:
        return f"Prefix wider than /{MIN_PREFIX[net.version]}"
    if net.version == 6 and net.network_address.ipv4_mapped:
        return "Use the IPv4 address instead of an IPv4-mapped one"
    for what in ("is_loopback", "is_link_local", "is_multicast", "is_unspecified", "is_reserved"):
        if getattr(net.network_address, what) or getattr(net.broadcast_address, what):
            return f"Refusing to block a {what[3:].replace('_', '-')} address"
    return None


def audit(db: Session, actor: str, action: str, target: Optional[str], **details) -> None:
    db.add(AuditEntry(actor=actor, action=action, target=target, details=details or None,
                      time=datetime.utcnow()))


def _active_filter(now: datetime):
    return (Block.removed_at.is_(None), or_(Block.expires_at.is_(None), Block.expires_at > now))


class ResponseEngine:
    def __init__(self):
        self.stats = {"blocks_added": 0, "blocks_removed": 0, "auto_blocks": 0, "auto_refused": 0,
                      "expired": 0}
        # Called after every change, e.g. to push it to this machine's kernel
        self.listeners = []

    def _changed(self) -> None:
        for listener in self.listeners:
            try:
                listener()
            except Exception as e:
                logger.error(f"Blocklist listener failed: {e}")

    # --- checks -------------------------------------------------------------

    def check(self, db: Session, net) -> None:
        """Raise BlockRefused if this network may not be blocked"""
        problem = _unsafe(net)
        if problem:
            raise BlockRefused(problem)
        for entry in db.query(AllowEntry):
            if net.overlaps(network(entry.cidr)):
                raise BlockRefused(f"Overlaps the allowlist entry {entry.cidr}")
        for (addr,) in db.query(Agent.remote_addr).filter(Agent.remote_addr.isnot(None)):
            try:
                agent_ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if agent_ip in net:
                raise BlockRefused(f"Would cut off the enrolled agent at {addr}")

    # --- blocks -------------------------------------------------------------

    def block(self, db: Session, cidr: str, *, reason: str, actor: str, minutes: Optional[int] = None,
              host_id: Optional[int] = None, source: str = "manual", alert_id: Optional[int] = None,
              now: datetime = None) -> Tuple[Block, bool]:
        """Block a network (or extend an existing block). Returns (block, created)."""
        now = now or datetime.utcnow()
        net = network(cidr)
        self.check(db, net)
        expires = now + timedelta(minutes=minutes) if minutes else None
        same_scope = Block.host_id.is_(None) if host_id is None else Block.host_id == host_id
        existing = db.query(Block).filter(Block.cidr == str(net), same_scope, *_active_filter(now)).first()
        if existing:
            # Keep the longer of the two
            if existing.expires_at is not None and (expires is None or expires > _naive(existing.expires_at)):
                existing.expires_at = expires
                audit(db, actor, "extend", str(net), block_id=existing.id,
                      expires_at=expires.isoformat() if expires else None, reason=reason)
                db.commit()
                self._changed()
            return existing, False

        block = Block(cidr=str(net), host_id=host_id, reason=reason, source=source, created_by=actor,
                      alert_id=alert_id, created_at=now, expires_at=expires)
        db.add(block)
        db.flush()
        audit(db, actor, "block", str(net), block_id=block.id, reason=reason, host_id=host_id,
              expires_at=expires.isoformat() if expires else None, source=source, alert_id=alert_id)
        db.commit()
        self.stats["blocks_added"] += 1
        logger.warning("Blocked", extra={"cidr": str(net), "by": actor, "reason": reason,
                                         "minutes": minutes, "host_id": host_id})
        self._changed()
        return block, True

    def unblock(self, db: Session, block: Block, actor: str, why: str = "unblock",
                now: datetime = None) -> bool:
        if block.removed_at is not None:
            return False
        block.removed_at = now or datetime.utcnow()
        block.removed_by = actor
        audit(db, actor, why, block.cidr, block_id=block.id)
        db.commit()
        self.stats["blocks_removed"] += 1
        logger.warning("Unblocked", extra={"cidr": block.cidr, "by": actor, "why": why})
        self._changed()
        return True

    def expire(self, now: datetime = None) -> int:
        """Record blocks whose time is up (enforcers already let them lapse)"""
        now = now or datetime.utcnow()
        db = SessionLocal()
        try:
            due = db.query(Block).filter(Block.removed_at.is_(None), Block.expires_at.isnot(None),
                                         Block.expires_at <= now).all()
            for block in due:
                block.removed_at = block.expires_at
                block.removed_by = EXPIRY_ACTOR
                audit(db, EXPIRY_ACTOR, "expire", block.cidr, block_id=block.id)
            db.commit()
            self.stats["expired"] += len(due)
            return len(due)
        finally:
            db.close()

    def active(self, db: Session, host_id: Optional[int] = None, everywhere_only: bool = False,
               now: datetime = None) -> List[Block]:
        now = now or datetime.utcnow()
        query = db.query(Block).filter(*_active_filter(now))
        if everywhere_only:
            query = query.filter(Block.host_id.is_(None))
        elif host_id is not None:
            query = query.filter(or_(Block.host_id.is_(None), Block.host_id == host_id))
        return query.order_by(Block.id).all()

    # --- allowlist ----------------------------------------------------------

    def allow(self, db: Session, cidr: str, actor: str, note: str = "") -> AllowEntry:
        net = network(cidr)
        if db.query(AllowEntry).filter(AllowEntry.cidr == str(net)).first():
            raise BlockRefused(f"{net} is already on the allowlist")
        entry = AllowEntry(cidr=str(net), note=note, created_by=actor)
        db.add(entry)
        audit(db, actor, "allow", str(net), note=note)
        db.commit()
        # Whatever it covers is unblocked now
        for block in self.active(db):
            if network(block.cidr).overlaps(net):
                self.unblock(db, block, actor, why="unblock_allowlisted")
        return entry

    def disallow(self, db: Session, entry: AllowEntry, actor: str) -> None:
        audit(db, actor, "allow_remove", entry.cidr)
        db.delete(entry)
        db.commit()

    # --- automatic rules ----------------------------------------------------

    def on_alert(self, alert: Dict[str, Any], listed: bool = False) -> Optional[Block]:
        """Called for every new alert; blocks its source when a rule says so"""
        if not settings.auto_block or not alert.get("src_ip"):
            return None
        by_type = (alert.get("alert_type") in settings.auto_block_types and
                   SEVERITY_RANK.get(alert.get("severity"), 0)
                   >= SEVERITY_RANK.get(settings.auto_block_min_severity.upper(), 3))
        listed = listed or bool(((alert.get("metadata") or {}).get("enrichment") or {})
                                .get("src", {}).get("threat_lists"))
        by_list = settings.auto_block_listed_sources and listed
        if not (by_type or by_list):
            return None

        source = alert["src_ip"]
        db = SessionLocal()
        try:
            since = datetime.utcnow() - timedelta(days=1)
            earlier = (db.query(Block).filter(Block.source == "auto", Block.created_at >= since,
                                              Block.cidr == str(network(source))).count())
            minutes = min(settings.auto_block_minutes * 2 ** earlier, MAX_AUTO_MINUTES)
            rule = (f"{alert.get('alert_type')} ({alert.get('severity')})" if by_type
                    else "source on a threat list")
            block, created = self.block(
                db, source, reason=f"Automatic: {rule}, alert {alert.get('id')}", actor=AUTO_ACTOR,
                minutes=minutes, source="auto", alert_id=alert.get("id"))
            if created:
                self.stats["auto_blocks"] += 1
            db.refresh(block)
            db.expunge(block)  # usable after the session closes
            return block
        except BlockRefused as e:
            self.stats["auto_refused"] += 1
            audit(db, AUTO_ACTOR, "auto_refused", source, alert_id=alert.get("id"), why=str(e))
            db.commit()
            logger.info("Automatic block refused", extra={"src_ip": source, "why": str(e)})
            return None
        except Exception as e:
            db.rollback()
            logger.error(f"Automatic block of {source} failed: {e}")
            return None
        finally:
            db.close()

    # --- what enforcers download ------------------------------------------

    @staticmethod
    def blocklist_text(blocks: List[Block]) -> Tuple[str, str]:
        """
        The agent's blocklist, and its version (a hash of the content):

            version 3f2a9c0d1e4b5a6f
            lease 300
            block 203.0.113.7/32 1794250000     (expiry, Unix seconds; 0 = none)
        """
        lines = []
        for b in blocks:
            expires = 0
            if b.expires_at:
                expires = int(_naive(b.expires_at).replace(tzinfo=timezone.utc).timestamp())
            lines.append(f"block {b.cidr} {expires}")
        lines.sort()
        version = hashlib.sha256("\n".join(lines).encode()).hexdigest()[:16]
        text = "\n".join([f"version {version}", f"lease {settings.block_lease_seconds}", *lines]) + "\n"
        return text, version

    def get_stats(self) -> Dict[str, Any]:
        return dict(self.stats, auto_block=settings.auto_block)

    def reset(self) -> None:
        for key in self.stats:
            self.stats[key] = 0


def _naive(value: datetime) -> datetime:
    return utc_naive(value)


response_engine = ResponseEngine()
