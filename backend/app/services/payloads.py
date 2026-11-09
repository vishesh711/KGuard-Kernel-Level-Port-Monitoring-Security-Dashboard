"""
Payload samples from eBPF agents: DNS messages and TLS ClientHellos.

Each sample is one packet's application data (base64), with its addresses,
direction, TCP sequence number and the local process. This service:

  - drops duplicates: on loopback, or when both ends run on one host, the
    same packet is seen leaving and arriving
  - reassembles ClientHellos that span several TCP segments, by sequence
    number (Chrome's, with a post-quantum key share, is about 1.8 KB)
  - parses them (dns_parser.py, tls_parser.py) and stores DnsQuery and
    TlsHandshake rows
  - runs DNS tunnelling detection on queries, and matches TLS fingerprints
    against the optional blocklist (MALICIOUS_TLS)
"""

import base64
import binascii
import hashlib
import logging
import time
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import settings
from ..database import SessionLocal
from ..models.payload import DnsQuery, TlsHandshake
from ..models.security_alert import AlertSeverity, AlertType, SecurityAlert
from .anomaly_detector import anomaly_detector
from .dns_parser import DNSParseError, entropy, parse_dns, qtype_name
from .dns_tunnel import DnsTunnelDetector, query_features
from .tls_parser import TLSParseError, parse_client_hello, record_length
from .websocket_manager import broadcast_security_alert

logger = logging.getLogger(__name__)

MAX_SAMPLE_BYTES = 1536  # KGUARD_PAYLOAD_MAX
DUPLICATE_SECONDS = 5.0
FLOW_TIMEOUT_SECONDS = 10.0
MAX_FLOWS = 10_000
MAX_RECENT = 100_000
MAX_HELLO_BYTES = 16 * 1024 + 5  # one TLS record


def load_blocklist(path: str) -> Dict[str, str]:
    """fingerprint (JA3 md5 or JA4) -> label, from a CSV file; '#' lines are comments"""
    if not path:
        return {}
    entries = {}
    try:
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = [f.strip() for f in line.split(",")]
            fingerprint = fields[0].lower()
            if len(fingerprint) < 32:
                continue
            entries[fingerprint] = ", ".join(f for f in fields[1:] if f)[:128] or "listed"
    except OSError as e:
        logger.error(f"Cannot read TLS fingerprint blocklist {path}: {e}")
    return entries


class PayloadService:
    def __init__(self):
        self.dns_tunnel = DnsTunnelDetector(anomaly_detector)
        self.blocklist = load_blocklist(settings.tls_fingerprint_blocklist)
        # (host, src, sport, dst, dport) -> {"time", "segments": {seq: bytes}, "sample": dict}
        self.flows: "OrderedDict[tuple, dict]" = OrderedDict()
        self.recent: "OrderedDict[tuple, float]" = OrderedDict()
        self.stats = {"samples": 0, "duplicates": 0, "invalid": 0, "dns_messages": 0,
                      "tls_handshakes": 0, "parse_errors": 0}

    def reset(self) -> None:
        self.flows.clear()
        self.recent.clear()
        self.dns_tunnel.reset()

    # ---- input ----

    def _decode(self, sample: Any) -> Optional[bytes]:
        if not isinstance(sample, dict) or sample.get("kind") not in ("dns", "tls"):
            return None
        for key in ("src_ip", "dst_ip"):
            if not isinstance(sample.get(key), str) or len(sample[key]) > 45:
                return None
        for key in ("src_port", "dst_port", "timestamp"):
            if not isinstance(sample.get(key), int) or isinstance(sample.get(key), bool):
                return None
        try:
            data = base64.b64decode(sample.get("data", ""), validate=True)
        except (binascii.Error, TypeError, ValueError):
            return None
        return data if 0 < len(data) <= MAX_SAMPLE_BYTES else None

    def _duplicate(self, host_id, sample, data: bytes, now: float) -> bool:
        key = (host_id, sample["kind"], sample["src_ip"], sample["src_port"], sample["dst_ip"],
               sample["dst_port"], sample.get("tcp_seq", 0), hashlib.blake2b(data, digest_size=8).digest())
        seen = self.recent.get(key)
        self.recent[key] = now
        self.recent.move_to_end(key)
        while len(self.recent) > MAX_RECENT:
            self.recent.popitem(last=False)
        return seen is not None and now - seen < DUPLICATE_SECONDS

    async def ingest(self, samples: List[Any], host_id: Optional[int] = None) -> Dict[str, int]:
        now = time.monotonic()
        dns_rows: List[DnsQuery] = []
        tls_rows: List[TlsHandshake] = []
        accepted = 0
        for sample in samples:
            data = self._decode(sample)
            if data is None:
                self.stats["invalid"] += 1
                continue
            accepted += 1
            if self._duplicate(host_id, sample, data, now):
                self.stats["duplicates"] += 1
                continue
            if sample["kind"] == "dns":
                row = self._dns(sample, data, host_id)
                if row:
                    dns_rows.append(row)
            else:
                row = self._tls(sample, data, host_id, now)
                if row:
                    tls_rows.append(row)
        self.stats["samples"] += accepted
        self._expire_flows(now)

        alerts = self._store(dns_rows, tls_rows)
        for alert in alerts:
            await broadcast_security_alert(alert.to_dict())
        return {"accepted": accepted, "dns": len(dns_rows), "tls": len(tls_rows), "alerts": len(alerts)}

    # ---- DNS ----

    def _dns(self, sample: dict, data: bytes, host_id) -> Optional[DnsQuery]:
        try:
            msg = parse_dns(data)
        except DNSParseError:
            self.stats["parse_errors"] += 1
            return None
        if not msg.qname or msg.opcode != 0:
            return None
        self.stats["dns_messages"] += 1
        client_is_src = not msg.is_response
        domain, sub, _ = query_features(msg.qname)
        pid = sample.get("pid")
        return DnsQuery(
            timestamp=sample["timestamp"],
            host_id=host_id,
            client_ip=sample["src_ip"] if client_is_src else sample["dst_ip"],
            client_port=sample["src_port"] if client_is_src else sample["dst_port"],
            server_ip=sample["dst_ip"] if client_is_src else sample["src_ip"],
            direction=sample.get("direction") if sample.get("direction") in ("in", "out") else None,
            is_response=msg.is_response,
            query_id=msg.id,
            qname=msg.qname[:255],
            qtype=msg.qtype,
            qtype_name=qtype_name(msg.qtype),
            domain=domain[:255],
            subdomain_length=min(len(sub), 255),
            entropy=round(entropy(sub.replace(".", "")), 3),
            rcode=msg.rcode if msg.is_response else None,
            answer_count=min(msg.answer_count, 32767) if msg.is_response else None,
            process_name=(sample.get("comm") or None) if isinstance(pid, int) and pid >= 0 else None,
            pid=pid if isinstance(pid, int) and pid >= 0 else None,
        )

    # ---- TLS ----

    def _tls(self, sample: dict, data: bytes, host_id, now: float) -> Optional[TlsHandshake]:
        key = (host_id, sample["src_ip"], sample["src_port"], sample["dst_ip"], sample["dst_port"])
        seq = sample.get("tcp_seq", 0) if isinstance(sample.get("tcp_seq"), int) else 0
        flow = self.flows.get(key)
        if flow is None:
            flow = {"time": now, "segments": {}, "sample": None}
            self.flows[key] = flow
        flow["segments"][seq] = data
        if record_length(data):
            flow["sample"] = sample
            flow["start"] = seq
        if not flow["sample"]:
            return None  # continuation before its first segment

        # Join contiguous segments from the first one
        need = record_length(flow["segments"][flow["start"]])
        hello, pos = b"", flow["start"]
        while pos in flow["segments"] and len(hello) < need:
            chunk = flow["segments"][pos]
            hello += chunk
            pos = (pos + len(chunk)) & 0xFFFFFFFF
        if len(hello) < need and need <= MAX_HELLO_BYTES:
            return None  # wait for the rest
        del self.flows[key]
        try:
            parsed = parse_client_hello(hello[:need])
        except TLSParseError:
            self.stats["parse_errors"] += 1
            return None
        self.stats["tls_handshakes"] += 1
        first = flow["sample"]
        pid = first.get("pid")
        ja3, ja4 = parsed.ja3, parsed.ja4
        return TlsHandshake(
            timestamp=first["timestamp"],
            host_id=host_id,
            client_ip=first["src_ip"],
            client_port=first["src_port"],
            server_ip=first["dst_ip"],
            server_port=first["dst_port"],
            direction=first.get("direction") if first.get("direction") in ("in", "out") else None,
            sni=parsed.sni,
            alpn=(parsed.alpn[0][:64] if parsed.alpn else None),
            tls_version=parsed.version_name,
            ja3=ja3,
            ja3_string=parsed.ja3_string,
            ja4=ja4,
            ja4_r=parsed.ja4_r,
            known_bad=self.blocklist.get(ja3) or self.blocklist.get(ja4),
            process_name=(first.get("comm") or None) if isinstance(pid, int) and pid >= 0 else None,
            pid=pid if isinstance(pid, int) and pid >= 0 else None,
        )

    def _expire_flows(self, now: float) -> None:
        while self.flows:
            key, flow = next(iter(self.flows.items()))
            if now - flow["time"] < FLOW_TIMEOUT_SECONDS and len(self.flows) <= MAX_FLOWS:
                break
            del self.flows[key]

    # ---- storage and alerts ----

    def _store(self, dns_rows: List[DnsQuery], tls_rows: List[TlsHandshake]) -> List[SecurityAlert]:
        if not dns_rows and not tls_rows:
            return []
        db = SessionLocal(expire_on_commit=False)
        try:
            db.add_all(dns_rows + tls_rows)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Error storing payload records: {e}")
            return []
        finally:
            db.close()

        alerts = []
        for row in dns_rows:
            if row.is_response:
                continue
            alert = self.dns_tunnel.observe(row.host_id, row.client_ip, row.qname, row.qtype or 0,
                                            row.timestamp / 1e9, row.id)
            if alert:
                alerts.append(alert)
        for row in tls_rows:
            if row.known_bad:
                alert = self._malicious_tls(row)
                if alert:
                    alerts.append(alert)
        return [a for a in alerts if anomaly_detector._store_alert(a)]

    def _malicious_tls(self, row: TlsHandshake) -> Optional[SecurityAlert]:
        cooldown = f"malicious_tls_{row.host_id}|{row.client_ip}|{row.ja4}"
        if not anomaly_detector._claim_cooldown(cooldown):
            return None
        who = f"{row.process_name} on {row.client_ip}" if row.process_name and row.direction == "out" \
            else row.client_ip
        return SecurityAlert(
            timestamp=datetime.utcnow(),
            alert_type=AlertType.MALICIOUS_TLS,
            severity=AlertSeverity.HIGH,
            title=f"Known-Bad TLS Client: {row.known_bad}",
            description=(
                f"{who} opened a TLS connection to {row.sni or row.server_ip}:{row.server_port} with a "
                f"client fingerprint on the blocklist ({row.known_bad}). JA3 {row.ja3}, JA4 {row.ja4}."
            ),
            src_ip=row.client_ip,
            dst_ip=row.server_ip,
            dst_port=row.server_port,
            host_id=row.host_id,
            alert_metadata={"ja3": row.ja3, "ja4": row.ja4, "sni": row.sni, "label": row.known_bad,
                            "process": row.process_name, "tls_handshake_id": row.id,
                            "detection_method": "tls_fingerprint_blocklist"},
        )

    def get_stats(self) -> Dict[str, Any]:
        return {**self.stats, "pending_flows": len(self.flows), "blocklist_entries": len(self.blocklist)}


payload_service = PayloadService()
