"""
Alert enrichment (roadmap S6.3): every alert, however it was raised, gets

    metadata.enrichment = {
        "mitre": [{"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery",
                   "url": "https://attack.mitre.org/techniques/T1046/"}],
        "src": {"ip": "203.0.113.7", "country": "NL", "country_name": "Netherlands",
                "asn": 64500, "as_org": "Example Hosting", "threat_lists": ["firehol_level1"]},
        "dst": {...}            # same, for the destination
    }

  - MITRE ATT&CK techniques from the alert type (table below).
  - Country and network owner from MaxMind GeoLite2 databases
    (GEOIP_COUNTRY_DB, GEOIP_ASN_DB). MaxMind requires a free account to
    download them, so they are not shipped; without them those fields are
    simply absent.
  - Which bad-IP lists contain the address: every *.txt, *.netset, *.ipset
    or *.list file in THREAT_LISTS_DIR, one address or prefix per line
    (FireHOL and Spamhaus DROP formats; "#" and ";" start comments). Files
    are re-read when they change; "python -m app.threatlists update" fetches
    the lists in THREAT_LIST_URLS.

Private, loopback and other non-public addresses are marked
{"scope": "not public"} and not looked up.

It runs as a SQLAlchemy before_insert hook on SecurityAlert, so no detector
needs to know about it.
"""

import bisect
import ipaddress
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import event

from ..config import settings
from ..models.security_alert import AlertType, SecurityAlert

logger = logging.getLogger(__name__)

ATTACK_URL = "https://attack.mitre.org/techniques/{}/"


def _technique(tid: str, name: str, tactic: str) -> Dict[str, str]:
    return {"id": tid, "name": name, "tactic": tactic, "url": ATTACK_URL.format(tid.replace(".", "/"))}


# Alert type -> ATT&CK techniques. Types with no clear technique map to
# nothing rather than to a guess.
MITRE = {
    AlertType.PORT_SCAN: [_technique("T1046", "Network Service Discovery", "Discovery")],
    AlertType.SUSPICIOUS_PORT: [_technique("T1046", "Network Service Discovery", "Discovery")],
    AlertType.BRUTE_FORCE: [_technique("T1110", "Brute Force", "Credential Access")],
    # MITRE gives SYN floods as the example of OS exhaustion floods
    AlertType.SYN_FLOOD: [_technique("T1499.001", "Endpoint Denial of Service: OS Exhaustion Flood",
                                     "Impact")],
    AlertType.HIGH_FREQUENCY: [_technique("T1498.001", "Network Denial of Service: Direct Network Flood",
                                          "Impact")],
    AlertType.AMPLIFICATION: [_technique("T1498.002", "Network Denial of Service: Reflection Amplification",
                                         "Impact")],
    AlertType.DNS_TUNNELING: [
        _technique("T1071.004", "Application Layer Protocol: DNS", "Command and Control"),
        _technique("T1572", "Protocol Tunneling", "Command and Control"),
    ],
    AlertType.MALICIOUS_TLS: [
        _technique("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
        _technique("T1573", "Encrypted Channel", "Command and Control"),
    ],
    AlertType.UNKNOWN_PROTOCOL: [_technique("T1095", "Non-Application Layer Protocol",
                                            "Command and Control")],
    # Spoofed sources and baseline anomalies say something is wrong, not which technique
    AlertType.SPOOFED_TRAFFIC: [],
    AlertType.UNUSUAL_TRAFFIC: [],
}

LIST_SUFFIXES = (".txt", ".netset", ".ipset", ".list")


def public(ip) -> bool:
    return ip.is_global and not ip.is_multicast


class ThreatLists:
    """Bad-IP lists, merged into sorted ranges per list for O(log n) lookups"""

    RECHECK_SECONDS = 60

    def __init__(self, directory: str = None):
        self.directory = directory
        self.lists: Dict[str, Dict[int, Tuple[List[int], List[int]]]] = {}
        self.sizes: Dict[str, int] = {}
        self.signature = None
        # Never checked: time.monotonic() counts from boot, so 0.0 would
        # skip the first load on a machine up for less than a minute
        self.checked = float("-inf")

    @staticmethod
    def parse(text: str) -> List[ipaddress._BaseNetwork]:
        nets = []
        for line in text.splitlines():
            token = line.split("#", 1)[0].split(";", 1)[0].strip().split()
            if not token:
                continue
            try:
                nets.append(ipaddress.ip_network(token[0], strict=False))
            except ValueError:
                continue
        return nets

    @staticmethod
    def _index(nets) -> Dict[int, Tuple[List[int], List[int]]]:
        index = {}
        for version in (4, 6):
            ranges = sorted((int(n.network_address), int(n.broadcast_address))
                            for n in nets if n.version == version)
            starts, ends = [], []
            for start, end in ranges:
                if ends and start <= ends[-1] + 1:
                    ends[-1] = max(ends[-1], end)
                else:
                    starts.append(start)
                    ends.append(end)
            index[version] = (starts, ends)
        return index

    def _files(self, directory: Path):
        try:
            return sorted(p for p in directory.iterdir() if p.suffix in LIST_SUFFIXES and p.is_file())
        except OSError:
            return []

    def refresh(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self.checked < self.RECHECK_SECONDS:
            return
        self.checked = now
        directory = Path(self.directory or settings.threat_lists_dir)
        files = self._files(directory)
        signature = tuple((p.name, p.stat().st_mtime_ns, p.stat().st_size) for p in files)
        if signature == self.signature:
            return
        lists, sizes = {}, {}
        for path in files:
            try:
                nets = self.parse(path.read_text(errors="replace"))
            except OSError as e:
                logger.error(f"Cannot read threat list {path}: {e}")
                continue
            lists[path.stem] = self._index(nets)
            sizes[path.stem] = len(nets)
        self.lists, self.sizes, self.signature = lists, sizes, signature
        if lists:
            logger.info("Threat lists loaded", extra={"lists": sizes})

    def match(self, ip) -> List[str]:
        self.refresh()
        value, found = int(ip), []
        for name, index in self.lists.items():
            starts, ends = index[ip.version]
            i = bisect.bisect_right(starts, value) - 1
            if i >= 0 and ends[i] >= value:
                found.append(name)
        return found


class GeoIP:
    """MaxMind databases, opened on first use and re-opened when replaced"""

    def __init__(self):
        self.readers: Dict[str, Tuple[Optional[float], Any]] = {}

    def _reader(self, path: str):
        try:
            mtime = os.stat(path).st_mtime
        except OSError:
            return None
        cached = self.readers.get(path)
        if cached and cached[0] == mtime:
            return cached[1]
        try:
            import maxminddb

            reader = maxminddb.open_database(path)
        except Exception as e:
            logger.error(f"Cannot open GeoIP database {path}: {e}")
            reader = None
        if cached and cached[1] is not None:
            cached[1].close()
        self.readers[path] = (mtime, reader)
        return reader

    def lookup(self, ip: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {}
        country_db = self._reader(settings.geoip_country_db)
        if country_db:
            record = country_db.get(ip) or {}
            country = record.get("country") or record.get("registered_country") or {}
            if country.get("iso_code"):
                info["country"] = country["iso_code"]
                info["country_name"] = (country.get("names") or {}).get("en")
        asn_db = self._reader(settings.geoip_asn_db)
        if asn_db:
            record = asn_db.get(ip) or {}
            if record.get("autonomous_system_number"):
                info["asn"] = record["autonomous_system_number"]
                info["as_org"] = record.get("autonomous_system_organization")
        return info

    def available(self) -> Dict[str, bool]:
        return {"country": self._reader(settings.geoip_country_db) is not None,
                "asn": self._reader(settings.geoip_asn_db) is not None}


class Enricher:
    def __init__(self):
        self.geoip = GeoIP()
        self.lists = ThreatLists()
        self.stats = {"alerts": 0, "listed": 0, "located": 0, "errors": 0}

    def address(self, text: Optional[str]) -> Optional[Dict[str, Any]]:
        if not text:
            return None
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return None
        if not public(ip):
            return {"ip": text, "scope": "not public"}
        info: Dict[str, Any] = {"ip": text, **self.geoip.lookup(text)}
        info["threat_lists"] = self.lists.match(ip)
        return info

    def enrich(self, alert: SecurityAlert) -> Dict[str, Any]:
        data: Dict[str, Any] = {"mitre": MITRE.get(alert.alert_type, [])}
        for side, address in (("src", alert.src_ip), ("dst", alert.dst_ip)):
            info = self.address(address)
            if info:
                data[side] = info
                if info.get("threat_lists"):
                    self.stats["listed"] += 1
                if info.get("country"):
                    self.stats["located"] += 1
        self.stats["alerts"] += 1
        return data

    def get_stats(self) -> Dict[str, Any]:
        self.lists.refresh()
        return dict(self.stats, geoip=self.geoip.available(), threat_lists=dict(self.lists.sizes))


enricher = Enricher()


@event.listens_for(SecurityAlert, "before_insert")
def _enrich_before_insert(mapper, connection, alert: SecurityAlert) -> None:
    try:
        data = enricher.enrich(alert)
    except Exception as e:
        # Enrichment must never lose an alert
        enricher.stats["errors"] += 1
        logger.error(f"Alert enrichment failed: {e}")
        return
    alert.alert_metadata = {**(alert.alert_metadata or {}), "enrichment": data}
