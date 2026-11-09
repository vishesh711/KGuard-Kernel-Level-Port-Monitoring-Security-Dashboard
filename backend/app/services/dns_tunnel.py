"""
DNS tunnelling detection (DNS_TUNNELING).

A DNS tunnel (iodine, dnscat2, DNS exfiltration malware) hides data in the
names it looks up under a domain the attacker controls:

    paa1bhsk2...mcsbkde7a.t.example.com   (iodine, base32 of IP packets)

and gets data back in the answers, typically TXT or NULL records. Through
any recursive resolver the queries reach the attacker's name server, so
it works where nothing else is allowed out.

Queries are grouped per host, client and registered domain over
`dns_tunnel_window_seconds`. Each group gets a score from 0 to 1:

    0.30 x long names         mean subdomain length, full at 40 characters
    0.30 x random-looking     share of queries with a subdomain of at least
                              30 characters and entropy >= 3.5 bits/char
    0.20 x never repeated     unique subdomains / queries
    0.20 x odd record types   share of TXT, NULL, ANY and private types

and an alert needs at least `dns_tunnel_min_queries` queries, at least 70%
of them unique (tunnels never repeat a name: every query carries new data,
which also defeats resolver caches) and a score of `dns_tunnel_score`.

Ordinary browsing looks up many different domains, each a few times, with
short, readable names. Reverse lookups (in-addr.arpa, ip6.arpa) and DNS
blocklist / reputation services, which encode addresses or hashes in names
on purpose, are skipped (`dns_tunnel_allowlist`).
"""

import logging
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Deque, Optional, Tuple

from ..config import settings
from ..models.security_alert import AlertSeverity, AlertType, SecurityAlert
from .dns_parser import base_domain, entropy, qtype_name, subdomain

if TYPE_CHECKING:
    from .anomaly_detector import AnomalyDetectorService

logger = logging.getLogger(__name__)

ODD_TYPES = {10, 16, 255} | set(range(65280, 65535))  # NULL, TXT, ANY, private use
LONG_SUBDOMAIN = 30
HIGH_ENTROPY = 3.5
MIN_UNIQUE_RATIO = 0.7
MAX_GROUPS = 50_000
MAX_QUERIES_PER_GROUP = 2_000


@dataclass(frozen=True)
class Query:
    time: float
    sub: str
    qtype: int
    query_id: Optional[int]  # DnsQuery row id


def query_features(name: str) -> Tuple[str, str, float]:
    """(registered domain, subdomain, entropy of the subdomain without dots)"""
    sub = subdomain(name)
    return base_domain(name), sub, entropy(sub.replace(".", ""))


def score(queries) -> dict:
    n = len(queries)
    subs = [q.sub for q in queries]
    lengths = [len(s) for s in subs]
    mean_len = sum(lengths) / n
    random_like = sum(1 for s in subs
                      if len(s) >= LONG_SUBDOMAIN and entropy(s.replace(".", "")) >= HIGH_ENTROPY)
    unique = len(set(subs))
    odd = sum(1 for q in queries if q.qtype in ODD_TYPES)
    value = (0.3 * min(mean_len / 40, 1.0) + 0.3 * random_like / n
             + 0.2 * unique / n + 0.2 * odd / n)
    return {
        "score": round(value, 3),
        "queries": n,
        "unique_subdomains": unique,
        "unique_ratio": round(unique / n, 3),
        "mean_subdomain_length": round(mean_len, 1),
        "random_looking": random_like,
        "odd_type_queries": odd,
        "bytes_in_names": sum(lengths),
    }


class DnsTunnelDetector:
    def __init__(self, detector: "AnomalyDetectorService"):
        self.detector = detector
        self.window = float(settings.dns_tunnel_window_seconds)
        self.min_queries = settings.dns_tunnel_min_queries
        self.threshold = settings.dns_tunnel_score
        self.allowlist = {d.lower().strip(".") for d in settings.dns_tunnel_allowlist}
        # (host, client ip, registered domain) -> recent queries
        self.groups: "OrderedDict[tuple, Deque[Query]]" = OrderedDict()

    def reset(self) -> None:
        self.groups.clear()

    def allowed(self, domain: str) -> bool:
        return domain in self.allowlist or any(domain.endswith("." + a) for a in self.allowlist)

    def observe(self, host_id: Optional[int], client: str, name: str, qtype: int, t: float,
                query_id: Optional[int] = None) -> Optional[SecurityAlert]:
        """Add one query (not a response); returns an alert when its group crosses the threshold"""
        if self.detector.is_trusted(client):
            return None
        domain, sub, _ = query_features(name)
        if not sub or self.allowed(domain):
            return None
        key = (host_id, client, domain)
        queries = self.groups.get(key)
        if queries is None:
            queries = deque(maxlen=MAX_QUERIES_PER_GROUP)
            self.groups[key] = queries
            if len(self.groups) > MAX_GROUPS:
                self.groups.popitem(last=False)
        else:
            self.groups.move_to_end(key)
        queries.append(Query(t, sub, qtype, query_id))
        while queries and queries[0].time < t - self.window:
            queries.popleft()
        if len(queries) < self.min_queries:
            return None

        features = score(queries)
        if features["unique_ratio"] < MIN_UNIQUE_RATIO or features["score"] < self.threshold:
            return None
        cooldown = f"dns_tunnel_{host_id}|{client}|{domain}"
        if not self.detector._claim_cooldown(cooldown):
            return None
        self.detector.stats["dns_tunnels_detected"] += 1
        return self._alert(host_id, client, domain, queries, features)

    def _alert(self, host_id, client, domain, queries, features) -> SecurityAlert:
        types = Counter(qtype_name(q.qtype) for q in queries)
        example = max(queries, key=lambda q: len(q.sub)).sub
        logger.warning(f"DNS tunnel suspected: {client} -> *.{domain} (score {features['score']})")
        return SecurityAlert(
            timestamp=datetime.utcnow(),
            alert_type=AlertType.DNS_TUNNELING,
            severity=AlertSeverity.HIGH if features["score"] >= 0.8 else AlertSeverity.MEDIUM,
            title=f"DNS Tunnel Suspected: {client} via {domain}",
            description=(
                f"{client} made {features['queries']} lookups under {domain} in {self.window:.0f} seconds, "
                f"{features['unique_subdomains']} with a different name, averaging "
                f"{features['mean_subdomain_length']:.0f} characters "
                f"(e.g. {example[:60]}{'...' if len(example) > 60 else ''}.{domain}), mostly "
                f"{types.most_common(1)[0][0]} records. Long, random, never-repeated names carry data: "
                f"this looks like a DNS tunnel (iodine, dnscat2) or exfiltration through DNS."
            ),
            src_ip=client,
            host_id=host_id,
            related_event_ids=[],
            alert_metadata={
                **features,
                "domain": domain,
                "record_types": dict(types.most_common(5)),
                "example": f"{example}.{domain}"[:255],
                "dns_query_ids": [q.query_id for q in queries if q.query_id is not None][-100:],
                "window_seconds": self.window,
                "detection_method": "dns_name_statistics",
            },
        )
