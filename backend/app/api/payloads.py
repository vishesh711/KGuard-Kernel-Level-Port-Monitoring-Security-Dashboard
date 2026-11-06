"""
DNS and TLS records from eBPF agents' payload samples.

    GET /api/dns/queries        recent lookups (filter by domain, client, host)
    GET /api/dns/domains        per registered domain: lookups, distinct names,
                                name length and entropy, tunnel score
    GET /api/tls/handshakes     recent ClientHellos with SNI, JA3, JA4
    GET /api/tls/fingerprints   per JA4: how often, which JA3s, server
                                names, processes and clients
"""

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.payload import DnsQuery, TlsHandshake
from ..services.dns_parser import subdomain
from ..services.dns_tunnel import Query as TunnelQuery
from ..services.dns_tunnel import score as tunnel_score

router = APIRouter(prefix="/api", tags=["payloads"])


def page(query, page_no: int, size: int):
    total = query.count()
    items = query.offset((page_no - 1) * size).limit(size).all()
    return {"items": [i.to_dict() for i in items], "total": total, "page": page_no, "size": size,
            "pages": (total + size - 1) // size}


@router.get("/dns/queries")
async def dns_queries(page_no: int = Query(1, ge=1, alias="page"), size: int = Query(50, ge=1, le=500),
                      domain: Optional[str] = None, client_ip: Optional[str] = None,
                      host_id: Optional[int] = None, responses: bool = False, db: Session = Depends(get_db)):
    q = db.query(DnsQuery)
    if not responses:
        q = q.filter(DnsQuery.is_response.is_(False))
    if domain:
        q = q.filter(DnsQuery.domain == domain.lower())
    if client_ip:
        q = q.filter(DnsQuery.client_ip == client_ip)
    if host_id is not None:
        q = q.filter(DnsQuery.host_id == host_id)
    return page(q.order_by(DnsQuery.timestamp.desc()), page_no, size)


@router.get("/dns/domains")
async def dns_domains(minutes: int = Query(60, ge=1, le=1440), limit: int = Query(50, ge=1, le=500),
                      db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(minutes=minutes)
    rows = (db.query(DnsQuery.domain, DnsQuery.qname, DnsQuery.qtype, DnsQuery.timestamp, DnsQuery.client_ip)
            .filter(DnsQuery.is_response.is_(False), DnsQuery.created_at >= since)
            .order_by(DnsQuery.id.desc()).limit(100_000).all())
    groups = defaultdict(list)
    clients = defaultdict(set)
    for domain, qname, qtype, ts, client in rows:
        groups[domain].append(TunnelQuery(ts / 1e9, subdomain(qname), qtype or 0, None))
        clients[domain].add(client)
    result = []
    for domain, queries in groups.items():
        features = tunnel_score(queries)
        result.append({"domain": domain, "clients": len(clients[domain]), **features})
    result.sort(key=lambda d: (d["score"], d["queries"]), reverse=True)
    return result[:limit]


@router.get("/tls/handshakes")
async def tls_handshakes(page_no: int = Query(1, ge=1, alias="page"), size: int = Query(50, ge=1, le=500),
                         ja4: Optional[str] = None, ja3: Optional[str] = None, sni: Optional[str] = None,
                         host_id: Optional[int] = None, db: Session = Depends(get_db)):
    q = db.query(TlsHandshake)
    if ja4:
        q = q.filter(TlsHandshake.ja4 == ja4)
    if ja3:
        q = q.filter(TlsHandshake.ja3 == ja3.lower())
    if sni:
        q = q.filter(TlsHandshake.sni == sni.lower())
    if host_id is not None:
        q = q.filter(TlsHandshake.host_id == host_id)
    return page(q.order_by(TlsHandshake.timestamp.desc()), page_no, size)


@router.get("/tls/fingerprints")
async def tls_fingerprints(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(get_db)):
    rows = db.query(TlsHandshake).order_by(TlsHandshake.id.desc()).limit(50_000).all()
    groups = defaultdict(list)
    for row in rows:
        groups[row.ja4].append(row)
    result = []
    for ja4, items in groups.items():
        result.append({
            "ja4": ja4,
            "handshakes": len(items),
            # Browsers that shuffle extensions show many JA3s for one JA4
            "ja3": dict(Counter(i.ja3 for i in items).most_common(10)),
            "server_names": dict(Counter(i.sni or "(none)" for i in items).most_common(10)),
            "processes": dict(Counter(i.process_name for i in items
                                      if i.process_name and i.direction == "out").most_common(10)),
            "clients": sorted({i.client_ip for i in items})[:20],
            "tls_version": items[0].tls_version,
            "alpn": items[0].alpn,
            "known_bad": next((i.known_bad for i in items if i.known_bad), None),
            "first_seen": min(i.timestamp for i in items),
            "last_seen": max(i.timestamp for i in items),
        })
    result.sort(key=lambda g: g["handshakes"], reverse=True)
    return result[:limit]
