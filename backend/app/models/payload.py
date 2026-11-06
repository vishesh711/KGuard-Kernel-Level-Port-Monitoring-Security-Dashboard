"""
Application-layer records from payload samples (eBPF agent): DNS lookups and
TLS ClientHellos with their client fingerprints.
"""

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
)
from sqlalchemy.sql import func

from ..database import Base


class DnsQuery(Base):
    __tablename__ = "dns_queries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(BigInteger, nullable=False, comment="Kernel timestamp (ns)")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    host_id = Column(Integer, nullable=True, index=True)
    client_ip = Column(String(45), nullable=False, index=True)
    client_port = Column(Integer, nullable=True)
    server_ip = Column(String(45), nullable=False)
    direction = Column(String(8), nullable=True)
    is_response = Column(Boolean, nullable=False, default=False)
    query_id = Column(Integer, nullable=True, comment="DNS message ID")
    qname = Column(String(255), nullable=False, index=True)
    qtype = Column(Integer, nullable=True)
    qtype_name = Column(String(12), nullable=True)
    domain = Column(String(255), nullable=True, index=True, comment="Registered domain")
    subdomain_length = Column(SmallInteger, nullable=True)
    entropy = Column(Float, nullable=True, comment="Bits per character of the subdomain")
    rcode = Column(SmallInteger, nullable=True)
    answer_count = Column(SmallInteger, nullable=True)
    process_name = Column(String(16), nullable=True)
    pid = Column(Integer, nullable=True)

    __table_args__ = (Index("idx_dns_domain_time", "domain", "timestamp"),)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "timestamp": self.timestamp,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "host_id": self.host_id, "client_ip": self.client_ip, "client_port": self.client_port,
            "server_ip": self.server_ip, "direction": self.direction, "is_response": self.is_response,
            "qname": self.qname, "qtype": self.qtype, "qtype_name": self.qtype_name, "domain": self.domain,
            "subdomain_length": self.subdomain_length, "entropy": self.entropy, "rcode": self.rcode,
            "answer_count": self.answer_count, "process_name": self.process_name, "pid": self.pid,
        }


class TlsHandshake(Base):
    __tablename__ = "tls_handshakes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(BigInteger, nullable=False, comment="Kernel timestamp (ns)")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    host_id = Column(Integer, nullable=True, index=True)
    client_ip = Column(String(45), nullable=False, index=True)
    client_port = Column(Integer, nullable=False)
    server_ip = Column(String(45), nullable=False)
    server_port = Column(Integer, nullable=False)
    direction = Column(String(8), nullable=True, comment="out: this host is the client")
    sni = Column(String(255), nullable=True, index=True, comment="Requested server name")
    alpn = Column(String(64), nullable=True, comment="First ALPN protocol offered")
    tls_version = Column(String(12), nullable=True, comment="Highest version offered")
    ja3 = Column(String(32), nullable=False, index=True)
    ja3_string = Column(Text, nullable=True)
    ja4 = Column(String(40), nullable=False, index=True)
    ja4_r = Column(Text, nullable=True, comment="JA4 before hashing")
    known_bad = Column(String(128), nullable=True, comment="Blocklist label when the fingerprint is listed")
    process_name = Column(String(16), nullable=True)
    pid = Column(Integer, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "timestamp": self.timestamp,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "host_id": self.host_id, "client_ip": self.client_ip, "client_port": self.client_port,
            "server_ip": self.server_ip, "server_port": self.server_port, "direction": self.direction,
            "sni": self.sni, "alpn": self.alpn, "tls_version": self.tls_version,
            "ja3": self.ja3, "ja3_string": self.ja3_string, "ja4": self.ja4, "ja4_r": self.ja4_r,
            "known_bad": self.known_bad, "process_name": self.process_name, "pid": self.pid,
        }
