"""
KGuard Backend Configuration

This module handles all configuration settings for the KGuard backend service.
Settings are loaded from environment variables with sensible defaults.
"""

import os
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # API Settings
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    debug: bool = False

    # Database
    database_url: str = "sqlite:///./data/kguard.db"

    # Security
    secret_key: str = "change-this-in-production-very-secret-key"
    access_token_expire_minutes: int = 30

    # CORS
    allowed_origins: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173"
    ]

    # Host names the API answers to when DEBUG is off (TrustedHostMiddleware)
    allowed_hosts: List[str] = ["localhost", "127.0.0.1", "*.local", "backend"]

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"

    # Kernel Module Interface
    # Where events come from: "device" (/dev/kguard, zero-copy mmap),
    # "proc" (/proc/kguard JSON) or "auto" (device if available, else proc)
    kguard_source: str = "auto"
    kguard_device_path: str = "/dev/kguard"
    proc_kguard_path: str = "/proc/kguard"
    # Look up which process owns each socket (needs the host's /proc; in
    # Docker that means pid: host)
    resolve_processes: bool = True
    proc_root: str = "/proc"
    data_collection_interval: float = 1.0

    # Kernel guard alerts: "auto" uses the module's in-kernel scan and SYN-rate
    # detection when it is loaded (and turns off the backend's own copies of
    # those rules); "off" always uses the backend's rules
    kernel_detection: str = "auto"
    kguard_module_path: str = "/sys/module/kguard"

    # Agents (remote hosts). Enrollment is disabled while the key is empty.
    agent_enrollment_key: str = ""
    max_ingest_events: int = 20000

    # Anomaly Detection
    # A source becomes a port scanner after trying this many distinct ports
    # within the detection window
    port_scan_threshold: int = 10
    # Connection attempts to these ports raise SUSPICIOUS_PORT alerts. Web
    # ports (80, 443) are left out: every visitor to a web server would alert.
    suspicious_ports: List[int] = [22, 23, 3389, 5432, 3306]
    # Sources (addresses or CIDR prefixes) never alerted on, e.g. monitoring
    # and management hosts
    trusted_sources: List[str] = []
    # Repeated new connections to login/database ports raise BRUTE_FORCE
    brute_force_ports: List[int] = [21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017]
    brute_force_threshold: int = 10
    # Half-open connections to one destination that make a SYN flood
    syn_flood_threshold: int = 200
    syn_flood_window_seconds: int = 10
    # Spoofing (SPOOFED_TRAFFIC): packets from one source whose hop count
    # (from the TTL) jumps by at least ttl_jump_hops, at least ttl_jump_packets times
    ttl_jump_hops: int = 5
    ttl_jump_packets: int = 3
    # Report sources in bogon ranges (documentation, benchmarking, reserved, ...);
    # turn off for labs that use those ranges internally
    bogon_detection: bool = True
    # Amplification (AMPLIFICATION): UDP replies from reflector ports
    # (DNS, NTP, memcached, SSDP, ...) of at least amplification_min_bytes
    amplification_min_bytes: int = 400
    # Unsolicited replies to one destination within the window
    amplification_threshold: int = 50
    amplification_window_seconds: int = 10
    # This host as a reflector: reply bytes to one client at least this many
    # times the request bytes, and at least reflector_min_bytes in the window
    reflector_ratio: float = 10.0
    reflector_min_bytes: int = 100_000
    # DNS tunnelling (DNS_TUNNELING), from eBPF agents' DNS samples: per
    # client and registered domain within the window (see dns_tunnel.py)
    dns_tunnel_window_seconds: int = 60
    dns_tunnel_min_queries: int = 20
    dns_tunnel_score: float = 0.6
    # Reverse lookups and DNS blocklist / reputation services encode data in
    # names on purpose
    dns_tunnel_allowlist: List[str] = [
        "in-addr.arpa", "ip6.arpa", "spamhaus.org", "spamcop.net", "sorbs.net", "surbl.org",
        "uribl.com", "barracudacentral.org", "sophosxl.net",
    ]
    # Known-bad TLS client fingerprints (MALICIOUS_TLS): a CSV file whose first
    # column is a JA3 (32 hex) or JA4 fingerprint and whose other columns are
    # a label, e.g. abuse.ch SSLBL's ja3_fingerprints.csv. Empty: no matching.
    tls_fingerprint_blocklist: str = ""
    # Traffic baseline (UNUSUAL_TRAFFIC): per host and port, per interval
    baseline_interval_seconds: int = 60
    baseline_alpha: float = 0.1
    baseline_warmup: int = 10
    baseline_sigma: float = 6.0
    baseline_ratio: float = 5.0
    baseline_min_count: int = 100
    # A source trying more connections than this per minute raises HIGH_FREQUENCY
    high_frequency_threshold: int = 100
    # How far back (seconds) detection looks at each source's activity
    detection_window_seconds: int = 60
    # Upper limit on remembered attempts per source, to bound memory use
    max_attempts_per_source: int = 10000
    alert_cooldown_seconds: int = 300
    max_events_per_minute: int = 1000

    # WebSocket
    websocket_max_connections: int = 100
    websocket_heartbeat_interval: int = 30
    # Most network events pushed live per collection cycle (alerts are never capped)
    websocket_max_events_per_batch: int = 20

    # Rate Limiting
    rate_limit_requests_per_minute: int = 100
    rate_limit_burst: int = 20

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")


# Global settings instance
settings = Settings()


def get_database_url() -> str:
    """Get the database URL, creating the folder for a SQLite file if needed"""
    url = settings.database_url
    prefix = "sqlite:///"
    if url.startswith(prefix) and ":memory:" not in url:
        folder = os.path.dirname(url[len(prefix):])
        if folder:
            os.makedirs(folder, exist_ok=True)
    return url
