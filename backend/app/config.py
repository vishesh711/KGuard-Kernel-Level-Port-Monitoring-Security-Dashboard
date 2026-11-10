"""
KGuard Backend Configuration

This module handles all configuration settings for the KGuard backend service.
Settings are loaded from environment variables with sensible defaults.
"""

import os
from typing import Dict, List

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
    # Signs login tokens. Required: the backend refuses to start without one
    # (at least 32 characters, e.g. openssl rand -hex 32)
    secret_key: str = ""
    # How long a login lasts (one shift)
    access_token_expire_minutes: int = 480
    # First admin, created only while there are no users at all
    admin_username: str = "admin"
    admin_password: str = ""
    # Requests per minute per client address to /api (0 = no limit)
    rate_limit_per_minute: int = 300
    # Failed logins per minute per address and per username (0 = no limit)
    login_attempts_per_minute: int = 5
    # Proxies whose X-Forwarded-For is believed (the frontend's nginx)
    forwarded_allow_ips: str = "127.0.0.1"

    # CORS: browser origins that may call the API ("*" is refused)
    allowed_origins: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173"
    ]

    # Host names the API answers to (TrustedHostMiddleware; "*" is refused)
    allowed_hosts: List[str] = ["localhost", "127.0.0.1", "backend"]

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"  # "json" (one object per line) or "text"
    # Also log to this file, rotated at log_max_bytes; empty = stdout only
    log_file: str = ""
    log_max_bytes: int = 10_000_000
    log_backup_count: int = 5

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

    # Notifications (S6.7): alerts at or above this severity go to every
    # configured channel, at most notify_max_per_hour per channel
    notify_min_severity: str = "HIGH"
    notify_max_per_hour: int = 30
    slack_webhook_url: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    telegram_api_base: str = "https://api.telegram.org"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_starttls: bool = True
    email_from: str = ""
    email_to: List[str] = []
    # Link to the dashboard in messages, e.g. https://kguard.example.com
    dashboard_url: str = ""

    # Bearer token Prometheus sends to GET /metrics (S6.8); empty = /metrics off
    metrics_token: str = ""

    # Detection state (S6.2): sliding windows and alert cooldowns in Redis,
    # so a restart keeps them and several backend processes agree.
    # Empty: kept in memory.
    redis_url: str = ""

    # Response engine (S6.4). Blocks are always available from the API;
    # automatic blocking is off until AUTO_BLOCK=true.
    auto_block: bool = False
    # Alert types that block their source automatically. Not SYN floods,
    # spoofing or amplification: their source addresses are easily forged,
    # so blocking them would let an attacker cut off anyone.
    auto_block_types: List[str] = ["PORT_SCAN", "BRUTE_FORCE"]
    auto_block_min_severity: str = "HIGH"
    # Also block the source of any alert when it is on a threat list (S6.3)
    auto_block_listed_sources: bool = False
    # How long an automatic block lasts; doubled for each earlier automatic
    # block of the same address in the last day (at most a week)
    auto_block_minutes: int = 60
    # Enforcers hold each block for at most this long and renew it, so a
    # block whose removal never reached them still ends soon
    block_lease_seconds: int = 300
    # Apply blocks with the kernel module on this machine over Netlink:
    # "auto" (when the module is loaded and the backend may: CAP_NET_ADMIN)
    # or "off" (leave enforcement to agents)
    local_enforcement: str = "auto"

    # Enrichment (S6.3): MaxMind GeoLite2 databases and bad-IP list files
    geoip_country_db: str = "./data/geoip/GeoLite2-Country.mmdb"
    geoip_asn_db: str = "./data/geoip/GeoLite2-ASN.mmdb"
    # Every *.txt / *.netset / *.ipset file here is a list named after the file
    threat_lists_dir: str = "./data/threatlists"
    # Lists fetched by "python -m app.threatlists update" (and every
    # threat_list_update_hours by the backend itself, when set)
    threat_list_urls: Dict[str, str] = {
        "firehol_level1": "https://iplists.firehol.org/files/firehol_level1.netset",
        "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
        "spamhaus_dropv6": "https://www.spamhaus.org/drop/dropv6.txt",
    }
    threat_list_update_hours: int = 0
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
    # ...within this many seconds. Longer than the scan window: SSH allows several
    # passwords per connection, so a brute force needs few connections a minute
    brute_force_window_seconds: int = 300
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
    # (200: SSDP answers are typically 250-350 bytes; only unsolicited replies count)
    amplification_min_bytes: int = 200
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
    # Data retention (retention.py), in days; 0 keeps that data forever.
    # Open alerts are never deleted automatically.
    retention_events_days: int = 7
    retention_metrics_days: int = 30
    retention_alerts_days: int = 90
    retention_interval_hours: int = 24
    retention_batch: int = 10_000
    # IPFIX flow export (flow_export.py): collectors as "host:port"; empty = off
    ipfix_collectors: List[str] = []
    ipfix_idle_timeout: int = 15
    ipfix_active_timeout: int = 60
    ipfix_template_refresh: int = 30
    ipfix_max_flows: int = 100_000
    # Packet capture on alert (packet_capture.py): records this server's
    # traffic (first pcap_snaplen bytes of each packet) for pcap_seconds and
    # saves the packets of each alert of pcap_min_severity or above.
    # Needs root or CAP_NET_RAW.
    pcap_on_alert: bool = False
    pcap_seconds: int = 30
    pcap_post_seconds: int = 5
    pcap_buffer_mb: int = 64
    pcap_snaplen: int = 256
    pcap_min_severity: str = "HIGH"
    pcap_dir: str = "./data/pcaps"
    pcap_max_files: int = 200
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
