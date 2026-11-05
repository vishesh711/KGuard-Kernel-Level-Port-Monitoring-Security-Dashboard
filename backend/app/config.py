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

    # Anomaly Detection
    # A source becomes a port scanner after trying this many distinct ports
    # within the detection window
    port_scan_threshold: int = 10
    # Connection attempts to these ports raise SUSPICIOUS_PORT alerts
    suspicious_ports: List[int] = [22, 23, 80, 443, 3389, 5432, 3306]
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
