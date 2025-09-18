"""
KGuard Backend Configuration

This module handles all configuration settings for the KGuard backend service.
Settings are loaded from environment variables with sensible defaults.
"""

from pydantic_settings import BaseSettings
from typing import List
import os


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
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "json"
    
    # Kernel Module Interface
    proc_kguard_path: str = "/proc/kguard"
    data_collection_interval: float = 1.0
    
    # Anomaly Detection
    port_scan_threshold: int = 10
    suspicious_ports: List[int] = [22, 23, 80, 443, 3389, 5432, 3306]
    alert_cooldown_seconds: int = 300
    max_events_per_minute: int = 1000
    
    # WebSocket
    websocket_max_connections: int = 100
    websocket_heartbeat_interval: int = 30
    
    # Rate Limiting
    rate_limit_requests_per_minute: int = 100
    rate_limit_burst: int = 20
    
    # Background Tasks
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/0"
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()


def get_database_url() -> str:
    """Get the database URL, handling SQLite path resolution"""
    # Ensure the data directory exists
    os.makedirs("data", exist_ok=True)
    return settings.database_url