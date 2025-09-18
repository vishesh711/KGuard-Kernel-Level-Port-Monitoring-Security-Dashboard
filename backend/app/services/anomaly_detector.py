"""
Anomaly Detection Service

This service analyzes network events to detect suspicious patterns
and generate security alerts.
"""

import logging
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from dataclasses import dataclass

from sqlalchemy.orm import Session
from sqlalchemy import and_, func
from ..database import SessionLocal
from ..models.network_event import NetworkEvent
from ..models.security_alert import SecurityAlert, AlertType, AlertSeverity
from ..config import settings

logger = logging.getLogger(__name__)


@dataclass
class DetectionPattern:
    """Data class for detection patterns"""
    src_ip: str
    event_count: int
    unique_ports: Set[int]
    time_window: timedelta
    first_seen: datetime
    last_seen: datetime
    event_ids: List[int]


class AnomalyDetectorService:
    """
    Service for detecting anomalous network behavior and generating alerts.
    """
    
    def __init__(self):
        self.port_scan_threshold = settings.port_scan_threshold
        self.suspicious_ports = set(settings.suspicious_ports)
        self.alert_cooldown = timedelta(seconds=settings.alert_cooldown_seconds)
        self.detection_window = timedelta(minutes=10)  # Analysis window
        
        # Cache for recent alerts to prevent spam
        self.recent_alerts: Dict[str, datetime] = {}
        
        self.stats = {
            "events_analyzed": 0,
            "alerts_generated": 0,
            "port_scans_detected": 0,
            "suspicious_ports_detected": 0,
            "last_analysis": None
        }
    
    async def analyze_events(self, events: List[NetworkEvent]) -> List[SecurityAlert]:
        """
        Analyze a batch of network events for suspicious patterns
        
        Args:
            events: List of network events to analyze
            
        Returns:
            List[SecurityAlert]: Generated security alerts
        """
        if not events:
            return []
        
        alerts = []
        self.stats["events_analyzed"] += len(events)
        
        try:
            # Group events by source IP for pattern analysis
            ip_patterns = self._group_events_by_source(events)
            
            # Detect port scanning
            port_scan_alerts = await self._detect_port_scans(ip_patterns)
            alerts.extend(port_scan_alerts)
            
            # Detect suspicious port access
            suspicious_port_alerts = await self._detect_suspicious_ports(events)
            alerts.extend(suspicious_port_alerts)
            
            # Detect high frequency connections
            high_freq_alerts = await self._detect_high_frequency(ip_patterns)
            alerts.extend(high_freq_alerts)
            
            # Update statistics
            self.stats["alerts_generated"] += len(alerts)
            self.stats["last_analysis"] = datetime.utcnow()
            
            logger.info(f"Analyzed {len(events)} events, generated {len(alerts)} alerts")
            
        except Exception as e:
            logger.error(f"Error during anomaly analysis: {e}")
        
        return alerts
    
    def _group_events_by_source(self, events: List[NetworkEvent]) -> Dict[str, DetectionPattern]:
        """
        Group events by source IP for pattern analysis
        
        Args:
            events: List of network events
            
        Returns:
            Dict[str, DetectionPattern]: Events grouped by source IP
        """
        patterns = {}
        
        for event in events:
            src_ip = event.src_ip
            
            if src_ip not in patterns:
                patterns[src_ip] = DetectionPattern(
                    src_ip=src_ip,
                    event_count=0,
                    unique_ports=set(),
                    time_window=timedelta(),
                    first_seen=event.created_at,
                    last_seen=event.created_at,
                    event_ids=[]
                )
            
            pattern = patterns[src_ip]
            pattern.event_count += 1
            pattern.unique_ports.add(event.dst_port)
            pattern.event_ids.append(event.id)
            
            # Update time window
            if event.created_at < pattern.first_seen:
                pattern.first_seen = event.created_at
            if event.created_at > pattern.last_seen:
                pattern.last_seen = event.created_at
            
            pattern.time_window = pattern.last_seen - pattern.first_seen
        
        return patterns
    
    async def _detect_port_scans(self, patterns: Dict[str, DetectionPattern]) -> List[SecurityAlert]:
        """
        Detect port scanning patterns
        
        Args:
            patterns: Events grouped by source IP
            
        Returns:
            List[SecurityAlert]: Port scan alerts
        """
        alerts = []
        
        for src_ip, pattern in patterns.items():
            # Check if this looks like a port scan
            if (len(pattern.unique_ports) >= self.port_scan_threshold and
                pattern.time_window.total_seconds() <= 60):  # Within 1 minute
                
                # Check cooldown to prevent alert spam
                alert_key = f"port_scan_{src_ip}"
                if self._is_in_cooldown(alert_key):
                    continue
                
                # Create port scan alert
                alert = SecurityAlert.create_port_scan_alert(
                    src_ip=src_ip,
                    event_count=pattern.event_count,
                    event_ids=pattern.event_ids
                )
                
                # Store alert in database
                if await self._store_alert(alert):
                    alerts.append(alert)
                    self.recent_alerts[alert_key] = datetime.utcnow()
                    self.stats["port_scans_detected"] += 1
                    
                    logger.warning(f"Port scan detected from {src_ip}: "
                                 f"{len(pattern.unique_ports)} unique ports in "
                                 f"{pattern.time_window.total_seconds():.1f} seconds")
        
        return alerts
    
    async def _detect_suspicious_ports(self, events: List[NetworkEvent]) -> List[SecurityAlert]:
        """
        Detect access to suspicious ports
        
        Args:
            events: List of network events
            
        Returns:
            List[SecurityAlert]: Suspicious port alerts
        """
        alerts = []
        
        for event in events:
            if event.dst_port in self.suspicious_ports:
                # Check cooldown
                alert_key = f"suspicious_port_{event.src_ip}_{event.dst_port}"
                if self._is_in_cooldown(alert_key):
                    continue
                
                # Create suspicious port alert
                alert = SecurityAlert.create_suspicious_port_alert(
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    dst_port=event.dst_port,
                    event_ids=[event.id]
                )
                
                # Store alert in database
                if await self._store_alert(alert):
                    alerts.append(alert)
                    self.recent_alerts[alert_key] = datetime.utcnow()
                    self.stats["suspicious_ports_detected"] += 1
                    
                    logger.warning(f"Suspicious port access: {event.src_ip} -> "
                                 f"{event.dst_ip}:{event.dst_port}")
        
        return alerts
    
    async def _detect_high_frequency(self, patterns: Dict[str, DetectionPattern]) -> List[SecurityAlert]:
        """
        Detect high frequency connection attempts
        
        Args:
            patterns: Events grouped by source IP
            
        Returns:
            List[SecurityAlert]: High frequency alerts
        """
        alerts = []
        high_freq_threshold = 50  # connections per minute
        
        for src_ip, pattern in patterns.items():
            if pattern.time_window.total_seconds() > 0:
                freq = pattern.event_count / (pattern.time_window.total_seconds() / 60)
                
                if freq > high_freq_threshold:
                    # Check cooldown
                    alert_key = f"high_freq_{src_ip}"
                    if self._is_in_cooldown(alert_key):
                        continue
                    
                    # Create high frequency alert
                    alert = SecurityAlert(
                        timestamp=datetime.utcnow(),
                        alert_type=AlertType.HIGH_FREQUENCY,
                        severity=AlertSeverity.MEDIUM,
                        title=f"High Frequency Connections from {src_ip}",
                        description=f"Detected {pattern.event_count} connections from {src_ip} "
                                   f"in {pattern.time_window.total_seconds():.1f} seconds "
                                   f"({freq:.1f} connections/minute)",
                        src_ip=src_ip,
                        related_event_ids=pattern.event_ids,
                        metadata={
                            "frequency": freq,
                            "event_count": pattern.event_count,
                            "time_window_seconds": pattern.time_window.total_seconds()
                        }
                    )
                    
                    # Store alert in database
                    if await self._store_alert(alert):
                        alerts.append(alert)
                        self.recent_alerts[alert_key] = datetime.utcnow()
                        
                        logger.warning(f"High frequency connections from {src_ip}: "
                                     f"{freq:.1f} connections/minute")
        
        return alerts
    
    def _is_in_cooldown(self, alert_key: str) -> bool:
        """
        Check if an alert type is in cooldown period
        
        Args:
            alert_key: Unique key for the alert type
            
        Returns:
            bool: True if in cooldown period
        """
        if alert_key not in self.recent_alerts:
            return False
        
        last_alert = self.recent_alerts[alert_key]
        return datetime.utcnow() - last_alert < self.alert_cooldown
    
    async def _store_alert(self, alert: SecurityAlert) -> bool:
        """
        Store alert in database
        
        Args:
            alert: Security alert to store
            
        Returns:
            bool: True if successfully stored
        """
        db = SessionLocal()
        try:
            db.add(alert)
            db.commit()
            db.refresh(alert)
            return True
        except Exception as e:
            logger.error(f"Error storing alert: {e}")
            db.rollback()
            return False
        finally:
            db.close()
    
    async def analyze_historical_patterns(self, hours: int = 24) -> Dict[str, Any]:
        """
        Analyze historical patterns for baseline establishment
        
        Args:
            hours: Number of hours to analyze
            
        Returns:
            Dict[str, Any]: Analysis results
        """
        db = SessionLocal()
        try:
            # Get events from the last N hours
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            events = db.query(NetworkEvent).filter(
                NetworkEvent.created_at >= cutoff_time
            ).all()
            
            if not events:
                return {"error": "No events found in time range"}
            
            # Analyze patterns
            analysis = {
                "time_range_hours": hours,
                "total_events": len(events),
                "unique_src_ips": len(set(e.src_ip for e in events)),
                "unique_dst_ips": len(set(e.dst_ip for e in events)),
                "protocol_distribution": dict(Counter(e.protocol for e in events)),
                "top_src_ips": self._get_top_ips([e.src_ip for e in events]),
                "top_dst_ports": self._get_top_ports([e.dst_port for e in events]),
                "suspicious_events": len([e for e in events if e.is_suspicious]),
                "hourly_distribution": self._get_hourly_distribution(events)
            }
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing historical patterns: {e}")
            return {"error": str(e)}
        finally:
            db.close()
    
    def _get_top_ips(self, ips: List[str], limit: int = 10) -> List[Dict[str, Any]]:
        """Get top IPs by frequency"""
        counter = Counter(ips)
        return [{"ip": ip, "count": count} for ip, count in counter.most_common(limit)]
    
    def _get_top_ports(self, ports: List[int], limit: int = 10) -> List[Dict[str, Any]]:
        """Get top ports by frequency"""
        counter = Counter(ports)
        return [{"port": port, "count": count} for port, count in counter.most_common(limit)]
    
    def _get_hourly_distribution(self, events: List[NetworkEvent]) -> List[Dict[str, Any]]:
        """Get hourly event distribution"""
        hourly_counts = defaultdict(int)
        for event in events:
            hour = event.created_at.hour
            hourly_counts[hour] += 1
        
        return [{"hour": hour, "count": count} for hour, count in sorted(hourly_counts.items())]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detection statistics"""
        return {
            **self.stats,
            "port_scan_threshold": self.port_scan_threshold,
            "suspicious_ports_count": len(self.suspicious_ports),
            "alert_cooldown_seconds": self.alert_cooldown.total_seconds(),
            "active_cooldowns": len(self.recent_alerts)
        }
    
    def cleanup_old_cooldowns(self) -> None:
        """Clean up expired cooldown entries"""
        current_time = datetime.utcnow()
        expired_keys = [
            key for key, timestamp in self.recent_alerts.items()
            if current_time - timestamp > self.alert_cooldown
        ]
        
        for key in expired_keys:
            del self.recent_alerts[key]
        
        if expired_keys:
            logger.debug(f"Cleaned up {len(expired_keys)} expired cooldown entries")


# Global instance
anomaly_detector = AnomalyDetectorService()