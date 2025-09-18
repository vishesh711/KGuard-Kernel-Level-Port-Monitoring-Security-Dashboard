"""
Security Alert Pydantic Schemas

This module contains Pydantic schemas for security alert API endpoints.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class AlertSeverityEnum(str, Enum):
    """Alert severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertTypeEnum(str, Enum):
    """Types of security alerts"""
    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE = "BRUTE_FORCE"
    SUSPICIOUS_PORT = "SUSPICIOUS_PORT"
    HIGH_FREQUENCY = "HIGH_FREQUENCY"
    UNUSUAL_TRAFFIC = "UNUSUAL_TRAFFIC"
    UNKNOWN_PROTOCOL = "UNKNOWN_PROTOCOL"


class SecurityAlertBase(BaseModel):
    """Base security alert schema"""
    alert_type: AlertTypeEnum = Field(..., description="Type of security alert")
    severity: AlertSeverityEnum = Field(..., description="Alert severity level")
    title: str = Field(..., max_length=200, description="Short alert title")
    description: str = Field(..., description="Detailed alert description")
    src_ip: Optional[str] = Field(None, description="Source IP address if applicable")
    dst_ip: Optional[str] = Field(None, description="Destination IP address if applicable")
    dst_port: Optional[int] = Field(None, ge=0, le=65535, description="Destination port if applicable")


class SecurityAlertCreate(SecurityAlertBase):
    """Schema for creating security alerts"""
    related_event_ids: Optional[List[int]] = Field(None, description="IDs of related network events")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional alert metadata")


class SecurityAlertResponse(SecurityAlertBase):
    """Schema for security alert API responses"""
    id: int = Field(..., description="Unique alert ID")
    timestamp: datetime = Field(..., description="When the alert was triggered")
    created_at: datetime = Field(..., description="Database insertion timestamp")
    related_event_ids: Optional[List[int]] = Field(None, description="IDs of related network events")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional alert metadata")
    acknowledged: bool = Field(..., description="Whether the alert has been acknowledged")
    acknowledged_at: Optional[datetime] = Field(None, description="When the alert was acknowledged")
    acknowledged_by: Optional[str] = Field(None, description="Who acknowledged the alert")
    resolved: bool = Field(..., description="Whether the alert has been resolved")
    resolved_at: Optional[datetime] = Field(None, description="When the alert was resolved")
    resolution_notes: Optional[str] = Field(None, description="Notes about alert resolution")
    
    class Config:
        from_attributes = True


class AlertAcknowledge(BaseModel):
    """Schema for acknowledging alerts"""
    acknowledged_by: str = Field(..., max_length=100, description="Who is acknowledging the alert")
    notes: Optional[str] = Field(None, description="Optional acknowledgment notes")


class AlertResolve(BaseModel):
    """Schema for resolving alerts"""
    resolved_by: str = Field(..., max_length=100, description="Who is resolving the alert")
    resolution_notes: str = Field(..., description="Notes about the resolution")


class AlertFilter(BaseModel):
    """Schema for filtering security alerts"""
    alert_type: Optional[AlertTypeEnum] = Field(None, description="Filter by alert type")
    severity: Optional[AlertSeverityEnum] = Field(None, description="Filter by severity")
    src_ip: Optional[str] = Field(None, description="Filter by source IP")
    dst_ip: Optional[str] = Field(None, description="Filter by destination IP")
    acknowledged: Optional[bool] = Field(None, description="Filter by acknowledgment status")
    resolved: Optional[bool] = Field(None, description="Filter by resolution status")
    start_time: Optional[datetime] = Field(None, description="Start time for filtering")
    end_time: Optional[datetime] = Field(None, description="End time for filtering")


class AlertStats(BaseModel):
    """Schema for alert statistics"""
    total_alerts: int = Field(..., description="Total number of alerts")
    unacknowledged_alerts: int = Field(..., description="Number of unacknowledged alerts")
    unresolved_alerts: int = Field(..., description="Number of unresolved alerts")
    critical_alerts: int = Field(..., description="Number of critical alerts")
    high_alerts: int = Field(..., description="Number of high severity alerts")
    medium_alerts: int = Field(..., description="Number of medium severity alerts")
    low_alerts: int = Field(..., description="Number of low severity alerts")
    alert_types_distribution: Dict[str, int] = Field(..., description="Distribution of alert types")
    alerts_per_hour: List[Dict[str, Any]] = Field(..., description="Alerts per hour for the last 24 hours")
    top_source_ips: List[Dict[str, Any]] = Field(..., description="Top source IPs by alert count")
    
    class Config:
        from_attributes = True