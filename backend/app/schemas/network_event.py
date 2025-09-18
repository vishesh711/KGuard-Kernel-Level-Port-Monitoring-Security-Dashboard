"""
Network Event Pydantic Schemas

This module contains Pydantic schemas for network event API endpoints.
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class NetworkEventBase(BaseModel):
    """Base network event schema"""
    timestamp: int = Field(..., description="High-resolution timestamp (nanoseconds)")
    src_ip: str = Field(..., description="Source IP address")
    dst_ip: str = Field(..., description="Destination IP address")
    src_port: int = Field(..., ge=0, le=65535, description="Source port number")
    dst_port: int = Field(..., ge=0, le=65535, description="Destination port number")
    protocol: str = Field(..., description="Protocol name (TCP, UDP, ICMP, etc.)")
    flags: int = Field(default=0, description="Protocol-specific flags")


class NetworkEventCreate(NetworkEventBase):
    """Schema for creating network events"""
    is_suspicious: bool = Field(default=False, description="Whether event is suspicious")
    event_type: str = Field(default="normal", description="Event classification type")


class NetworkEventResponse(NetworkEventBase):
    """Schema for network event API responses"""
    id: int = Field(..., description="Unique event ID")
    created_at: datetime = Field(..., description="Database insertion timestamp")
    is_suspicious: bool = Field(..., description="Whether event is suspicious")
    event_type: str = Field(..., description="Event classification type")
    
    class Config:
        from_attributes = True


class NetworkEventFilter(BaseModel):
    """Schema for filtering network events"""
    src_ip: Optional[str] = Field(None, description="Filter by source IP")
    dst_ip: Optional[str] = Field(None, description="Filter by destination IP")
    src_port: Optional[int] = Field(None, ge=0, le=65535, description="Filter by source port")
    dst_port: Optional[int] = Field(None, ge=0, le=65535, description="Filter by destination port")
    protocol: Optional[str] = Field(None, description="Filter by protocol")
    is_suspicious: Optional[bool] = Field(None, description="Filter by suspicious flag")
    start_time: Optional[datetime] = Field(None, description="Start time for filtering")
    end_time: Optional[datetime] = Field(None, description="End time for filtering")


class NetworkEventStats(BaseModel):
    """Schema for network event statistics"""
    total_events: int = Field(..., description="Total number of events")
    suspicious_events: int = Field(..., description="Number of suspicious events")
    unique_src_ips: int = Field(..., description="Number of unique source IPs")
    unique_dst_ips: int = Field(..., description="Number of unique destination IPs")
    protocol_distribution: dict = Field(..., description="Distribution of protocols")
    top_src_ips: list = Field(..., description="Top source IPs by event count")
    top_dst_ports: list = Field(..., description="Top destination ports by event count")
    events_per_hour: list = Field(..., description="Events per hour for the last 24 hours")
    
    class Config:
        from_attributes = True


class TrafficSummary(BaseModel):
    """Schema for traffic summary statistics"""
    timestamp: datetime = Field(..., description="Summary timestamp")
    total_packets: int = Field(..., description="Total packets in time period")
    tcp_packets: int = Field(..., description="TCP packets count")
    udp_packets: int = Field(..., description="UDP packets count")
    icmp_packets: int = Field(..., description="ICMP packets count")
    unique_connections: int = Field(..., description="Unique connections count")
    suspicious_activity: int = Field(..., description="Suspicious activity count")
    
    class Config:
        from_attributes = True