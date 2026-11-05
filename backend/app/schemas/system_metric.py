"""
System Metric Pydantic Schemas

This module contains Pydantic schemas for system metric API endpoints.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class SystemMetricBase(BaseModel):
    """Base system metric schema"""
    metric_name: str = Field(..., max_length=100, description="Name of the metric")
    metric_category: str = Field(..., max_length=50, description="Category of the metric")
    value: float = Field(..., description="Numeric value of the metric")
    unit: Optional[str] = Field(None, max_length=20, description="Unit of measurement")
    source: Optional[str] = Field(None, max_length=50, description="Source component")
    tags: Optional[str] = Field(None, max_length=200, description="Additional tags")


class SystemMetricCreate(SystemMetricBase):
    """Schema for creating system metrics"""
    pass


class SystemMetricResponse(SystemMetricBase):
    """Schema for system metric API responses"""
    id: int = Field(..., description="Unique metric ID")
    timestamp: datetime = Field(..., description="When the metric was recorded")

    model_config = ConfigDict(from_attributes=True)


class SystemMetricFilter(BaseModel):
    """Schema for filtering system metrics"""
    metric_name: Optional[str] = Field(None, description="Filter by metric name")
    metric_category: Optional[str] = Field(None, description="Filter by category")
    source: Optional[str] = Field(None, description="Filter by source")
    start_time: Optional[datetime] = Field(None, description="Start time for filtering")
    end_time: Optional[datetime] = Field(None, description="End time for filtering")


class MetricSummary(BaseModel):
    """Schema for metric summary statistics"""
    metric_name: str = Field(..., description="Metric name")
    current_value: float = Field(..., description="Current metric value")
    average_value: float = Field(..., description="Average value over time period")
    min_value: float = Field(..., description="Minimum value over time period")
    max_value: float = Field(..., description="Maximum value over time period")
    unit: Optional[str] = Field(None, description="Unit of measurement")
    last_updated: datetime = Field(..., description="When metric was last updated")

    model_config = ConfigDict(from_attributes=True)


class SystemHealth(BaseModel):
    """Schema for overall system health"""
    cpu_usage: float = Field(..., description="CPU usage percentage")
    memory_usage: float = Field(..., description="Memory usage percentage")
    disk_usage: float = Field(..., description="Disk usage percentage")
    network_events_per_second: float = Field(..., description="Network events per second")
    active_alerts: int = Field(..., description="Number of active alerts")
    database_connections: int = Field(..., description="Number of database connections")
    websocket_connections: int = Field(..., description="Number of WebSocket connections")
    uptime_seconds: float = Field(..., description="System uptime in seconds")
    last_updated: datetime = Field(..., description="When health data was last updated")

    model_config = ConfigDict(from_attributes=True)
