"""
Network Events API Endpoints

This module provides REST API endpoints for network events.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, and_, case, cast, desc, func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.network_event import NetworkEvent
from ..schemas.common import PaginatedResponse
from ..schemas.network_event import (
    NetworkEventResponse,
    NetworkEventStats,
    TrafficSummary,
)
from .buckets import bucket_expr, fill_series

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("/", response_model=PaginatedResponse[NetworkEventResponse])
async def get_events(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(25, ge=1, le=100, description="Page size"),
    src_ip: Optional[str] = Query(None, description="Filter by source IP"),
    dst_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    src_port: Optional[int] = Query(None, ge=0, le=65535, description="Filter by source port"),
    dst_port: Optional[int] = Query(None, ge=0, le=65535, description="Filter by destination port"),
    protocol: Optional[str] = Query(None, description="Filter by protocol"),
    is_suspicious: Optional[bool] = Query(None, description="Filter by suspicious flag"),
    direction: Optional[str] = Query(None, pattern="^(in|out|fwd)$", description="Filter by direction"),
    process_name: Optional[str] = Query(None, description="Filter by process name"),
    start_time: Optional[datetime] = Query(None, description="Start time filter"),
    end_time: Optional[datetime] = Query(None, description="End time filter"),
    db: Session = Depends(get_db)
):
    """
    Get paginated list of network events with optional filtering
    """
    try:
        # Build query with filters
        query = db.query(NetworkEvent)

        if src_ip:
            query = query.filter(NetworkEvent.src_ip == src_ip)
        if dst_ip:
            query = query.filter(NetworkEvent.dst_ip == dst_ip)
        if src_port is not None:
            query = query.filter(NetworkEvent.src_port == src_port)
        if dst_port is not None:
            query = query.filter(NetworkEvent.dst_port == dst_port)
        if protocol:
            query = query.filter(NetworkEvent.protocol == protocol)
        if is_suspicious is not None:
            query = query.filter(NetworkEvent.is_suspicious == is_suspicious)
        if direction:
            query = query.filter(NetworkEvent.direction == direction)
        if process_name:
            query = query.filter(NetworkEvent.process_name == process_name)
        if start_time:
            query = query.filter(NetworkEvent.created_at >= start_time)
        if end_time:
            query = query.filter(NetworkEvent.created_at <= end_time)

        # Get total count
        total = query.count()

        # Apply pagination and ordering
        events = query.order_by(desc(NetworkEvent.created_at)).offset(
            (page - 1) * size
        ).limit(size).all()

        # Calculate pagination info
        pages = (total + size - 1) // size

        return PaginatedResponse(
            items=[NetworkEventResponse.model_validate(event) for event in events],
            total=total,
            page=page,
            size=size,
            pages=pages
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving events: {str(e)}")


@router.get("/{event_id}", response_model=NetworkEventResponse)
async def get_event(event_id: int, db: Session = Depends(get_db)):
    """
    Get a specific network event by ID
    """
    event = db.query(NetworkEvent).filter(NetworkEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    return NetworkEventResponse.model_validate(event)


@router.get("/stats/summary", response_model=NetworkEventStats)
async def get_event_stats(
    hours: int = Query(24, ge=1, le=168, description="Hours to analyze"),
    db: Session = Depends(get_db)
):
    """
    Get network event statistics for the specified time period
    """
    try:
        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)

        # Base query for time range
        base_query = db.query(NetworkEvent).filter(
            and_(
                NetworkEvent.created_at >= start_time,
                NetworkEvent.created_at <= end_time
            )
        )

        # Total events
        total_events = base_query.count()

        # Suspicious events
        suspicious_events = base_query.filter(NetworkEvent.is_suspicious == True).count()

        # Unique IPs
        unique_src_ips = base_query.with_entities(NetworkEvent.src_ip).distinct().count()
        unique_dst_ips = base_query.with_entities(NetworkEvent.dst_ip).distinct().count()

        # Protocol distribution
        protocol_dist = db.query(
            NetworkEvent.protocol,
            func.count(NetworkEvent.id).label('count')
        ).filter(
            and_(
                NetworkEvent.created_at >= start_time,
                NetworkEvent.created_at <= end_time
            )
        ).group_by(NetworkEvent.protocol).all()

        protocol_distribution = {proto: count for proto, count in protocol_dist}

        # Top source IPs
        top_src_ips = db.query(
            NetworkEvent.src_ip,
            func.count(NetworkEvent.id).label('count')
        ).filter(
            and_(
                NetworkEvent.created_at >= start_time,
                NetworkEvent.created_at <= end_time
            )
        ).group_by(NetworkEvent.src_ip).order_by(desc('count')).limit(10).all()

        top_src_ips_list = [{"ip": ip, "count": count} for ip, count in top_src_ips]

        # Top destination ports
        top_dst_ports = db.query(
            NetworkEvent.dst_port,
            func.count(NetworkEvent.id).label('count')
        ).filter(
            and_(
                NetworkEvent.created_at >= start_time,
                NetworkEvent.created_at <= end_time
            )
        ).group_by(NetworkEvent.dst_port).order_by(desc('count')).limit(10).all()

        top_dst_ports_list = [{"port": port, "count": count} for port, count in top_dst_ports]

        # Events per hour, grouped in the database
        hour_bucket = bucket_expr(db, NetworkEvent.created_at, 3600)
        hourly = db.query(hour_bucket, func.count(NetworkEvent.id)).filter(
            and_(
                NetworkEvent.created_at >= start_time,
                NetworkEvent.created_at <= end_time
            )
        ).group_by(hour_bucket).all()

        events_per_hour = [
            {"hour": hour.isoformat(), "count": count}
            for hour, count in fill_series(dict(hourly), start_time, end_time, 3600, limit=hours)
        ]

        return NetworkEventStats(
            total_events=total_events,
            suspicious_events=suspicious_events,
            unique_src_ips=unique_src_ips,
            unique_dst_ips=unique_dst_ips,
            protocol_distribution=protocol_distribution,
            top_src_ips=top_src_ips_list,
            top_dst_ports=top_dst_ports_list,
            events_per_hour=events_per_hour
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error calculating statistics: {str(e)}")


@router.get("/stats/traffic", response_model=List[TrafficSummary])
async def get_traffic_summary(
    hours: int = Query(24, ge=1, le=168, description="Hours to analyze"),
    interval: int = Query(1, ge=1, le=24, description="Interval in hours"),
    db: Session = Depends(get_db)
):
    """
    Get traffic summary statistics over time intervals
    """
    try:
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        bucket_seconds = interval * 3600
        bucket = bucket_expr(db, NetworkEvent.created_at, bucket_seconds)
        in_range = and_(
            NetworkEvent.created_at >= start_time,
            NetworkEvent.created_at <= end_time
        )

        def count_protocol(name):
            return func.sum(case((NetworkEvent.protocol == name, 1), else_=0))

        connection = (
            NetworkEvent.src_ip + ":" + cast(NetworkEvent.src_port, String) + "->"
            + NetworkEvent.dst_ip + ":" + cast(NetworkEvent.dst_port, String)
        )

        rows = db.query(
            bucket,
            func.count(NetworkEvent.id),
            count_protocol("TCP"),
            count_protocol("UDP"),
            count_protocol("ICMP"),
            func.count(func.distinct(connection)),
            func.sum(case((NetworkEvent.is_suspicious.is_(True), 1), else_=0)),
        ).filter(in_range).group_by(bucket).all()

        by_bucket = {row[0]: row[1:] for row in rows}
        empty = (0, 0, 0, 0, 0, 0)
        totals = {b: values[0] for b, values in by_bucket.items()}
        limit = -(-hours // interval)  # ceiling division

        summaries = []
        for period_start, _ in fill_series(totals, start_time, end_time, bucket_seconds, limit=limit):
            b = int(period_start.replace(tzinfo=timezone.utc).timestamp()) // bucket_seconds
            total, tcp, udp, icmp, connections, suspicious = by_bucket.get(b, empty)
            summaries.append(TrafficSummary(
                timestamp=period_start,
                total_packets=total or 0,
                tcp_packets=tcp or 0,
                udp_packets=udp or 0,
                icmp_packets=icmp or 0,
                unique_connections=connections or 0,
                suspicious_activity=suspicious or 0
            ))

        return summaries

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating traffic summary: {str(e)}")


@router.delete("/cleanup")
async def cleanup_old_events(
    days: int = Query(30, ge=1, le=365, description="Delete events older than N days"),
    db: Session = Depends(get_db)
):
    """
    Clean up old network events to manage database size
    """
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days)

        # Delete old events
        deleted = db.query(NetworkEvent).filter(
            NetworkEvent.created_at < cutoff_date
        ).delete()

        db.commit()

        return {
            "success": True,
            "message": f"Deleted {deleted} events older than {days} days",
            "deleted_count": deleted
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error cleaning up events: {str(e)}")
