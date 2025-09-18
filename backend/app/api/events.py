"""
Network Events API Endpoints

This module provides REST API endpoints for network events.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import and_, func, desc
from typing import List, Optional
from datetime import datetime, timedelta

from ..database import get_db
from ..models.network_event import NetworkEvent
from ..schemas.network_event import (
    NetworkEventResponse, NetworkEventFilter, NetworkEventStats, TrafficSummary
)
from ..schemas.common import PaginatedResponse

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
            items=[NetworkEventResponse.from_orm(event) for event in events],
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
    
    return NetworkEventResponse.from_orm(event)


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
        
        # Events per hour
        events_per_hour = []
        for i in range(hours):
            hour_start = start_time + timedelta(hours=i)
            hour_end = hour_start + timedelta(hours=1)
            
            count = db.query(NetworkEvent).filter(
                and_(
                    NetworkEvent.created_at >= hour_start,
                    NetworkEvent.created_at < hour_end
                )
            ).count()
            
            events_per_hour.append({
                "hour": hour_start.isoformat(),
                "count": count
            })
        
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
        summaries = []
        end_time = datetime.utcnow()
        
        for i in range(0, hours, interval):
            period_end = end_time - timedelta(hours=i)
            period_start = period_end - timedelta(hours=interval)
            
            # Query events in this time period
            events = db.query(NetworkEvent).filter(
                and_(
                    NetworkEvent.created_at >= period_start,
                    NetworkEvent.created_at < period_end
                )
            ).all()
            
            # Calculate statistics
            total_packets = len(events)
            tcp_packets = len([e for e in events if e.protocol == 'TCP'])
            udp_packets = len([e for e in events if e.protocol == 'UDP'])
            icmp_packets = len([e for e in events if e.protocol == 'ICMP'])
            
            # Unique connections (src_ip:src_port -> dst_ip:dst_port)
            connections = set()
            suspicious_count = 0
            
            for event in events:
                connections.add(f"{event.src_ip}:{event.src_port}->{event.dst_ip}:{event.dst_port}")
                if event.is_suspicious:
                    suspicious_count += 1
            
            summary = TrafficSummary(
                timestamp=period_start,
                total_packets=total_packets,
                tcp_packets=tcp_packets,
                udp_packets=udp_packets,
                icmp_packets=icmp_packets,
                unique_connections=len(connections),
                suspicious_activity=suspicious_count
            )
            
            summaries.append(summary)
        
        return list(reversed(summaries))  # Return chronologically
        
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
        
        # Count events to be deleted
        count = db.query(NetworkEvent).filter(
            NetworkEvent.created_at < cutoff_date
        ).count()
        
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