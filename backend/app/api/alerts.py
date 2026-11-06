"""
Security Alerts API Endpoints

This module provides REST API endpoints for security alerts.
"""

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy import and_, desc, func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.security_alert import AlertSeverity, AlertType, SecurityAlert
from ..schemas.common import PaginatedResponse, SuccessResponse
from ..schemas.security_alert import AlertAcknowledge, AlertResolve, AlertStats, SecurityAlertResponse
from ..services.packet_capture import packet_capture
from .buckets import bucket_expr, fill_series

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("/", response_model=PaginatedResponse[SecurityAlertResponse])
async def get_alerts(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(25, ge=1, le=100, description="Page size"),
    alert_type: Optional[AlertType] = Query(None, description="Filter by alert type"),
    severity: Optional[AlertSeverity] = Query(None, description="Filter by severity"),
    src_ip: Optional[str] = Query(None, description="Filter by source IP"),
    acknowledged: Optional[bool] = Query(None, description="Filter by acknowledgment status"),
    resolved: Optional[bool] = Query(None, description="Filter by resolution status"),
    start_time: Optional[datetime] = Query(None, description="Start time filter"),
    end_time: Optional[datetime] = Query(None, description="End time filter"),
    db: Session = Depends(get_db)
):
    """
    Get paginated list of security alerts with optional filtering
    """
    try:
        # Build query with filters
        query = db.query(SecurityAlert)

        if alert_type:
            query = query.filter(SecurityAlert.alert_type == alert_type)
        if severity:
            query = query.filter(SecurityAlert.severity == severity)
        if src_ip:
            query = query.filter(SecurityAlert.src_ip == src_ip)
        if acknowledged is not None:
            query = query.filter(SecurityAlert.acknowledged == acknowledged)
        if resolved is not None:
            query = query.filter(SecurityAlert.resolved == resolved)
        if start_time:
            query = query.filter(SecurityAlert.timestamp >= start_time)
        if end_time:
            query = query.filter(SecurityAlert.timestamp <= end_time)

        # Get total count
        total = query.count()

        # Apply pagination and ordering
        alerts = query.order_by(desc(SecurityAlert.timestamp)).offset(
            (page - 1) * size
        ).limit(size).all()

        # Calculate pagination info
        pages = (total + size - 1) // size

        return PaginatedResponse(
            items=[SecurityAlertResponse.model_validate(alert) for alert in alerts],
            total=total,
            page=page,
            size=size,
            pages=pages
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving alerts: {str(e)}")


@router.get("/{alert_id}", response_model=SecurityAlertResponse)
async def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """
    Get a specific security alert by ID
    """
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return SecurityAlertResponse.model_validate(alert)


@router.get("/{alert_id}/pcap")
async def get_alert_pcap(alert_id: int):
    """The packets saved for an alert (packet capture on alert), as a pcap file"""
    path = packet_capture.path_for(alert_id)
    if not path:
        raise HTTPException(status_code=404, detail="No packet capture for this alert")
    return FileResponse(path, media_type="application/vnd.tcpdump.pcap", filename=path.name)


@router.post("/{alert_id}/acknowledge", response_model=SuccessResponse)
async def acknowledge_alert(
    alert_id: int,
    acknowledge_data: AlertAcknowledge,
    db: Session = Depends(get_db)
):
    """
    Acknowledge a security alert
    """
    try:
        alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        if alert.acknowledged:
            raise HTTPException(status_code=400, detail="Alert already acknowledged")

        # Update alert
        alert.acknowledged = True
        alert.acknowledged_at = datetime.utcnow()
        alert.acknowledged_by = acknowledge_data.acknowledged_by

        # Add notes to metadata if provided
        if acknowledge_data.notes:
            # Assign a new dict: in-place changes to a JSON column are not saved
            alert.alert_metadata = {
                **(alert.alert_metadata or {}),
                "acknowledgment_notes": acknowledge_data.notes,
            }

        db.commit()

        return SuccessResponse(
            success=True,
            message=f"Alert {alert_id} acknowledged successfully",
            timestamp=datetime.utcnow()
        )

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error acknowledging alert: {str(e)}")


@router.post("/{alert_id}/resolve", response_model=SuccessResponse)
async def resolve_alert(
    alert_id: int,
    resolve_data: AlertResolve,
    db: Session = Depends(get_db)
):
    """
    Resolve a security alert
    """
    try:
        alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        if alert.resolved:
            raise HTTPException(status_code=400, detail="Alert already resolved")

        # Update alert
        alert.resolved = True
        alert.resolved_at = datetime.utcnow()
        alert.resolution_notes = resolve_data.resolution_notes

        # Auto-acknowledge if not already acknowledged
        if not alert.acknowledged:
            alert.acknowledged = True
            alert.acknowledged_at = datetime.utcnow()
            alert.acknowledged_by = resolve_data.resolved_by

        # Add resolver to metadata
        alert.alert_metadata = {
            **(alert.alert_metadata or {}),
            "resolved_by": resolve_data.resolved_by,
        }

        db.commit()

        return SuccessResponse(
            success=True,
            message=f"Alert {alert_id} resolved successfully",
            timestamp=datetime.utcnow()
        )

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error resolving alert: {str(e)}")


@router.get("/stats/summary", response_model=AlertStats)
async def get_alert_stats(
    hours: int = Query(24, ge=1, le=168, description="Hours to analyze"),
    db: Session = Depends(get_db)
):
    """
    Get security alert statistics for the specified time period
    """
    try:
        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)

        # Base query for time range
        base_query = db.query(SecurityAlert).filter(
            and_(
                SecurityAlert.timestamp >= start_time,
                SecurityAlert.timestamp <= end_time
            )
        )

        # Total alerts
        total_alerts = base_query.count()

        # Status counts
        unacknowledged_alerts = base_query.filter(SecurityAlert.acknowledged == False).count()
        unresolved_alerts = base_query.filter(SecurityAlert.resolved == False).count()

        # Severity counts, one grouped query
        severity_rows = db.query(
            SecurityAlert.severity, func.count(SecurityAlert.id)
        ).filter(
            and_(
                SecurityAlert.timestamp >= start_time,
                SecurityAlert.timestamp <= end_time
            )
        ).group_by(SecurityAlert.severity).all()
        severity_counts = {severity: count for severity, count in severity_rows}
        critical_alerts = severity_counts.get(AlertSeverity.CRITICAL, 0)
        high_alerts = severity_counts.get(AlertSeverity.HIGH, 0)
        medium_alerts = severity_counts.get(AlertSeverity.MEDIUM, 0)
        low_alerts = severity_counts.get(AlertSeverity.LOW, 0)

        # Alert types distribution
        alert_types = db.query(
            SecurityAlert.alert_type,
            func.count(SecurityAlert.id).label('count')
        ).filter(
            and_(
                SecurityAlert.timestamp >= start_time,
                SecurityAlert.timestamp <= end_time
            )
        ).group_by(SecurityAlert.alert_type).all()

        alert_types_distribution = {alert_type.value: count for alert_type, count in alert_types}

        # Alerts per hour, grouped in the database
        hour_bucket = bucket_expr(db, SecurityAlert.timestamp, 3600)
        hourly = db.query(hour_bucket, func.count(SecurityAlert.id)).filter(
            and_(
                SecurityAlert.timestamp >= start_time,
                SecurityAlert.timestamp <= end_time
            )
        ).group_by(hour_bucket).all()

        alerts_per_hour = [
            {"hour": hour.isoformat(), "count": count}
            for hour, count in fill_series(dict(hourly), start_time, end_time, 3600, limit=hours)
        ]

        # Top source IPs by alert count
        top_source_ips = db.query(
            SecurityAlert.src_ip,
            func.count(SecurityAlert.id).label('count')
        ).filter(
            and_(
                SecurityAlert.timestamp >= start_time,
                SecurityAlert.timestamp <= end_time,
                SecurityAlert.src_ip.isnot(None)
            )
        ).group_by(SecurityAlert.src_ip).order_by(desc('count')).limit(10).all()

        top_source_ips_list = [{"ip": ip, "count": count} for ip, count in top_source_ips]

        return AlertStats(
            total_alerts=total_alerts,
            unacknowledged_alerts=unacknowledged_alerts,
            unresolved_alerts=unresolved_alerts,
            critical_alerts=critical_alerts,
            high_alerts=high_alerts,
            medium_alerts=medium_alerts,
            low_alerts=low_alerts,
            alert_types_distribution=alert_types_distribution,
            alerts_per_hour=alerts_per_hour,
            top_source_ips=top_source_ips_list
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error calculating alert statistics: {str(e)}")


@router.delete("/cleanup")
async def cleanup_old_alerts(
    days: int = Query(90, ge=1, le=365, description="Delete resolved alerts older than N days"),
    db: Session = Depends(get_db)
):
    """
    Clean up old resolved alerts to manage database size
    """
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days)

        # Delete old resolved alerts
        deleted = db.query(SecurityAlert).filter(
            and_(
                SecurityAlert.timestamp < cutoff_date,
                SecurityAlert.resolved == True
            )
        ).delete()

        db.commit()

        return {
            "success": True,
            "message": f"Deleted {deleted} resolved alerts older than {days} days",
            "deleted_count": deleted
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error cleaning up alerts: {str(e)}")


@router.get("/active/summary")
async def get_active_alerts_summary(db: Session = Depends(get_db)):
    """
    Get a quick summary of active (unresolved) alerts
    """
    try:
        # Get unresolved alerts
        active_alerts = db.query(SecurityAlert).filter(
            SecurityAlert.resolved == False
        ).all()

        # Group by severity
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        # Group by type
        type_counts = {}

        # Recent alerts (last 24 hours)
        recent_cutoff = datetime.utcnow() - timedelta(hours=24)
        recent_alerts = []

        for alert in active_alerts:
            # Count by severity
            severity_counts[alert.severity.value] += 1

            # Count by type
            alert_type = alert.alert_type.value
            type_counts[alert_type] = type_counts.get(alert_type, 0) + 1

            # Collect recent alerts
            if alert.timestamp >= recent_cutoff:
                recent_alerts.append({
                    "id": alert.id,
                    "type": alert_type,
                    "severity": alert.severity.value,
                    "title": alert.title,
                    "timestamp": alert.timestamp.isoformat(),
                    "src_ip": alert.src_ip
                })

        return {
            "total_active": len(active_alerts),
            "severity_breakdown": severity_counts,
            "type_breakdown": type_counts,
            "recent_alerts": sorted(recent_alerts, key=lambda x: x["timestamp"], reverse=True)[:10]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting active alerts summary: {str(e)}")
