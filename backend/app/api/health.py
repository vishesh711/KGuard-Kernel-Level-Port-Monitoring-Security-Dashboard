"""
Health Check API Endpoints

This module provides health check and system status endpoints.
"""

import os
import time
from datetime import datetime

import psutil
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..config import settings
from ..database import check_db_connection, get_db
from ..schemas.common import HealthCheck
from ..services.anomaly_detector import anomaly_detector
from ..services.auth import current_user
from ..services.data_collector import data_collector
from ..services.flow_export import flow_exporter
from ..services.packet_capture import packet_capture
from ..services.payloads import payload_service
from ..services.retention import retention_job

# GET /api/health/ is public (Docker and load balancers probe it); every
# other health endpoint needs a login
router = APIRouter(prefix="/api/health", tags=["health"])

# Store startup time for uptime calculation
startup_time = time.time()


@router.get("/", response_model=HealthCheck)
async def health_check(db: Session = Depends(get_db)):
    """
    Comprehensive health check endpoint
    """
    try:
        # Check database connection
        db_healthy = check_db_connection()

        # Check kernel module connection
        kernel_status = await data_collector.test_kernel_connection()
        kernel_healthy = kernel_status.get("proc_exists", False) and kernel_status.get("readable", False)

        # Calculate uptime
        uptime_seconds = time.time() - startup_time

        # Determine overall status
        status = "healthy"
        if not db_healthy:
            status = "unhealthy"
        elif not kernel_healthy:
            status = "degraded"

        return HealthCheck(
            status=status,
            timestamp=datetime.utcnow(),
            version="1.0.0",
            database=db_healthy,
            kernel_module=kernel_healthy,
            uptime_seconds=uptime_seconds
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")


@router.get("/detailed", dependencies=[Depends(current_user)])
async def detailed_health_check(db: Session = Depends(get_db)):
    """
    Detailed health check with system metrics
    """
    try:
        # Basic health info
        basic_health = await health_check(db)

        # System metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        # Service statistics
        collector_stats = data_collector.get_stats()
        detector_stats = anomaly_detector.get_stats()

        # Kernel module detailed status
        kernel_status = await data_collector.test_kernel_connection()

        return {
            "basic_health": basic_health.model_dump(),
            "system_metrics": {
                "cpu_usage_percent": cpu_percent,
                "memory_usage_percent": memory.percent,
                "memory_available_mb": memory.available // (1024 * 1024),
                "disk_usage_percent": disk.percent,
                "disk_free_gb": disk.free // (1024 * 1024 * 1024)
            },
            "services": {
                "data_collector": collector_stats,
                "anomaly_detector": detector_stats,
                "flow_export": flow_exporter.get_stats(),
                "payloads": payload_service.get_stats(),
                "packet_capture": packet_capture.get_stats(),
                "retention": retention_job.get_stats(),
            },
            "kernel_module": kernel_status,
            "configuration": {
                "debug_mode": settings.debug,
                "log_level": settings.log_level,
                "database_url": settings.database_url.split("://")[0] + "://***",  # Hide credentials
                "collection_interval": settings.data_collection_interval,
                "port_scan_threshold": settings.port_scan_threshold
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Detailed health check failed: {str(e)}")


@router.get("/database", dependencies=[Depends(current_user)])
async def database_health(db: Session = Depends(get_db)):
    """
    Database-specific health check
    """
    try:
        # Test basic connection
        connection_ok = check_db_connection()

        if not connection_ok:
            return {
                "status": "unhealthy",
                "connection": False,
                "error": "Cannot connect to database"
            }

        # Test query performance
        start_time = time.time()
        db.execute(text("SELECT 1")).fetchone()
        query_time = time.time() - start_time

        # Get table counts
        from ..models.network_event import NetworkEvent
        from ..models.security_alert import SecurityAlert

        event_count = db.query(NetworkEvent).count()
        alert_count = db.query(SecurityAlert).count()

        return {
            "status": "healthy",
            "connection": True,
            "query_time_ms": round(query_time * 1000, 2),
            "tables": {
                "network_events": event_count,
                "security_alerts": alert_count
            }
        }

    except Exception as e:
        return {
            "status": "unhealthy",
            "connection": False,
            "error": str(e)
        }


@router.get("/kernel", dependencies=[Depends(current_user)])
async def kernel_module_health():
    """
    Kernel module specific health check
    """
    try:
        status = await data_collector.test_kernel_connection()

        # Healthy once the collector is reading and the kernel is not dropping events
        if status["proc_exists"] and status["readable"] and status["collector_running"]:
            health_status = "degraded" if status["kernel_events_dropped"] else "healthy"
        elif status["proc_exists"] and status["readable"]:
            health_status = "degraded"
        else:
            health_status = "unhealthy"

        return {
            "status": health_status,
            "details": status,
            "recommendations": _get_kernel_recommendations(status)
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


def _get_kernel_recommendations(status: dict) -> list:
    """Get recommendations based on kernel module status"""
    recommendations = []

    if not status["proc_exists"]:
        recommendations.append("Load the KGuard kernel module: sudo insmod kguard.ko")
        recommendations.append("Check if the module compiled successfully")
        recommendations.append("Verify kernel headers are installed")

    elif not status["readable"]:
        recommendations.append("Check file permissions on /proc/kguard")
        recommendations.append("Ensure the application is running with appropriate privileges")

    elif not status["collector_running"]:
        recommendations.append("Restart the backend so the data collector starts")

    elif status["kernel_events_dropped"]:
        recommendations.append(
            "The kernel buffer overflowed; reload the module with a larger buffer_size "
            "or lower DATA_COLLECTION_INTERVAL"
        )

    return recommendations


@router.get("/services", dependencies=[Depends(current_user)])
async def services_health():
    """
    Check health of background services
    """
    try:
        collector_stats = data_collector.get_stats()
        detector_stats = anomaly_detector.get_stats()

        # Determine service health
        collector_healthy = collector_stats["running"] and collector_stats["errors"] < 10
        detector_healthy = detector_stats["events_analyzed"] > 0 or detector_stats["last_analysis"] is None

        return {
            "data_collector": {
                "status": "healthy" if collector_healthy else "degraded",
                "running": collector_stats["running"],
                "stats": collector_stats
            },
            "anomaly_detector": {
                "status": "healthy" if detector_healthy else "degraded",
                "stats": detector_stats
            }
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


@router.get("/metrics", dependencies=[Depends(current_user)])
async def system_metrics():
    """
    Get current system performance metrics
    """
    try:
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()

        # Memory metrics
        memory = psutil.virtual_memory()

        # Disk metrics
        disk = psutil.disk_usage('/')

        # Network metrics (if available)
        try:
            network = psutil.net_io_counters()
            network_stats = {
                "bytes_sent": network.bytes_sent,
                "bytes_recv": network.bytes_recv,
                "packets_sent": network.packets_sent,
                "packets_recv": network.packets_recv
            }
        except Exception:
            network_stats = None

        # Process metrics
        process = psutil.Process(os.getpid())
        process_memory = process.memory_info()

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "cpu": {
                "usage_percent": cpu_percent,
                "count": cpu_count
            },
            "memory": {
                "total_mb": memory.total // (1024 * 1024),
                "available_mb": memory.available // (1024 * 1024),
                "used_mb": memory.used // (1024 * 1024),
                "usage_percent": memory.percent
            },
            "disk": {
                "total_gb": disk.total // (1024 * 1024 * 1024),
                "free_gb": disk.free // (1024 * 1024 * 1024),
                "used_gb": disk.used // (1024 * 1024 * 1024),
                "usage_percent": disk.percent
            },
            "network": network_stats,
            "process": {
                "memory_mb": process_memory.rss // (1024 * 1024),
                "cpu_percent": process.cpu_percent()
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting system metrics: {str(e)}")
