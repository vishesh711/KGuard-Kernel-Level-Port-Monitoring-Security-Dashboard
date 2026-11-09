"""
KGuard Backend Main Application

This is the main FastAPI application that brings together all components
of the KGuard security monitoring backend.
"""

import asyncio
import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from .api import agents_router, alerts_router, auth_router, events_router, health_router, payloads_router
from .config import settings
from .database import check_db_connection, init_db
from .logging_setup import RequestContextMiddleware, configure_logging
from .security import SecurityMiddleware, security_problems
from .services.anomaly_detector import anomaly_detector
from .services.auth import current_user, ensure_bootstrap_admin, websocket_user
from .services.baseline import traffic_baseline
from .services.data_collector import data_collector
from .services.kernel_alerts import kernel_alerts
from .services.packet_capture import packet_capture
from .services.retention import retention_job
from .services.websocket_manager import connection_manager

configure_logging()
logger = logging.getLogger(__name__)


async def periodic_tasks():
    """Housekeeping, stats broadcast every 30 seconds, and the traffic baseline"""
    from .services.websocket_manager import broadcast_stats_update

    loop = asyncio.get_running_loop()
    next_stats = next_baseline = loop.time()
    while True:
        try:
            now = loop.time()
            if now >= next_baseline:
                next_baseline = now + settings.baseline_interval_seconds
                await traffic_baseline.tick()

            if now >= next_stats:
                next_stats = now + 30
                anomaly_detector.cleanup_old_cooldowns()
                if retention_job.due():
                    # Batched deletes; off the event loop so the API stays responsive
                    await loop.run_in_executor(None, retention_job.run)
                if connection_manager.active_connections:
                    await broadcast_stats_update({
                        "data_collector": data_collector.get_stats(),
                        "anomaly_detector": anomaly_detector.get_stats(),
                        "kernel_alerts": kernel_alerts.get_stats(),
                        "websocket": connection_manager.get_stats(),
                    })

            await asyncio.sleep(max(0.5, min(next_stats, next_baseline) - loop.time()))
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Error in periodic tasks: {e}")
            await asyncio.sleep(60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start background work on startup and stop it cleanly on shutdown"""
    logger.info("Starting KGuard Backend Service")

    problems = security_problems()
    if problems:
        for problem in problems:
            logger.critical(f"Refusing to start: {problem}")
        raise RuntimeError("; ".join(problems))

    init_db()
    if not check_db_connection():
        raise RuntimeError("Database connection failed")
    logger.info("Database initialized successfully")
    ensure_bootstrap_admin()

    packet_capture.start()
    background = [
        asyncio.create_task(data_collector.start_collection(), name="data_collector"),
        asyncio.create_task(periodic_tasks(), name="periodic_tasks"),
    ]
    logger.info("KGuard Backend Service started successfully")

    try:
        yield
    finally:
        logger.info("Shutting down KGuard Backend Service")
        data_collector.stop_collection()
        kernel_alerts.close()
        packet_capture.stop()
        for task in background:
            task.cancel()
        await asyncio.gather(*background, return_exceptions=True)
        await connection_manager.shutdown()
        logger.info("KGuard Backend Service shut down successfully")


# Create FastAPI application
app = FastAPI(
    title="KGuard Security Monitoring API",
    description="Backend API for KGuard kernel-level network monitoring and security dashboard",
    version="1.0.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan
)

# Middleware, innermost first (each add_middleware wraps the ones before).
# CORS: only the listed origins; logins are bearer tokens, not cookies, so
# no credentials mode
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID", "Retry-After"],
    max_age=600,
)
# Only answer to the listed host names (stops DNS rebinding and Host header tricks)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
# Rate limit and security headers
app.add_middleware(SecurityMiddleware)
# Outermost: request IDs, access log, and a logged 500 for unhandled errors
app.add_middleware(RequestContextMiddleware, debug=settings.debug)

# Include API routers
# Every endpoint needs a login except: POST /api/auth/login, GET /api/health/
# (liveness probe), GET / and the agents' enroll and ingest endpoints (which
# use the enrollment key and agent tokens). Admin-only endpoints say so.
logged_in = [Depends(current_user)]
app.include_router(auth_router)
app.include_router(events_router, dependencies=logged_in)
app.include_router(alerts_router, dependencies=logged_in)
app.include_router(health_router)
app.include_router(agents_router)
app.include_router(payloads_router, dependencies=logged_in)


@app.get("/")
async def root():
    """Root endpoint with basic API information"""
    return {
        "name": "KGuard Security Monitoring API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs" if settings.debug else "disabled",
        "health": "/api/health"
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time updates. Needs a login token:
    /ws?token=<access_token>; without a valid one the handshake is refused.
    """
    user = websocket_user(websocket, websocket.query_params.get("token", ""))
    if user is None:
        logger.warning("WebSocket refused: no valid token")
        await websocket.close(code=1008)
        return
    client_id = None
    try:
        # Accept connection
        client_id = await connection_manager.connect(websocket)
        logger.info(f"WebSocket client {client_id} connected", extra={"username": user.username})

        # Handle incoming messages
        while True:
            try:
                # Wait for message from client
                message = await websocket.receive_text()
                await connection_manager.handle_client_message(client_id, message)

            except WebSocketDisconnect:
                logger.info(f"WebSocket client {client_id} disconnected")
                break
            except Exception as e:
                logger.error(f"Error handling WebSocket message from {client_id}: {e}")
                break

    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")

    finally:
        if client_id:
            await connection_manager.disconnect(client_id)


if __name__ == "__main__":
    # Same as python -m app
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_config=None,
        access_log=False,
        proxy_headers=True,
        forwarded_allow_ips=settings.forwarded_allow_ips,
    )
