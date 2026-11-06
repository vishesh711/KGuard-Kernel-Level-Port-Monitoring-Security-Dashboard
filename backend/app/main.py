"""
KGuard Backend Main Application

This is the main FastAPI application that brings together all components
of the KGuard security monitoring backend.
"""

import asyncio
import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from .api import agents_router, alerts_router, events_router, health_router
from .config import settings
from .database import check_db_connection, init_db
from .services.anomaly_detector import anomaly_detector
from .services.baseline import traffic_baseline
from .services.data_collector import data_collector
from .services.kernel_alerts import kernel_alerts
from .services.websocket_manager import connection_manager

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
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

    init_db()
    if not check_db_connection():
        raise RuntimeError("Database connection failed")
    logger.info("Database initialized successfully")

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

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Add trusted host middleware for security
if not settings.debug:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.allowed_hosts
    )

# Include API routers
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(health_router)
app.include_router(agents_router)


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
    WebSocket endpoint for real-time updates
    """
    client_id = None
    try:
        # Accept connection
        client_id = await connection_manager.connect(websocket)
        logger.info(f"WebSocket client {client_id} connected")

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


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc) if settings.debug else "An unexpected error occurred"
        }
    )


@app.middleware("http")
async def log_requests(request, call_next):
    """Request logging middleware"""
    start_time = asyncio.get_event_loop().time()

    response = await call_next(request)

    process_time = asyncio.get_event_loop().time() - start_time

    logger.info(
        f"{request.method} {request.url.path} - "
        f"Status: {response.status_code} - "
        f"Time: {process_time:.3f}s"
    )

    return response


if __name__ == "__main__":
    # Run the application
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )
