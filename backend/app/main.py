"""
KGuard Backend Main Application

This is the main FastAPI application that brings together all components
of the KGuard security monitoring backend.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from .config import settings
from .database import init_db, check_db_connection
from .api import events_router, alerts_router, health_router
from .services.websocket_manager import connection_manager
from .services.data_collector import data_collector
from .services.anomaly_detector import anomaly_detector

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager
    Handles startup and shutdown tasks
    """
    # Startup
    logger.info("Starting KGuard Backend Service")
    
    try:
        # Initialize database
        logger.info("Initializing database...")
        init_db()
        
        # Check database connection
        if not check_db_connection():
            logger.error("Database connection failed!")
            raise Exception("Database connection failed")
        
        logger.info("Database initialized successfully")
        
        # Start data collection service
        logger.info("Starting data collection service...")
        asyncio.create_task(data_collector.start_collection())
        
        logger.info("KGuard Backend Service started successfully")
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down KGuard Backend Service")
    
    try:
        # Stop data collection
        data_collector.stop_collection()
        
        # Shutdown WebSocket connections
        await connection_manager.shutdown()
        
        logger.info("KGuard Backend Service shut down successfully")
        
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")


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
        allowed_hosts=["localhost", "127.0.0.1", "*.local"]
    )

# Include API routers
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(health_router)


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


# Background task for periodic operations
async def periodic_tasks():
    """Background tasks that run periodically"""
    while True:
        try:
            # Clean up old anomaly detector cooldowns
            anomaly_detector.cleanup_old_cooldowns()
            
            # Broadcast system stats every 30 seconds
            if connection_manager.active_connections:
                from .services.websocket_manager import broadcast_stats_update
                
                stats = {
                    "data_collector": data_collector.get_stats(),
                    "anomaly_detector": anomaly_detector.get_stats(),
                    "websocket": connection_manager.get_stats()
                }
                
                await broadcast_stats_update(stats)
            
            await asyncio.sleep(30)
            
        except Exception as e:
            logger.error(f"Error in periodic tasks: {e}")
            await asyncio.sleep(60)  # Wait longer on error


# Start periodic tasks when the app starts
@app.on_event("startup")
async def start_periodic_tasks():
    """Start background periodic tasks"""
    asyncio.create_task(periodic_tasks())


if __name__ == "__main__":
    # Run the application
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )