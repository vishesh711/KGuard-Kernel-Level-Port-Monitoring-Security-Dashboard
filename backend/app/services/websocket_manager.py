"""
WebSocket Manager Service

This service manages WebSocket connections and broadcasts real-time updates
to connected clients.
"""

import asyncio
import json
import logging
from typing import Dict, List, Set, Any, Optional
from datetime import datetime
from fastapi import WebSocket, WebSocketDisconnect
from dataclasses import dataclass, asdict

from ..config import settings

logger = logging.getLogger(__name__)


@dataclass
class WebSocketMessage:
    """WebSocket message structure"""
    type: str
    data: Any
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()
    
    def to_json(self) -> str:
        """Convert message to JSON string"""
        return json.dumps(asdict(self))


class ConnectionManager:
    """Manages WebSocket connections and message broadcasting"""
    
    def __init__(self):
        # Active connections
        self.active_connections: Dict[str, WebSocket] = {}
        
        # Connection metadata
        self.connection_info: Dict[str, Dict[str, Any]] = {}
        
        # Message queues for each connection
        self.message_queues: Dict[str, asyncio.Queue] = {}
        
        # Statistics
        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "messages_sent": 0,
            "messages_failed": 0,
            "last_activity": None
        }
        
        # Configuration
        self.max_connections = settings.websocket_max_connections
        self.heartbeat_interval = settings.websocket_heartbeat_interval
        
        # Background tasks
        self.heartbeat_task: Optional[asyncio.Task] = None
        self.cleanup_task: Optional[asyncio.Task] = None
    
    async def connect(self, websocket: WebSocket, client_id: str = None) -> str:
        """
        Accept a new WebSocket connection
        
        Args:
            websocket: WebSocket connection
            client_id: Optional client identifier
            
        Returns:
            str: Connection ID
        """
        # Check connection limit
        if len(self.active_connections) >= self.max_connections:
            await websocket.close(code=1008, reason="Connection limit exceeded")
            raise Exception("Maximum connections exceeded")
        
        # Generate connection ID if not provided
        if not client_id:
            client_id = f"client_{len(self.active_connections)}_{int(datetime.utcnow().timestamp())}"
        
        # Accept the connection
        await websocket.accept()
        
        # Store connection
        self.active_connections[client_id] = websocket
        self.connection_info[client_id] = {
            "connected_at": datetime.utcnow(),
            "last_ping": datetime.utcnow(),
            "messages_sent": 0,
            "messages_received": 0
        }
        self.message_queues[client_id] = asyncio.Queue()
        
        # Update statistics
        self.stats["total_connections"] += 1
        self.stats["active_connections"] = len(self.active_connections)
        self.stats["last_activity"] = datetime.utcnow()
        
        logger.info(f"WebSocket client {client_id} connected. Active connections: {len(self.active_connections)}")
        
        # Send welcome message
        welcome_msg = WebSocketMessage(
            type="connection",
            data={
                "status": "connected",
                "client_id": client_id,
                "server_time": datetime.utcnow().isoformat()
            }
        )
        await self._send_to_client(client_id, welcome_msg)
        
        # Start background tasks if this is the first connection
        if len(self.active_connections) == 1:
            await self._start_background_tasks()
        
        return client_id
    
    async def disconnect(self, client_id: str):
        """
        Disconnect a WebSocket client
        
        Args:
            client_id: Client identifier
        """
        if client_id in self.active_connections:
            # Remove connection
            del self.active_connections[client_id]
            del self.connection_info[client_id]
            del self.message_queues[client_id]
            
            # Update statistics
            self.stats["active_connections"] = len(self.active_connections)
            
            logger.info(f"WebSocket client {client_id} disconnected. Active connections: {len(self.active_connections)}")
            
            # Stop background tasks if no connections remain
            if len(self.active_connections) == 0:
                await self._stop_background_tasks()
    
    async def broadcast(self, message: WebSocketMessage, exclude: Set[str] = None):
        """
        Broadcast a message to all connected clients
        
        Args:
            message: Message to broadcast
            exclude: Set of client IDs to exclude from broadcast
        """
        if not self.active_connections:
            return
        
        exclude = exclude or set()
        
        # Send to all active connections
        disconnected_clients = []
        
        for client_id in list(self.active_connections.keys()):
            if client_id in exclude:
                continue
            
            try:
                await self._send_to_client(client_id, message)
            except Exception as e:
                logger.warning(f"Failed to send message to client {client_id}: {e}")
                disconnected_clients.append(client_id)
        
        # Clean up disconnected clients
        for client_id in disconnected_clients:
            await self.disconnect(client_id)
        
        logger.debug(f"Broadcasted message to {len(self.active_connections) - len(exclude)} clients")
    
    async def send_to_client(self, client_id: str, message: WebSocketMessage) -> bool:
        """
        Send a message to a specific client
        
        Args:
            client_id: Target client ID
            message: Message to send
            
        Returns:
            bool: True if message was sent successfully
        """
        if client_id not in self.active_connections:
            logger.warning(f"Client {client_id} not found")
            return False
        
        try:
            await self._send_to_client(client_id, message)
            return True
        except Exception as e:
            logger.error(f"Failed to send message to client {client_id}: {e}")
            await self.disconnect(client_id)
            return False
    
    async def _send_to_client(self, client_id: str, message: WebSocketMessage):
        """
        Internal method to send message to client
        
        Args:
            client_id: Client identifier
            message: Message to send
        """
        websocket = self.active_connections[client_id]
        
        try:
            await websocket.send_text(message.to_json())
            
            # Update statistics
            self.connection_info[client_id]["messages_sent"] += 1
            self.stats["messages_sent"] += 1
            self.stats["last_activity"] = datetime.utcnow()
            
        except Exception as e:
            self.stats["messages_failed"] += 1
            raise e
    
    async def handle_client_message(self, client_id: str, message: str):
        """
        Handle incoming message from client
        
        Args:
            client_id: Client identifier
            message: Received message
        """
        try:
            data = json.loads(message)
            msg_type = data.get("type", "unknown")
            
            # Update statistics
            self.connection_info[client_id]["messages_received"] += 1
            self.connection_info[client_id]["last_ping"] = datetime.utcnow()
            
            # Handle different message types
            if msg_type == "ping":
                # Respond to ping with pong
                pong_msg = WebSocketMessage(
                    type="pong",
                    data={"server_time": datetime.utcnow().isoformat()}
                )
                await self._send_to_client(client_id, pong_msg)
            
            elif msg_type == "subscribe":
                # Handle subscription requests
                await self._handle_subscription(client_id, data)
            
            elif msg_type == "unsubscribe":
                # Handle unsubscription requests
                await self._handle_unsubscription(client_id, data)
            
            else:
                logger.warning(f"Unknown message type from client {client_id}: {msg_type}")
        
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON from client {client_id}: {message}")
        except Exception as e:
            logger.error(f"Error handling message from client {client_id}: {e}")
    
    async def _handle_subscription(self, client_id: str, data: dict):
        """Handle subscription requests"""
        # For now, all clients receive all messages
        # In the future, this could be extended to support filtered subscriptions
        response = WebSocketMessage(
            type="subscription",
            data={
                "status": "subscribed",
                "channels": data.get("channels", ["all"])
            }
        )
        await self._send_to_client(client_id, response)
    
    async def _handle_unsubscription(self, client_id: str, data: dict):
        """Handle unsubscription requests"""
        response = WebSocketMessage(
            type="subscription",
            data={
                "status": "unsubscribed",
                "channels": data.get("channels", [])
            }
        )
        await self._send_to_client(client_id, response)
    
    async def _start_background_tasks(self):
        """Start background maintenance tasks"""
        if not self.heartbeat_task or self.heartbeat_task.done():
            self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        
        if not self.cleanup_task or self.cleanup_task.done():
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        logger.info("WebSocket background tasks started")
    
    async def _stop_background_tasks(self):
        """Stop background maintenance tasks"""
        if self.heartbeat_task and not self.heartbeat_task.done():
            self.heartbeat_task.cancel()
            try:
                await self.heartbeat_task
            except asyncio.CancelledError:
                pass
        
        if self.cleanup_task and not self.cleanup_task.done():
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        logger.info("WebSocket background tasks stopped")
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeat messages"""
        try:
            while self.active_connections:
                heartbeat_msg = WebSocketMessage(
                    type="heartbeat",
                    data={
                        "server_time": datetime.utcnow().isoformat(),
                        "active_connections": len(self.active_connections)
                    }
                )
                
                await self.broadcast(heartbeat_msg)
                await asyncio.sleep(self.heartbeat_interval)
        
        except asyncio.CancelledError:
            logger.info("Heartbeat loop cancelled")
        except Exception as e:
            logger.error(f"Error in heartbeat loop: {e}")
    
    async def _cleanup_loop(self):
        """Periodic cleanup of stale connections"""
        try:
            while self.active_connections:
                current_time = datetime.utcnow()
                stale_clients = []
                
                # Check for stale connections (no activity for 5 minutes)
                for client_id, info in self.connection_info.items():
                    if (current_time - info["last_ping"]).total_seconds() > 300:
                        stale_clients.append(client_id)
                
                # Disconnect stale clients
                for client_id in stale_clients:
                    logger.warning(f"Disconnecting stale client: {client_id}")
                    await self.disconnect(client_id)
                
                await asyncio.sleep(60)  # Run cleanup every minute
        
        except asyncio.CancelledError:
            logger.info("Cleanup loop cancelled")
        except Exception as e:
            logger.error(f"Error in cleanup loop: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        return {
            **self.stats,
            "connection_details": {
                client_id: {
                    "connected_at": info["connected_at"].isoformat(),
                    "last_ping": info["last_ping"].isoformat(),
                    "messages_sent": info["messages_sent"],
                    "messages_received": info["messages_received"]
                }
                for client_id, info in self.connection_info.items()
            }
        }
    
    async def shutdown(self):
        """Shutdown the connection manager"""
        logger.info("Shutting down WebSocket connection manager")
        
        # Disconnect all clients
        for client_id in list(self.active_connections.keys()):
            try:
                websocket = self.active_connections[client_id]
                await websocket.close(code=1001, reason="Server shutdown")
            except Exception as e:
                logger.error(f"Error closing connection {client_id}: {e}")
        
        # Stop background tasks
        await self._stop_background_tasks()
        
        # Clear all data
        self.active_connections.clear()
        self.connection_info.clear()
        self.message_queues.clear()


# Global connection manager instance
connection_manager = ConnectionManager()


# Message broadcasting functions
async def broadcast_network_event(event_data: dict):
    """Broadcast a new network event to all connected clients"""
    message = WebSocketMessage(
        type="network_event",
        data=event_data
    )
    await connection_manager.broadcast(message)


async def broadcast_security_alert(alert_data: dict):
    """Broadcast a new security alert to all connected clients"""
    message = WebSocketMessage(
        type="security_alert",
        data=alert_data
    )
    await connection_manager.broadcast(message)


async def broadcast_system_metric(metric_data: dict):
    """Broadcast a system metric update to all connected clients"""
    message = WebSocketMessage(
        type="system_metric",
        data=metric_data
    )
    await connection_manager.broadcast(message)


async def broadcast_stats_update(stats_data: dict):
    """Broadcast statistics update to all connected clients"""
    message = WebSocketMessage(
        type="stats_update",
        data=stats_data
    )
    await connection_manager.broadcast(message)