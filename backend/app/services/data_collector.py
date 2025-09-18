"""
Data Collector Service

This service continuously reads network events from the kernel module
via /proc/kguard and stores them in the database.
"""

import asyncio
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session
from ..database import SessionLocal
from ..models.network_event import NetworkEvent
from ..config import settings

logger = logging.getLogger(__name__)


class DataCollectorService:
    """
    Service for collecting network events from the kernel module
    and storing them in the database.
    """
    
    def __init__(self):
        self.proc_path = Path(settings.proc_kguard_path)
        self.collection_interval = settings.data_collection_interval
        self.running = False
        self.stats = {
            "events_collected": 0,
            "events_stored": 0,
            "errors": 0,
            "last_collection": None
        }
    
    async def start_collection(self) -> None:
        """Start the data collection loop"""
        if self.running:
            logger.warning("Data collection is already running")
            return
        
        self.running = True
        logger.info("Starting data collection service")
        
        try:
            while self.running:
                await self._collect_and_store_events()
                await asyncio.sleep(self.collection_interval)
        except Exception as e:
            logger.error(f"Data collection loop error: {e}")
            self.running = False
            raise
    
    def stop_collection(self) -> None:
        """Stop the data collection loop"""
        logger.info("Stopping data collection service")
        self.running = False
    
    async def _collect_and_store_events(self) -> None:
        """Collect events from kernel module and store in database"""
        try:
            # Read events from /proc/kguard
            events_data = await self._read_kernel_events()
            if not events_data:
                return
            
            # Parse and validate events
            events = self._parse_events(events_data)
            if not events:
                return
            
            # Store events in database
            stored_count = await self._store_events(events)
            
            # Update statistics
            self.stats["events_collected"] += len(events)
            self.stats["events_stored"] += stored_count
            self.stats["last_collection"] = datetime.utcnow()
            
            logger.debug(f"Collected {len(events)} events, stored {stored_count}")
            
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Error collecting events: {e}")
    
    async def _read_kernel_events(self) -> Optional[str]:
        """
        Read events from /proc/kguard
        
        Returns:
            Optional[str]: Raw JSON data from kernel module
        """
        try:
            if not self.proc_path.exists():
                logger.warning(f"Kernel module interface not found: {self.proc_path}")
                return None
            
            # Read the proc file
            with open(self.proc_path, 'r') as f:
                data = f.read().strip()
            
            if not data:
                logger.debug("No data available from kernel module")
                return None
            
            return data
            
        except FileNotFoundError:
            logger.warning("Kernel module not loaded or /proc/kguard not available")
            return None
        except PermissionError:
            logger.error("Permission denied reading /proc/kguard")
            return None
        except Exception as e:
            logger.error(f"Error reading kernel events: {e}")
            return None
    
    def _parse_events(self, raw_data: str) -> List[Dict[str, Any]]:
        """
        Parse JSON events from kernel module
        
        Args:
            raw_data: Raw JSON string from kernel module
            
        Returns:
            List[Dict[str, Any]]: Parsed event dictionaries
        """
        try:
            # Parse JSON data
            data = json.loads(raw_data)
            
            # Handle different response formats
            if isinstance(data, dict):
                if "events" in data:
                    events = data["events"]
                elif "error" in data:
                    logger.warning(f"Kernel module error: {data['error']}")
                    return []
                else:
                    events = [data]  # Single event
            elif isinstance(data, list):
                events = data
            else:
                logger.error(f"Unexpected data format: {type(data)}")
                return []
            
            # Validate and clean events
            valid_events = []
            for event in events:
                if self._validate_event(event):
                    valid_events.append(event)
                else:
                    logger.warning(f"Invalid event data: {event}")
            
            return valid_events
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON from kernel module: {e}")
            return []
        except Exception as e:
            logger.error(f"Error parsing events: {e}")
            return []
    
    def _validate_event(self, event: Dict[str, Any]) -> bool:
        """
        Validate event data from kernel module
        
        Args:
            event: Event dictionary to validate
            
        Returns:
            bool: True if event is valid
        """
        required_fields = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
        
        # Check required fields
        for field in required_fields:
            if field not in event:
                logger.warning(f"Missing required field '{field}' in event")
                return False
        
        # Validate data types and ranges
        try:
            # Timestamp should be a positive integer
            if not isinstance(event["timestamp"], int) or event["timestamp"] <= 0:
                return False
            
            # IP addresses should be strings
            if not isinstance(event["src_ip"], str) or not isinstance(event["dst_ip"], str):
                return False
            
            # Ports should be integers in valid range
            src_port = int(event["src_port"])
            dst_port = int(event["dst_port"])
            if not (0 <= src_port <= 65535) or not (0 <= dst_port <= 65535):
                return False
            
            # Protocol should be a string
            if not isinstance(event["protocol"], str):
                return False
            
            return True
            
        except (ValueError, TypeError) as e:
            logger.warning(f"Event validation error: {e}")
            return False
    
    async def _store_events(self, events: List[Dict[str, Any]]) -> int:
        """
        Store events in the database
        
        Args:
            events: List of validated event dictionaries
            
        Returns:
            int: Number of events successfully stored
        """
        if not events:
            return 0
        
        stored_count = 0
        db = SessionLocal()
        
        try:
            for event_data in events:
                try:
                    # Create NetworkEvent from kernel data
                    event = NetworkEvent.from_kernel_event(event_data)
                    
                    # Add to database session
                    db.add(event)
                    stored_count += 1
                    
                except Exception as e:
                    logger.error(f"Error creating event from data {event_data}: {e}")
                    continue
            
            # Commit all events
            if stored_count > 0:
                db.commit()
                logger.debug(f"Successfully stored {stored_count} events")
            
        except Exception as e:
            logger.error(f"Database error storing events: {e}")
            db.rollback()
            stored_count = 0
        finally:
            db.close()
        
        return stored_count
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get collection statistics
        
        Returns:
            Dict[str, Any]: Collection statistics
        """
        return {
            **self.stats,
            "running": self.running,
            "proc_path": str(self.proc_path),
            "collection_interval": self.collection_interval
        }
    
    async def test_kernel_connection(self) -> Dict[str, Any]:
        """
        Test connection to kernel module
        
        Returns:
            Dict[str, Any]: Connection test results
        """
        result = {
            "proc_exists": self.proc_path.exists(),
            "readable": False,
            "has_data": False,
            "data_valid": False,
            "error": None
        }
        
        try:
            if result["proc_exists"]:
                # Try to read the file
                with open(self.proc_path, 'r') as f:
                    data = f.read().strip()
                result["readable"] = True
                
                if data:
                    result["has_data"] = True
                    
                    # Try to parse the data
                    try:
                        json.loads(data)
                        result["data_valid"] = True
                    except json.JSONDecodeError:
                        result["error"] = "Invalid JSON format"
                else:
                    result["error"] = "No data available"
            else:
                result["error"] = "Kernel module not loaded or /proc/kguard not found"
                
        except PermissionError:
            result["error"] = "Permission denied"
        except Exception as e:
            result["error"] = str(e)
        
        return result


# Global instance
data_collector = DataCollectorService()