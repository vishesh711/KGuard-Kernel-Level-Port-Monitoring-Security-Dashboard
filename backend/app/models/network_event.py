"""
Network Event Database Model

This module defines the NetworkEvent model for storing network traffic events
captured by the kernel module.
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, BigInteger, Index
from sqlalchemy.sql import func
from datetime import datetime

from ..database import Base


class NetworkEvent(Base):
    """
    Network Event Model
    
    Stores network traffic events captured by the KGuard kernel module.
    Each event represents a network packet with extracted metadata.
    """
    
    __tablename__ = "network_events"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # Timestamp information
    timestamp = Column(BigInteger, nullable=False, index=True, 
                      comment="High-resolution timestamp from kernel (nanoseconds)")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), 
                       nullable=False, comment="Database insertion timestamp")
    
    # Network information
    src_ip = Column(String(45), nullable=False, index=True, 
                   comment="Source IP address (IPv4 or IPv6)")
    dst_ip = Column(String(45), nullable=False, index=True, 
                   comment="Destination IP address (IPv4 or IPv6)")
    src_port = Column(Integer, nullable=False, 
                     comment="Source port number")
    dst_port = Column(Integer, nullable=False, index=True, 
                     comment="Destination port number")
    
    # Protocol information
    protocol = Column(String(10), nullable=False, index=True, 
                     comment="Protocol name (TCP, UDP, ICMP, etc.)")
    flags = Column(Integer, default=0, 
                  comment="Protocol-specific flags")
    
    # Classification
    is_suspicious = Column(Boolean, default=False, index=True, 
                          comment="Whether this event was flagged as suspicious")
    event_type = Column(String(20), default="normal", 
                       comment="Event classification type")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_timestamp_src_ip', 'timestamp', 'src_ip'),
        Index('idx_dst_port_protocol', 'dst_port', 'protocol'),
        Index('idx_suspicious_timestamp', 'is_suspicious', 'timestamp'),
        Index('idx_created_at', 'created_at'),
    )
    
    def __repr__(self) -> str:
        return (f"<NetworkEvent(id={self.id}, "
                f"src={self.src_ip}:{self.src_port}, "
                f"dst={self.dst_ip}:{self.dst_port}, "
                f"protocol={self.protocol}, "
                f"suspicious={self.is_suspicious})>")
    
    def to_dict(self) -> dict:
        """Convert model to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "flags": self.flags,
            "is_suspicious": self.is_suspicious,
            "event_type": self.event_type
        }
    
    @classmethod
    def from_kernel_event(cls, kernel_data: dict) -> "NetworkEvent":
        """
        Create NetworkEvent from kernel module data
        
        Args:
            kernel_data: Dictionary containing kernel event data
            
        Returns:
            NetworkEvent: New instance with data from kernel
        """
        return cls(
            timestamp=kernel_data.get("timestamp", 0),
            src_ip=kernel_data.get("src_ip", ""),
            dst_ip=kernel_data.get("dst_ip", ""),
            src_port=kernel_data.get("src_port", 0),
            dst_port=kernel_data.get("dst_port", 0),
            protocol=kernel_data.get("protocol", "UNKNOWN"),
            flags=kernel_data.get("flags", 0),
            is_suspicious=False,  # Will be determined by anomaly detection
            event_type="normal"
        )