"""
System Metrics Database Model

This module defines the SystemMetric model for storing system performance
and monitoring metrics.
"""


from sqlalchemy import Column, DateTime, Float, Index, Integer, String
from sqlalchemy.sql import func

from ..database import Base


class SystemMetric(Base):
    """
    System Metric Model

    Stores system performance metrics and monitoring data
    for the KGuard application.
    """

    __tablename__ = "system_metrics"

    # Primary key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)

    # Timestamp
    timestamp = Column(DateTime(timezone=True), server_default=func.now(),
                      nullable=False, index=True,
                      comment="When the metric was recorded")

    # Metric identification
    metric_name = Column(String(100), nullable=False, index=True,
                        comment="Name of the metric")
    metric_category = Column(String(50), nullable=False, index=True,
                           comment="Category of the metric (performance, security, etc.)")

    # Metric value
    value = Column(Float, nullable=False,
                  comment="Numeric value of the metric")
    unit = Column(String(20), nullable=True,
                 comment="Unit of measurement")

    # Additional context
    source = Column(String(50), nullable=True,
                   comment="Source component that generated the metric")
    tags = Column(String(200), nullable=True,
                 comment="Additional tags for filtering/grouping")

    # Indexes for performance
    __table_args__ = (
        Index('idx_metric_timestamp', 'metric_name', 'timestamp'),
        Index('idx_category_timestamp', 'metric_category', 'timestamp'),
    )

    def __repr__(self) -> str:
        return (f"<SystemMetric(id={self.id}, "
                f"name={self.metric_name}, "
                f"value={self.value}, "
                f"timestamp={self.timestamp})>")

    def to_dict(self) -> dict:
        """Convert model to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "metric_name": self.metric_name,
            "metric_category": self.metric_category,
            "value": self.value,
            "unit": self.unit,
            "source": self.source,
            "tags": self.tags
        }

    @classmethod
    def create_performance_metric(cls, name: str, value: float,
                                 unit: str = None, source: str = None) -> "SystemMetric":
        """
        Create a performance metric

        Args:
            name: Metric name
            value: Metric value
            unit: Unit of measurement
            source: Source component

        Returns:
            SystemMetric: New performance metric
        """
        return cls(
            metric_name=name,
            metric_category="performance",
            value=value,
            unit=unit,
            source=source
        )

    @classmethod
    def create_security_metric(cls, name: str, value: float,
                              source: str = None, tags: str = None) -> "SystemMetric":
        """
        Create a security metric

        Args:
            name: Metric name
            value: Metric value
            source: Source component
            tags: Additional tags

        Returns:
            SystemMetric: New security metric
        """
        return cls(
            metric_name=name,
            metric_category="security",
            value=value,
            source=source,
            tags=tags
        )
