"""
Common Pydantic Schemas

This module contains shared schemas used across the API.
"""

from pydantic import BaseModel
from typing import List, TypeVar, Generic, Optional
from datetime import datetime

T = TypeVar('T')


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response schema"""
    items: List[T]
    total: int
    page: int
    size: int
    pages: int
    
    class Config:
        from_attributes = True


class HealthCheck(BaseModel):
    """Health check response schema"""
    status: str
    timestamp: datetime
    version: str
    database: bool
    kernel_module: bool
    uptime_seconds: float
    
    class Config:
        from_attributes = True


class ErrorResponse(BaseModel):
    """Error response schema"""
    error: str
    detail: Optional[str] = None
    timestamp: datetime
    
    class Config:
        from_attributes = True


class SuccessResponse(BaseModel):
    """Generic success response schema"""
    success: bool
    message: str
    timestamp: datetime
    
    class Config:
        from_attributes = True