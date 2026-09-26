"""
NYAYAI - Common Pydantic Schemas
Module: backend.app.schemas.common
"""

from typing import Generic, TypeVar, Optional, Any, Dict
from pydantic import BaseModel, Field

T = TypeVar("T")


class APIResponse(BaseModel, Generic[T]):
    success: bool = True
    message: Optional[str] = None
    data: Optional[T] = None


class ErrorResponse(BaseModel):
    status: int
    message: str
    error_code: str
    details: Optional[Dict[str, Any]] = None
    success: bool = False
