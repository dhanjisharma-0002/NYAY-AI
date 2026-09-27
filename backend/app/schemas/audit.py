"""
NYAYAI - Audit Trail Schemas (Phase 12)
Module: backend.app.schemas.audit
Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class AuditLogEntryOut(BaseModel):
    audit_id: str
    user_id: Optional[str] = None
    action: str
    resource_type: str
    resource_id: str
    timestamp: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AuditLogListResponse(BaseModel):
    success: bool = True
    total: int
    limit: int
    offset: int
    items: List[AuditLogEntryOut]
