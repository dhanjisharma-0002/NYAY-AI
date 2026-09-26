"""
NYAYAI - Case Management Schemas (Phase 4)
Module: backend.app.schemas.cases
Defines validation contracts for case docket creation, listing, retrieval, and updates.
"""

from typing import Optional, List
from enum import Enum
from pydantic import BaseModel, Field, field_validator


class CaseStatusEnum(str, Enum):
    """Permitted lifecycle statuses for investigative cases."""
    OPEN = "OPEN"
    UNDER_ANALYSIS = "UNDER_ANALYSIS"
    COMPLETED = "COMPLETED"
    ARCHIVED = "ARCHIVED"


class CaseCreateRequest(BaseModel):
    """Payload for registering a new case docket."""
    title: str = Field(..., min_length=1, max_length=256, description="Mandatory case heading")
    description: Optional[str] = Field(None, description="Detailed case narrative and context")
    case_number: Optional[str] = Field(None, description="Optional custom case docket number")
    status: Optional[CaseStatusEnum] = Field(default=CaseStatusEnum.OPEN, description="Initial case status")
    jurisdiction: Optional[str] = Field(default="High Court of Delhi", description="Judicial or police jurisdiction")

    @field_validator("title")
    def validate_title_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Case title cannot be empty or solely whitespace.")
        return v.strip()


class CaseUpdateRequest(BaseModel):
    """Payload for patching an existing case docket."""
    title: Optional[str] = Field(None, min_length=1, max_length=256, description="Updated case heading")
    description: Optional[str] = Field(None, description="Updated case narrative")
    status: Optional[CaseStatusEnum] = Field(None, description="Updated case lifecycle status")
    jurisdiction: Optional[str] = Field(None, description="Updated jurisdiction")

    @field_validator("title")
    def validate_title_if_provided(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not v.strip():
            raise ValueError("Case title cannot be empty or solely whitespace.")
        return v.strip() if v is not None else None


class CaseResponse(BaseModel):
    """Standardized representation of a case docket."""
    case_id: str
    case_number: str
    title: str
    description: Optional[str] = None
    status: str
    created_by: str
    created_at: str
    updated_at: str
    jurisdiction: Optional[str] = None
    investigator_id: Optional[str] = None
    evidence_count: int = 0

    class Config:
        from_attributes = True


class CaseListResponse(BaseModel):
    """Paginated list of case dockets."""
    success: bool = True
    total: int
    data: List[CaseResponse]
