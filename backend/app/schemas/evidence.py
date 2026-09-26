"""
NYAYAI - Evidence Schemas (Phase 5)
Module: backend.app.schemas.evidence
Defines validation contracts and serialization responses for evidence intake.
"""

from typing import Optional, List
from pydantic import BaseModel, Field


class EvidenceUploadResponse(BaseModel):
    """Standardized response format for evidence intake."""
    evidence_id: str
    case_id: str
    filename: str
    media_type: str
    file_size: int
    sha256_hash: str
    status: str = "SECURED"
    created_at: str

    # Backward compatibility attributes
    original_filename: Optional[str] = None
    file_size_bytes: Optional[int] = None
    mime_type: Optional[str] = None
    vault_status: Optional[str] = "SECURED_READONLY"
    genesis_event_hash: Optional[str] = None

    class Config:
        from_attributes = True


class EvidenceResponse(BaseModel):
    """Detailed evidence item representation."""
    evidence_id: str
    case_id: str
    filename: str
    original_filename: str
    file_size: int
    file_size_bytes: int
    media_type: str
    mime_type: str
    sha256_hash: str
    vault_status: str = "SECURED_READONLY"
    status: str = "SECURED"
    source_description: Optional[str] = None
    created_at: str

    class Config:
        from_attributes = True


class EvidenceListResponse(BaseModel):
    """Collection response for evidence queries."""
    total: int
    data: List[EvidenceResponse]


class EvidenceIntegrityResponse(BaseModel):
    """Response format for evidence integrity verification (Phase 6)."""
    evidence_id: str
    stored_hash: str
    current_hash: Optional[str] = None
    integrity_status: str  # "VERIFIED", "MISMATCH", "ERROR"
    verified_at: str
    error_message: Optional[str] = None
    custody_event_id: Optional[str] = None

    class Config:
        from_attributes = True

