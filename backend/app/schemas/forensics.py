"""
NYAYAI - Forensics Schemas
Module: backend.app.schemas.forensics
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class ForensicInspectRequest(BaseModel):
    evidence_id: str
    extract_exif: bool = True
    verify_magic_bytes: bool = True


class ForensicReportResponse(BaseModel):
    evidence_id: str
    format_valid: bool
    magic_bytes: str
    detected_mime: str
    anomalies: List[str] = []
    filesystem_metadata: Dict[str, Any] = {}
    exif_metadata: Dict[str, Any] = {}


class ForensicAnalysisResponse(BaseModel):
    analysis_id: str
    evidence_id: str
    analysis_type: str = "FORENSIC_INSPECTION"
    status: str = "COMPLETED"
    format_valid: bool
    magic_bytes: str
    detected_mime: str
    anomalies: List[str] = []
    metadata: Dict[str, Any] = {}
    prediction: str
    confidence: float
    risk_score: float
    findings: List[str] = []
    explanation: Optional[str] = None
    custody_event_id: Optional[str] = None
    created_at: str

    class Config:
        from_attributes = True

