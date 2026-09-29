"""
NYAYAI - Case Docket Finalization & Sealing Schemas (Phase 17)
Module: backend.app.schemas.case_finalization
Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class CaseFinalizationRequest(BaseModel):
    """Payload for finalizing and sealing an investigative case docket."""
    certification_notes: Optional[str] = Field(
        None,
        description="Investigator or judicial certification remarks upon finalization"
    )
    certifying_officer_name: Optional[str] = Field(
        None,
        description="Name of officer or judge sealing the docket"
    )
    badge_number: Optional[str] = Field(
        None,
        description="Official badge number or judicial credential ID"
    )


class CaseFinalizationResponse(BaseModel):
    """Result of case docket finalization and cryptographic sealing."""
    case_id: str
    case_number: str
    previous_status: str
    new_status: str
    sealed_at: str
    docket_sealing_hash: str
    total_evidence_sealed: int
    court_reports_referenced: int
    custody_events_appended: int
    sealed_by: str


class EvidenceManifestItem(BaseModel):
    """Cryptographic sealing record for an individual evidence artifact."""
    evidence_id: str
    original_filename: str
    sha256_hash: str
    status: str
    terminal_custody_hash: str


class ReportManifestItem(BaseModel):
    """Reference to an authorized judicial court admissibility report."""
    report_id: str
    report_type: str
    report_sha256: str
    verification_code: Optional[str] = None
    created_at: str


class DocketSealingManifestResponse(BaseModel):
    """Complete manifest and cryptographic verification record of a sealed case docket."""
    case_id: str
    case_number: str
    status: str
    is_sealed: bool
    docket_sealing_hash: Optional[str] = None
    sealed_at: Optional[str] = None
    sealed_by: Optional[str] = None
    certification_notes: Optional[str] = None
    evidence_manifest: List[EvidenceManifestItem] = Field(default_factory=list)
    reports_manifest: List[ReportManifestItem] = Field(default_factory=list)
