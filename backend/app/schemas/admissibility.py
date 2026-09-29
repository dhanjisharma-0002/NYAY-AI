"""
NYAYAI - Case Docket Judicial Admissibility & Verification Schemas (Phase 18)
Module: backend.app.schemas.admissibility
Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class AdmissibilityStatusEnum(str, Enum):
    """Technical evidentiary admissibility determination statuses under BSA 2023."""
    ADMISSIBLE = "ADMISSIBLE"
    INADMISSIBLE_TAMPERED = "INADMISSIBLE_TAMPERED"
    CHAIN_OF_CUSTODY_BREACHED = "CHAIN_OF_CUSTODY_BREACHED"
    SEALING_HASH_MISMATCH = "SEALING_HASH_MISMATCH"
    UNSEALED = "UNSEALED"
    MISSING_COURT_REPORT = "MISSING_COURT_REPORT"
    EMPTY_CASE = "EMPTY_CASE"


class CaseAdmissibilityRequest(BaseModel):
    """Payload for initiating judicial admissibility verification of a case docket."""
    court_bench: Optional[str] = Field(
        None,
        description="Presiding judicial bench or courtroom identification (e.g. 'Courtroom 4B, High Court of Delhi')"
    )
    judicial_officer_name: Optional[str] = Field(
        None,
        description="Name or title of presiding judge, magistrate, or forensic auditor"
    )
    verification_notes: Optional[str] = Field(
        None,
        description="Judicial verification remarks or case tender notes"
    )


class AdmissibilityCheckBreakdown(BaseModel):
    """Granular results of technical verification checks."""
    vault_integrity_passed: bool
    custody_chains_intact: bool
    sealing_hash_verified: bool
    court_reports_valid: bool
    total_evidence_verified: int
    compromised_evidence_count: int
    broken_custody_chains_count: int
    compromised_evidence_ids: List[str] = Field(default_factory=list)
    broken_chain_evidence_ids: List[str] = Field(default_factory=list)


class SealingVerificationDetail(BaseModel):
    """Fidelity of the Phase 17 deterministic sealing manifest."""
    is_sealed: bool
    expected_sealing_hash: Optional[str] = None
    recalculated_sealing_hash: Optional[str] = None
    hashes_match: bool


class EvidenceAdmissibilityItem(BaseModel):
    """Cryptographic audit summary for an individual evidence artifact."""
    evidence_id: str
    original_filename: str
    stored_hash: str
    vault_file_hash: Optional[str] = None
    vault_integrity: str
    custody_chain_intact: bool
    total_custody_events: int


class ReportAdmissibilityItem(BaseModel):
    """Integrity audit summary for an official court admissibility report."""
    report_id: str
    report_type: str
    stored_sha256: str
    vault_file_sha256: Optional[str] = None
    is_valid: bool


class CaseAdmissibilityResponse(BaseModel):
    """Comprehensive judicial admissibility assessment and certificate."""
    case_id: str
    case_number: str
    case_status: str
    admissibility_status: str
    is_admissible: bool
    statutory_framework: str = "BSA_2023_SECTION_63"
    verified_at: str
    verifier: Dict[str, Any]
    checks: AdmissibilityCheckBreakdown
    sealing_verification: SealingVerificationDetail
    admissibility_summary: str
    evidence_items: List[EvidenceAdmissibilityItem] = Field(default_factory=list)
    reports: List[ReportAdmissibilityItem] = Field(default_factory=list)


class AdmissibilityCertificateResponse(BaseModel):
    """Certified representation of a judicial admissibility determination."""
    case_id: str
    case_number: str
    case_status: str
    admissibility_status: str
    is_admissible: bool
    statutory_framework: str = "BSA_2023_SECTION_63"
    verified_at: str
    verifier: Dict[str, Any]
    checks: AdmissibilityCheckBreakdown
    sealing_verification: SealingVerificationDetail
    admissibility_summary: str
    evidence_items: List[EvidenceAdmissibilityItem] = Field(default_factory=list)
    reports: List[ReportAdmissibilityItem] = Field(default_factory=list)
