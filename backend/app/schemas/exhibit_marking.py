"""
NYAYAI - Courtroom Exhibit Marking & Evidence Tender Schemas (Phase 21)
Module: backend.app.schemas.exhibit_marking
Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ExhibitRulingEnum(str, Enum):
    """Official judicial rulings on courtroom admissibility of electronic evidence under BSA 2023."""
    ADMITTED_AS_EXHIBIT = "ADMITTED_AS_EXHIBIT"
    MARKED_FOR_IDENTIFICATION = "MARKED_FOR_IDENTIFICATION"
    OBJECTED_DECISION_RESERVED = "OBJECTED_DECISION_RESERVED"
    REJECTED = "REJECTED"


class TenderingPartyEnum(str, Enum):
    """Courtroom party tendering electronic evidence artifacts or Section 63 reports."""
    PROSECUTION = "PROSECUTION"
    DEFENCE = "DEFENCE"
    COURT = "COURT"


class ExhibitItemTypeEnum(str, Enum):
    """Categorical type of the digital artifact tendered or marked."""
    EVIDENCE = "EVIDENCE"
    REPORT = "REPORT"


class EvidenceTenderRequest(BaseModel):
    """Request payload for formal courtroom tendering of evidence or Section 63 reports."""
    target_id: str = Field(..., description="Unique evidence_id or report_id being tendered")
    target_type: ExhibitItemTypeEnum = Field(default=ExhibitItemTypeEnum.EVIDENCE, description="Artifact category: EVIDENCE or REPORT")
    tendering_party: TenderingPartyEnum = Field(..., description="Party tendering evidence: PROSECUTION, DEFENCE, or COURT")
    tendering_witness: Optional[str] = Field(None, description="Witness designation through whom evidence is tendered (e.g. 'PW-1 Insp. Sharma')")
    purpose: Optional[str] = Field(None, description="Courtroom purpose (e.g. 'Trial Presentation', 'Cross-examination', 'Corroboration')")
    tender_notes: Optional[str] = Field(None, description="Additional advocate/officer tender remarks")


class EvidenceTenderResponse(BaseModel):
    """Response returned upon successful courtroom evidence tender."""
    success: bool = True
    tender_id: str = Field(..., description="Unique courtroom tender reference identifier")
    case_id: str = Field(..., description="Case docket ID")
    case_number: str = Field(..., description="Official case docket number")
    target_id: str = Field(..., description="Target evidence or report ID")
    target_type: str = Field(..., description="EVIDENCE or REPORT")
    target_filename: Optional[str] = Field(None, description="Original filename or report reference")
    sha256_hash: str = Field(..., description="Authoritative SHA-256 digest of tendered artifact")
    tendering_party: str = Field(..., description="PROSECUTION, DEFENCE, or COURT")
    tendering_witness: Optional[str] = Field(None, description="Witness designation")
    purpose: Optional[str] = Field(None, description="Stated courtroom purpose")
    tender_notes: Optional[str] = Field(None, description="Tender remarks")
    tendered_by: str = Field(..., description="User ID of tendering advocate or officer")
    tendered_by_username: Optional[str] = Field(None, description="Username of tendering advocate or officer")
    tendered_at: str = Field(..., description="ISO-8601 UTC timestamp of tendering")
    status: str = Field(default="TENDERED", description="Courtroom status (TENDERED)")
    custody_event_id: Optional[str] = Field(None, description="Linked custody event ID for evidence items")
    audit_id: str = Field(..., description="Compliance audit log entry ID")


class ExhibitMarkingRequest(BaseModel):
    """Official judicial exhibit marking and admissibility ruling payload (JUDGE only)."""
    target_id: str = Field(..., description="Target evidence_id or report_id")
    target_type: ExhibitItemTypeEnum = Field(default=ExhibitItemTypeEnum.EVIDENCE, description="EVIDENCE or REPORT")
    exhibit_number: str = Field(..., description="Formal judicial exhibit identifier (e.g. 'Ex. P-1', 'Ex. D-1', 'MO-1', 'Mark A')")
    tendering_party: TenderingPartyEnum = Field(..., description="Party tendering evidence: PROSECUTION, DEFENCE, or COURT")
    ruling: ExhibitRulingEnum = Field(..., description="Judicial determination: ADMITTED_AS_EXHIBIT, MARKED_FOR_IDENTIFICATION, OBJECTED_DECISION_RESERVED, REJECTED")
    tendering_witness: Optional[str] = Field(None, description="Witness designation (e.g. 'PW-1 Insp. Sharma')")
    court_bench: Optional[str] = Field(None, description="Court name and bench (e.g. 'Sessions Court 4, Patiala House Courts')")
    judicial_officer_name: Optional[str] = Field(None, description="Presiding judicial officer name (e.g. 'Hon\'ble Justice S. K. Gupta')")
    order_reference: Optional[str] = Field(None, description="Court order sheet reference or proceeding number")
    objections_raised: Optional[str] = Field(None, description="Statutory objections raised under BSA 2023 Section 63")
    ruling_rationale: Optional[str] = Field(None, description="Judicial reasoning and statutory grounds for ruling")


class ExhibitRecordResponse(BaseModel):
    """Complete official judicial exhibit record representation."""
    success: bool = True
    exhibit_id: str = Field(..., description="Internal exhibit tracking identifier")
    case_id: str = Field(..., description="Case docket ID")
    case_number: str = Field(..., description="Official case docket number")
    exhibit_number: str = Field(..., description="Official judicial exhibit number (e.g. 'Ex. P-1')")
    target_id: str = Field(..., description="Target evidence or report ID")
    target_type: str = Field(..., description="EVIDENCE or REPORT")
    target_filename: Optional[str] = Field(None, description="Original filename or report reference")
    sha256_hash: str = Field(..., description="SHA-256 digest of artifact")
    tendering_party: str = Field(..., description="PROSECUTION, DEFENCE, or COURT")
    tendering_witness: Optional[str] = Field(None, description="Witness designation")
    ruling: str = Field(..., description="Judicial admissibility ruling")
    court_bench: Optional[str] = Field(None, description="Court name and bench")
    judicial_officer_name: Optional[str] = Field(None, description="Presiding judge name")
    order_reference: Optional[str] = Field(None, description="Court order reference")
    objections_raised: Optional[str] = Field(None, description="Recorded counsel objections")
    ruling_rationale: Optional[str] = Field(None, description="Judicial reasoning")
    marked_by: str = Field(..., description="User ID of presiding judicial officer")
    marked_by_username: Optional[str] = Field(None, description="Username of presiding judge")
    marked_at: str = Field(..., description="ISO-8601 UTC timestamp of marking")
    custody_event_id: Optional[str] = Field(None, description="Linked custody event ID for evidence items")
    custody_event_hash: Optional[str] = Field(None, description="Linked custody block SHA-256 digest")
    audit_id: str = Field(..., description="Compliance audit log entry ID")


class EvidenceExhibitStatusResponse(BaseModel):
    """Detailed courtroom exhibit and tender status for a single evidence artifact."""
    case_id: str = Field(..., description="Case docket ID")
    case_number: str = Field(..., description="Official case docket number")
    evidence_id: str = Field(..., description="Evidence ID")
    original_filename: str = Field(..., description="Original filename")
    sha256_hash: str = Field(..., description="Intake SHA-256 hash")
    is_tendered: bool = Field(default=False, description="Whether evidence has been tendered in court")
    is_marked: bool = Field(default=False, description="Whether evidence has been marked by judge")
    exhibit_number: Optional[str] = Field(None, description="Assigned judicial exhibit number")
    ruling: Optional[str] = Field(None, description="Judicial ruling if marked")
    tendering_party: Optional[str] = Field(None, description="Party that tendered item")
    tendering_witness: Optional[str] = Field(None, description="Witness through whom item was presented")
    judicial_officer_name: Optional[str] = Field(None, description="Presiding judge name")
    court_bench: Optional[str] = Field(None, description="Court bench")
    marked_at: Optional[str] = Field(None, description="Marking timestamp")
    tendered_at: Optional[str] = Field(None, description="Tendering timestamp")
    status: str = Field(..., description="Courtroom status: e.g. ADMITTED_AS_EXHIBIT, TENDERED, UNMARKED")


class CaseExhibitRegisterResponse(BaseModel):
    """Consolidated Judicial Exhibit Register for a case docket."""
    success: bool = True
    case_id: str = Field(..., description="Case docket ID")
    case_number: str = Field(..., description="Official case docket number")
    case_status: str = Field(..., description="Case docket lifecycle status")
    docket_sealing_hash: Optional[str] = Field(None, description="Phase 17 docket sealing manifest hash")
    total_exhibits: int = Field(default=0, description="Total marked exhibits in docket")
    admitted_count: int = Field(default=0, description="Total ADMITTED_AS_EXHIBIT count")
    mfi_count: int = Field(default=0, description="Total MARKED_FOR_IDENTIFICATION count")
    objected_count: int = Field(default=0, description="Total OBJECTED_DECISION_RESERVED count")
    rejected_count: int = Field(default=0, description="Total REJECTED count")
    exhibits: List[ExhibitRecordResponse] = Field(default_factory=list, description="Chronologically ordered exhibit list")
    tenders: List[EvidenceTenderResponse] = Field(default_factory=list, description="Chronologically ordered tender history")
