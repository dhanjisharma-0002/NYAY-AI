"""
NYAYAI - Trial Disposition, Objection Resolution & Exhibit Disposal Schemas (Phase 22)
Module: backend.app.schemas.trial_disposition
Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class TrialVerdictEnum(str, Enum):
    """Statutory judicial trial verdict classifications under BNSS 2023."""
    CONVICTED = "CONVICTED"
    ACQUITTED = "ACQUITTED"
    DISCHARGED = "DISCHARGED"
    DISMISSED = "DISMISSED"
    PARTIALLY_CONVICTED = "PARTIALLY_CONVICTED"


class ResolvedRulingEnum(str, Enum):
    """Permitted final rulings for resolving reserved objections or MFI exhibits."""
    ADMITTED_AS_EXHIBIT = "ADMITTED_AS_EXHIBIT"
    REJECTED = "REJECTED"


class DisposalTypeEnum(str, Enum):
    """Statutory electronic/physical evidence disposal directions under BNSS 2023 Section 503."""
    RETURNED_TO_OWNER = "RETURNED_TO_OWNER"
    CONFISCATED = "CONFISCATED"
    DESTROYED = "DESTROYED"
    RETAINED_FOR_APPEAL = "RETAINED_FOR_APPEAL"


class TrialVerdictRequest(BaseModel):
    """Payload for pronouncing judicial trial verdict and judgment (JUDGE only)."""
    verdict: TrialVerdictEnum = Field(..., description="Judicial verdict: CONVICTED, ACQUITTED, DISCHARGED, DISMISSED, PARTIALLY_CONVICTED")
    order_reference: Optional[str] = Field(None, description="Court judgment citation, order sheet reference, or proceeding number")
    court_bench: Optional[str] = Field(None, description="Presiding court and bench designation")
    judicial_officer_name: Optional[str] = Field(None, description="Presiding judge name")
    disposition_summary: Optional[str] = Field(None, description="Summary of trial judgment, findings, and sentencing")
    statutory_provisions: Optional[List[str]] = Field(default_factory=list, description="Statutory sections adjudicated under BNSS / BNS / IT Act")
    appeal_limitation_days: Optional[int] = Field(default=60, description="Statutory appeal limitation period in days (default: 60)")


class TrialVerdictResponse(BaseModel):
    """Response returned upon formal pronouncement of judicial trial verdict."""
    success: bool = True
    disposition_id: str = Field(..., description="Unique judicial disposition reference identifier")
    case_id: str = Field(..., description="Case docket ID")
    case_number: str = Field(..., description="Official case docket number")
    verdict: str = Field(..., description="Pronounced judicial verdict")
    court_bench: Optional[str] = Field(None, description="Court name and bench")
    judicial_officer_name: Optional[str] = Field(None, description="Presiding judge name")
    order_reference: Optional[str] = Field(None, description="Court order or judgment reference")
    disposition_summary: Optional[str] = Field(None, description="Judgment summary")
    statutory_provisions: Optional[List[str]] = Field(default_factory=list, description="Adjudicated statutory provisions")
    appeal_limitation_days: int = Field(default=60, description="Appellate limitation period in days")
    pronounced_by: str = Field(..., description="User ID of presiding judicial officer")
    pronounced_by_username: Optional[str] = Field(None, description="Username of presiding judge")
    pronounced_at: str = Field(..., description="ISO-8601 UTC timestamp of verdict pronouncement")
    appellate_hold_expires_at: Optional[str] = Field(None, description="Calculated expiration timestamp for appellate legal hold")
    audit_id: str = Field(..., description="Compliance audit log entry ID")


class ObjectionResolutionRequest(BaseModel):
    """Payload for resolving a reserved Section 63 objection or MFI exhibit (JUDGE only)."""
    final_ruling: ResolvedRulingEnum = Field(..., description="Final judicial determination: ADMITTED_AS_EXHIBIT or REJECTED")
    ruling_rationale: Optional[str] = Field(None, description="Statutory judicial reasoning and grounds under BSA 2023 Section 63")
    order_reference: Optional[str] = Field(None, description="Court order sheet reference")
    court_bench: Optional[str] = Field(None, description="Court name and bench")
    judicial_officer_name: Optional[str] = Field(None, description="Presiding judicial officer name")


class ObjectionResolutionResponse(BaseModel):
    """Response returned upon resolving a reserved objection or MFI exhibit."""
    success: bool = True
    resolution_id: str = Field(..., description="Unique objection resolution tracking identifier")
    case_id: str = Field(..., description="Case docket ID")
    case_number: str = Field(..., description="Official case docket number")
    exhibit_number: str = Field(..., description="Judicial exhibit number (e.g. 'Ex. P-1')")
    target_id: str = Field(..., description="Target evidence or report ID")
    target_type: str = Field(..., description="EVIDENCE or REPORT")
    target_filename: Optional[str] = Field(None, description="Original filename or report reference")
    sha256_hash: str = Field(..., description="SHA-256 digest of artifact")
    prior_ruling: str = Field(..., description="Prior ruling state before resolution (e.g. OBJECTED_DECISION_RESERVED)")
    final_ruling: str = Field(..., description="Final resolved ruling: ADMITTED_AS_EXHIBIT or REJECTED")
    ruling_rationale: Optional[str] = Field(None, description="Judicial reasoning")
    order_reference: Optional[str] = Field(None, description="Court order reference")
    resolved_by: str = Field(..., description="User ID of presiding judicial officer")
    resolved_by_username: Optional[str] = Field(None, description="Username of presiding judge")
    resolved_at: str = Field(..., description="ISO-8601 UTC timestamp of resolution")
    custody_event_id: Optional[str] = Field(None, description="Linked custody event ID for evidence items")
    audit_id: str = Field(..., description="Compliance audit log entry ID")


class ExhibitDisposalOrderRequest(BaseModel):
    """Payload for issuing statutory evidence disposal orders under BNSS 2023 Section 503 (JUDGE only)."""
    disposal_type: DisposalTypeEnum = Field(..., description="Disposal direction: RETURNED_TO_OWNER, CONFISCATED, DESTROYED, RETAINED_FOR_APPEAL")
    statutory_authority: Optional[str] = Field(default="BNSS_2023_SECTION_503", description="Governing statutory section")
    disposal_instructions: Optional[str] = Field(None, description="Specific court directions for registry / Malkhana custody")
    recipient_details: Optional[str] = Field(None, description="Details of recipient for RETURNED_TO_OWNER")
    appellate_hold: Optional[bool] = Field(default=False, description="Flag indicating active retention hold during appeal limitation period")
    order_reference: Optional[str] = Field(None, description="Court disposal order reference")
    court_bench: Optional[str] = Field(None, description="Court name and bench")
    judicial_officer_name: Optional[str] = Field(None, description="Presiding judicial officer name")


class ExhibitDisposalOrderResponse(BaseModel):
    """Response returned upon formal issuance of statutory exhibit disposal order."""
    success: bool = True
    disposal_order_id: str = Field(..., description="Unique exhibit disposal order identifier")
    case_id: str = Field(..., description="Case docket ID")
    case_number: str = Field(..., description="Official case docket number")
    exhibit_number: str = Field(..., description="Judicial exhibit number (e.g. 'Ex. P-1')")
    target_id: str = Field(..., description="Target evidence or report ID")
    target_type: str = Field(..., description="EVIDENCE or REPORT")
    target_filename: Optional[str] = Field(None, description="Original filename or report reference")
    sha256_hash: str = Field(..., description="SHA-256 digest of artifact")
    disposal_type: str = Field(..., description="Disposal type: RETURNED_TO_OWNER, CONFISCATED, DESTROYED, RETAINED_FOR_APPEAL")
    statutory_authority: str = Field(default="BNSS_2023_SECTION_503", description="Statutory authority")
    disposal_instructions: Optional[str] = Field(None, description="Registry / Malkhana instructions")
    recipient_details: Optional[str] = Field(None, description="Recipient details")
    appellate_hold: bool = Field(default=False, description="Active appellate retention hold")
    order_reference: Optional[str] = Field(None, description="Court order reference")
    ordered_by: str = Field(..., description="User ID of presiding judicial officer")
    ordered_by_username: Optional[str] = Field(None, description="Username of presiding judge")
    ordered_at: str = Field(..., description="ISO-8601 UTC timestamp of disposal order")
    custody_event_id: Optional[str] = Field(None, description="Linked custody event ID for evidence items")
    audit_id: str = Field(..., description="Compliance audit log entry ID")


class CaseArchivalRequest(BaseModel):
    """Payload for final judicial case docket archival (JUDGE only)."""
    reason: Optional[str] = Field(None, description="Archival rationale and trial conclusion remarks")
    order_reference: Optional[str] = Field(None, description="Final disposal and consignment order reference")
    record_room_reference: Optional[str] = Field(None, description="Judicial record room or repository reference")


class CaseArchivalResponse(BaseModel):
    """Response returned upon formal judicial case docket archival."""
    success: bool = True
    case_id: str = Field(..., description="Case docket ID")
    case_number: str = Field(..., description="Official case docket number")
    previous_status: str = Field(..., description="Previous lifecycle status (COMPLETED)")
    current_status: str = Field(default="ARCHIVED", description="Current lifecycle status (ARCHIVED)")
    verdict: str = Field(..., description="Adjudicated trial verdict")
    total_exhibits_disposed: int = Field(default=0, description="Total exhibits with statutory disposal orders")
    appellate_holds_active: int = Field(default=0, description="Total active appellate legal holds")
    reason: Optional[str] = Field(None, description="Archival remarks")
    order_reference: Optional[str] = Field(None, description="Order reference")
    record_room_reference: Optional[str] = Field(None, description="Record room reference")
    archived_by: str = Field(..., description="User ID of presiding judicial officer")
    archived_by_username: Optional[str] = Field(None, description="Username of presiding judge")
    archived_at: str = Field(..., description="ISO-8601 UTC timestamp of archival")
    audit_id: str = Field(..., description="Compliance audit log entry ID")


class CaseTrialDispositionRegisterResponse(BaseModel):
    """Consolidated Trial Disposition and Exhibit Disposal Register for a case docket."""
    success: bool = True
    case_id: str = Field(..., description="Case docket ID")
    case_number: str = Field(..., description="Official case docket number")
    case_status: str = Field(..., description="Case docket lifecycle status (e.g. COMPLETED, ARCHIVED)")
    has_verdict: bool = Field(default=False, description="Whether final trial verdict has been pronounced")
    verdict: Optional[TrialVerdictResponse] = Field(None, description="Pronounced trial verdict details if available")
    total_exhibits: int = Field(default=0, description="Total marked exhibits in docket")
    unresolved_exhibits_count: int = Field(default=0, description="Exhibits pending objection resolution or MFI conversion")
    disposed_exhibits_count: int = Field(default=0, description="Exhibits with recorded statutory disposal orders")
    pending_disposal_count: int = Field(default=0, description="Exhibits pending disposal orders")
    is_ready_for_archival: bool = Field(default=False, description="Whether case docket meets all criteria for judicial archival")
    resolutions: List[ObjectionResolutionResponse] = Field(default_factory=list, description="Objection resolutions history")
    disposal_orders: List[ExhibitDisposalOrderResponse] = Field(default_factory=list, description="Exhibit disposal orders history")
