"""
NYAYAI - Case Management API Router (Phase 4)
Module: backend.app.api.cases
Endpoints:
- POST  /api/cases            : Create a new case docket (INVESTIGATOR, ADMIN)
- GET   /api/cases            : List all case dockets with optional status filter
- GET   /api/cases/{case_id}  : Retrieve detailed case docket metadata
- PATCH /api/cases/{case_id}  : Partially update case metadata / status (INVESTIGATOR, ADMIN)

Enforces strict role-based access control ('Only authorized users should access cases').
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, status, File, Form, UploadFile, Body
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.user import User
from backend.app.models.audit import AuditLog
from backend.app.utils.exceptions import AppException
from backend.app.core.security import require_roles
from backend.app.schemas.cases import CaseCreateRequest, CaseUpdateRequest, CaseStatusEnum
from backend.app.schemas.case_intelligence import CaseIntelligenceSummaryResponse
from backend.app.schemas.operational_view import OperationalCaseViewResponse
from backend.app.schemas.dashboard import OperationalDashboardResponse
from backend.app.schemas.pipeline_batch import CaseBatchPipelineRequest, CaseBatchPipelineResponse
from backend.app.schemas.case_finalization import (
    CaseFinalizationRequest,
    CaseFinalizationResponse,
    DocketSealingManifestResponse
)
from backend.app.schemas.admissibility import (
    CaseAdmissibilityRequest,
    CaseAdmissibilityResponse,
    AdmissibilityCertificateResponse
)
from backend.app.schemas.export_bundle import (
    ExportBundleRequest,
    ExportBundleResponse,
    BundleManifestResponse
)
from backend.app.schemas.bundle_verification import BundleVerificationResponse
from backend.app.schemas.exhibit_marking import (
    EvidenceTenderRequest,
    EvidenceTenderResponse,
    ExhibitMarkingRequest,
    ExhibitRecordResponse,
    EvidenceExhibitStatusResponse,
    CaseExhibitRegisterResponse
)
from backend.app.schemas.trial_disposition import (
    TrialVerdictRequest,
    TrialVerdictResponse,
    ObjectionResolutionRequest,
    ObjectionResolutionResponse,
    ExhibitDisposalOrderRequest,
    ExhibitDisposalOrderResponse,
    CaseArchivalRequest,
    CaseArchivalResponse,
    CaseTrialDispositionRegisterResponse
)
from backend.app.services.case_service import CaseService
from backend.app.services.case_intelligence_service import CaseIntelligenceService
from backend.app.services.dashboard_service import DashboardService
from backend.app.services.pipeline_batch_service import PipelineBatchService
from backend.app.services.case_finalization_service import CaseFinalizationService
from backend.app.services.admissibility_service import AdmissibilityService
from backend.app.services.export_bundle_service import ExportBundleService
from backend.app.services.bundle_verification_service import BundleVerificationService
from backend.app.services.exhibit_marking_service import ExhibitMarkingService
from backend.app.services.trial_disposition_service import TrialDispositionService

router = APIRouter(prefix="/cases", tags=["Cases"])

# Case creators: INVESTIGATOR, ADMIN, and legacy SYSTEM_LEAD
auth_case_creator = require_roles("INVESTIGATOR", "ADMIN", "SYSTEM_LEAD")

# Case finalizers: INVESTIGATOR, ADMIN, JUDGE, SYSTEM_LEAD
auth_case_finalizer = require_roles("INVESTIGATOR", "ADMIN", "JUDGE", "SYSTEM_LEAD")

# Case viewers: INVESTIGATOR, ADMIN, LAWYER, JUDGE, and legacy roles
auth_case_viewer = require_roles(
    "INVESTIGATOR", "ADMIN", "LAWYER", "JUDGE", "SYSTEM_LEAD", "FORENSIC_EXPERT", "AUDITOR"
)

# Judicial admissibility verifiers (Phase 18): JUDGE, ADMIN, AUDITOR, SYSTEM_LEAD, LAWYER, INVESTIGATOR
auth_admissibility_verifier = require_roles(
    "JUDGE", "ADMIN", "AUDITOR", "SYSTEM_LEAD", "LAWYER", "INVESTIGATOR"
)

# Judicial exhibit markers (Phase 21): strictly restricted to JUDGE
auth_judge_only = require_roles("JUDGE")

# Evidence tenderers (Phase 21): LAWYER, INVESTIGATOR, JUDGE, ADMIN, SYSTEM_LEAD
auth_tenderer = require_roles("LAWYER", "INVESTIGATOR", "JUDGE", "ADMIN", "SYSTEM_LEAD")


@router.post("", status_code=status.HTTP_201_CREATED, summary="Create a new case docket")
def create_case(
    payload: CaseCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_creator)
):
    """
    Registers a new investigative case docket.
    - Generates unique case_id and case_number.
    - Sets initial status to OPEN.
    - Restricts creation strictly to authorized creators (INVESTIGATOR, ADMIN).
    """
    service = CaseService(db)
    new_case = service.create_case(payload, created_by=current_user.id)
    return {
        "success": True,
        "data": {
            "case_id": new_case.case_id,
            "case_number": new_case.case_number,
            "title": new_case.title,
            "description": new_case.description,
            "status": new_case.status,
            "created_by": new_case.created_by,
            "created_at": new_case.created_at.isoformat(),
            "updated_at": new_case.updated_at.isoformat(),
            "jurisdiction": new_case.jurisdiction,
            "investigator_id": new_case.investigator_id,
            "evidence_count": 0
        }
    }


@router.get("", status_code=status.HTTP_200_OK, summary="List case dockets")
def list_cases(
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_viewer)
):
    """
    Lists all case dockets with optional lifecycle status filter (OPEN, UNDER_ANALYSIS, COMPLETED, ARCHIVED).
    Restricted to authorized actors (INVESTIGATOR, ADMIN, LAWYER, JUDGE).
    """
    service = CaseService(db)
    cases = service.list_cases(status=status)
    items = [
        {
            "case_id": c.case_id,
            "case_number": c.case_number,
            "title": c.title,
            "description": c.description,
            "status": c.status,
            "created_by": c.created_by,
            "created_at": c.created_at.isoformat(),
            "updated_at": c.updated_at.isoformat(),
            "jurisdiction": c.jurisdiction,
            "investigator_id": c.investigator_id,
            "evidence_count": len(c.evidence_items) if hasattr(c, "evidence_items") and c.evidence_items else 0
        }
        for c in cases
    ]
    return {
        "success": True,
        "total": len(items),
        "data": items
    }


@router.get(
    "/operational-dashboard",
    response_model=OperationalDashboardResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve investigator portfolio operational dashboard"
)
def get_operational_dashboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_viewer)
):
    """
    Investigator Portfolio Operational Dashboard (Phase 15):
    Cross-case operational dashboard aggregating portfolio health, evidence metrics,
    pending actions, and urgent cases deterministically without N+1 queries.
    """
    service = DashboardService(db)
    return service.get_portfolio_dashboard(current_user)


@router.get(
    "/portfolio-overview",
    response_model=OperationalDashboardResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve investigator portfolio operational dashboard (alias)"
)
def get_portfolio_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_viewer)
):
    """
    Investigator Portfolio Operational Dashboard Alias (Phase 15).
    """
    service = DashboardService(db)
    return service.get_portfolio_dashboard(current_user)


@router.get("/{case_id}", status_code=status.HTTP_200_OK, summary="Retrieve case details by ID")
def get_case_details(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_viewer)
):
    """
    Retrieves detailed metadata for a specific case docket.
    Raises HTTP 404 (CASE_NOT_FOUND) if case does not exist.
    """
    service = CaseService(db)
    c = service.get_case(case_id)
    evidence_items = []
    if hasattr(c, "evidence_items") and c.evidence_items:
        evidence_items = [
            {
                "evidence_id": e.evidence_id,
                "original_filename": e.original_filename,
                "file_size_bytes": e.file_size_bytes,
                "mime_type": e.mime_type,
                "sha256_hash": e.sha256_hash,
                "status": e.status,
                "created_at": e.created_at.isoformat()
            }
            for e in c.evidence_items
        ]

    return {
        "success": True,
        "data": {
            "case_id": c.case_id,
            "case_number": c.case_number,
            "title": c.title,
            "description": c.description,
            "status": c.status,
            "created_by": c.created_by,
            "created_at": c.created_at.isoformat(),
            "updated_at": c.updated_at.isoformat(),
            "jurisdiction": c.jurisdiction,
            "investigator_id": c.investigator_id,
            "evidence_items": evidence_items
        }
    }


@router.patch("/{case_id}", status_code=status.HTTP_200_OK, summary="Partially update a case docket")
def update_case(
    case_id: str,
    payload: CaseUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_creator)
):
    """
    Updates case title, description, jurisdiction, or status.
    Lifecycle statuses allowed: OPEN, UNDER_ANALYSIS, COMPLETED, ARCHIVED.
    Restricted strictly to case managers (INVESTIGATOR, ADMIN).
    """
    # Archival Governance Check (Phase 22):
    # Direct transition to ARCHIVED is strictly forbidden via generic PATCH on finalized/sealed cases.
    if payload.status in ("ARCHIVED", CaseStatusEnum.ARCHIVED):
        is_sealed = db.query(AuditLog).filter_by(resource_id=case_id, action="CASE_FINALIZED").first() is not None
        has_exhibits = db.query(AuditLog).filter(
            AuditLog.resource_id == case_id,
            AuditLog.action.in_(["EXHIBIT_MARKED", "EXHIBIT_TENDERED"])
        ).first() is not None
        if is_sealed or has_exhibits:
            raise AppException(
                message="Direct transition to ARCHIVED is forbidden for finalized cases. Case docket must be archived through the judicial disposition gateway (POST /api/cases/{case_id}/archive).",
                status_code=400,
                error_code="ARCHIVAL_GOVERNANCE_BYPASS"
            )

    service = CaseService(db)
    updated_case = service.update_case(case_id, payload)
    return {
        "success": True,
        "message": "Case docket updated successfully.",
        "data": {
            "case_id": updated_case.case_id,
            "case_number": updated_case.case_number,
            "title": updated_case.title,
            "description": updated_case.description,
            "status": updated_case.status,
            "created_by": updated_case.created_by,
            "created_at": updated_case.created_at.isoformat(),
            "updated_at": updated_case.updated_at.isoformat(),
            "jurisdiction": updated_case.jurisdiction,
            "investigator_id": updated_case.investigator_id,
            "evidence_count": len(updated_case.evidence_items) if hasattr(updated_case, "evidence_items") and updated_case.evidence_items else 0
        }
    }


@router.get(
    "/{case_id}/intelligence-summary",
    response_model=CaseIntelligenceSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve consolidated case intelligence summary"
)
@router.get(
    "/{case_id}/summary",
    response_model=CaseIntelligenceSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve consolidated case intelligence summary (alias)"
)
def get_case_intelligence_summary(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_viewer)
):
    """
    Consolidated Case & Evidence Intelligence Summary (Phase 13):
    Aggregates existing case metadata, evidence inventory, cryptographic integrity,
    forensic inspection findings, AI screening results, explainability records,
    correlation intelligence, timeline, custody chains, court reports,
    report verification history, and audit trail into a single unified read-only payload.
    """
    service = CaseIntelligenceService(db)
    return service.get_case_intelligence_summary(case_id)


@router.get(
    "/{case_id}/operational-view",
    response_model=OperationalCaseViewResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve investigator operational case view"
)
def get_operational_case_view(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_viewer)
):
    """
    Investigator Operational Case View (Phase 14):
    Provides actionable triage information, critical alerts, pending actions,
    and key investigation metrics on top of the Phase 13 Case Intelligence Summary.
    """
    service = CaseIntelligenceService(db)
    return service.get_operational_case_view(case_id)


@router.get(
    "/{case_id}/overview",
    response_model=OperationalCaseViewResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve investigator operational case view (alias)"
)
def get_operational_case_view_alias(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_viewer)
):
    """
    Investigator Operational Case View Alias (Phase 14).
    """
    service = CaseIntelligenceService(db)
    return service.get_operational_case_view(case_id)


@router.post(
    "/{case_id}/process-pipeline",
    response_model=CaseBatchPipelineResponse,
    status_code=status.HTTP_200_OK,
    summary="Batch execute analysis pipeline across pending evidence in case docket"
)
def process_case_pipeline(
    case_id: str,
    payload: Optional[CaseBatchPipelineRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_creator)
):
    """
    Case Docket Batch Pipeline Orchestrator (Phase 16):
    Sequentially processes pending unanalyzed evidence through the forensic,
    AI screening, legal explainability, and cryptographic custody chain.
    """
    force_reanalysis = payload.force_reanalysis if payload else False
    service = PipelineBatchService(db)
    return service.process_case_pipeline(case_id, current_user, force_reanalysis=force_reanalysis)


@router.post(
    "/{case_id}/run-analysis",
    response_model=CaseBatchPipelineResponse,
    status_code=status.HTTP_200_OK,
    summary="Batch execute analysis pipeline across pending evidence in case docket (alias)"
)
def run_case_analysis_alias(
    case_id: str,
    payload: Optional[CaseBatchPipelineRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_creator)
):
    """
    Case Docket Batch Pipeline Orchestrator Alias (Phase 16).
    """
    force_reanalysis = payload.force_reanalysis if payload else False
    service = PipelineBatchService(db)
    return service.process_case_pipeline(case_id, current_user, force_reanalysis=force_reanalysis)


@router.post(
    "/{case_id}/finalize",
    response_model=CaseFinalizationResponse,
    status_code=status.HTTP_200_OK,
    summary="Formally finalize and cryptographically seal case docket"
)
def finalize_case_endpoint(
    case_id: str,
    payload: Optional[CaseFinalizationRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_finalizer)
):
    """
    Case Docket Finalization & Judicial Sealing (Phase 17):
    Validates that all evidence is analyzed, zero compromises or storage errors exist,
    all custody chains are unbroken, and an official court report exists.
    Computes deterministic SHA-256 docket sealing manifest, appends terminal
    DOCKET_SEALED custody event to each evidence item, transitions case to COMPLETED,
    and logs exactly one CASE_FINALIZED audit event.
    """
    service = CaseFinalizationService(db)
    return service.finalize_case(case_id, current_user, payload=payload)


@router.post(
    "/{case_id}/seal",
    response_model=CaseFinalizationResponse,
    status_code=status.HTTP_200_OK,
    summary="Formally finalize and cryptographically seal case docket (alias)"
)
def seal_case_alias_endpoint(
    case_id: str,
    payload: Optional[CaseFinalizationRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_finalizer)
):
    """
    Case Docket Sealing Alias (Phase 17).
    """
    service = CaseFinalizationService(db)
    return service.finalize_case(case_id, current_user, payload=payload)


@router.get(
    "/{case_id}/sealing-manifest",
    response_model=DocketSealingManifestResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve cryptographic sealing manifest for a case docket"
)
def get_sealing_manifest_endpoint(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_viewer)
):
    """
    Case Docket Sealing Manifest Inspection (Phase 17):
    Returns evidence manifest items with baseline SHA-256 and terminal custody hashes,
    court report references, and root docket sealing hash.
    """
    service = CaseFinalizationService(db)
    return service.get_sealing_manifest(case_id)


# ============================================================================
# Phase 18: Case Docket Judicial Admissibility & Verification Gateway
# ============================================================================

@router.post(
    "/{case_id}/verify-admissibility",
    response_model=CaseAdmissibilityResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify case docket judicial admissibility under BSA 2023 Section 63"
)
def verify_case_admissibility_endpoint(
    case_id: str,
    payload: Optional[CaseAdmissibilityRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_admissibility_verifier)
):
    """
    Case Docket Judicial Admissibility & Cryptographic Verification Gateway (Phase 18):
    Performs comprehensive, strictly read-only technical admissibility verification
    under Section 63 of Bharatiya Sakshya Adhiniyam, 2023:
    1. Validates docket finalization / sealing state.
    2. Streaming SHA-256 verification of physical vault files.
    3. Cryptographically audits custody chains from genesis through DOCKET_SEALED.
    4. Deterministically recomputes and matches Phase 17 docket sealing manifest hash.
    5. Validates court report artifact integrity.
    6. Emits exactly one CASE_ADMISSIBILITY_VERIFIED audit event.
    """
    service = AdmissibilityService(db)
    return service.verify_case_admissibility(case_id, current_user, payload=payload)


@router.post(
    "/{case_id}/judicial-verification",
    response_model=CaseAdmissibilityResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify case docket judicial admissibility under BSA 2023 (alias)"
)
def judicial_verification_alias_endpoint(
    case_id: str,
    payload: Optional[CaseAdmissibilityRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_admissibility_verifier)
):
    """
    Case Docket Judicial Verification Alias (Phase 18).
    """
    service = AdmissibilityService(db)
    return service.verify_case_admissibility(case_id, current_user, payload=payload)


@router.get(
    "/{case_id}/admissibility-certificate",
    response_model=AdmissibilityCertificateResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve official judicial admissibility certificate for a case docket"
)
def get_admissibility_certificate_endpoint(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_admissibility_verifier)
):
    """
    Judicial Admissibility Certificate Query (Phase 18):
    Returns recorded admissibility determination and cryptographic check breakdown.
    """
    service = AdmissibilityService(db)
    return service.get_admissibility_certificate(case_id, current_user)


# ============================================================================
# Phase 19: Case Docket Judicial Discovery & Cryptographic Export Bundle Gateway
# ============================================================================

@router.post(
    "/{case_id}/export-bundle",
    response_model=ExportBundleResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate judicial discovery and cryptographic export bundle"
)
def export_case_bundle_endpoint(
    case_id: str,
    payload: Optional[ExportBundleRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_admissibility_verifier)
):
    """
    Case Docket Judicial Discovery & Cryptographic Export Bundle Gateway (Phase 19):
    Packages finalized and admissibility-verified case docket into a standardized,
    offline-verifiable digital evidence discovery archive (.zip) with deterministic root checksum.
    """
    service = ExportBundleService(db)
    return service.export_case_bundle(case_id, current_user, payload=payload)


@router.post(
    "/{case_id}/create-disclosure-package",
    response_model=ExportBundleResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate judicial discovery and cryptographic export bundle (alias)"
)
def create_disclosure_package_alias_endpoint(
    case_id: str,
    payload: Optional[ExportBundleRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_admissibility_verifier)
):
    """
    Case Docket Judicial Discovery Package Alias (Phase 19).
    """
    service = ExportBundleService(db)
    return service.export_case_bundle(case_id, current_user, payload=payload)


@router.get(
    "/{case_id}/export-bundle/manifest",
    response_model=BundleManifestResponse,
    status_code=status.HTTP_200_OK,
    summary="Inspect judicial discovery bundle manifest and root checksum"
)
def get_bundle_manifest_endpoint(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_admissibility_verifier)
):
    """
    Discovery Bundle Manifest Inspection (Phase 19):
    Inspects bundle metadata, individual constituent hashes, and root SHA-256 without downloading.
    """
    service = ExportBundleService(db)
    return service.get_bundle_manifest(case_id, current_user)


@router.get(
    "/{case_id}/download-bundle",
    summary="Download complete judicial discovery and disclosure bundle (.zip)"
)
def download_bundle_endpoint(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_admissibility_verifier)
):
    """
    Binary Bundle Streaming Download (Phase 19):
    Streams the verified digital evidence discovery archive (.zip) with proper attachment headers.
    """
    service = ExportBundleService(db)
    bundle_path, bundle_filename = service.get_bundle_file_for_download(case_id, current_user)
    return FileResponse(
        path=bundle_path,
        media_type="application/zip",
        filename=bundle_filename,
        headers={"Content-Disposition": f'attachment; filename="{bundle_filename}"'}
    )


@router.post(
    "/{case_id}/verify-bundle",
    response_model=BundleVerificationResponse,
    status_code=status.HTTP_200_OK,
    summary="Cryptographically verify judicial discovery bundle archive (.zip)"
)
def verify_bundle_endpoint(
    case_id: str,
    file: UploadFile = File(..., description="Uploaded judicial discovery bundle (.zip)"),
    notes: Optional[str] = Form(None, description="Auditor verification notes"),
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_admissibility_verifier)
):
    """
    Judicial Discovery Bundle Cryptographic Verification & Tamper Audit Gateway (Phase 20):
    Safely inspects and cryptographically audits an uploaded discovery .zip archive under BSA 2023 Section 63.
    """
    service = BundleVerificationService(db)
    return service.verify_uploaded_bundle(case_id, file, current_user, notes=notes)


@router.post(
    "/{case_id}/verify-disclosure-package",
    response_model=BundleVerificationResponse,
    status_code=status.HTTP_200_OK,
    summary="Cryptographically verify judicial discovery bundle archive (alias)"
)
def verify_disclosure_package_alias_endpoint(
    case_id: str,
    file: UploadFile = File(..., description="Uploaded judicial discovery bundle (.zip)"),
    notes: Optional[str] = Form(None, description="Auditor verification notes"),
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_admissibility_verifier)
):
    """
    Judicial Discovery Package Verification Alias (Phase 20).
    """
    service = BundleVerificationService(db)
    return service.verify_uploaded_bundle(case_id, file, current_user, notes=notes)


# ============================================================================
# Phase 21: Judicial Courtroom Exhibit Marking, Tender & Admissibility Gateway
# ============================================================================

@router.post(
    "/{case_id}/exhibits/tender",
    response_model=EvidenceTenderResponse,
    status_code=status.HTTP_200_OK,
    summary="Tender digital evidence artifact or Section 63 report in courtroom proceedings"
)
def tender_evidence_endpoint(
    case_id: str,
    payload: EvidenceTenderRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_tenderer)
):
    """
    Courtroom Evidence Tendering Gateway (Phase 21):
    Allows authorized counsel (LAWYER) or investigating officers (INVESTIGATOR)
    to formally tender digital evidence or official Section 63 reports into the court record.
    Tendering records courtroom presentation without assigning final exhibit number or ruling.
    """
    service = ExhibitMarkingService(db)
    return service.tender_evidence(case_id, current_user, payload)


@router.post(
    "/{case_id}/tender-evidence",
    response_model=EvidenceTenderResponse,
    status_code=status.HTTP_200_OK,
    summary="Tender digital evidence artifact or Section 63 report in courtroom proceedings (alias)"
)
def tender_evidence_alias_endpoint(
    case_id: str,
    payload: EvidenceTenderRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_tenderer)
):
    """Courtroom Evidence Tendering Gateway Alias (Phase 21)."""
    service = ExhibitMarkingService(db)
    return service.tender_evidence(case_id, current_user, payload)


@router.post(
    "/{case_id}/exhibits/mark",
    response_model=ExhibitRecordResponse,
    status_code=status.HTTP_200_OK,
    summary="Officially mark courtroom exhibit and record judicial admissibility ruling"
)
def mark_exhibit_endpoint(
    case_id: str,
    payload: ExhibitMarkingRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_judge_only)
):
    """
    Judicial Exhibit Marking & Admissibility Ruling Gateway (Phase 21):
    Enforces statutory judicial authority under BSA 2023 Section 63:
    1. Strictly restricted to JUDGE (administrators and advocates cannot make judicial rulings).
    2. Validates case is sealed (COMPLETED) with verified Section 63 admissibility.
    3. Assigns official judicial exhibit identifier (e.g. 'Ex. P-1', 'Ex. D-1', 'MO-1').
    4. Evaluates and records statutory ruling:
       - ADMITTED_AS_EXHIBIT
       - MARKED_FOR_IDENTIFICATION
       - OBJECTED_DECISION_RESERVED
       - REJECTED
    5. Appends terminal JUDICIAL_EXHIBIT_MARKED custody block to evidence items.
    6. Emits single EXHIBIT_MARKED audit event.
    7. Strictly enforces case-scoped exhibit identifier uniqueness and double-admission protection.
    """
    service = ExhibitMarkingService(db)
    return service.mark_exhibit(case_id, current_user, payload)


@router.post(
    "/{case_id}/mark-exhibit",
    response_model=ExhibitRecordResponse,
    status_code=status.HTTP_200_OK,
    summary="Officially mark courtroom exhibit and record judicial admissibility ruling (alias)"
)
def mark_exhibit_alias_endpoint(
    case_id: str,
    payload: ExhibitMarkingRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_judge_only)
):
    """Judicial Exhibit Marking & Ruling Gateway Alias (Phase 21)."""
    service = ExhibitMarkingService(db)
    return service.mark_exhibit(case_id, current_user, payload)


@router.get(
    "/{case_id}/exhibits",
    response_model=CaseExhibitRegisterResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve consolidated Judicial Exhibit Register for a case docket"
)
def get_case_exhibit_register_endpoint(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_viewer)
):
    """
    Judicial Exhibit Register Query (Phase 21):
    Returns chronologically ordered exhibit history, tendering records, and ruling breakdown.
    Strictly read-only; never exposes internal filesystem storage paths.
    """
    service = ExhibitMarkingService(db)
    return service.get_case_exhibit_register(case_id, current_user)


@router.get(
    "/{case_id}/exhibit-register",
    response_model=CaseExhibitRegisterResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve consolidated Judicial Exhibit Register for a case docket (alias)"
)
def get_case_exhibit_register_alias_endpoint(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_viewer)
):
    """Judicial Exhibit Register Query Alias (Phase 21)."""
    service = ExhibitMarkingService(db)
    return service.get_case_exhibit_register(case_id, current_user)


@router.get(
    "/{case_id}/exhibits/{exhibit_number}",
    response_model=ExhibitRecordResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve specific judicial exhibit record by court exhibit number"
)
def get_exhibit_by_number_endpoint(
    case_id: str,
    exhibit_number: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_viewer)
):
    """
    Exhibit Record Lookup (Phase 21):
    Retrieves full judicial exhibit record by assigned exhibit number (e.g. 'Ex. P-1').
    """
    service = ExhibitMarkingService(db)
    return service.get_exhibit_by_number(case_id, exhibit_number, current_user)


@router.get(
    "/{case_id}/evidence/{evidence_id}/exhibit",
    response_model=EvidenceExhibitStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Inspect courtroom exhibit marking and tender status for an evidence artifact"
)
def get_evidence_exhibit_endpoint(
    case_id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_viewer)
):
    """
    Evidence Exhibit Status Inspection (Phase 21):
    Inspects whether an evidence artifact is tendered or marked as an exhibit,
    including ruling, presiding judicial officer, court bench, and timestamps.
    """
    service = ExhibitMarkingService(db)
    return service.get_evidence_exhibit(case_id, evidence_id, current_user)


# ==============================================================================
# PHASE 22: JUDICIAL TRIAL DISPOSITION, OBJECTION RESOLUTION & EXHIBIT DISPOSAL
# ==============================================================================

@router.post(
    "/{case_id}/disposition/verdict",
    response_model=TrialVerdictResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Pronounce judicial trial verdict and record judgment disposition"
)
@router.post(
    "/{case_id}/verdict",
    response_model=TrialVerdictResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Pronounce judicial trial verdict (alias)"
)
def pronounce_verdict_endpoint(
    case_id: str,
    payload: TrialVerdictRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_judge_only)
):
    """
    Trial Verdict Pronouncement (Phase 22):
    Officially records trial verdict (CONVICTED, ACQUITTED, DISCHARGED, DISMISSED, PARTIALLY_CONVICTED)
    and calculates statutory appellate limitation holds. Strictly JUDGE only.
    """
    service = TrialDispositionService(db)
    return service.record_trial_verdict(case_id, current_user, payload)


@router.post(
    "/{case_id}/exhibits/{exhibit_number}/resolve-objection",
    response_model=ObjectionResolutionResponse,
    status_code=status.HTTP_200_OK,
    summary="Resolve reserved Section 63 objection or MFI exhibit marking"
)
@router.post(
    "/{case_id}/resolve-objection/{exhibit_number}",
    response_model=ObjectionResolutionResponse,
    status_code=status.HTTP_200_OK,
    summary="Resolve reserved Section 63 objection or MFI exhibit marking (alias)"
)
def resolve_objection_endpoint(
    case_id: str,
    exhibit_number: str,
    payload: ObjectionResolutionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_judge_only)
):
    """
    Objection Resolution Gateway (Phase 22):
    Resolves reserved Section 63 objections (OBJECTED_DECISION_RESERVED) or
    converts identification exhibits (MARKED_FOR_IDENTIFICATION) to ADMITTED_AS_EXHIBIT or REJECTED.
    Strictly JUDGE only.
    """
    service = TrialDispositionService(db)
    return service.resolve_objection(case_id, exhibit_number, current_user, payload)


@router.post(
    "/{case_id}/exhibits/{exhibit_number}/disposal-order",
    response_model=ExhibitDisposalOrderResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Issue statutory exhibit disposal order under BNSS 2023 Section 503"
)
@router.post(
    "/{case_id}/exhibits/{exhibit_number}/disposal",
    response_model=ExhibitDisposalOrderResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Issue statutory exhibit disposal order under BNSS 2023 Section 503 (alias)"
)
def order_exhibit_disposal_endpoint(
    case_id: str,
    exhibit_number: str,
    payload: ExhibitDisposalOrderRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_judge_only)
):
    """
    Exhibit Disposal Order Gateway (Phase 22):
    Issues statutory disposal directions under BNSS 2023 Section 503
    (RETURNED_TO_OWNER, CONFISCATED, DESTROYED, RETAINED_FOR_APPEAL).
    CRITICAL: DESTROYED orders strictly record judicial disposal; physical WORM files are NEVER deleted.
    Strictly JUDGE only.
    """
    service = TrialDispositionService(db)
    return service.order_exhibit_disposal(case_id, exhibit_number, current_user, payload)


@router.post(
    "/{case_id}/archive",
    response_model=CaseArchivalResponse,
    status_code=status.HTTP_200_OK,
    summary="Formally archive case docket upon trial judgment and complete exhibit disposal"
)
def archive_case_endpoint(
    case_id: str,
    payload: CaseArchivalRequest = Body(default_factory=CaseArchivalRequest),
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_judge_only)
):
    """
    Governed Docket Archival Gateway (Phase 22):
    Transitions case.status from COMPLETED to ARCHIVED only when:
    1. Case is COMPLETED.
    2. Trial verdict has been pronounced.
    3. All exhibits have definitive rulings (no unresolved objections or MFI).
    4. All exhibits have statutory disposal orders.
    Strictly JUDGE only.
    """
    service = TrialDispositionService(db)
    return service.archive_case(case_id, current_user, payload)


@router.get(
    "/{case_id}/disposition",
    response_model=CaseTrialDispositionRegisterResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve consolidated Trial Disposition and Exhibit Disposal Register"
)
def get_trial_disposition_endpoint(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_viewer)
):
    """
    Trial Disposition Register Query (Phase 22):
    Retrieves complete verdict, objection resolutions, disposal orders, and archival readiness.
    Read-only case-scoped access.
    """
    service = TrialDispositionService(db)
    return service.get_trial_disposition(case_id, current_user)


@router.get(
    "/{case_id}/exhibits/{exhibit_number}/disposal",
    response_model=ExhibitDisposalOrderResponse,
    status_code=status.HTTP_200_OK,
    summary="Inspect statutory disposal order and appellate hold status for an exhibit"
)
def get_exhibit_disposal_endpoint(
    case_id: str,
    exhibit_number: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_case_viewer)
):
    """
    Exhibit Disposal Status Inspection (Phase 22):
    Retrieves statutory disposal order and retention hold for a specific exhibit.
    Read-only case-scoped access.
    """
    service = TrialDispositionService(db)
    return service.get_exhibit_disposal(case_id, exhibit_number, current_user)









