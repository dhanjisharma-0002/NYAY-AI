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
from fastapi import APIRouter, Depends, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.user import User
from backend.app.core.security import require_roles
from backend.app.schemas.cases import CaseCreateRequest, CaseUpdateRequest
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
from backend.app.services.case_service import CaseService
from backend.app.services.case_intelligence_service import CaseIntelligenceService
from backend.app.services.dashboard_service import DashboardService
from backend.app.services.pipeline_batch_service import PipelineBatchService
from backend.app.services.case_finalization_service import CaseFinalizationService
from backend.app.services.admissibility_service import AdmissibilityService
from backend.app.services.export_bundle_service import ExportBundleService

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







