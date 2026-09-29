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
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.user import User
from backend.app.core.security import require_roles
from backend.app.schemas.cases import CaseCreateRequest, CaseUpdateRequest
from backend.app.schemas.case_intelligence import CaseIntelligenceSummaryResponse
from backend.app.services.case_service import CaseService
from backend.app.services.case_intelligence_service import CaseIntelligenceService

router = APIRouter(prefix="/cases", tags=["Cases"])

# Case creators: INVESTIGATOR, ADMIN, and legacy SYSTEM_LEAD
auth_case_creator = require_roles("INVESTIGATOR", "ADMIN", "SYSTEM_LEAD")

# Case viewers: INVESTIGATOR, ADMIN, LAWYER, JUDGE, and legacy roles
auth_case_viewer = require_roles(
    "INVESTIGATOR", "ADMIN", "LAWYER", "JUDGE", "SYSTEM_LEAD", "FORENSIC_EXPERT", "AUDITOR"
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

