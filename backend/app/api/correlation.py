"""
NYAYAI - Evidence Correlation API Router (Phase 9)
Module: backend.app.api.correlation
Integration Lead: Dhananjay Sharma (Backend & System Integration Lead)
Module Lead: Ridhi Mashi (Evidence Intelligence & Chain-of-Custody Engineer)

Endpoints:
- GET  /api/correlation/case/{case_id} : Retrieve timeline, relationships, cross_evidence_matches, red_flags
- POST /api/correlation/analyze       : Trigger correlation analysis for a case docket
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.user import User
from backend.app.core.security import require_roles
from backend.app.schemas.correlation import (
    CorrelationRequest,
    CaseCorrelationResponse
)
from backend.app.services.correlation_service import CorrelationService

router = APIRouter(prefix="/correlation", tags=["Evidence Correlation"])

# Authorized viewers: Legal, investigative, judicial, and forensic personnel
auth_correlation_viewer = require_roles(
    "INVESTIGATOR", "ADMIN", "JUDGE", "LAWYER", "SYSTEM_LEAD", "FORENSIC_EXPERT", "AUDITOR"
)


@router.get(
    "/case/{case_id}",
    response_model=CaseCorrelationResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve multi-evidence timeline, relationships, cross-evidence matches, and red flags"
)
def get_case_correlation(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_correlation_viewer)
):
    """
    Retrieve comprehensive Evidence Intelligence for a case docket (Phase 9):
    - timeline: Chronological ordering of documented evidence intake and custody events
    - relationships: Directed relationships between evidence items (Evidence A -> related_to -> Evidence B with reason)
    - cross_evidence_matches: Identical hashes, shared sources, matching formats
    - red_flags: Evidence-based inconsistencies and anomalies without criminality claims
    """
    service = CorrelationService(db)
    return service.correlate_case(case_id)


@router.post(
    "/analyze",
    response_model=CaseCorrelationResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger multi-evidence timeline assembly and correlation analysis"
)
def trigger_correlation(
    payload: CorrelationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_correlation_viewer)
):
    """Trigger multi-evidence timeline assembly and correlation analysis."""
    service = CorrelationService(db)
    return service.correlate_case(payload.case_id)
