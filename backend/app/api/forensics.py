"""
NYAYAI - Forensics API Router (Phase 7)
Module: backend.app.api.forensics
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.user import User
from backend.app.schemas.forensics import ForensicInspectRequest, ForensicAnalysisResponse
from backend.app.services.forensic_service import ForensicService
from backend.app.core.security import require_roles

router = APIRouter(prefix="/forensics", tags=["Forensic Engine"])

auth_analyzer = require_roles("INVESTIGATOR", "ADMIN", "FORENSIC_EXPERT", "SYSTEM_LEAD")


@router.post(
    "/analyze/{evidence_id}",
    status_code=status.HTTP_200_OK,
    response_model=ForensicAnalysisResponse,
    summary="Orchestrate full forensic inspection pipeline"
)
def analyze_evidence_forensics(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_analyzer)
):
    """
    Forensic Orchestration API (Phase 7):
    1. Authenticates authorized investigator or admin.
    2. Verifies evidence docket access.
    3. Verifies evidence file integrity against vaulted SHA-256 hash.
    4. Dispatches evidence reference to pluggable forensic engine adapter.
    5. Receives structured non-destructive inspection output.
    6. Persists AnalysisResult.
    7. Appends verifiable block to Chain of Custody ledger.
    8. Records compliance audit trail event.
    9. Returns structured forensic report.
    """
    service = ForensicService(db)
    result = service.orchestrate_analysis(
        evidence_id=evidence_id,
        user_id=current_user.id,
        username=current_user.username
    )
    return result


@router.post("/inspect", status_code=status.HTTP_200_OK, summary="Legacy forensic inspect")
def inspect_evidence(payload: ForensicInspectRequest, db: Session = Depends(get_db)):
    """Run non-destructive byte & metadata inspection on vaulted evidence."""
    service = ForensicService(db)
    result = service.inspect_evidence(payload.evidence_id)
    return {"success": True, "data": result}


@router.get("/{evidence_id}", summary="Get stored forensic results")
def get_forensic_results(evidence_id: str, db: Session = Depends(get_db)):
    """Fetch stored forensic analysis results for evidence item."""
    service = ForensicService(db)
    result = service.inspect_evidence(evidence_id)
    return {"success": True, "data": result}
