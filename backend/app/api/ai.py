"""
NYAYAI - AI Analysis API Router (Phase 7)
Module: backend.app.api.ai
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.user import User
from backend.app.schemas.ai import AITamperRequest, AIAnalysisResponse
from backend.app.services.ai_service import AIService
from backend.app.core.security import require_roles

router = APIRouter(prefix="/ai", tags=["AI Engine"])

auth_analyzer = require_roles("INVESTIGATOR", "ADMIN", "FORENSIC_EXPERT", "SYSTEM_LEAD")


@router.post(
    "/analyze/{evidence_id}",
    status_code=status.HTTP_200_OK,
    response_model=AIAnalysisResponse,
    summary="Orchestrate full AI inference pipeline"
)
def analyze_evidence_ai(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_analyzer)
):
    """
    AI Orchestration API (Phase 7):
    1. Authenticates authorized investigator or admin.
    2. Verifies evidence docket access.
    3. Verifies evidence file integrity against vaulted SHA-256 hash.
    4. Dispatches evidence reference to pluggable AI engine adapter.
    5. Receives structured non-fabricated inference metrics:
       - evidence_id
       - analysis_type
       - prediction
       - confidence
       - risk_score
       - findings
       - explanation
       - model_version
    6. Persists AnalysisResult with lifecycle status (COMPLETED / FAILED).
    7. Appends verifiable block to Chain of Custody ledger.
    8. Records compliance audit trail event.
    9. Returns structured AI analysis result.
    """
    service = AIService(db)
    result = service.orchestrate_analysis(
        evidence_id=evidence_id,
        user_id=current_user.id,
        username=current_user.username
    )
    return result


@router.post("/tamper-check", status_code=status.HTTP_200_OK, summary="Legacy AI tamper check")
def screen_tampering(payload: AITamperRequest, db: Session = Depends(get_db)):
    """Execute AI screening for media manipulation & synthetic tampering."""
    service = AIService(db)
    result = service.screen_evidence_tampering(payload.evidence_id)
    return {"success": True, "data": result}


@router.get("/{evidence_id}", summary="Get stored AI results")
def get_ai_results(evidence_id: str, db: Session = Depends(get_db)):
    """Retrieve AI inference results for specific evidence item."""
    service = AIService(db)
    result = service.screen_evidence_tampering(evidence_id)
    return {"success": True, "data": result}
