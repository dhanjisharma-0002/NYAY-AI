"""
NYAYAI - Public QR Verification API Router
Module: backend.app.api.verification
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.schemas.verification import VerificationResponse
from backend.app.services.report_service import ReportService

router = APIRouter(tags=["Public Verification"])


@router.get("/verification/{report_id}", response_model=VerificationResponse)
@router.get("/reports/verify/{report_id}", response_model=VerificationResponse)
def verify_report_authenticity(report_id: str, db: Session = Depends(get_db)):
    """
    Public QR Verification Endpoint:
    Allows judiciary, officers, and lawyers to scan printed QR code to verify
    SHA-256 seal against the immutable repository.
    """
    service = ReportService(db)
    result = service.verify_report(report_id)
    return VerificationResponse(**result)
