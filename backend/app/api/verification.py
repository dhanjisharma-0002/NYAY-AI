"""
NYAYAI - Public QR Verification & Verification Audit API Router (Phase 11)
Module: backend.app.api.verification
Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

from typing import List
from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.schemas.verification import VerificationResponse, VerificationRecordOut
from backend.app.services.verification_service import VerificationService

router = APIRouter(tags=["Public Verification"])


@router.get(
    "/verification/{verification_code_or_id}",
    response_model=VerificationResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify court report authenticity via report_id, verification_code, or SHA-256"
)
@router.get(
    "/reports/verify/{verification_code_or_id}",
    response_model=VerificationResponse,
    status_code=status.HTTP_200_OK,
    summary="Public QR scan verification gateway"
)
def verify_report_authenticity(
    verification_code_or_id: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Public QR Verification Endpoint (Phase 11):
    Allows judiciary, investigators, lawyers, and public scanning of printed QR codes
    to cryptographically verify BSA 2023 report authenticity.

    Safe Public Behavior:
    - Never leaks internal filesystem paths, server secrets, or database credentials.
    - Resolves via report_id, unique verification_code, or report SHA-256.
    - Automatically records an immutable VerificationRecord.
    - Appends a standardized AuditLog entry.
    """
    client_ip = request.client.host if request.client else None
    if "x-forwarded-for" in request.headers:
        client_ip = request.headers["x-forwarded-for"].split(",")[0].strip()
    user_agent = request.headers.get("user-agent")

    service = VerificationService(db)
    result = service.verify_report(
        code_or_id=verification_code_or_id,
        ip_address=client_ip,
        user_agent=user_agent,
        verification_method="QR_CODE"
    )
    return VerificationResponse(**result)


@router.get(
    "/reports/{report_id}/verifications",
    response_model=List[VerificationRecordOut],
    status_code=status.HTTP_200_OK,
    summary="Retrieve verification audit history for an issued report"
)
def get_report_verifications_history(
    report_id: str,
    db: Session = Depends(get_db)
):
    """
    Verification Audit History:
    Retrieves chronological verification attempts for an evidentiary report docket.
    """
    service = VerificationService(db)
    records = service.get_verification_history(report_id)
    return [
        VerificationRecordOut(
            verification_id=r.verification_id,
            report_id=r.report_id,
            verification_method=r.verification_method,
            verifier_identifier=r.verifier_identifier,
            status=r.status,
            ip_address=r.ip_address,
            timestamp=r.timestamp.isoformat() if r.timestamp else ""
        )
        for r in records
    ]
