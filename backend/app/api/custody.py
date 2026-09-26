"""
NYAYAI - Chain of Custody API Router (Phase 8)
Module: backend.app.api.custody
Integration Lead: Dhananjay Sharma (Backend & System Integration Lead)
Module Lead: Ridhi Mashi (Evidence Intelligence & Chain-of-Custody Engineer)

Endpoints:
- GET  /api/custody/evidence/{evidence_id}        : Retrieve chronological custody history (Authorized roles only)
- POST /api/custody/evidence/{evidence_id}/events : Append an authorized custody event (transfer, view, download)
- GET  /api/custody/{evidence_id}                : Legacy alias
- GET  /api/evidence/{evidence_id}/custody       : Legacy alias
- POST /api/custody/{evidence_id}/verify         : Cryptographic chain verification
"""

from typing import Optional
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.user import User
from backend.app.core.security import require_roles, get_current_user_optional
from backend.app.schemas.custody import (
    CustodyHistoryResponse,
    CustodyVerifyResponse,
    CustodyEventCreateRequest
)
from backend.app.services.custody_service import CustodyService

router = APIRouter(tags=["Chain of Custody"])

# Strict authorization for viewing and appending custody records (Security requirement)
# Authorized viewers: INVESTIGATOR, ADMIN, JUDGE, AUDITOR, SYSTEM_LEAD, FORENSIC_EXPERT
auth_custody_viewer = require_roles(
    "INVESTIGATOR", "ADMIN", "JUDGE", "AUDITOR", "SYSTEM_LEAD", "FORENSIC_EXPERT"
)

# Authorized custody officers for appending transfer/custody events
auth_custody_officer = require_roles(
    "INVESTIGATOR", "ADMIN", "SYSTEM_LEAD", "FORENSIC_EXPERT"
)


@router.get(
    "/custody/evidence/{evidence_id}",
    response_model=CustodyHistoryResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve chronological custody history"
)
def get_custody_history(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_custody_viewer)
):
    """
    Retrieve chronological custody history for an evidence artifact (Phase 8).
    - Requires authenticated authorized role (INVESTIGATOR, ADMIN, JUDGE, AUDITOR, SYSTEM_LEAD, FORENSIC_EXPERT).
    - Cryptographically validates the SHA-256 hash chain: Current Event -> previous event hash -> current event hash.
    - Sanitizes sensitive internal server storage paths.
    - Returns events ordered chronologically by monotonic sequence.
    """
    service = CustodyService(db)
    return service.get_chronological_history(evidence_id)


@router.post(
    "/custody/evidence/{evidence_id}/events",
    status_code=status.HTTP_201_CREATED,
    summary="Append a verifiable custody event block"
)
def append_custody_event(
    evidence_id: str,
    payload: CustodyEventCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_custody_officer)
):
    """
    Append an authorized custody event block (e.g. EVIDENCE_TRANSFERRED, EVIDENCE_VIEWED, EVIDENCE_DOWNLOADED).
    Seals a new cryptographic block linked to the prior block's hash.
    """
    service = CustodyService(db)
    new_event = service.record_event(
        evidence_id=evidence_id,
        event_type=payload.event_type,
        user_id=current_user.id,
        description=payload.description,
        details=payload.details
    )
    return {
        "success": True,
        "message": f"Custody event '{payload.event_type}' recorded successfully.",
        "event": new_event
    }


@router.get(
    "/custody/{evidence_id}",
    response_model=CustodyHistoryResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve custody history (alias)"
)
@router.get(
    "/evidence/{evidence_id}/custody",
    status_code=status.HTTP_200_OK,
    summary="Retrieve custody history (legacy endpoint)"
)
def get_custody_ledger_legacy(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Legacy alias endpoint for backward compatibility."""
    service = CustodyService(db)
    return service.get_chronological_history(evidence_id)


@router.post(
    "/custody/{evidence_id}/verify",
    response_model=CustodyVerifyResponse,
    status_code=status.HTTP_200_OK,
    summary="Cryptographic custody chain verification"
)
@router.post(
    "/evidence/{evidence_id}/custody/verify",
    status_code=status.HTTP_200_OK,
    summary="Cryptographic custody chain verification (legacy)"
)
def verify_custody_chain(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Perform mathematical SHA-256 verification across all blocks in the custody chain."""
    service = CustodyService(db)
    return service.verify_ledger(evidence_id)

