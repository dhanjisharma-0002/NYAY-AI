"""
NYAYAI - Evidence API Router (Phase 5)
Module: backend.app.api.evidence
Endpoints:
- POST /api/evidence/upload           : Secure evidence intake for authorized investigators
- POST /cases/{case_id}/evidence      : Backward-compatible case evidence upload
- GET  /evidence/{evidence_id}        : Retrieve evidence artifact details
- GET  /evidence                      : List vaulted evidence artifacts
"""

from typing import Optional
from fastapi import APIRouter, Depends, UploadFile, File, Form, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.user import User
from backend.app.models.evidence import Evidence
from backend.app.schemas.evidence import EvidenceIntegrityResponse
from backend.app.core.security import require_roles, get_current_user, get_current_user_optional
from backend.app.services.evidence_service import EvidenceService
from backend.app.services.integrity_service import EvidenceIntegrityService

router = APIRouter(tags=["Evidence"])

# Authorized evidence uploaders: INVESTIGATOR, ADMIN, and legacy SYSTEM_LEAD
auth_uploader = require_roles("INVESTIGATOR", "ADMIN", "SYSTEM_LEAD")

# Authorized evidence viewers: INVESTIGATOR, ADMIN, LAWYER, JUDGE, etc.
auth_viewer = require_roles(
    "INVESTIGATOR", "ADMIN", "LAWYER", "JUDGE", "SYSTEM_LEAD", "FORENSIC_EXPERT", "AUDITOR"
)


@router.post("/evidence/upload", status_code=status.HTTP_201_CREATED, summary="Secure evidence file intake")
async def upload_evidence(
    case_id: str = Form(..., description="Target case docket ID"),
    file: UploadFile = File(..., description="Evidence file (Image, Video, Audio, Document)"),
    source_description: Optional[str] = Form(None, description="Seizure location or device origin"),
    client_sha256: Optional[str] = Form(None, description="Pre-computed client SHA-256 for transmission verification"),
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_uploader)
):
    """
    Secure Evidence Intake Pipeline:
    1. Authenticates investigator or admin.
    2. Verifies case exists and is accessible.
    3. Validates file format and blocks arbitrary executables.
    4. Determines canonical media type (Image, Video, Audio, Document).
    5. Generates unique evidence_id.
    6. Computes cryptographic SHA-256 hash.
    7. Stores original file in WORM vault with unique path.
    8. Stores low-level forensic metadata.
    9. Creates genesis chain-of-custody block.
    10. Records compliance audit log.
    11. Returns evidence information.
    """
    service = EvidenceService(db)
    evidence = service.intake_evidence(
        case_id=case_id,
        upload_file=file,
        source_description=source_description,
        client_sha256=client_sha256,
        user_id=current_user.id
    )

    created_iso = evidence.created_at.isoformat()
    return {
        "evidence_id": evidence.evidence_id,
        "case_id": evidence.case_id,
        "filename": evidence.original_filename,
        "media_type": evidence.media_type,
        "file_size": evidence.file_size,
        "sha256_hash": evidence.sha256_hash,
        "status": evidence.status,
        "created_at": created_iso,
        "success": True,
        "data": {
            "evidence_id": evidence.evidence_id,
            "case_id": evidence.case_id,
            "filename": evidence.original_filename,
            "original_filename": evidence.original_filename,
            "media_type": evidence.media_type,
            "mime_type": evidence.mime_type,
            "file_size": evidence.file_size,
            "file_size_bytes": evidence.file_size_bytes,
            "sha256_hash": evidence.sha256_hash,
            "vault_status": "SECURED_READONLY",
            "genesis_event_hash": evidence.custody_events[0].event_hash if evidence.custody_events else "",
            "status": evidence.status,
            "created_at": created_iso
        }
    }


@router.post("/cases/{case_id}/evidence", status_code=status.HTTP_201_CREATED, summary="Legacy case evidence intake")
async def intake_case_evidence(
    case_id: str,
    file: UploadFile = File(...),
    source_description: Optional[str] = Form(None),
    client_sha256: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Backward-compatible case evidence intake endpoint."""
    user_id = current_user.id if current_user else "USR-SYSTEM-LEAD"
    service = EvidenceService(db)
    evidence = service.intake_evidence(
        case_id=case_id,
        upload_file=file,
        source_description=source_description,
        client_sha256=client_sha256,
        user_id=user_id
    )
    return {
        "evidence_id": evidence.evidence_id,
        "case_id": evidence.case_id,
        "filename": evidence.original_filename,
        "media_type": evidence.media_type,
        "file_size": evidence.file_size,
        "sha256_hash": evidence.sha256_hash,
        "status": evidence.status,
        "created_at": evidence.created_at.isoformat(),
        "success": True,
        "data": {
            "evidence_id": evidence.evidence_id,
            "case_id": evidence.case_id,
            "original_filename": evidence.original_filename,
            "file_size_bytes": evidence.file_size_bytes,
            "mime_type": evidence.mime_type,
            "sha256_hash": evidence.sha256_hash,
            "vault_status": "SECURED_READONLY",
            "genesis_event_hash": evidence.custody_events[0].event_hash if evidence.custody_events else "",
            "created_at": evidence.created_at.isoformat()
        }
    }


@router.get("/evidence/{evidence_id}", status_code=status.HTTP_200_OK, summary="Retrieve evidence artifact details")
def get_evidence(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Retrieve evidence artifact details by ID."""
    service = EvidenceService(db)
    evidence = service.get_evidence(evidence_id)
    return {
        "success": True,
        "data": {
            "evidence_id": evidence.evidence_id,
            "case_id": evidence.case_id,
            "filename": evidence.original_filename,
            "original_filename": evidence.original_filename,
            "file_size": evidence.file_size,
            "file_size_bytes": evidence.file_size_bytes,
            "media_type": evidence.media_type,
            "mime_type": evidence.mime_type,
            "sha256_hash": evidence.sha256_hash,
            "status": evidence.status,
            "source_description": evidence.source_description,
            "created_at": evidence.created_at.isoformat()
        }
    }


@router.get("/evidence", status_code=status.HTTP_200_OK, summary="List evidence artifacts")
def list_evidence(
    case_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """List evidence items, optionally filtered by case_id."""
    service = EvidenceService(db)
    if case_id:
        items = service.list_case_evidence(case_id)
    else:
        items = db.query(Evidence).all()

    data = [
        {
            "evidence_id": e.evidence_id,
            "case_id": e.case_id,
            "filename": e.original_filename,
            "original_filename": e.original_filename,
            "file_size": e.file_size,
            "file_size_bytes": e.file_size_bytes,
            "media_type": e.media_type,
            "mime_type": e.mime_type,
            "sha256_hash": e.sha256_hash,
            "status": e.status,
            "created_at": e.created_at.isoformat()
        }
        for e in items
    ]
    return {"success": True, "total": len(data), "data": data}


@router.post(
    "/evidence/{evidence_id}/verify-integrity",
    status_code=status.HTTP_200_OK,
    response_model=EvidenceIntegrityResponse,
    summary="Cryptographic evidence integrity verification"
)
def verify_evidence_integrity(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """
    Cryptographic Evidence Integrity Verification (Phase 6):
    1. Retrieves original stored file from storage abstraction.
    2. Calculates current SHA-256 hash using reusable HashingService.
    3. Compares with registered SHA-256 hash.
    4. Appends a verifiable tamper-evident block to the Chain of Custody.
    5. Creates a compliance audit log entry.
    6. Returns verification report:
       - evidence_id
       - stored_hash
       - current_hash
       - integrity_status: 'VERIFIED' | 'MISMATCH' | 'ERROR'
       - verified_at
    """
    actor_id = current_user.id if current_user else "SYSTEM_VERIFICATION_DAEMON"
    actor_username = current_user.username if current_user else "system_verifier"

    service = EvidenceIntegrityService(db)
    result = service.verify_evidence_integrity(
        evidence_id=evidence_id,
        actor_user_id=actor_id,
        actor_username=actor_username
    )
    return result

