"""
NYAYAI - Evidence Intake & Vault API Router
Module Lead: Dhananjay Sharma (Backend & System Integration Lead)

Enforces:
- Rule 2: Never overwrite original evidence files (vaulted & read-only)
- Rule 5: Unique evidence_id
- Rule 7: SHA-256 integrity calculation
- Rule 8: Genesis custody block generation
"""

import os
import shutil
import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from sqlalchemy.orm import Session
from database.connection import get_db
from database.models import Case, EvidenceItem, CustodyEvent, User
from backend.app.core.config import settings
from backend.app.core.security import get_current_user_id
from forensic_engine import calculate_sha256
from custody import CryptographicCustodyLedger, GENESIS_HASH

router = APIRouter(tags=["Evidence"])
custody_ledger = CryptographicCustodyLedger()


@router.post("/cases/{case_id}/evidence", status_code=status.HTTP_201_CREATED)
async def intake_evidence(
    case_id: str,
    file: UploadFile = File(...),
    source_description: Optional[str] = Form(None),
    client_sha256: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user_id)
):
    case = db.query(Case).filter_by(case_id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' does not exist.")

    # Generate unique evidence ID (Rule 5)
    evidence_id = f"EVD-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:6].upper()}"

    # Target secure vault directory (Rule 2)
    vault_dir = os.path.join(settings.EVIDENCE_VAULT_PATH, case_id, evidence_id)
    os.makedirs(vault_dir, exist_ok=True)
    vault_file_path = os.path.join(vault_dir, file.filename)

    # Stream file into vault
    with open(vault_file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Compute deterministic SHA-256 (Rule 7)
    calculated_hash = calculate_sha256(vault_file_path)
    file_size = os.path.getsize(vault_file_path)

    # Verify against client-calculated hash if supplied by Ayushi's frontend
    if client_sha256 and client_sha256.lower() != calculated_hash:
        # File corrupted during upload transit
        os.remove(vault_file_path)
        raise HTTPException(
            status_code=400,
            detail=f"Integrity transmission error: Client SHA-256 ({client_sha256}) did not match server hash ({calculated_hash})."
        )

    # Mark vaulted file as read-only (Rule 2)
    try:
        import stat
        os.chmod(vault_file_path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    except Exception:
        pass # Windows handles attributes differently

    detected_mime = file.content_type or "application/octet-stream"

    # Save to Database
    evidence_record = EvidenceItem(
        evidence_id=evidence_id,
        case_id=case_id,
        original_filename=file.filename,
        vault_path=vault_file_path,
        file_size_bytes=file_size,
        mime_type=detected_mime,
        sha256_hash=calculated_hash,
        source_description=source_description,
        intake_by_user_id=user_id,
        status="SECURED"
    )
    db.add(evidence_record)

    # Create Genesis Block in Custody Ledger (Rule 8)
    genesis_block = custody_ledger.create_event(
        evidence_id=evidence_id,
        sequence_number=1,
        action="EVIDENCE_INTAKE_RECORDED",
        actor_id=user_id,
        details={
            "original_filename": file.filename,
            "file_size_bytes": file_size,
            "mime_type": detected_mime,
            "sha256_hash": calculated_hash,
            "source": source_description or "Unspecified acquisition source"
        },
        previous_event_hash=GENESIS_HASH
    )

    import json
    custody_db_event = CustodyEvent(
        event_id=genesis_block["event_id"],
        evidence_id=evidence_id,
        sequence_number=genesis_block["sequence_number"],
        action=genesis_block["action"],
        actor_id=genesis_block["actor_id"],
        timestamp=genesis_block["timestamp"],
        previous_event_hash=genesis_block["previous_event_hash"],
        event_hash=genesis_block["event_hash"],
        payload_json=json.dumps(genesis_block["payload_json"])
    )
    db.add(custody_db_event)
    db.commit()

    return {
        "success": True,
        "data": {
            "evidence_id": evidence_id,
            "case_id": case_id,
            "original_filename": file.filename,
            "file_size_bytes": file_size,
            "mime_type": detected_mime,
            "sha256_hash": calculated_hash,
            "vault_status": "SECURED_READONLY",
            "genesis_event_hash": genesis_block["event_hash"],
            "created_at": evidence_record.created_at.isoformat()
        }
    }


@router.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: str, db: Session = Depends(get_db)):
    evidence = db.query(EvidenceItem).filter_by(evidence_id=evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence '{evidence_id}' not found.")

    return {
        "success": True,
        "data": {
            "evidence_id": evidence.evidence_id,
            "case_id": evidence.case_id,
            "original_filename": evidence.original_filename,
            "file_size_bytes": evidence.file_size_bytes,
            "mime_type": evidence.mime_type,
            "sha256_hash": evidence.sha256_hash,
            "status": evidence.status,
            "source_description": evidence.source_description,
            "created_at": evidence.created_at.isoformat()
        }
    }
