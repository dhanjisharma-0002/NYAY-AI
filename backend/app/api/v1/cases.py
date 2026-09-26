"""
NYAYAI - Cases API Router
Module Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

from typing import List, Optional
from datetime import datetime, timezone
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database.connection import get_db
from database.models import Case, EvidenceItem, User
from backend.app.core.security import get_current_user_id

router = APIRouter(prefix="/cases", tags=["Cases"])


class CaseCreateRequest(BaseModel):
    title: str
    description: Optional[str] = None
    jurisdiction: str = "Republic of India"


class CaseResponse(BaseModel):
    case_id: str
    title: str
    description: Optional[str]
    jurisdiction: str
    status: str
    investigator_id: str
    evidence_count: int
    created_at: str


@router.post("", status_code=status.HTTP_201_CREATED)
def create_case(
    payload: CaseCreateRequest,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user_id)
):
    case_code = f"CASE-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:6].upper()}"

    # Ensure user exists in db
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        # Create user record if not present
        user = User(
            id=user_id,
            username=f"user_{user_id[:8]}",
            email=f"{user_id[:8]}@nyayai.gov.in",
            hashed_password="hash",
            full_name="Assigned Investigator",
            role="INVESTIGATOR"
        )
        db.add(user)
        db.commit()

    new_case = Case(
        case_id=case_code,
        title=payload.title,
        description=payload.description,
        investigator_id=user_id,
        jurisdiction=payload.jurisdiction,
        status="OPEN"
    )
    db.add(new_case)
    db.commit()
    db.refresh(new_case)

    return {
        "success": True,
        "data": {
            "case_id": new_case.case_id,
            "title": new_case.title,
            "description": new_case.description,
            "status": new_case.status,
            "investigator_id": new_case.investigator_id,
            "jurisdiction": new_case.jurisdiction,
            "evidence_count": 0,
            "created_at": new_case.created_at.isoformat()
        }
    }


@router.get("")
def list_cases(
    db: Session = Depends(get_db),
    status: Optional[str] = None
):
    query = db.query(Case)
    if status:
        query = query.filter_by(status=status)
    cases = query.order_by(Case.created_at.desc()).all()

    items = []
    for c in cases:
        items.append({
            "case_id": c.case_id,
            "title": c.title,
            "description": c.description,
            "jurisdiction": c.jurisdiction,
            "status": c.status,
            "evidence_count": len(c.evidence_items),
            "created_at": c.created_at.isoformat()
        })

    return {"success": True, "total": len(items), "data": items}


@router.get("/{case_id}")
def get_case(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter_by(case_id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    evidence_list = [
        {
            "evidence_id": e.evidence_id,
            "original_filename": e.original_filename,
            "file_size_bytes": e.file_size_bytes,
            "mime_type": e.mime_type,
            "sha256_hash": e.sha256_hash,
            "status": e.status,
            "created_at": e.created_at.isoformat()
        }
        for e in case.evidence_items
    ]

    return {
        "success": True,
        "data": {
            "case_id": case.case_id,
            "title": case.title,
            "description": case.description,
            "jurisdiction": case.jurisdiction,
            "status": case.status,
            "investigator_id": case.investigator_id,
            "created_at": case.created_at.isoformat(),
            "evidence_items": evidence_list
        }
    }
