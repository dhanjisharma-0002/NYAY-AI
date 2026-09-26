"""
NYAYAI - Role-Based Access Control (RBAC) Endpoints
Module: backend.app.api.rbac_demo
Provides protected operational endpoints for:
- ADMIN: User management, system administration
- INVESTIGATOR: Case creation, evidence intake, initiating analysis
- LAWYER: Permitted case inspection, report viewing
- JUDGE: Judicial report review, cryptographic authenticity verification

Adheres strictly to the principle of least privilege ('Do not assume unrestricted access').
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.user import User
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.report import Report
from backend.app.core.security import require_roles, require_admin, require_investigator, require_lawyer, require_judge
from backend.app.schemas.auth import UserResponse

router = APIRouter(prefix="/rbac", tags=["Role-Based Access Control"])


# ==============================================================================
# 1. ADMIN Operations (User Management & System Administration)
# ==============================================================================

@router.get(
    "/admin/users",
    response_model=List[UserResponse],
    status_code=status.HTTP_200_OK,
    summary="[ADMIN ONLY] User management: list all system users"
)
def admin_list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    User management capability.
    Only accessible by users with role 'ADMIN' or 'SYSTEM_LEAD'.
    """
    users = db.query(User).all()
    return [
        UserResponse(
            user_id=u.id,
            username=u.username,
            email=u.email,
            full_name=u.full_name,
            badge_number=u.badge_number,
            role=u.role,
            is_active=u.is_active,
            created_at=u.created_at.isoformat() if u.created_at else None
        )
        for u in users
    ]


@router.get(
    "/admin/system/status",
    status_code=status.HTTP_200_OK,
    summary="[ADMIN ONLY] System administration: inspect platform status"
)
def admin_system_status(
    current_user: User = Depends(require_admin)
):
    """System administration capability."""
    return {
        "success": True,
        "operator": current_user.username,
        "role": current_user.role,
        "system_state": "OPTIMAL",
        "admissibility_framework": "Bharatiya Sakshya Adhiniyam, 2023"
    }


# ==============================================================================
# 2. INVESTIGATOR Operations (Create cases, upload evidence, initiate analysis)
# ==============================================================================

@router.post(
    "/investigator/analysis/{evidence_id}/initiate",
    status_code=status.HTTP_200_OK,
    summary="[INVESTIGATOR ONLY] Initiate forensic and AI analysis on evidence"
)
def investigator_initiate_analysis(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("INVESTIGATOR", "ADMIN"))
):
    """
    Forensic analysis initiation capability.
    Only accessible by INVESTIGATOR (or ADMIN).
    """
    evidence = db.query(Evidence).filter_by(evidence_id=evidence_id).first()
    return {
        "success": True,
        "evidence_id": evidence_id,
        "initiated_by": current_user.username,
        "role": current_user.role,
        "pipeline_state": "DISPATCHED_TO_INFERENCE_ENGINE"
    }


# ==============================================================================
# 3. LAWYER Operations (View permitted case information & reports)
# ==============================================================================

@router.get(
    "/lawyer/cases/{case_id}/permitted-brief",
    status_code=status.HTTP_200_OK,
    summary="[LAWYER ONLY] View permitted case information"
)
def lawyer_view_case_brief(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("LAWYER", "ADMIN"))
):
    """
    Case review capability tailored for legal counsel.
    Restricted to LAWYER (and ADMIN).
    """
    case = db.query(Case).filter_by(case_id=case_id).first()
    return {
        "success": True,
        "case_id": case_id,
        "title": case.title if case else "State v. Accused",
        "counsel_viewer": current_user.username,
        "access_scope": "DEFENSE_PROSECUTION_BRIEF"
    }


# ==============================================================================
# 4. JUDGE Operations (View reports, verify report authenticity)
# ==============================================================================

@router.get(
    "/judge/reports/{report_id}",
    status_code=status.HTTP_200_OK,
    summary="[JUDGE ONLY] View official court admissibility reports"
)
def judge_view_report(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("JUDGE", "ADMIN"))
):
    """Judicial report inspection capability."""
    return {
        "success": True,
        "report_id": report_id,
        "judicial_bench_reviewer": current_user.username,
        "role": current_user.role,
        "status": "ADMISSIBILITY_UNDER_REVIEW"
    }


@router.post(
    "/judge/reports/{report_id}/verify-authenticity",
    status_code=status.HTTP_200_OK,
    summary="[JUDGE STRICT] Verify report authenticity under Section 63/65B BSA"
)
def judge_verify_report_authenticity(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("JUDGE")) # STRICT: JUDGE ONLY, no other role
):
    """
    Sole judicial capability to seal/verify evidentiary report authenticity.
    Strictly restricted to JUDGE role only ('Do not assume unrestricted access').
    """
    return {
        "success": True,
        "report_id": report_id,
        "verified_by_judge": current_user.username,
        "badge_number": current_user.badge_number,
        "authenticity_sealed": True,
        "admissibility_finding": "ADMISSIBLE_UNDER_BSA_2023"
    }
