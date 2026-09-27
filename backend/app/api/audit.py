"""
NYAYAI - Audit Trail & Review API Router (Phase 12)
Module: backend.app.api.audit
Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.user import User
from backend.app.core.security import require_roles
from backend.app.schemas.audit import AuditLogListResponse
from backend.app.services.audit_service import AuditService

router = APIRouter(prefix="/audit", tags=["Audit Trail"])

# Audit Reviewers: ADMIN, AUDITOR, and SYSTEM_LEAD only
auth_auditor = require_roles("ADMIN", "AUDITOR", "SYSTEM_LEAD")


@router.get(
    "",
    response_model=AuditLogListResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve system-wide paginated audit history"
)
def get_audit_logs(
    action: Optional[str] = Query(None, description="Filter by audit action (e.g. EVIDENCE_UPLOADED)"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type (e.g. CASE, EVIDENCE, REPORT)"),
    user_id: Optional[str] = Query(None, description="Filter by actor user_id"),
    limit: int = Query(50, ge=1, le=100, description="Page limit (default 50, max 100)"),
    offset: int = Query(0, ge=0, description="Page offset"),
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_auditor)
):
    """
    Retrieves chronologically sorted, paginated audit records.
    Restricted strictly to roles with audit:read permission (ADMIN, AUDITOR, SYSTEM_LEAD).
    """
    service = AuditService(db)
    return service.list_audit_logs(
        action=action,
        resource_type=resource_type,
        user_id=user_id,
        limit=limit,
        offset=offset
    )


@router.get(
    "/cases/{case_id}",
    response_model=AuditLogListResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve audit trail for a case docket"
)
def get_case_audit_history(
    case_id: str,
    limit: int = Query(50, ge=1, le=100, description="Page limit (default 50, max 100)"),
    offset: int = Query(0, ge=0, description="Page offset"),
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_auditor)
):
    """
    Retrieves all audit events for a case docket, including case, evidence, and report actions.
    """
    service = AuditService(db)
    return service.get_case_audit_history(case_id=case_id, limit=limit, offset=offset)


@router.get(
    "/evidence/{evidence_id}",
    response_model=AuditLogListResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve audit trail for an evidence artifact"
)
def get_evidence_audit_history(
    evidence_id: str,
    limit: int = Query(50, ge=1, le=100, description="Page limit (default 50, max 100)"),
    offset: int = Query(0, ge=0, description="Page offset"),
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_auditor)
):
    """
    Retrieves chronological audit events for a specific evidence item.
    """
    service = AuditService(db)
    return service.get_evidence_audit_history(evidence_id=evidence_id, limit=limit, offset=offset)


@router.get(
    "/reports/{report_id}",
    response_model=AuditLogListResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve audit trail for an issued court report"
)
def get_report_audit_history(
    report_id: str,
    limit: int = Query(50, ge=1, le=100, description="Page limit (default 50, max 100)"),
    offset: int = Query(0, ge=0, description="Page offset"),
    db: Session = Depends(get_db),
    current_user: User = Depends(auth_auditor)
):
    """
    Retrieves chronological audit events for a specific court report certificate.
    """
    service = AuditService(db)
    return service.get_report_audit_history(report_id=report_id, limit=limit, offset=offset)
