"""
NYAYAI - Case Management Service (Phase 4)
Module: backend.app.services.case_service
Handles business logic for case registration, listing, retrieval, and status updates.
"""

import uuid
from typing import List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from backend.app.models.case import Case, generate_case_number
from backend.app.models.user import User
from backend.app.models.audit import AuditLog
from backend.app.schemas.cases import CaseCreateRequest, CaseUpdateRequest, CaseStatusEnum
from backend.app.services.base import BaseService
from backend.app.utils.exceptions import EntityNotFoundException, ValidationException


class CaseService(BaseService):
    """Encapsulates case lifecycle management and persistence."""

    def create_case(self, payload: CaseCreateRequest, created_by: str) -> Case:
        """
        Creates a new investigative case docket with a unique case_id and case_number.
        Initializes status to OPEN.
        """
        # 1. Verify that creator user exists in database
        creator = self.db.query(User).filter_by(id=created_by).first()
        if not creator:
            # Fallback or auto-provision if investigator ID format
            creator = self.db.query(User).filter(
                (User.id == created_by) | (User.username == created_by)
            ).first()
            if not creator:
                raise ValidationException(f"Authorized creator with identifier '{created_by}' was not found.")

        # 2. Generate unique case_id
        case_id = f"CASE-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:8].upper()}"

        # 3. Determine case_number
        if payload.case_number and payload.case_number.strip():
            case_number = payload.case_number.strip()
        else:
            case_number = generate_case_number()

        # 4. Set initial status
        initial_status = payload.status.value if isinstance(payload.status, CaseStatusEnum) else (payload.status or "OPEN")

        now = datetime.now(timezone.utc)
        new_case = Case(
            case_id=case_id,
            case_number=case_number,
            title=payload.title,
            description=payload.description,
            status=initial_status,
            created_by=creator.id,
            jurisdiction=payload.jurisdiction or "High Court of Delhi",
            created_at=now,
            updated_at=now
        )
        self.db.add(new_case)

        # Audit Log: CASE_CREATED
        audit_entry = AuditLog(
            audit_id=f"AUD-{uuid.uuid4().hex[:12].upper()}",
            user_id=creator.id,
            action="CASE_CREATED",
            resource_type="CASE",
            resource_id=new_case.case_id,
            meta_data={
                "case_number": new_case.case_number,
                "title": new_case.title,
                "jurisdiction": new_case.jurisdiction,
                "status": new_case.status
            }
        )
        self.db.add(audit_entry)

        self.db.commit()
        self.db.refresh(new_case)
        self.logger.info(f"Registered case docket {case_id} ({case_number}) by {creator.username}")
        return new_case

    def get_case(self, case_id: str) -> Case:
        """Retrieves a single case docket by case_id. Raises 404 if not found."""
        case = self.db.query(Case).filter_by(case_id=case_id).first()
        if not case:
            raise EntityNotFoundException("Case", case_id)
        return case

    def list_cases(self, status: Optional[str] = None) -> List[Case]:
        """Lists all case dockets, with optional filtering by status."""
        query = self.db.query(Case)
        if status:
            cleaned_status = status.strip().upper()
            query = query.filter(Case.status == cleaned_status)
        return query.order_by(Case.created_at.desc()).all()

    def update_case(self, case_id: str, payload: CaseUpdateRequest) -> Case:
        """
        Applies partial updates to a case docket (title, description, status, jurisdiction).
        Updates the updated_at timestamp.
        """
        case = self.get_case(case_id)

        if payload.title is not None:
            if not payload.title.strip():
                raise ValidationException("Case title cannot be empty.")
            case.title = payload.title.strip()

        if payload.description is not None:
            case.description = payload.description

        if payload.status is not None:
            status_val = payload.status.value if isinstance(payload.status, CaseStatusEnum) else str(payload.status).upper()
            case.status = status_val

        if payload.jurisdiction is not None:
            case.jurisdiction = payload.jurisdiction

        case.updated_at = datetime.now(timezone.utc)

        # Audit Log: CASE_UPDATED
        audit_entry = AuditLog(
            audit_id=f"AUD-{uuid.uuid4().hex[:12].upper()}",
            user_id=case.created_by,
            action="CASE_UPDATED",
            resource_type="CASE",
            resource_id=case.case_id,
            meta_data={
                "status": case.status,
                "title": case.title,
                "jurisdiction": case.jurisdiction
            }
        )
        self.db.add(audit_entry)

        self.db.commit()
        self.db.refresh(case)
        self.logger.info(f"Updated case docket {case_id}: status={case.status}, title={case.title}")
        return case

