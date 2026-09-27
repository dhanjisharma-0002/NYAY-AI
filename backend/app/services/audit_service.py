"""
NYAYAI - Audit Trail Service (Phase 12)
Module: backend.app.services.audit_service
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Provides centralized querying, filtering, pagination, and emission of
tamper-evident system audit trail records.
"""

import uuid
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.app.services.base import BaseService
from backend.app.models.audit import AuditLog
from backend.app.models.case import Case
from backend.app.models.evidence import EvidenceItem
from backend.app.models.report import Report
from backend.app.models.base import utc_now
from backend.app.utils.logger import get_logger

logger = get_logger("audit_service")


class AuditService(BaseService):
    """
    Central service for querying, filtering, and persisting audit trail events.
    Enforces safe data sanitization to prevent sensitive credential leakage.
    """

    @staticmethod
    def _sanitize_meta_data(meta: Any) -> Any:
        """
        Sanitizes sensitive information (passwords, tokens, secret keys, vault absolute paths)
        from audit metadata before client delivery.
        """
        if isinstance(meta, dict):
            sanitized = {}
            for k, v in meta.items():
                k_lower = str(k).lower()
                if any(s in k_lower for s in ["password", "token", "secret", "private_key", "credential", "database_url", "db_url", "storage_reference", "vault_path"]):
                    continue
                sanitized[k] = AuditService._sanitize_meta_data(v)
            return sanitized
        elif isinstance(meta, list):
            return [AuditService._sanitize_meta_data(item) for item in meta]
        return meta

    def _serialize_record(self, record: AuditLog) -> Dict[str, Any]:
        """Serializes an AuditLog row to a dictionary with formatted timestamp and sanitized metadata."""
        return {
            "audit_id": record.audit_id,
            "user_id": record.user_id,
            "action": record.action,
            "resource_type": record.resource_type,
            "resource_id": record.resource_id,
            "timestamp": record.timestamp.isoformat() if record.timestamp else "",
            "metadata": self._sanitize_meta_data(record.meta_data or {})
        }

    def record_audit(
        self,
        action: str,
        resource_type: str,
        resource_id: str,
        user_id: Optional[str] = None,
        meta_data: Optional[Dict[str, Any]] = None
    ) -> AuditLog:
        """
        Helper method to create and persist an AuditLog entry.
        """
        audit_entry = AuditLog(
            audit_id=f"AUD-{uuid.uuid4().hex[:12].upper()}",
            user_id=user_id,
            action=action.strip().upper(),
            resource_type=resource_type.strip().upper(),
            resource_id=str(resource_id).strip(),
            meta_data=meta_data or {}
        )
        self.db.add(audit_entry)
        self.db.commit()
        self.db.refresh(audit_entry)
        return audit_entry

    def list_audit_logs(
        self,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        user_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Retrieves paginated, chronologically ordered audit logs with optional filters.
        Safe defaults: limit=50, max limit=100, offset=0.
        """
        safe_limit = max(1, min(limit, 100))
        safe_offset = max(0, offset)

        query = self.db.query(AuditLog)

        if action and action.strip():
            query = query.filter(AuditLog.action == action.strip().upper())

        if resource_type and resource_type.strip():
            query = query.filter(AuditLog.resource_type == resource_type.strip().upper())

        if user_id and user_id.strip():
            query = query.filter(AuditLog.user_id == user_id.strip())

        total = query.count()
        records = (
            query.order_by(AuditLog.timestamp.desc(), AuditLog.audit_id.desc())
            .offset(safe_offset)
            .limit(safe_limit)
            .all()
        )

        return {
            "success": True,
            "total": total,
            "limit": safe_limit,
            "offset": safe_offset,
            "items": [self._serialize_record(r) for r in records]
        }

    def get_case_audit_history(
        self,
        case_id: str,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Retrieves all audit events associated with a case docket, including
        case lifecycle actions, linked evidence operations, and generated reports.
        """
        safe_limit = max(1, min(limit, 100))
        safe_offset = max(0, offset)

        cleaned_case_id = str(case_id).strip()

        # Gather related evidence IDs and report IDs in this case
        evidence_ids = [
            e.evidence_id
            for e in self.db.query(EvidenceItem.evidence_id).filter_by(case_id=cleaned_case_id).all()
        ]
        report_ids = [
            r.report_id
            for r in self.db.query(Report.report_id).filter_by(case_id=cleaned_case_id).all()
        ]

        all_target_ids = [cleaned_case_id] + evidence_ids + report_ids

        query = self.db.query(AuditLog).filter(AuditLog.resource_id.in_(all_target_ids))

        total = query.count()
        records = (
            query.order_by(AuditLog.timestamp.desc(), AuditLog.audit_id.desc())
            .offset(safe_offset)
            .limit(safe_limit)
            .all()
        )

        return {
            "success": True,
            "total": total,
            "limit": safe_limit,
            "offset": safe_offset,
            "items": [self._serialize_record(r) for r in records]
        }

    def get_evidence_audit_history(
        self,
        evidence_id: str,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Retrieves chronological audit trail for a specific evidence item.
        """
        safe_limit = max(1, min(limit, 100))
        safe_offset = max(0, offset)

        cleaned_evidence_id = str(evidence_id).strip()
        query = self.db.query(AuditLog).filter(AuditLog.resource_id == cleaned_evidence_id)

        total = query.count()
        records = (
            query.order_by(AuditLog.timestamp.desc(), AuditLog.audit_id.desc())
            .offset(safe_offset)
            .limit(safe_limit)
            .all()
        )

        return {
            "success": True,
            "total": total,
            "limit": safe_limit,
            "offset": safe_offset,
            "items": [self._serialize_record(r) for r in records]
        }

    def get_report_audit_history(
        self,
        report_id: str,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Retrieves chronological audit trail for an issued court admissibility report.
        """
        safe_limit = max(1, min(limit, 100))
        safe_offset = max(0, offset)

        cleaned_report_id = str(report_id).strip()
        query = self.db.query(AuditLog).filter(AuditLog.resource_id == cleaned_report_id)

        total = query.count()
        records = (
            query.order_by(AuditLog.timestamp.desc(), AuditLog.audit_id.desc())
            .offset(safe_offset)
            .limit(safe_limit)
            .all()
        )

        return {
            "success": True,
            "total": total,
            "limit": safe_limit,
            "offset": safe_offset,
            "items": [self._serialize_record(r) for r in records]
        }
