"""
NYAYAI - Public Report Verification & Verification Audit Service (Phase 11)
Module: backend.app.services.verification_service
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Provides centralized public verification, cryptographic report sealing checks,
tamper-evident audit logging, and verification event recording.
"""

import os
import uuid
import hashlib
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session

from backend.app.services.base import BaseService
from backend.app.models.report import Report, CourtReport
from backend.app.models.case import Case
from backend.app.models.evidence import EvidenceItem
from backend.app.models.verification import VerificationRecord
from backend.app.models.audit import AuditLog
from backend.app.models.base import utc_now
from backend.app.utils.exceptions import EntityNotFoundException
from backend.app.utils.logger import get_logger

logger = get_logger("verification_service")


class VerificationService(BaseService):
    """
    Central service for validating electronic evidence reports, logging public
    verification requests, and maintaining an immutable audit trail.
    """

    def find_report(self, identifier: str) -> Optional[Report]:
        """
        Finds a report by report_id, verification_code, or report_sha256.
        """
        if not identifier:
            return None
        cleaned = str(identifier).strip()

        # 1. Lookup by primary report_id
        report = self.db.query(Report).filter_by(report_id=cleaned).first()
        if report:
            return report

        # 2. Lookup by unique verification_code
        report = self.db.query(Report).filter_by(verification_code=cleaned).first()
        if report:
            return report

        # 3. Lookup by exact cryptographic SHA-256 hash
        report = self.db.query(Report).filter_by(report_sha256=cleaned).first()
        return report

    def verify_report(
        self,
        code_or_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        verification_method: str = "QR_CODE",
        verifier_identifier: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Public verification core:
        1. Resolves report by report_id or verification_code.
        2. Validates cryptographic integrity of the report artifact.
        3. Creates an immutable VerificationRecord.
        4. Appends a standardized AuditLog entry.
        5. Returns a safe, unredacted-for-court verification dictionary without sensitive server data.
        """
        report = self.find_report(code_or_id)

        if not report:
            # Record failed verification audit attempt for security monitoring
            try:
                failed_audit = AuditLog(
                    audit_id=f"AUD-{uuid.uuid4().hex[:12].upper()}",
                    user_id=None,
                    action="REPORT_VERIFICATION_FAILED",
                    resource_type="REPORT",
                    resource_id=str(code_or_id)[:64],
                    meta_data={
                        "status": "NOT_FOUND",
                        "attempted_identifier": str(code_or_id)[:64],
                        "ip_address": ip_address,
                        "user_agent": user_agent,
                        "verification_method": verification_method
                    }
                )
                self.db.add(failed_audit)
                self.db.commit()
            except Exception as audit_err:
                self.db.rollback()
                logger.warning(f"Could not record failed verification audit log: {audit_err}")

            raise EntityNotFoundException("Report", code_or_id)

        # Check physical file cryptographic integrity if report artifact is present in vault
        is_authentic = (report.status not in ("TAMPERED", "INTEGRITY_COMPROMISED", "INVALID"))
        integrity_status = "AUTHENTIC_AND_UNCOMPROMISED" if is_authentic else "INTEGRITY_COMPROMISED"

        if is_authentic and report.storage_reference and os.path.exists(report.storage_reference):
            try:
                with open(report.storage_reference, "rb") as f:
                    file_bytes = f.read()
                raw_hash = hashlib.sha256(file_bytes).hexdigest().lower()
                norm_hash = hashlib.sha256(file_bytes.replace(b"\r\n", b"\n")).hexdigest().lower()
                expected_sha = report.report_sha256.lower()
                if expected_sha not in (raw_hash, norm_hash):
                    is_authentic = False
                    integrity_status = "INTEGRITY_COMPROMISED"
                    logger.warning(
                        f"Hash mismatch on report {report.report_id}! Expected {expected_sha}, got raw={raw_hash}, norm={norm_hash}"
                    )
            except Exception as read_err:
                logger.warning(f"Could not read report file for hash validation: {read_err}")


        # Lookup case metadata and evidence metrics
        case = self.db.query(Case).filter_by(case_id=report.case_id).first()
        evidence_count = self.db.query(EvidenceItem).filter_by(case_id=report.case_id).count()

        matched_via = "report_id" if report.report_id == str(code_or_id).strip() else (
            "verification_code" if report.verification_code == str(code_or_id).strip() else "report_sha256"
        )

        # Persist VerificationRecord
        ver_id = f"VER-{uuid.uuid4().hex[:12].upper()}"
        verification_record = VerificationRecord(
            verification_id=ver_id,
            report_id=report.report_id,
            verification_method=verification_method,
            verifier_identifier=verifier_identifier or "PUBLIC_GATEWAY",
            status="VALID" if is_authentic else "TAMPER_DETECTED",
            ip_address=ip_address,
            meta_data={
                "user_agent": user_agent,
                "matched_by": matched_via,
                "lookup_identifier": str(code_or_id)[:64]
            }
        )
        self.db.add(verification_record)

        # Persist AuditLog
        audit_id = f"AUD-{uuid.uuid4().hex[:12].upper()}"
        audit_entry = AuditLog(
            audit_id=audit_id,
            user_id=None,
            action="REPORT_VERIFIED" if is_authentic else "REPORT_INTEGRITY_COMPROMISED",
            resource_type="REPORT",
            resource_id=report.report_id,
            meta_data={
                "verification_id": ver_id,
                "verification_code": report.verification_code,
                "status": verification_record.status,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "verification_method": verification_method,
                "matched_by": matched_via
            }
        )
        self.db.add(audit_entry)

        try:
            self.db.commit()
            self.db.refresh(verification_record)
        except Exception as commit_err:
            self.db.rollback()
            logger.error(f"Failed committing verification record / audit log: {commit_err}")
            raise commit_err

        # Return safe public dictionary (Zero sensitive information leakage)
        return {
            "verified": is_authentic,
            "report_id": report.report_id,
            "case_id": report.case_id,
            "case_title": case.title if case else "N/A",
            "official_report_sha256": report.report_sha256,
            "compliance_framework": report.compliance_framework or report.report_type,
            "certified_evidence_count": evidence_count,
            "issued_at": report.created_at.isoformat() if report.created_at else "",
            "integrity_status": integrity_status,
            "verification_code": report.verification_code,
            "report_type": report.report_type,
            "verification_id": verification_record.verification_id,
            "verification_method": verification_record.verification_method,
            "verified_at": verification_record.timestamp.isoformat() if verification_record.timestamp else utc_now().isoformat()
        }

    def get_verification_history(self, report_id: str) -> List[VerificationRecord]:
        """
        Retrieves chronological verification history for a report docket.
        """
        report = self.find_report(report_id)
        if not report:
            raise EntityNotFoundException("Report", report_id)

        return (
            self.db.query(VerificationRecord)
            .filter_by(report_id=report.report_id)
            .order_by(VerificationRecord.timestamp.desc())
            .all()
        )
