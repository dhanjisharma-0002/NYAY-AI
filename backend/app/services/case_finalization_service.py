"""
NYAYAI - Case Docket Finalization & Sealing Service (Phase 17)
Module: backend.app.services.case_finalization_service
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Orchestrates formal judicial closure and cryptographic sealing of case dockets:
1. Reuses existing models and services (Case, Evidence, CustodyEvent, Report, AuditLog).
2. Enforces validation gates:
   - Rejects empty cases.
   - Rejects cases with pending forensic or AI analysis.
   - Rejects cases with INTEGRITY_COMPROMISED or STORAGE_ERROR evidence.
   - Validates custody-chain integrity across all evidence items.
   - Requires at least one official court admissibility report.
3. Computes deterministic SHA-256 docket sealing manifest.
4. Appends terminal DOCKET_SEALED custody event to every evidence item.
5. Transitions case status from UNDER_ANALYSIS to COMPLETED.
6. Emits exactly one CASE_FINALIZED audit event.
7. Preserves idempotency: already COMPLETED/ARCHIVED cases cannot be finalized again.
8. Enforces RBAC: INVESTIGATOR (owner/assigned), ADMIN, JUDGE.
"""

import json
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from sqlalchemy.orm import Session

from backend.app.models.user import User
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.evidence_metadata import EvidenceMetadata
from backend.app.models.analysis_result import AnalysisResult
from backend.app.models.custody import CustodyEvent
from backend.app.models.report import Report, CourtReport
from backend.app.models.audit import AuditLog
from backend.app.schemas.case_finalization import CaseFinalizationRequest
from backend.app.services.base import BaseService
from backend.app.services.custody_service import CustodyService
from backend.app.utils.exceptions import (
    EntityNotFoundException,
    PermissionDeniedException,
    AppException
)
from backend.app.utils.logger import get_logger
from custody import CryptographicCustodyLedger, GENESIS_HASH

logger = get_logger("case_finalization_service")


class CaseFinalizationService(BaseService):
    """
    Coordinates pre-closure validation, cryptographic docket sealing, terminal
    custody block chaining, case lifecycle transition, and audit logging.
    """

    def __init__(self, db: Session):
        super().__init__(db)
        self.ledger = CryptographicCustodyLedger()
        self.custody_service = CustodyService(db)

    def finalize_case(
        self,
        case_id: str,
        current_user: User,
        payload: Optional[CaseFinalizationRequest] = None
    ) -> Dict[str, Any]:
        """
        Validates readiness, seals the docket, appends terminal custody events,
        transitions status to COMPLETED, and records audit trail.
        """
        # 1. Verify case existence
        case = self.db.query(Case).filter_by(case_id=case_id).first()
        if not case:
            raise EntityNotFoundException("Case", case_id)

        # 2. RBAC & Role Isolation
        user_role = (current_user.role or "").strip().upper()
        if user_role == "INVESTIGATOR":
            if case.created_by != current_user.id and case.created_by != current_user.username:
                raise PermissionDeniedException(
                    f"Access forbidden: Investigator '{current_user.username}' is not authorized to finalize case '{case_id}'."
                )
        elif user_role not in ("ADMIN", "JUDGE", "SYSTEM_LEAD"):
            raise PermissionDeniedException(
                f"Access forbidden: Role '{user_role}' is not authorized to finalize case dockets."
            )

        # 3. Idempotency & Conflict Check
        if case.status in ("COMPLETED", "ARCHIVED"):
            raise AppException(
                message=f"Case docket '{case_id}' is already {case.status} and cannot be finalized again.",
                status_code=409,
                error_code=f"CASE_ALREADY_{case.status}",
                details={"case_id": case_id, "current_status": case.status}
            )

        # 4. Batch query all evidence items in case docket
        evidence_records = (
            self.db.query(Evidence)
            .filter_by(case_id=case_id)
            .order_by(Evidence.evidence_id.asc())
            .all()
        )

        # Validation: Reject empty cases
        if not evidence_records:
            raise AppException(
                message=f"Cannot finalize empty case docket '{case_id}'. At least one evidence item is required.",
                status_code=400,
                error_code="EMPTY_CASE_DOCKET",
                details={"case_id": case_id}
            )

        evidence_ids = [e.evidence_id for e in evidence_records]

        # 5. Batch query metadata, AI analysis, reports, and custody events
        metadata_records = (
            self.db.query(EvidenceMetadata)
            .filter(EvidenceMetadata.evidence_id.in_(evidence_ids))
            .all()
        )
        metadata_ev_ids = {m.evidence_id for m in metadata_records}

        ai_records = (
            self.db.query(AnalysisResult)
            .filter(AnalysisResult.evidence_id.in_(evidence_ids))
            .all()
        )
        ai_ev_ids = {a.evidence_id for a in ai_records}

        reports = (
            self.db.query(Report)
            .filter_by(case_id=case_id)
            .order_by(Report.report_id.asc())
            .all()
        )
        legacy_reports = (
            self.db.query(CourtReport)
            .filter_by(case_id=case_id)
            .order_by(CourtReport.report_id.asc())
            .all()
        ) if not reports else []

        total_reports = len(reports) + len(legacy_reports)

        custody_events = (
            self.db.query(CustodyEvent)
            .filter(CustodyEvent.evidence_id.in_(evidence_ids))
            .order_by(CustodyEvent.sequence_number.asc())
            .all()
        )
        custody_map: Dict[str, List[CustodyEvent]] = {eid: [] for eid in evidence_ids}
        for ce in custody_events:
            custody_map[ce.evidence_id].append(ce)

        # 6. Validation Gates

        # A. Pending Analysis Rejection
        pending_items = [
            e.evidence_id for e in evidence_records
            if (e.evidence_id not in metadata_ev_ids or e.evidence_id not in ai_ev_ids)
        ]
        if pending_items:
            raise AppException(
                message=f"Case docket '{case_id}' cannot be finalized: pending forensic or AI analysis remains on {len(pending_items)} evidence item(s).",
                status_code=400,
                error_code="PENDING_ANALYSIS_REMAINS",
                details={"pending_evidence_ids": pending_items}
            )

        # B. Compromised or Errored Evidence Rejection
        compromised_items = [
            e.evidence_id for e in evidence_records
            if e.status in ("INTEGRITY_COMPROMISED", "STORAGE_ERROR")
        ]
        if compromised_items:
            raise AppException(
                message=f"Case docket '{case_id}' cannot be finalized: {len(compromised_items)} evidence item(s) are compromised or encountered storage errors.",
                status_code=400,
                error_code="EVIDENCE_INTEGRITY_COMPROMISED",
                details={"compromised_evidence_ids": compromised_items}
            )

        # C. Custody-Chain Integrity Validation
        broken_chains: List[str] = []
        for eid in evidence_ids:
            hist = self.custody_service.get_chronological_history(eid)
            if not hist.get("chain_intact"):
                broken_chains.append(eid)

        if broken_chains:
            raise AppException(
                message=f"Case docket '{case_id}' cannot be finalized: cryptographic chain of custody integrity check failed for evidence item(s).",
                status_code=400,
                error_code="BROKEN_CUSTODY_CHAIN",
                details={"broken_chains": broken_chains}
            )

        # D. Official Court Report Requirement
        if total_reports == 0:
            raise AppException(
                message=f"Case docket '{case_id}' cannot be finalized: at least one official court admissibility report (BSA 2023) is required.",
                status_code=400,
                error_code="COURT_REPORT_REQUIRED",
                details={"case_id": case_id, "reports_count": 0}
            )

        # 7. Compute Deterministic Docket Sealing Manifest
        latest_custody_hashes: Dict[str, str] = {}
        for e in evidence_records:
            ev_events = custody_map[e.evidence_id]
            latest_custody_hashes[e.evidence_id] = ev_events[-1].event_hash if ev_events else GENESIS_HASH

        evidence_manifest_items = [
            {
                "evidence_id": e.evidence_id,
                "original_filename": e.original_filename,
                "sha256_hash": e.sha256_hash,
                "status": e.status,
                "terminal_custody_hash": latest_custody_hashes[e.evidence_id]
            }
            for e in evidence_records
        ]

        reports_manifest_items = []
        for r in reports:
            reports_manifest_items.append({
                "report_id": r.report_id,
                "report_type": r.report_type,
                "report_sha256": r.report_sha256,
                "verification_code": r.verification_code,
                "created_at": r.created_at.isoformat() if hasattr(r.created_at, "isoformat") else str(r.created_at)
            })
        for lr in legacy_reports:
            reports_manifest_items.append({
                "report_id": lr.report_id,
                "report_type": "PDF",
                "report_sha256": lr.report_sha256,
                "verification_code": lr.compliance_framework,
                "created_at": lr.created_at.isoformat() if hasattr(lr.created_at, "isoformat") else str(lr.created_at)
            })

        manifest_payload = {
            "case_id": case.case_id,
            "case_number": case.case_number,
            "evidence": [
                {
                    "evidence_id": item["evidence_id"],
                    "sha256_hash": item["sha256_hash"],
                    "terminal_custody_hash": item["terminal_custody_hash"]
                }
                for item in evidence_manifest_items
            ],
            "reports": [
                {
                    "report_id": item["report_id"],
                    "report_sha256": item["report_sha256"]
                }
                for item in reports_manifest_items
            ]
        }
        manifest_bytes = json.dumps(manifest_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        docket_sealing_hash = hashlib.sha256(manifest_bytes).hexdigest().lower()

        # 8. Append Terminal DOCKET_SEALED Custody Event to Every Evidence Item
        now = datetime.now(timezone.utc)
        sealed_at_iso = now.isoformat()

        certifying_name = (
            (payload.certifying_officer_name if payload else None)
            or current_user.full_name
            or current_user.username
        )
        badge_num = (payload.badge_number if payload else None) or getattr(current_user, "badge_number", None)
        notes = (payload.certification_notes if payload else None) or "Case docket formally finalized and sealed for court submission under BSA 2023."

        custody_events_appended = 0
        for e in evidence_records:
            self.custody_service.record_event(
                evidence_id=e.evidence_id,
                event_type="DOCKET_SEALED",
                user_id=current_user.id,
                description=f"Case docket '{case.case_id}' finalized and sealed by {certifying_name}. Sealing hash: {docket_sealing_hash[:16]}...",
                details={
                    "case_id": case.case_id,
                    "case_number": case.case_number,
                    "docket_sealing_hash": docket_sealing_hash,
                    "sealed_status": "COMPLETED",
                    "certifying_officer": certifying_name,
                    "badge_number": badge_num,
                    "certification_notes": notes,
                    "compliance_framework": "BSA_2023_SEC_63_65B"
                }
            )
            custody_events_appended += 1

        # 9. Transition Case to COMPLETED
        previous_status = case.status
        case.status = "COMPLETED"
        case.updated_at = now
        self.db.add(case)

        # 10. Record Exactly One CASE_FINALIZED Audit Event
        audit_entry = AuditLog(
            audit_id=f"AUD-{now.year}-{uuid.uuid4().hex[:8].upper()}",
            user_id=current_user.id,
            action="CASE_FINALIZED",
            resource_type="CASE",
            resource_id=case.case_id,
            timestamp=now,
            meta_data={
                "case_number": case.case_number,
                "previous_status": previous_status,
                "new_status": "COMPLETED",
                "docket_sealing_hash": docket_sealing_hash,
                "total_evidence_sealed": len(evidence_records),
                "court_reports_referenced": total_reports,
                "certifying_officer": certifying_name,
                "badge_number": badge_num,
                "certification_notes": notes
            }
        )
        self.db.add(audit_entry)
        self.db.commit()
        self.db.refresh(case)

        logger.info(
            f"Case docket {case.case_id} sealed and COMPLETED by {certifying_name} [sealing_hash: {docket_sealing_hash}]"
        )

        return {
            "case_id": case.case_id,
            "case_number": case.case_number,
            "previous_status": previous_status,
            "new_status": "COMPLETED",
            "sealed_at": sealed_at_iso,
            "docket_sealing_hash": docket_sealing_hash,
            "total_evidence_sealed": len(evidence_records),
            "court_reports_referenced": total_reports,
            "custody_events_appended": custody_events_appended,
            "sealed_by": current_user.id
        }

    def get_sealing_manifest(self, case_id: str) -> Dict[str, Any]:
        """
        Retrieves the complete cryptographic sealing manifest for a case docket.
        """
        case = self.db.query(Case).filter_by(case_id=case_id).first()
        if not case:
            raise EntityNotFoundException("Case", case_id)

        evidence_records = (
            self.db.query(Evidence)
            .filter_by(case_id=case_id)
            .order_by(Evidence.evidence_id.asc())
            .all()
        )
        reports = (
            self.db.query(Report)
            .filter_by(case_id=case_id)
            .order_by(Report.report_id.asc())
            .all()
        )
        legacy_reports = (
            self.db.query(CourtReport)
            .filter_by(case_id=case_id)
            .order_by(CourtReport.report_id.asc())
            .all()
        ) if not reports else []

        evidence_ids = [e.evidence_id for e in evidence_records]
        custody_events = (
            self.db.query(CustodyEvent)
            .filter(CustodyEvent.evidence_id.in_(evidence_ids))
            .order_by(CustodyEvent.sequence_number.asc())
            .all()
        ) if evidence_ids else []

        custody_map: Dict[str, List[CustodyEvent]] = {eid: [] for eid in evidence_ids}
        for ce in custody_events:
            custody_map[ce.evidence_id].append(ce)

        is_sealed = (case.status == "COMPLETED")

        evidence_manifest = []
        for e in evidence_records:
            evs = custody_map.get(e.evidence_id, [])
            if not evs:
                term_hash = GENESIS_HASH
            elif is_sealed and evs[-1].event_type == "DOCKET_SEALED":
                term_hash = evs[-1].previous_hash
            else:
                term_hash = evs[-1].event_hash
            evidence_manifest.append({
                "evidence_id": e.evidence_id,
                "original_filename": e.original_filename,
                "sha256_hash": e.sha256_hash,
                "status": e.status,
                "terminal_custody_hash": term_hash
            })

        reports_manifest = []
        for r in reports:
            reports_manifest.append({
                "report_id": r.report_id,
                "report_type": r.report_type,
                "report_sha256": r.report_sha256,
                "verification_code": r.verification_code,
                "created_at": r.created_at.isoformat() if hasattr(r.created_at, "isoformat") else str(r.created_at)
            })
        for lr in legacy_reports:
            reports_manifest.append({
                "report_id": lr.report_id,
                "report_type": "PDF",
                "report_sha256": lr.report_sha256,
                "verification_code": lr.compliance_framework,
                "created_at": lr.created_at.isoformat() if hasattr(lr.created_at, "isoformat") else str(lr.created_at)
            })

        is_sealed = (case.status == "COMPLETED")
        docket_sealing_hash = None
        sealed_at = None
        sealed_by = None
        notes = None

        if is_sealed:
            final_audit = (
                self.db.query(AuditLog)
                .filter_by(resource_id=case_id, action="CASE_FINALIZED")
                .order_by(AuditLog.timestamp.desc())
                .first()
            )
            if final_audit and final_audit.meta_data:
                docket_sealing_hash = final_audit.meta_data.get("docket_sealing_hash")
                sealed_at = final_audit.timestamp.isoformat() if hasattr(final_audit.timestamp, "isoformat") else str(final_audit.timestamp)
                sealed_by = final_audit.user_id
                notes = final_audit.meta_data.get("certification_notes")

        return {
            "case_id": case.case_id,
            "case_number": case.case_number,
            "status": case.status,
            "is_sealed": is_sealed,
            "docket_sealing_hash": docket_sealing_hash,
            "sealed_at": sealed_at,
            "sealed_by": sealed_by,
            "certification_notes": notes,
            "evidence_manifest": evidence_manifest,
            "reports_manifest": reports_manifest
        }
