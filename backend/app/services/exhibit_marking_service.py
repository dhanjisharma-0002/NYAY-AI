"""
NYAYAI - Judicial Courtroom Exhibit Marking & Evidence Tender Service (Phase 21)
Module: backend.app.services.exhibit_marking_service
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Enforces statutory electronic evidence presentation, courtroom tendering, and
judicial exhibit marking under Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023) Section 63
and Bharatiya Nagarik Suraksha Sanhita, 2023 (BNSS 2023):
1. Pre-condition validation: Case must be finalized and cryptographically sealed (COMPLETED).
2. Admissibility gate: Docket must have verified BSA 2023 Section 63 admissibility status.
3. Strict RBAC: Only a JUDGE may perform official judicial marking and admissibility rulings.
   LAWYER and INVESTIGATOR can perform courtroom tendering with case-scoped authorization.
   ADMIN/SYSTEM_LEAD are administrative roles and never represent judicial authority.
4. Cryptographic custody extension: Appends EXHIBIT_TENDERED_IN_COURT and JUDICIAL_EXHIBIT_MARKED
   custody blocks to evidence items without breaking or modifying historical chains.
5. Unique exhibit numbers: Enforces case-scoped exhibit identifier uniqueness (e.g. 'Ex. P-1').
6. Double-admission protection: Re-admitting an already admitted exhibit returns HTTP 409 Conflict.
7. Idempotency: Repeated identical requests return the existing record without corrupting history.
8. Zero WORM mutation: Never modifies physical binary files, hashes, or case status.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy.orm import Session

from backend.app.models.user import User
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence, EvidenceItem
from backend.app.models.report import Report, CourtReport
from backend.app.models.custody import CustodyEvent
from backend.app.models.audit import AuditLog
from backend.app.schemas.exhibit_marking import (
    ExhibitRulingEnum,
    TenderingPartyEnum,
    ExhibitItemTypeEnum,
    EvidenceTenderRequest,
    EvidenceTenderResponse,
    ExhibitMarkingRequest,
    ExhibitRecordResponse,
    EvidenceExhibitStatusResponse,
    CaseExhibitRegisterResponse
)
from backend.app.services.base import BaseService
from backend.app.services.custody_service import CustodyService
from backend.app.services.admissibility_service import AdmissibilityService
from backend.app.services.case_finalization_service import CaseFinalizationService
from backend.app.utils.exceptions import (
    AppException,
    EntityNotFoundException,
    PermissionDeniedException,
    ValidationException
)
from backend.app.utils.logger import get_logger

logger = get_logger("exhibit_marking_service")


class ExhibitMarkingService(BaseService):
    """
    Coordinates courtroom evidence tendering, judicial exhibit marking,
    admissibility rulings, and exhibit ledger queries under BSA 2023.
    """

    def __init__(self, db: Session):
        super().__init__(db)
        self.custody_service = CustodyService(db)
        self.admissibility_service = AdmissibilityService(db)
        self.finalization_service = CaseFinalizationService(db)

    def _check_case_access(self, case: Case, current_user: User, action: str = "view") -> None:
        """
        Enforces statutory separation of powers and case-scoped authorization:
        - JUDGE: Permitted for all courtroom actions (marking, tendering, viewing).
        - LAWYER: Permitted for tendering and viewing on assigned/scoped cases.
        - INVESTIGATOR: Permitted for tendering and viewing on owned/assigned cases.
        - ADMIN/SYSTEM_LEAD: Permitted for tendering and viewing; strictly forbidden from marking.
        - AUDITOR: Strictly read-only viewing.
        """
        user_role = (current_user.role or "").strip().upper()

        # 1. Official judicial marking/ruling: Strictly restricted to JUDGE
        if action == "mark":
            if user_role != "JUDGE":
                raise PermissionDeniedException(
                    f"Access forbidden: Only a JUDGE may perform official judicial exhibit marking and admissibility rulings. Role '{user_role}' lacks judicial authority."
                )
            return

        # 2. JUDGE has unrestricted court-wide authority for tendering and viewing
        if user_role == "JUDGE":
            return

        # 3. INVESTIGATOR: Scoped strictly to owned/created cases (cross-case access rejected)
        if user_role == "INVESTIGATOR":
            if case.created_by != current_user.id and case.created_by != current_user.username:
                raise PermissionDeniedException(
                    f"Access forbidden: Investigator '{current_user.username}' is not authorized for case '{case.case_id}' (cross-case access denied)."
                )
            return

        # 4. LAWYER: Permitted on cases with case-scoped association
        if user_role == "LAWYER":
            desc = (case.description or "").lower()
            # If case description explicitly restricts to assigned counsel, enforce matching
            if "assigned_counsel" in desc or "counsel:" in desc or "lawyer:" in desc:
                if current_user.username.lower() not in desc and current_user.id.lower() not in desc:
                    raise PermissionDeniedException(
                        f"Access forbidden: Lawyer '{current_user.username}' is not assigned to case '{case.case_id}' (cross-case access denied)."
                    )
            return

        # 5. ADMIN / SYSTEM_LEAD: Technical support; permitted for tendering and viewing
        if user_role in ("ADMIN", "SYSTEM_LEAD"):
            return

        # 6. AUDITOR: Strictly read-only
        if user_role == "AUDITOR":
            if action in ("tender", "mark"):
                raise PermissionDeniedException(
                    f"Access forbidden: Auditor role is strictly read-only and cannot tender or mark exhibits."
                )
            return

        raise PermissionDeniedException(
            f"Access forbidden: Role '{user_role}' lacks authorization for case '{case.case_id}'."
        )

    def _validate_case_preconditions(
        self,
        case_id: str,
        current_user: User,
        action: str = "view"
    ) -> Tuple[Case, str]:
        """
        Validates case existence, access rights, docket sealing, and Section 63 admissibility.
        """
        case = self.db.query(Case).filter_by(case_id=case_id).first()
        if not case:
            raise EntityNotFoundException("Case", case_id)

        # Enforce RBAC
        self._check_case_access(case, current_user, action=action)

        # Pre-condition: Case must be finalized and sealed (COMPLETED)
        if case.status != "COMPLETED":
            raise AppException(
                message=f"Case docket '{case_id}' is in status '{case.status}' and cannot be presented for trial exhibit operations. Docket must be formally finalized and sealed under BSA 2023.",
                status_code=400,
                error_code="CASE_NOT_SEALED",
                details={"case_id": case_id, "current_status": case.status}
            )

        # Pre-condition: Sealing manifest must be valid
        final_audit = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case_id, action="CASE_FINALIZED")
            .first()
        )
        if not final_audit or not final_audit.meta_data or not final_audit.meta_data.get("docket_sealing_hash"):
            raise AppException(
                message=f"Case docket '{case_id}' lacks an authoritative judicial sealing manifest. Cannot perform trial exhibit operations.",
                status_code=400,
                error_code="INVALID_DOCKET_SEALING",
                details={"case_id": case_id}
            )
        docket_sealing_hash = final_audit.meta_data.get("docket_sealing_hash")

        # Pre-condition: Phase 18 Admissibility verification must be valid
        cert = self.admissibility_service.get_admissibility_certificate(case_id, current_user)
        if not cert.get("is_admissible") or cert.get("admissibility_status") != "ADMISSIBLE":
            raise AppException(
                message=f"Case docket '{case_id}' has not passed judicial admissibility verification under BSA 2023 Section 63 (status: {cert.get('admissibility_status')}).",
                status_code=400,
                error_code="INADMISSIBLE_DOCKET",
                details={"case_id": case_id, "admissibility_status": cert.get("admissibility_status")}
            )

        return case, docket_sealing_hash

    def _resolve_target(
        self,
        case: Case,
        target_id: str,
        target_type: str
    ) -> Tuple[str, str, str, Any]:
        """
        Resolves and validates the target digital evidence item or official court report.
        """
        ttype = str(target_type).upper().strip()
        if ttype == "EVIDENCE":
            ev = self.db.query(Evidence).filter_by(evidence_id=target_id, case_id=case.case_id).first()
            if not ev:
                raise EntityNotFoundException("Evidence", target_id)
            if ev.status in ("INTEGRITY_COMPROMISED", "STORAGE_ERROR"):
                raise AppException(
                    message=f"Evidence '{target_id}' cannot be tendered or marked: integrity status is {ev.status}.",
                    status_code=400,
                    error_code="EVIDENCE_COMPROMISED",
                    details={"evidence_id": target_id, "status": ev.status}
                )
            return ev.evidence_id, ev.original_filename, ev.sha256_hash, ev

        elif ttype == "REPORT":
            rep = self.db.query(Report).filter_by(report_id=target_id, case_id=case.case_id).first()
            if not rep:
                rep = self.db.query(CourtReport).filter_by(report_id=target_id, case_id=case.case_id).first()
            if not rep:
                raise EntityNotFoundException("Report", target_id)
            filename = f"CourtReport_{rep.report_id}.pdf"
            return rep.report_id, filename, rep.report_sha256, rep

        else:
            raise ValidationException(
                f"Unsupported target_type '{target_type}'. Must be 'EVIDENCE' or 'REPORT'."
            )

    def _reconstruct_tender_response(self, audit: AuditLog) -> Dict[str, Any]:
        """Reconstructs EvidenceTenderResponse from an immutable AuditLog record."""
        meta = audit.meta_data or {}
        return {
            "success": True,
            "tender_id": meta.get("tender_id", f"TND-{audit.audit_id[4:]}"),
            "case_id": meta.get("case_id"),
            "case_number": meta.get("case_number"),
            "target_id": meta.get("target_id"),
            "target_type": meta.get("target_type"),
            "target_filename": meta.get("target_filename"),
            "sha256_hash": meta.get("sha256_hash"),
            "tendering_party": meta.get("tendering_party"),
            "tendering_witness": meta.get("tendering_witness"),
            "purpose": meta.get("purpose"),
            "tender_notes": meta.get("tender_notes"),
            "tendered_by": meta.get("tendered_by"),
            "tendered_by_username": meta.get("tendered_by_username"),
            "tendered_at": meta.get("tendered_at", audit.timestamp.isoformat()),
            "status": "TENDERED",
            "custody_event_id": meta.get("custody_event_id"),
            "audit_id": audit.audit_id
        }

    def _reconstruct_exhibit_response(self, audit: AuditLog) -> Dict[str, Any]:
        """Reconstructs ExhibitRecordResponse from an immutable AuditLog record."""
        meta = audit.meta_data or {}
        return {
            "success": True,
            "exhibit_id": meta.get("exhibit_id", f"EXH-{audit.audit_id[4:]}"),
            "case_id": meta.get("case_id"),
            "case_number": meta.get("case_number"),
            "exhibit_number": meta.get("exhibit_number"),
            "target_id": meta.get("target_id"),
            "target_type": meta.get("target_type"),
            "target_filename": meta.get("target_filename"),
            "sha256_hash": meta.get("sha256_hash"),
            "tendering_party": meta.get("tendering_party"),
            "tendering_witness": meta.get("tendering_witness"),
            "ruling": meta.get("ruling"),
            "court_bench": meta.get("court_bench"),
            "judicial_officer_name": meta.get("judicial_officer_name"),
            "order_reference": meta.get("order_reference"),
            "objections_raised": meta.get("objections_raised"),
            "ruling_rationale": meta.get("ruling_rationale"),
            "marked_by": meta.get("marked_by"),
            "marked_by_username": meta.get("marked_by_username"),
            "marked_at": meta.get("marked_at", audit.timestamp.isoformat()),
            "custody_event_id": meta.get("custody_event_id"),
            "custody_event_hash": meta.get("custody_event_hash"),
            "audit_id": audit.audit_id
        }

    def tender_evidence(
        self,
        case_id: str,
        current_user: User,
        payload: EvidenceTenderRequest
    ) -> Dict[str, Any]:
        """
        Formally tenders a digital evidence item or Section 63 court report in trial proceedings.
        Tendering submits evidence to the court record without assigning final exhibit number or ruling.
        """
        case, docket_sealing_hash = self._validate_case_preconditions(case_id, current_user, action="tender")

        ttype_str = payload.target_type.value if hasattr(payload.target_type, "value") else str(payload.target_type)
        party_str = payload.tendering_party.value if hasattr(payload.tendering_party, "value") else str(payload.tendering_party)

        target_id, filename, sha256_hash, target_obj = self._resolve_target(case, payload.target_id, ttype_str)

        # Idempotency check: Return existing tender if identical request was previously submitted
        existing_tenders = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case.case_id, action="EXHIBIT_TENDERED")
            .all()
        )
        for t in existing_tenders:
            m = t.meta_data or {}
            if (
                m.get("target_id") == target_id
                and m.get("tendering_party") == party_str
                and m.get("tendering_witness") == payload.tendering_witness
            ):
                logger.info(f"Idempotent evidence tender returned for target '{target_id}' in case '{case_id}'")
                return self._reconstruct_tender_response(t)

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        tender_id = f"TND-{now.year}-{uuid.uuid4().hex[:8].upper()}"

        # Cryptographic Custody Extension (Evidence only, avoiding FK mismatch on reports)
        custody_event_id = None
        if ttype_str == "EVIDENCE":
            desc = (
                f"Evidence '{filename}' formally tendered in court by {party_str} "
                f"({current_user.username}). Witness: {payload.tendering_witness or 'Direct Tender'}. "
                f"Purpose: {payload.purpose or 'Trial Presentation'}."
            )
            ce = self.custody_service.record_event(
                evidence_id=target_id,
                event_type="EXHIBIT_TENDERED_IN_COURT",
                user_id=current_user.id,
                description=desc,
                details={
                    "case_id": case.case_id,
                    "case_number": case.case_number,
                    "target_id": target_id,
                    "target_type": ttype_str,
                    "tendering_party": party_str,
                    "tendering_witness": payload.tendering_witness,
                    "purpose": payload.purpose,
                    "tender_notes": payload.tender_notes,
                    "tender_id": tender_id,
                    "status": "TENDERED"
                }
            )
            custody_event_id = ce.get("event_id")

        # Record Compliance Audit Log: EXHIBIT_TENDERED
        audit_id = f"AUD-{now.year}-{uuid.uuid4().hex[:8].upper()}"
        audit = AuditLog(
            audit_id=audit_id,
            user_id=current_user.id,
            action="EXHIBIT_TENDERED",
            resource_type="CASE",
            resource_id=case.case_id,
            timestamp=now,
            meta_data={
                "tender_id": tender_id,
                "case_id": case.case_id,
                "case_number": case.case_number,
                "target_id": target_id,
                "target_type": ttype_str,
                "target_filename": filename,
                "sha256_hash": sha256_hash,
                "tendering_party": party_str,
                "tendering_witness": payload.tendering_witness,
                "purpose": payload.purpose,
                "tender_notes": payload.tender_notes,
                "tendered_by": current_user.id,
                "tendered_by_username": current_user.username,
                "tendered_at": now_iso,
                "custody_event_id": custody_event_id
            }
        )
        self.db.add(audit)
        self.db.commit()

        logger.info(f"Target '{target_id}' tendered in court for case '{case_id}' by {party_str} [{tender_id}]")

        return {
            "success": True,
            "tender_id": tender_id,
            "case_id": case.case_id,
            "case_number": case.case_number,
            "target_id": target_id,
            "target_type": ttype_str,
            "target_filename": filename,
            "sha256_hash": sha256_hash,
            "tendering_party": party_str,
            "tendering_witness": payload.tendering_witness,
            "purpose": payload.purpose,
            "tender_notes": payload.tender_notes,
            "tendered_by": current_user.id,
            "tendered_by_username": current_user.username,
            "tendered_at": now_iso,
            "status": "TENDERED",
            "custody_event_id": custody_event_id,
            "audit_id": audit_id
        }

    def mark_exhibit(
        self,
        case_id: str,
        current_user: User,
        payload: ExhibitMarkingRequest
    ) -> Dict[str, Any]:
        """
        Formally marks electronic evidence or court report as a judicial trial exhibit
        and records official admissibility determination under BSA 2023 Section 63.
        Strictly restricted to JUDGE.
        """
        case, docket_sealing_hash = self._validate_case_preconditions(case_id, current_user, action="mark")

        clean_ex_num = payload.exhibit_number.strip()
        if not clean_ex_num:
            raise ValidationException("exhibit_number cannot be blank.")

        ttype_str = payload.target_type.value if hasattr(payload.target_type, "value") else str(payload.target_type)
        party_str = payload.tendering_party.value if hasattr(payload.tendering_party, "value") else str(payload.tendering_party)
        ruling_str = payload.ruling.value if hasattr(payload.ruling, "value") else str(payload.ruling)

        target_id, filename, sha256_hash, target_obj = self._resolve_target(case, payload.target_id, ttype_str)

        # Audit and uniqueness validation
        existing_markings = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case.case_id, action="EXHIBIT_MARKED")
            .all()
        )

        for m in existing_markings:
            meta = m.meta_data or {}
            ex_num = meta.get("exhibit_number", "").strip()
            tid = meta.get("target_id")
            rul = meta.get("ruling")

            # 1. Duplicate exhibit number check across different targets
            if ex_num.upper() == clean_ex_num.upper() and tid != target_id:
                raise AppException(
                    message=f"Exhibit identifier '{clean_ex_num}' is already assigned to target '{tid}' in case docket '{case.case_id}'. Duplicate exhibit numbers are prohibited.",
                    status_code=409,
                    error_code="DUPLICATE_EXHIBIT_NUMBER",
                    details={"exhibit_number": clean_ex_num, "existing_target_id": tid}
                )

            # 2. Double admission guard: Target already admitted
            if tid == target_id and rul == "ADMITTED_AS_EXHIBIT":
                # If identical mark request, return idempotently
                if ex_num.upper() == clean_ex_num.upper() and ruling_str == "ADMITTED_AS_EXHIBIT":
                    logger.info(f"Idempotent exhibit marking returned for admitted target '{target_id}' [{clean_ex_num}]")
                    return self._reconstruct_exhibit_response(m)
                raise AppException(
                    message=f"Target '{target_id}' has already been formally admitted as exhibit '{ex_num}' in case docket '{case.case_id}'. Re-admission is prohibited.",
                    status_code=409,
                    error_code="TARGET_ALREADY_ADMITTED",
                    details={"target_id": target_id, "exhibit_number": ex_num}
                )

            # 3. Identical request idempotency
            if tid == target_id and ex_num.upper() == clean_ex_num.upper() and rul == ruling_str:
                logger.info(f"Idempotent exhibit marking returned for target '{target_id}' [{clean_ex_num}]")
                return self._reconstruct_exhibit_response(m)

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        exhibit_id = f"EXH-{now.year}-{uuid.uuid4().hex[:8].upper()}"
        judge_name = (
            payload.judicial_officer_name
            or current_user.full_name
            or current_user.username
        )
        bench = payload.court_bench or case.jurisdiction or "Court of Competent Jurisdiction"

        # Cryptographic Custody Extension (Evidence only)
        custody_event_id = None
        custody_event_hash = None
        if ttype_str == "EVIDENCE":
            desc = (
                f"Judicial Exhibit '{clean_ex_num}' marked by {judge_name}. "
                f"Ruling: {ruling_str}. Bench: {bench}. "
                f"Order: {payload.order_reference or 'Court Proceedings Record'}."
            )
            ce = self.custody_service.record_event(
                evidence_id=target_id,
                event_type="JUDICIAL_EXHIBIT_MARKED",
                user_id=current_user.id,
                description=desc,
                details={
                    "case_id": case.case_id,
                    "case_number": case.case_number,
                    "target_id": target_id,
                    "target_type": ttype_str,
                    "exhibit_number": clean_ex_num,
                    "exhibit_id": exhibit_id,
                    "tendering_party": party_str,
                    "tendering_witness": payload.tendering_witness,
                    "ruling": ruling_str,
                    "court_bench": bench,
                    "judicial_officer_name": judge_name,
                    "order_reference": payload.order_reference,
                    "objections_raised": payload.objections_raised,
                    "ruling_rationale": payload.ruling_rationale
                }
            )
            custody_event_id = ce.get("event_id")
            custody_event_hash = ce.get("event_hash")

        # Record Compliance Audit Log: EXHIBIT_MARKED
        audit_id = f"AUD-{now.year}-{uuid.uuid4().hex[:8].upper()}"
        audit = AuditLog(
            audit_id=audit_id,
            user_id=current_user.id,
            action="EXHIBIT_MARKED",
            resource_type="CASE",
            resource_id=case.case_id,
            timestamp=now,
            meta_data={
                "exhibit_id": exhibit_id,
                "case_id": case.case_id,
                "case_number": case.case_number,
                "exhibit_number": clean_ex_num,
                "target_id": target_id,
                "target_type": ttype_str,
                "target_filename": filename,
                "sha256_hash": sha256_hash,
                "tendering_party": party_str,
                "tendering_witness": payload.tendering_witness,
                "ruling": ruling_str,
                "court_bench": bench,
                "judicial_officer_name": judge_name,
                "order_reference": payload.order_reference,
                "objections_raised": payload.objections_raised,
                "ruling_rationale": payload.ruling_rationale,
                "marked_by": current_user.id,
                "marked_by_username": current_user.username,
                "marked_at": now_iso,
                "custody_event_id": custody_event_id,
                "custody_event_hash": custody_event_hash
            }
        )
        self.db.add(audit)
        self.db.commit()

        logger.info(f"Exhibit '{clean_ex_num}' marked for target '{target_id}' in case '{case_id}' with ruling '{ruling_str}'")

        return {
            "success": True,
            "exhibit_id": exhibit_id,
            "case_id": case.case_id,
            "case_number": case.case_number,
            "exhibit_number": clean_ex_num,
            "target_id": target_id,
            "target_type": ttype_str,
            "target_filename": filename,
            "sha256_hash": sha256_hash,
            "tendering_party": party_str,
            "tendering_witness": payload.tendering_witness,
            "ruling": ruling_str,
            "court_bench": bench,
            "judicial_officer_name": judge_name,
            "order_reference": payload.order_reference,
            "objections_raised": payload.objections_raised,
            "ruling_rationale": payload.ruling_rationale,
            "marked_by": current_user.id,
            "marked_by_username": current_user.username,
            "marked_at": now_iso,
            "custody_event_id": custody_event_id,
            "custody_event_hash": custody_event_hash,
            "audit_id": audit_id
        }

    def get_case_exhibit_register(
        self,
        case_id: str,
        current_user: User
    ) -> Dict[str, Any]:
        """
        Retrieves the complete, chronologically sorted Judicial Exhibit Register for a case docket.
        Strictly read-only; sanitizes sensitive internal paths.
        """
        case = self.db.query(Case).filter_by(case_id=case_id).first()
        if not case:
            raise EntityNotFoundException("Case", case_id)

        self._check_case_access(case, current_user, action="view")

        # Fetch sealing hash if finalized
        final_audit = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case_id, action="CASE_FINALIZED")
            .first()
        )
        docket_sealing_hash = (final_audit.meta_data or {}).get("docket_sealing_hash") if final_audit else None

        # Fetch exhibit markings chronologically
        marked_audits = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case_id, action="EXHIBIT_MARKED")
            .order_by(AuditLog.timestamp.asc())
            .all()
        )
        exhibit_items = [self._reconstruct_exhibit_response(a) for a in marked_audits]

        # Fetch tenders chronologically
        tender_audits = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case_id, action="EXHIBIT_TENDERED")
            .order_by(AuditLog.timestamp.asc())
            .all()
        )
        tender_items = [self._reconstruct_tender_response(a) for a in tender_audits]

        # Aggregate counts
        admitted = sum(1 for e in exhibit_items if e.get("ruling") == "ADMITTED_AS_EXHIBIT")
        mfi = sum(1 for e in exhibit_items if e.get("ruling") == "MARKED_FOR_IDENTIFICATION")
        objected = sum(1 for e in exhibit_items if e.get("ruling") == "OBJECTED_DECISION_RESERVED")
        rejected = sum(1 for e in exhibit_items if e.get("ruling") == "REJECTED")

        return {
            "success": True,
            "case_id": case.case_id,
            "case_number": case.case_number,
            "case_status": case.status,
            "docket_sealing_hash": docket_sealing_hash,
            "total_exhibits": len(exhibit_items),
            "admitted_count": admitted,
            "mfi_count": mfi,
            "objected_count": objected,
            "rejected_count": rejected,
            "exhibits": exhibit_items,
            "tenders": tender_items
        }

    def get_exhibit_by_number(
        self,
        case_id: str,
        exhibit_number: str,
        current_user: User
    ) -> Dict[str, Any]:
        """
        Retrieves a specific judicial exhibit record by court exhibit number (e.g. 'Ex. P-1').
        """
        case = self.db.query(Case).filter_by(case_id=case_id).first()
        if not case:
            raise EntityNotFoundException("Case", case_id)

        self._check_case_access(case, current_user, action="view")

        clean_ex = exhibit_number.strip().upper()

        marked_audits = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case_id, action="EXHIBIT_MARKED")
            .all()
        )
        for a in marked_audits:
            meta = a.meta_data or {}
            if meta.get("exhibit_number", "").strip().upper() == clean_ex:
                return self._reconstruct_exhibit_response(a)

        raise EntityNotFoundException("Exhibit", exhibit_number)

    def get_evidence_exhibit(
        self,
        case_id: str,
        evidence_id: str,
        current_user: User
    ) -> Dict[str, Any]:
        """
        Inspects courtroom exhibit marking and tender status for a single evidence artifact.
        """
        case = self.db.query(Case).filter_by(case_id=case_id).first()
        if not case:
            raise EntityNotFoundException("Case", case_id)

        self._check_case_access(case, current_user, action="view")

        evidence = self.db.query(Evidence).filter_by(evidence_id=evidence_id, case_id=case.case_id).first()
        if not evidence:
            raise EntityNotFoundException("Evidence", evidence_id)

        # Look for exhibit marking
        marked_audits = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case_id, action="EXHIBIT_MARKED")
            .order_by(AuditLog.timestamp.desc())
            .all()
        )
        marking_record = None
        for a in marked_audits:
            if (a.meta_data or {}).get("target_id") == evidence_id:
                marking_record = a.meta_data
                break

        # Look for tendering record
        tender_audits = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case_id, action="EXHIBIT_TENDERED")
            .order_by(AuditLog.timestamp.desc())
            .all()
        )
        tender_record = None
        for a in tender_audits:
            if (a.meta_data or {}).get("target_id") == evidence_id:
                tender_record = a.meta_data
                break

        is_marked = marking_record is not None
        is_tendered = tender_record is not None

        if is_marked:
            current_status = marking_record.get("ruling", "MARKED")
        elif is_tendered:
            current_status = "TENDERED"
        else:
            current_status = "UNMARKED"

        return {
            "case_id": case.case_id,
            "case_number": case.case_number,
            "evidence_id": evidence.evidence_id,
            "original_filename": evidence.original_filename,
            "sha256_hash": evidence.sha256_hash,
            "is_tendered": is_tendered,
            "is_marked": is_marked,
            "exhibit_number": marking_record.get("exhibit_number") if marking_record else None,
            "ruling": marking_record.get("ruling") if marking_record else None,
            "tendering_party": (marking_record or tender_record or {}).get("tendering_party"),
            "tendering_witness": (marking_record or tender_record or {}).get("tendering_witness"),
            "judicial_officer_name": marking_record.get("judicial_officer_name") if marking_record else None,
            "court_bench": marking_record.get("court_bench") if marking_record else None,
            "marked_at": marking_record.get("marked_at") if marking_record else None,
            "tendered_at": tender_record.get("tendered_at") if tender_record else None,
            "status": current_status
        }
