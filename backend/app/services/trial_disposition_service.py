"""
NYAYAI - Judicial Trial Disposition, Objection Resolution & Exhibit Disposal Service (Phase 22)
Module: backend.app.services.trial_disposition_service
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Enforces statutory judicial trial disposition, objection resolution, exhibit disposal,
and governed docket archival under Bharatiya Nagarik Suraksha Sanhita, 2023 (BNSS 2023) Section 503
and Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023) Section 63:
1. Strict Judicial Authority: All write operations (verdict, objection resolution, disposal orders,
   archival) are restricted strictly to JUDGE. Non-judges receive HTTP 403 Forbidden.
2. Case Pre-conditions: Docket must be finalized and cryptographically sealed (COMPLETED) with
   verified BSA Section 63 admissibility certificate.
3. Verdict Pronouncement: Adjudicates trial outcomes (CONVICTED, ACQUITTED, DISCHARGED, DISMISSED,
   PARTIALLY_CONVICTED) and calculates statutory appellate limitation holds.
4. Objection Resolution: Resolves reserved Section 63 objections (OBJECTED_DECISION_RESERVED) and
   MFI items (MARKED_FOR_IDENTIFICATION) into final rulings (ADMITTED_AS_EXHIBIT or REJECTED).
   Exhibits already in final states cannot be resolved (HTTP 409 Conflict).
5. Statutory Evidence Disposal: Enforces BNSS 2023 Section 503 disposal orders (RETURNED_TO_OWNER,
   CONFISCATED, DESTROYED, RETAINED_FOR_APPEAL).
   CRITICAL: DESTROYED orders strictly log judicial disposal and NEVER physically delete WORM vault files.
6. Governed Docket Archival: Transitions COMPLETED -> ARCHIVED only when trial verdict is pronounced,
   all exhibits are fully resolved, and all exhibits have statutory disposal orders.
7. Cryptographic Custody Continuity: Appends EXHIBIT_OBJECTION_RESOLVED, EXHIBIT_DISPOSAL_ORDERED,
   and DOCKET_ARCHIVED custody blocks to evidence items without breaking historical chains.
8. Idempotency & Conflict: Repeated identical requests return the existing record; conflicting
   subsequent determinations return HTTP 409 Conflict.
9. Zero DB Mutations: Operates entirely through existing AuditLog JSON metadata and CustodyEvent chaining.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy.orm import Session

from backend.app.models.user import User
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.report import Report, CourtReport
from backend.app.models.custody import CustodyEvent
from backend.app.models.audit import AuditLog
from backend.app.schemas.trial_disposition import (
    TrialVerdictEnum,
    ResolvedRulingEnum,
    DisposalTypeEnum,
    TrialVerdictRequest,
    TrialVerdictResponse,
    ObjectionResolutionRequest,
    ObjectionResolutionResponse,
    ExhibitDisposalOrderRequest,
    ExhibitDisposalOrderResponse,
    CaseArchivalRequest,
    CaseArchivalResponse,
    CaseTrialDispositionRegisterResponse
)
from backend.app.services.base import BaseService
from backend.app.services.custody_service import CustodyService
from backend.app.services.admissibility_service import AdmissibilityService
from backend.app.services.case_finalization_service import CaseFinalizationService
from backend.app.services.exhibit_marking_service import ExhibitMarkingService
from backend.app.utils.exceptions import (
    AppException,
    EntityNotFoundException,
    PermissionDeniedException,
    ValidationException
)
from backend.app.utils.logger import get_logger

logger = get_logger("trial_disposition_service")


class TrialDispositionService(BaseService):
    """
    Coordinates judicial trial verdict pronouncement, reserved objection resolution,
    statutory exhibit disposal orders, and governed case archival.
    """

    def __init__(self, db: Session):
        super().__init__(db)
        self.custody_service = CustodyService(db)
        self.admissibility_service = AdmissibilityService(db)
        self.finalization_service = CaseFinalizationService(db)
        self.exhibit_service = ExhibitMarkingService(db)

    def _check_case_access(self, case: Case, current_user: User, action: str = "view") -> None:
        """
        Enforces statutory separation of powers and case-scoped authorization:
        - Judicial write actions (verdict, resolve_objection, disposal_order, archive): Strictly JUDGE only.
        - Read actions: JUDGE, ADMIN, SYSTEM_LEAD, AUDITOR permitted court-wide.
        - INVESTIGATOR: Permitted strictly for owned/created cases.
        - LAWYER: Permitted strictly for assigned cases.
        """
        user_role = (current_user.role or "").strip().upper()

        # 1. Strict Judicial Authority for all disposition write operations
        if action in ("verdict", "resolve_objection", "disposal_order", "archive"):
            if user_role != "JUDGE":
                raise PermissionDeniedException(
                    f"Access forbidden: Only a JUDGE may perform judicial disposition operations ({action}). "
                    f"Role '{user_role}' lacks judicial authority."
                )
            return

        # 2. JUDGE, ADMIN, SYSTEM_LEAD, AUDITOR have court-wide read access
        if user_role in ("JUDGE", "ADMIN", "SYSTEM_LEAD", "AUDITOR"):
            return

        # 3. INVESTIGATOR: Scoped strictly to owned/created cases
        if user_role == "INVESTIGATOR":
            if case.created_by != current_user.id and case.created_by != current_user.username:
                raise PermissionDeniedException(
                    f"Access forbidden: Investigator '{current_user.username}' is not authorized for case '{case.case_id}' (cross-case access denied)."
                )
            return

        # 4. LAWYER: Permitted on cases with case-scoped association
        if user_role == "LAWYER":
            desc = (case.description or "").lower()
            if "assigned_counsel" in desc or "counsel:" in desc or "lawyer:" in desc:
                if current_user.username.lower() not in desc and current_user.id.lower() not in desc:
                    raise PermissionDeniedException(
                        f"Access forbidden: Lawyer '{current_user.username}' is not assigned to case '{case.case_id}' (cross-case access denied)."
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

        # Pre-condition: Case must be COMPLETED (or ARCHIVED for read queries)
        if action != "view" and case.status not in ("COMPLETED", "ARCHIVED"):
            raise AppException(
                message=f"Case docket '{case_id}' is in status '{case.status}' and cannot undergo trial disposition. Docket must be formally finalized and sealed under BSA 2023.",
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
                message=f"Case docket '{case_id}' lacks an authoritative judicial sealing manifest. Cannot perform trial disposition operations.",
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

    def _find_exhibit_marking(self, case_id: str, exhibit_number: str) -> Tuple[AuditLog, Dict[str, Any]]:
        """
        Locates the original exhibit marking record by court exhibit number (e.g. 'Ex. P-1').
        """
        clean_ex = exhibit_number.strip().upper()
        marked_audits = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case_id, action="EXHIBIT_MARKED")
            .all()
        )
        for a in marked_audits:
            meta = a.meta_data or {}
            if meta.get("exhibit_number", "").strip().upper() == clean_ex:
                return a, meta

        raise EntityNotFoundException("Exhibit", exhibit_number)

    def _get_effective_exhibit_ruling(self, case_id: str, exhibit_number: str, initial_ruling: str) -> str:
        """
        Determines current effective ruling taking into account any subsequent objection resolution.
        """
        clean_ex = exhibit_number.strip().upper()
        res_audits = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case_id, action="OBJECTION_DECISION_RESOLVED")
            .order_by(AuditLog.timestamp.desc())
            .all()
        )
        for a in res_audits:
            meta = a.meta_data or {}
            if meta.get("exhibit_number", "").strip().upper() == clean_ex:
                return meta.get("final_ruling", initial_ruling)
        return initial_ruling

    def _reconstruct_verdict_response(self, audit: AuditLog) -> Dict[str, Any]:
        """Reconstructs TrialVerdictResponse from immutable AuditLog."""
        meta = audit.meta_data or {}
        return {
            "success": True,
            "disposition_id": meta.get("disposition_id", f"DISP-{audit.audit_id[4:]}"),
            "case_id": meta.get("case_id"),
            "case_number": meta.get("case_number"),
            "verdict": meta.get("verdict"),
            "court_bench": meta.get("court_bench"),
            "judicial_officer_name": meta.get("judicial_officer_name"),
            "order_reference": meta.get("order_reference"),
            "disposition_summary": meta.get("disposition_summary"),
            "statutory_provisions": meta.get("statutory_provisions", []),
            "appeal_limitation_days": meta.get("appeal_limitation_days", 60),
            "pronounced_by": meta.get("pronounced_by"),
            "pronounced_by_username": meta.get("pronounced_by_username"),
            "pronounced_at": meta.get("pronounced_at", audit.timestamp.isoformat()),
            "appellate_hold_expires_at": meta.get("appellate_hold_expires_at"),
            "audit_id": audit.audit_id
        }

    def _reconstruct_resolution_response(self, audit: AuditLog) -> Dict[str, Any]:
        """Reconstructs ObjectionResolutionResponse from immutable AuditLog."""
        meta = audit.meta_data or {}
        return {
            "success": True,
            "resolution_id": meta.get("resolution_id", f"RES-{audit.audit_id[4:]}"),
            "case_id": meta.get("case_id"),
            "case_number": meta.get("case_number"),
            "exhibit_number": meta.get("exhibit_number"),
            "target_id": meta.get("target_id"),
            "target_type": meta.get("target_type"),
            "target_filename": meta.get("target_filename"),
            "sha256_hash": meta.get("sha256_hash"),
            "prior_ruling": meta.get("prior_ruling"),
            "final_ruling": meta.get("final_ruling"),
            "ruling_rationale": meta.get("ruling_rationale"),
            "order_reference": meta.get("order_reference"),
            "resolved_by": meta.get("resolved_by"),
            "resolved_by_username": meta.get("resolved_by_username"),
            "resolved_at": meta.get("resolved_at", audit.timestamp.isoformat()),
            "custody_event_id": meta.get("custody_event_id"),
            "audit_id": audit.audit_id
        }

    def _reconstruct_disposal_response(self, audit: AuditLog) -> Dict[str, Any]:
        """Reconstructs ExhibitDisposalOrderResponse from immutable AuditLog."""
        meta = audit.meta_data or {}
        return {
            "success": True,
            "disposal_order_id": meta.get("disposal_order_id", f"DSP-{audit.audit_id[4:]}"),
            "case_id": meta.get("case_id"),
            "case_number": meta.get("case_number"),
            "exhibit_number": meta.get("exhibit_number"),
            "target_id": meta.get("target_id"),
            "target_type": meta.get("target_type"),
            "target_filename": meta.get("target_filename"),
            "sha256_hash": meta.get("sha256_hash"),
            "disposal_type": meta.get("disposal_type"),
            "statutory_authority": meta.get("statutory_authority", "BNSS_2023_SECTION_503"),
            "disposal_instructions": meta.get("disposal_instructions"),
            "recipient_details": meta.get("recipient_details"),
            "appellate_hold": bool(meta.get("appellate_hold", False)),
            "order_reference": meta.get("order_reference"),
            "ordered_by": meta.get("ordered_by"),
            "ordered_by_username": meta.get("ordered_by_username"),
            "ordered_at": meta.get("ordered_at", audit.timestamp.isoformat()),
            "custody_event_id": meta.get("custody_event_id"),
            "audit_id": audit.audit_id
        }

    def record_trial_verdict(
        self,
        case_id: str,
        current_user: User,
        payload: TrialVerdictRequest
    ) -> Dict[str, Any]:
        """
        Pronounces official judicial trial verdict and records judgment disposition (JUDGE only).
        """
        case, docket_sealing_hash = self._validate_case_preconditions(case_id, current_user, action="verdict")

        verdict_str = payload.verdict.value if hasattr(payload.verdict, "value") else str(payload.verdict)

        # Check existing trial verdict in docket
        existing_verdict = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case.case_id, action="TRIAL_VERDICT_RECORDED")
            .first()
        )
        if existing_verdict:
            meta = existing_verdict.meta_data or {}
            if meta.get("verdict") == verdict_str:
                logger.info(f"Idempotent verdict pronouncement returned for case '{case_id}' [{verdict_str}]")
                return self._reconstruct_verdict_response(existing_verdict)
            raise AppException(
                message=f"Trial verdict has already been formally pronounced as '{meta.get('verdict')}' for case docket '{case_id}'. Conflicting verdict modification is prohibited.",
                status_code=409,
                error_code="TRIAL_ALREADY_ADJUDICATED",
                details={"case_id": case_id, "existing_verdict": meta.get("verdict")}
            )

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        disposition_id = f"DISP-{now.year}-{uuid.uuid4().hex[:8].upper()}"

        judge_name = (
            payload.judicial_officer_name
            or current_user.full_name
            or current_user.username
        )
        bench = payload.court_bench or case.jurisdiction or "Court of Competent Jurisdiction"

        # Calculate statutory appellate limitation hold
        limitation_days = payload.appeal_limitation_days if payload.appeal_limitation_days is not None else 60
        hold_expiry = (now + timedelta(days=limitation_days)).isoformat()

        # Record Compliance Audit Log: TRIAL_VERDICT_RECORDED
        audit_id = f"AUD-{now.year}-{uuid.uuid4().hex[:8].upper()}"
        audit = AuditLog(
            audit_id=audit_id,
            user_id=current_user.id,
            action="TRIAL_VERDICT_RECORDED",
            resource_type="CASE",
            resource_id=case.case_id,
            timestamp=now,
            meta_data={
                "disposition_id": disposition_id,
                "case_id": case.case_id,
                "case_number": case.case_number,
                "verdict": verdict_str,
                "court_bench": bench,
                "judicial_officer_name": judge_name,
                "order_reference": payload.order_reference,
                "disposition_summary": payload.disposition_summary,
                "statutory_provisions": payload.statutory_provisions or [],
                "appeal_limitation_days": limitation_days,
                "appellate_hold_expires_at": hold_expiry,
                "pronounced_by": current_user.id,
                "pronounced_by_username": current_user.username,
                "pronounced_at": now_iso
            }
        )
        self.db.add(audit)
        self.db.commit()

        logger.info(f"Trial verdict '{verdict_str}' formally pronounced for case '{case_id}' by {judge_name} [{disposition_id}]")

        return {
            "success": True,
            "disposition_id": disposition_id,
            "case_id": case.case_id,
            "case_number": case.case_number,
            "verdict": verdict_str,
            "court_bench": bench,
            "judicial_officer_name": judge_name,
            "order_reference": payload.order_reference,
            "disposition_summary": payload.disposition_summary,
            "statutory_provisions": payload.statutory_provisions or [],
            "appeal_limitation_days": limitation_days,
            "pronounced_by": current_user.id,
            "pronounced_by_username": current_user.username,
            "pronounced_at": now_iso,
            "appellate_hold_expires_at": hold_expiry,
            "audit_id": audit_id
        }

    def resolve_objection(
        self,
        case_id: str,
        exhibit_number: str,
        current_user: User,
        payload: ObjectionResolutionRequest
    ) -> Dict[str, Any]:
        """
        Formally resolves a reserved Section 63 objection (OBJECTED_DECISION_RESERVED) or
        converts an identification marking (MARKED_FOR_IDENTIFICATION) to ADMITTED_AS_EXHIBIT or REJECTED.
        Strictly restricted to JUDGE.
        """
        case, docket_sealing_hash = self._validate_case_preconditions(case_id, current_user, action="resolve_objection")

        clean_ex = exhibit_number.strip().upper()
        marking_audit, marking_meta = self._find_exhibit_marking(case.case_id, clean_ex)

        initial_ruling = marking_meta.get("ruling")
        effective_ruling = self._get_effective_exhibit_ruling(case.case_id, clean_ex, initial_ruling)

        final_ruling_str = payload.final_ruling.value if hasattr(payload.final_ruling, "value") else str(payload.final_ruling)
        if final_ruling_str not in ("ADMITTED_AS_EXHIBIT", "REJECTED"):
            raise ValidationException("Final ruling must be ADMITTED_AS_EXHIBIT or REJECTED.")

        target_id = marking_meta.get("target_id")
        target_type = marking_meta.get("target_type")
        target_filename = marking_meta.get("target_filename")
        sha256_hash = marking_meta.get("sha256_hash")

        # Check existing resolution in AuditLog
        existing_res = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case.case_id, action="OBJECTION_DECISION_RESOLVED")
            .all()
        )
        for r in existing_res:
            m = r.meta_data or {}
            if m.get("exhibit_number", "").strip().upper() == clean_ex:
                if m.get("final_ruling") == final_ruling_str:
                    logger.info(f"Idempotent objection resolution returned for exhibit '{clean_ex}' [{final_ruling_str}]")
                    return self._reconstruct_resolution_response(r)
                raise AppException(
                    message=f"Exhibit '{clean_ex}' has already been resolved with ruling '{m.get('final_ruling')}'. Conflicting ruling resolution is prohibited.",
                    status_code=409,
                    error_code="EXHIBIT_ALREADY_RESOLVED",
                    details={"exhibit_number": clean_ex, "current_ruling": m.get("final_ruling")}
                )

        # Exhibit must be in OBJECTED_DECISION_RESERVED or MARKED_FOR_IDENTIFICATION to be resolved
        if effective_ruling not in ("OBJECTED_DECISION_RESERVED", "MARKED_FOR_IDENTIFICATION"):
            raise AppException(
                message=f"Exhibit '{clean_ex}' is already in final ruling state '{effective_ruling}'. Only exhibits in OBJECTED_DECISION_RESERVED or MARKED_FOR_IDENTIFICATION can be resolved.",
                status_code=409,
                error_code="EXHIBIT_NOT_RESERVED",
                details={"exhibit_number": clean_ex, "current_ruling": effective_ruling}
            )

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        resolution_id = f"RES-{now.year}-{uuid.uuid4().hex[:8].upper()}"

        judge_name = (
            payload.judicial_officer_name
            or current_user.full_name
            or current_user.username
        )
        bench = payload.court_bench or case.jurisdiction or "Court of Competent Jurisdiction"

        # Cryptographic Custody Extension (Evidence only)
        custody_event_id = None
        if target_type == "EVIDENCE":
            desc = (
                f"Judicial objection resolved for exhibit '{clean_ex}' by {judge_name}. "
                f"Prior: {effective_ruling} -> Final: {final_ruling_str}. "
                f"Rationale: {payload.ruling_rationale or 'Admissibility determined upon final hearing'}."
            )
            ce = self.custody_service.record_event(
                evidence_id=target_id,
                event_type="EXHIBIT_OBJECTION_RESOLVED",
                user_id=current_user.id,
                description=desc,
                details={
                    "case_id": case.case_id,
                    "case_number": case.case_number,
                    "exhibit_number": clean_ex,
                    "resolution_id": resolution_id,
                    "target_id": target_id,
                    "target_type": target_type,
                    "prior_ruling": effective_ruling,
                    "final_ruling": final_ruling_str,
                    "ruling_rationale": payload.ruling_rationale,
                    "order_reference": payload.order_reference,
                    "court_bench": bench,
                    "judicial_officer_name": judge_name
                }
            )
            custody_event_id = ce.get("event_id")

        # Record Compliance Audit Log: OBJECTION_DECISION_RESOLVED
        audit_id = f"AUD-{now.year}-{uuid.uuid4().hex[:8].upper()}"
        audit = AuditLog(
            audit_id=audit_id,
            user_id=current_user.id,
            action="OBJECTION_DECISION_RESOLVED",
            resource_type="CASE",
            resource_id=case.case_id,
            timestamp=now,
            meta_data={
                "resolution_id": resolution_id,
                "case_id": case.case_id,
                "case_number": case.case_number,
                "exhibit_number": clean_ex,
                "target_id": target_id,
                "target_type": target_type,
                "target_filename": target_filename,
                "sha256_hash": sha256_hash,
                "prior_ruling": effective_ruling,
                "final_ruling": final_ruling_str,
                "ruling_rationale": payload.ruling_rationale,
                "order_reference": payload.order_reference,
                "court_bench": bench,
                "judicial_officer_name": judge_name,
                "resolved_by": current_user.id,
                "resolved_by_username": current_user.username,
                "resolved_at": now_iso,
                "custody_event_id": custody_event_id
            }
        )
        self.db.add(audit)
        self.db.commit()

        logger.info(f"Exhibit '{clean_ex}' objection resolved: {effective_ruling} -> {final_ruling_str} [{resolution_id}]")

        return {
            "success": True,
            "resolution_id": resolution_id,
            "case_id": case.case_id,
            "case_number": case.case_number,
            "exhibit_number": clean_ex,
            "target_id": target_id,
            "target_type": target_type,
            "target_filename": target_filename,
            "sha256_hash": sha256_hash,
            "prior_ruling": effective_ruling,
            "final_ruling": final_ruling_str,
            "ruling_rationale": payload.ruling_rationale,
            "order_reference": payload.order_reference,
            "resolved_by": current_user.id,
            "resolved_by_username": current_user.username,
            "resolved_at": now_iso,
            "custody_event_id": custody_event_id,
            "audit_id": audit_id
        }

    def order_exhibit_disposal(
        self,
        case_id: str,
        exhibit_number: str,
        current_user: User,
        payload: ExhibitDisposalOrderRequest
    ) -> Dict[str, Any]:
        """
        Passes formal statutory exhibit disposal order under BNSS 2023 Section 503 (JUDGE only).
        Permitted types: RETURNED_TO_OWNER, CONFISCATED, DESTROYED, RETAINED_FOR_APPEAL.
        CRITICAL: DESTROYED orders strictly log judicial disposal; physical WORM files are NEVER deleted.
        """
        case, docket_sealing_hash = self._validate_case_preconditions(case_id, current_user, action="disposal_order")

        clean_ex = exhibit_number.strip().upper()
        marking_audit, marking_meta = self._find_exhibit_marking(case.case_id, clean_ex)

        disposal_str = payload.disposal_type.value if hasattr(payload.disposal_type, "value") else str(payload.disposal_type)
        if disposal_str not in ("RETURNED_TO_OWNER", "CONFISCATED", "DESTROYED", "RETAINED_FOR_APPEAL"):
            raise ValidationException(f"Unsupported disposal type '{disposal_str}'.")

        target_id = marking_meta.get("target_id")
        target_type = marking_meta.get("target_type")
        target_filename = marking_meta.get("target_filename")
        sha256_hash = marking_meta.get("sha256_hash")

        # Check existing disposal order for exhibit
        existing_orders = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case.case_id, action="EXHIBIT_DISPOSAL_ORDERED")
            .all()
        )
        for o in existing_orders:
            m = o.meta_data or {}
            if m.get("exhibit_number", "").strip().upper() == clean_ex:
                if m.get("disposal_type") == disposal_str:
                    logger.info(f"Idempotent disposal order returned for exhibit '{clean_ex}' [{disposal_str}]")
                    return self._reconstruct_disposal_response(o)
                raise AppException(
                    message=f"Exhibit '{clean_ex}' already has an active disposal order '{m.get('disposal_type')}'. Conflicting disposal orders are prohibited.",
                    status_code=409,
                    error_code="DISPOSAL_ALREADY_ORDERED",
                    details={"exhibit_number": clean_ex, "current_disposal_type": m.get("disposal_type")}
                )

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        disposal_order_id = f"DSP-{now.year}-{uuid.uuid4().hex[:8].upper()}"

        judge_name = (
            payload.judicial_officer_name
            or current_user.full_name
            or current_user.username
        )
        bench = payload.court_bench or case.jurisdiction or "Court of Competent Jurisdiction"
        statutory_authority = payload.statutory_authority or "BNSS_2023_SECTION_503"
        appellate_hold = bool(payload.appellate_hold or disposal_str == "RETAINED_FOR_APPEAL")

        # Cryptographic Custody Extension (Evidence only)
        # Note: If disposal_type == DESTROYED, digital custody records the legal destruction order,
        # but physical storage reference and file remain completely intact in WORM vault.
        custody_event_id = None
        if target_type == "EVIDENCE":
            desc = (
                f"Statutory exhibit disposal ordered for '{clean_ex}' under {statutory_authority} by {judge_name}. "
                f"Disposal Type: {disposal_str}. Appellate Hold: {appellate_hold}. "
                f"Order: {payload.order_reference or 'Court Disposal Sheet'}."
            )
            ce = self.custody_service.record_event(
                evidence_id=target_id,
                event_type="EXHIBIT_DISPOSAL_ORDERED",
                user_id=current_user.id,
                description=desc,
                details={
                    "case_id": case.case_id,
                    "case_number": case.case_number,
                    "exhibit_number": clean_ex,
                    "disposal_order_id": disposal_order_id,
                    "target_id": target_id,
                    "target_type": target_type,
                    "disposal_type": disposal_str,
                    "statutory_authority": statutory_authority,
                    "disposal_instructions": payload.disposal_instructions,
                    "recipient_details": payload.recipient_details,
                    "appellate_hold": appellate_hold,
                    "order_reference": payload.order_reference,
                    "court_bench": bench,
                    "judicial_officer_name": judge_name,
                    "worm_file_preserved": True
                }
            )
            custody_event_id = ce.get("event_id")

        # Record Compliance Audit Log: EXHIBIT_DISPOSAL_ORDERED
        audit_id = f"AUD-{now.year}-{uuid.uuid4().hex[:8].upper()}"
        audit = AuditLog(
            audit_id=audit_id,
            user_id=current_user.id,
            action="EXHIBIT_DISPOSAL_ORDERED",
            resource_type="CASE",
            resource_id=case.case_id,
            timestamp=now,
            meta_data={
                "disposal_order_id": disposal_order_id,
                "case_id": case.case_id,
                "case_number": case.case_number,
                "exhibit_number": clean_ex,
                "target_id": target_id,
                "target_type": target_type,
                "target_filename": target_filename,
                "sha256_hash": sha256_hash,
                "disposal_type": disposal_str,
                "statutory_authority": statutory_authority,
                "disposal_instructions": payload.disposal_instructions,
                "recipient_details": payload.recipient_details,
                "appellate_hold": appellate_hold,
                "order_reference": payload.order_reference,
                "court_bench": bench,
                "judicial_officer_name": judge_name,
                "ordered_by": current_user.id,
                "ordered_by_username": current_user.username,
                "ordered_at": now_iso,
                "custody_event_id": custody_event_id,
                "worm_file_preserved": True
            }
        )
        self.db.add(audit)
        self.db.commit()

        logger.info(f"Disposal order '{disposal_str}' recorded for exhibit '{clean_ex}' in case '{case_id}' [{disposal_order_id}]")

        return {
            "success": True,
            "disposal_order_id": disposal_order_id,
            "case_id": case.case_id,
            "case_number": case.case_number,
            "exhibit_number": clean_ex,
            "target_id": target_id,
            "target_type": target_type,
            "target_filename": target_filename,
            "sha256_hash": sha256_hash,
            "disposal_type": disposal_str,
            "statutory_authority": statutory_authority,
            "disposal_instructions": payload.disposal_instructions,
            "recipient_details": payload.recipient_details,
            "appellate_hold": appellate_hold,
            "order_reference": payload.order_reference,
            "ordered_by": current_user.id,
            "ordered_by_username": current_user.username,
            "ordered_at": now_iso,
            "custody_event_id": custody_event_id,
            "audit_id": audit_id
        }

    def archive_case(
        self,
        case_id: str,
        current_user: User,
        payload: CaseArchivalRequest
    ) -> Dict[str, Any]:
        """
        Formally archives a finalized case docket at the conclusion of trial (JUDGE only).
        Pre-conditions:
        1. Case must be in COMPLETED status.
        2. Trial verdict must have been formally pronounced.
        3. All exhibits in docket must have definitive rulings (no unresolved objections or MFI).
        4. All exhibits in docket must have recorded statutory disposal orders under BNSS 2023.
        Transitions case.status from COMPLETED -> ARCHIVED.
        """
        case, docket_sealing_hash = self._validate_case_preconditions(case_id, current_user, action="archive")

        # Idempotency check: Already archived
        if case.status == "ARCHIVED":
            existing_arch = (
                self.db.query(AuditLog)
                .filter_by(resource_id=case.case_id, action="CASE_DOCKET_ARCHIVED")
                .first()
            )
            if existing_arch:
                logger.info(f"Idempotent archival returned for already archived case '{case_id}'")
                meta = existing_arch.meta_data or {}
                return {
                    "success": True,
                    "case_id": case.case_id,
                    "case_number": case.case_number,
                    "previous_status": "COMPLETED",
                    "current_status": "ARCHIVED",
                    "verdict": meta.get("verdict", "CONVICTED"),
                    "total_exhibits_disposed": meta.get("total_exhibits_disposed", 0),
                    "appellate_holds_active": meta.get("appellate_holds_active", 0),
                    "reason": meta.get("reason"),
                    "order_reference": meta.get("order_reference"),
                    "record_room_reference": meta.get("record_room_reference"),
                    "archived_by": meta.get("archived_by", current_user.id),
                    "archived_by_username": meta.get("archived_by_username", current_user.username),
                    "archived_at": meta.get("archived_at", existing_arch.timestamp.isoformat()),
                    "audit_id": existing_arch.audit_id
                }

        if case.status != "COMPLETED":
            raise AppException(
                message=f"Case docket '{case_id}' is in status '{case.status}' and cannot be archived. Docket must be COMPLETED.",
                status_code=400,
                error_code="CASE_NOT_COMPLETED",
                details={"case_id": case_id, "current_status": case.status}
            )

        # 1. Verify Trial Verdict Exists
        verdict_audit = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case.case_id, action="TRIAL_VERDICT_RECORDED")
            .first()
        )
        if not verdict_audit or not (verdict_audit.meta_data or {}).get("verdict"):
            raise AppException(
                message=f"Case docket '{case_id}' cannot be archived: trial verdict has not been pronounced. Pronounce verdict via POST /api/cases/{case_id}/disposition/verdict.",
                status_code=400,
                error_code="VERDICT_REQUIRED",
                details={"case_id": case_id}
            )
        verdict_str = (verdict_audit.meta_data or {}).get("verdict")

        # 2. Verify All Marked Exhibits are Resolved and Disposed
        marked_audits = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case.case_id, action="EXHIBIT_MARKED")
            .all()
        )

        # Map all disposal orders
        disposal_audits = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case.case_id, action="EXHIBIT_DISPOSAL_ORDERED")
            .all()
        )
        disposed_exhibits = {
            (a.meta_data or {}).get("exhibit_number", "").strip().upper()
            for a in disposal_audits
        }
        appellate_holds_count = sum(
            1 for a in disposal_audits if (a.meta_data or {}).get("appellate_hold")
        )

        unresolved_exhibits = []
        undisposed_exhibits = []

        for ma in marked_audits:
            meta = ma.meta_data or {}
            ex_num = meta.get("exhibit_number", "").strip().upper()
            initial_rul = meta.get("ruling")
            effective_rul = self._get_effective_exhibit_ruling(case.case_id, ex_num, initial_rul)

            # Check if ruling is unresolved (OBJECTED_DECISION_RESERVED or MARKED_FOR_IDENTIFICATION)
            if effective_rul in ("OBJECTED_DECISION_RESERVED", "MARKED_FOR_IDENTIFICATION"):
                unresolved_exhibits.append({"exhibit_number": ex_num, "status": effective_rul})

            # Check if disposal order is missing
            if ex_num not in disposed_exhibits:
                undisposed_exhibits.append(ex_num)

        if unresolved_exhibits:
            raise AppException(
                message=f"Case docket '{case_id}' cannot be archived: {len(unresolved_exhibits)} exhibit(s) have unresolved rulings ({unresolved_exhibits[0]['exhibit_number']}: {unresolved_exhibits[0]['status']}). All objections must be resolved prior to archival.",
                status_code=400,
                error_code="UNRESOLVED_EXHIBITS",
                details={"case_id": case_id, "unresolved_exhibits": unresolved_exhibits}
            )

        if undisposed_exhibits:
            raise AppException(
                message=f"Case docket '{case_id}' cannot be archived: {len(undisposed_exhibits)} exhibit(s) lack statutory disposal orders ({undisposed_exhibits[0]}). Orders under BNSS Section 503 required.",
                status_code=400,
                error_code="UNDISPOSED_EXHIBITS",
                details={"case_id": case_id, "undisposed_exhibits": undisposed_exhibits}
            )

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        # Append DOCKET_ARCHIVED custody events to all evidence items in case
        evidence_items = self.db.query(Evidence).filter_by(case_id=case.case_id).all()
        for ev in evidence_items:
            try:
                self.custody_service.record_event(
                    evidence_id=ev.evidence_id,
                    event_type="DOCKET_ARCHIVED",
                    user_id=current_user.id,
                    description=f"Case docket '{case.case_number}' formally archived following trial judgment ({verdict_str}) and exhibit disposal.",
                    details={
                        "case_id": case.case_id,
                        "case_number": case.case_number,
                        "verdict": verdict_str,
                        "reason": payload.reason,
                        "order_reference": payload.order_reference,
                        "record_room_reference": payload.record_room_reference,
                        "archived_by": current_user.id
                    }
                )
            except Exception as ce_err:
                logger.warning(f"Could not append DOCKET_ARCHIVED event to evidence {ev.evidence_id}: {ce_err}")

        # Transition Case Lifecycle Status
        case.status = "ARCHIVED"
        case.updated_at = now

        # Record Compliance Audit Log: CASE_DOCKET_ARCHIVED
        audit_id = f"AUD-{now.year}-{uuid.uuid4().hex[:8].upper()}"
        audit = AuditLog(
            audit_id=audit_id,
            user_id=current_user.id,
            action="CASE_DOCKET_ARCHIVED",
            resource_type="CASE",
            resource_id=case.case_id,
            timestamp=now,
            meta_data={
                "case_id": case.case_id,
                "case_number": case.case_number,
                "previous_status": "COMPLETED",
                "current_status": "ARCHIVED",
                "verdict": verdict_str,
                "total_exhibits_disposed": len(disposed_exhibits),
                "appellate_holds_active": appellate_holds_count,
                "reason": payload.reason,
                "order_reference": payload.order_reference,
                "record_room_reference": payload.record_room_reference,
                "archived_by": current_user.id,
                "archived_by_username": current_user.username,
                "archived_at": now_iso
            }
        )
        self.db.add(audit)
        self.db.commit()

        logger.info(f"Case docket '{case_id}' successfully transitioned to ARCHIVED by Hon'ble Judge '{current_user.username}'")

        return {
            "success": True,
            "case_id": case.case_id,
            "case_number": case.case_number,
            "previous_status": "COMPLETED",
            "current_status": "ARCHIVED",
            "verdict": verdict_str,
            "total_exhibits_disposed": len(disposed_exhibits),
            "appellate_holds_active": appellate_holds_count,
            "reason": payload.reason,
            "order_reference": payload.order_reference,
            "record_room_reference": payload.record_room_reference,
            "archived_by": current_user.id,
            "archived_by_username": current_user.username,
            "archived_at": now_iso,
            "audit_id": audit_id
        }

    def get_trial_disposition(
        self,
        case_id: str,
        current_user: User
    ) -> Dict[str, Any]:
        """
        Retrieves consolidated Trial Disposition and Exhibit Disposal Register for a case docket.
        Read-only access for Judge, Lawyer, Investigator, Auditor, Admin.
        """
        case = self.db.query(Case).filter_by(case_id=case_id).first()
        if not case:
            raise EntityNotFoundException("Case", case_id)

        self._check_case_access(case, current_user, action="view")

        # Fetch verdict
        verdict_audit = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case_id, action="TRIAL_VERDICT_RECORDED")
            .first()
        )
        verdict_res = self._reconstruct_verdict_response(verdict_audit) if verdict_audit else None

        # Fetch resolutions
        res_audits = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case_id, action="OBJECTION_DECISION_RESOLVED")
            .order_by(AuditLog.timestamp.asc())
            .all()
        )
        resolutions = [self._reconstruct_resolution_response(a) for a in res_audits]

        # Fetch disposal orders
        dsp_audits = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case_id, action="EXHIBIT_DISPOSAL_ORDERED")
            .order_by(AuditLog.timestamp.asc())
            .all()
        )
        disposal_orders = [self._reconstruct_disposal_response(a) for a in dsp_audits]

        # Fetch total marked exhibits
        marked_audits = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case_id, action="EXHIBIT_MARKED")
            .all()
        )
        total_exhibits = len(marked_audits)

        # Count unresolved exhibits
        unresolved_count = 0
        for ma in marked_audits:
            meta = ma.meta_data or {}
            ex_num = meta.get("exhibit_number", "").strip().upper()
            eff_rul = self._get_effective_exhibit_ruling(case_id, ex_num, meta.get("ruling"))
            if eff_rul in ("OBJECTED_DECISION_RESERVED", "MARKED_FOR_IDENTIFICATION"):
                unresolved_count += 1

        disposed_count = len(disposal_orders)
        pending_disposal = max(0, total_exhibits - disposed_count)

        is_ready = bool(
            case.status == "COMPLETED"
            and verdict_res is not None
            and unresolved_count == 0
            and pending_disposal == 0
            and total_exhibits > 0
        )

        return {
            "success": True,
            "case_id": case.case_id,
            "case_number": case.case_number,
            "case_status": case.status,
            "has_verdict": verdict_res is not None,
            "verdict": verdict_res,
            "total_exhibits": total_exhibits,
            "unresolved_exhibits_count": unresolved_count,
            "disposed_exhibits_count": disposed_count,
            "pending_disposal_count": pending_disposal,
            "is_ready_for_archival": is_ready,
            "resolutions": resolutions,
            "disposal_orders": disposal_orders
        }

    def get_exhibit_disposal(
        self,
        case_id: str,
        exhibit_number: str,
        current_user: User
    ) -> Dict[str, Any]:
        """
        Inspects statutory disposal order and appellate hold status for a single exhibit.
        """
        case = self.db.query(Case).filter_by(case_id=case_id).first()
        if not case:
            raise EntityNotFoundException("Case", case_id)

        self._check_case_access(case, current_user, action="view")

        clean_ex = exhibit_number.strip().upper()

        dsp_audits = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case_id, action="EXHIBIT_DISPOSAL_ORDERED")
            .order_by(AuditLog.timestamp.desc())
            .all()
        )
        for a in dsp_audits:
            meta = a.meta_data or {}
            if meta.get("exhibit_number", "").strip().upper() == clean_ex:
                return self._reconstruct_disposal_response(a)

        raise EntityNotFoundException("DisposalOrder", exhibit_number)
