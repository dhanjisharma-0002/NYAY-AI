"""
NYAYAI - Investigator Portfolio Operational Dashboard Service (Phase 15)
Module: backend.app.services.dashboard_service
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Provides high-performance, cross-case operational dashboard metrics without N+1 query overhead.
Aggregates portfolio health, evidence metrics, pending actions, and urgent cases deterministically.
"""

import json
from typing import Dict, List, Any, Set
from sqlalchemy.orm import Session

from custody import CryptographicCustodyLedger
from backend.app.models.user import User
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.evidence_metadata import EvidenceMetadata
from backend.app.models.analysis_result import AnalysisResult
from backend.app.models.custody import CustodyEvent
from backend.app.models.report import Report
from backend.app.models.verification import VerificationRecord
from backend.app.services.base import BaseService
from backend.app.services.case_service import CaseService


class DashboardService(BaseService):
    """
    Computes portfolio-level operational triage metrics across accessible case dockets.
    Guarantees:
    - Zero N+1 query amplification (set-based queries).
    - Strictly read-only execution (zero database mutations).
    - Role-based isolation (INVESTIGATOR views owned/assigned cases; ADMIN/AUDITOR/JUDGE views system-wide).
    """

    def __init__(self, db: Session):
        super().__init__(db)
        self.ledger = CryptographicCustodyLedger()
        self.case_service = CaseService(db)

    def get_accessible_cases(self, current_user: User) -> List[Case]:
        """
        Retrieves case dockets accessible to the requesting user role.
        INVESTIGATOR: Only cases created by or assigned to the user.
        ADMIN, JUDGE, AUDITOR, SYSTEM_LEAD, LAWYER, FORENSIC_EXPERT: Broader case access.
        """
        role = (current_user.role or "").strip().upper()
        query = self.db.query(Case)

        if role == "INVESTIGATOR":
            query = query.filter(
                (Case.created_by == current_user.id) |
                (Case.created_by == current_user.username)
            )

        return query.order_by(Case.created_at.desc()).all()

    def get_portfolio_dashboard(self, current_user: User) -> Dict[str, Any]:
        """
        Generates cross-case operational dashboard metrics.
        Returns:
        - total_cases
        - status_counts
        - cases_requiring_attention
        - urgent_cases
        - evidence_metrics (total, verified, compromised, storage_errors)
        - pending_actions (forensic_analysis, ai_analysis, court_reports)
        """
        # 1. Retrieve accessible cases (1 query)
        cases = self.get_accessible_cases(current_user)

        if not cases:
            return {
                "total_cases": 0,
                "status_counts": {},
                "cases_requiring_attention": 0,
                "urgent_cases": [],
                "evidence_metrics": {
                    "total": 0,
                    "verified": 0,
                    "compromised": 0,
                    "storage_errors": 0
                },
                "pending_actions": {
                    "forensic_analysis": 0,
                    "ai_analysis": 0,
                    "court_reports": 0
                }
            }

        # 2. Case status distribution
        status_counts: Dict[str, int] = {}
        for c in cases:
            st = c.status or "UNKNOWN"
            status_counts[st] = status_counts.get(st, 0) + 1

        case_ids = [c.case_id for c in cases]

        # 3. Batch query evidence across all accessible cases (1 query)
        evidence_items = (
            self.db.query(Evidence)
            .filter(Evidence.case_id.in_(case_ids))
            .all()
        )

        total_evidence = len(evidence_items)
        verified_evidence = sum(1 for e in evidence_items if e.status == "VERIFIED")
        compromised_evidence = sum(1 for e in evidence_items if e.status == "INTEGRITY_COMPROMISED")
        storage_error_evidence = sum(1 for e in evidence_items if e.status == "STORAGE_ERROR")

        case_ev_map: Dict[str, List[Evidence]] = {cid: [] for cid in case_ids}
        for e in evidence_items:
            case_ev_map[e.case_id].append(e)

        all_ev_ids = [e.evidence_id for e in evidence_items]

        # 4. Batch query forensic inspections (1 query)
        inspected_ev_ids: Set[str] = set()
        anomalous_ev_ids: Set[str] = set()
        if all_ev_ids:
            meta_records = (
                self.db.query(EvidenceMetadata)
                .filter(EvidenceMetadata.evidence_id.in_(all_ev_ids))
                .all()
            )
            for m in meta_records:
                inspected_ev_ids.add(m.evidence_id)
                if not m.format_valid or (m.anomalies and len(m.anomalies) > 0):
                    anomalous_ev_ids.add(m.evidence_id)

        pending_forensics = total_evidence - len(inspected_ev_ids)

        # 5. Batch query AI analysis results (1 query)
        analyzed_ev_ids: Set[str] = set()
        ai_tampered_ev_ids: Set[str] = set()
        if all_ev_ids:
            ai_records = (
                self.db.query(AnalysisResult)
                .filter(AnalysisResult.evidence_id.in_(all_ev_ids))
                .all()
            )
            for a in ai_records:
                analyzed_ev_ids.add(a.evidence_id)
                pred_str = str(a.prediction).upper() if a.prediction else ""
                if not ("NO_TAMPER" in pred_str or "AUTHENTIC" in pred_str or "CLEAN" in pred_str):
                    if a.tamper_detected or "TAMPER" in pred_str:
                        ai_tampered_ev_ids.add(a.evidence_id)

        pending_ai = total_evidence - len(analyzed_ev_ids)

        # 6. Batch query court reports & verifications (2 queries)
        reports = (
            self.db.query(Report)
            .filter(Report.case_id.in_(case_ids))
            .all()
        )
        case_reports_map: Dict[str, List[str]] = {cid: [] for cid in case_ids}
        for r in reports:
            case_reports_map[r.case_id].append(r.report_id)
        all_report_ids = [r.report_id for r in reports]

        tampered_report_ids: Set[str] = set()
        if all_report_ids:
            ver_records = (
                self.db.query(VerificationRecord.report_id)
                .filter(
                    VerificationRecord.report_id.in_(all_report_ids),
                    VerificationRecord.status.in_(["TAMPER_DETECTED", "INVALID", "TAMPERED"])
                )
                .all()
            )
            tampered_report_ids = {v[0] for v in ver_records}

        # 7. Batch query custody events and verify chain in-memory (1 query)
        broken_custody_ev_ids: Set[str] = set()
        if all_ev_ids:
            custody_events = (
                self.db.query(CustodyEvent)
                .filter(CustodyEvent.evidence_id.in_(all_ev_ids))
                .order_by(CustodyEvent.sequence_number.asc())
                .all()
            )
            ev_custody_map: Dict[str, List[CustodyEvent]] = {}
            for ce in custody_events:
                ev_custody_map.setdefault(ce.evidence_id, []).append(ce)

            for ev_id, c_list in ev_custody_map.items():
                blocks = []
                for ev in c_list:
                    try:
                        payload = json.loads(ev.payload_json) if isinstance(ev.payload_json, str) else ev.payload_json
                    except Exception:
                        payload = {"raw": ev.payload_json}
                    ts_str = ev.timestamp if isinstance(ev.timestamp, str) else ev.timestamp.isoformat()
                    blocks.append({
                        "event_id": ev.event_id,
                        "evidence_id": ev.evidence_id,
                        "sequence_number": ev.sequence_number,
                        "action": ev.action,
                        "actor_id": ev.actor_id,
                        "timestamp": ts_str,
                        "previous_event_hash": ev.previous_event_hash,
                        "event_hash": ev.event_hash,
                        "payload_json": payload
                    })
                verification = self.ledger.verify_chain(blocks)
                if not verification["is_valid"]:
                    broken_custody_ev_ids.add(ev_id)

        # 8. Derive per-case triage, urgent cases list, and court report action in memory
        urgent_cases: List[Dict[str, Any]] = []
        cases_requiring_attention = 0
        pending_court_reports = 0

        for c in cases:
            cid = c.case_id
            c_evs = case_ev_map.get(cid, [])
            c_ev_ids = {e.evidence_id for e in c_evs}
            c_rep_ids = case_reports_map.get(cid, [])

            has_compromised = any(e.status == "INTEGRITY_COMPROMISED" for e in c_evs)
            has_storage_err = any(e.status == "STORAGE_ERROR" for e in c_evs)
            has_broken_custody = any(eid in broken_custody_ev_ids for eid in c_ev_ids)
            has_ai_tamper = any(eid in ai_tampered_ev_ids for eid in c_ev_ids)
            has_forensic_anom = any(eid in anomalous_ev_ids for eid in c_ev_ids)
            has_tampered_report = any(rid in tampered_report_ids for rid in c_rep_ids)

            has_uninspected = any(eid not in inspected_ev_ids for eid in c_ev_ids)
            has_unanalyzed = any(eid not in analyzed_ev_ids for eid in c_ev_ids)
            needs_court_report = (
                len(c_evs) > 0 and
                len(c_rep_ids) == 0 and
                not has_compromised and
                not has_broken_custody
            )

            if needs_court_report:
                pending_court_reports += 1

            # HIGH Alerts qualifying case for urgent_cases
            high_alerts: List[str] = []
            if has_compromised:
                high_alerts.append("INTEGRITY_COMPROMISED")
            if has_broken_custody:
                high_alerts.append("BROKEN_CUSTODY_CHAIN")
            if has_ai_tamper:
                high_alerts.append("AI_TAMPER_DETECTED")
            if has_tampered_report:
                high_alerts.append("TAMPERED_REPORT_VERIFICATION")

            if high_alerts:
                urgent_cases.append({
                    "case_id": c.case_id,
                    "case_number": c.case_number,
                    "title": c.title,
                    "status": c.status,
                    "high_alert_types": high_alerts
                })

            requires_attention = bool(
                high_alerts or
                has_storage_err or
                has_forensic_anom or
                has_uninspected or
                has_unanalyzed or
                needs_court_report
            )
            if requires_attention:
                cases_requiring_attention += 1

        return {
            "total_cases": len(cases),
            "status_counts": status_counts,
            "cases_requiring_attention": cases_requiring_attention,
            "urgent_cases": urgent_cases,
            "evidence_metrics": {
                "total": total_evidence,
                "verified": verified_evidence,
                "compromised": compromised_evidence,
                "storage_errors": storage_error_evidence
            },
            "pending_actions": {
                "forensic_analysis": pending_forensics,
                "ai_analysis": pending_ai,
                "court_reports": pending_court_reports
            }
        }
