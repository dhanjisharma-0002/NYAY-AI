"""
NYAYAI - Case Intelligence Summary Service (Phase 13)
Module: backend.app.services.case_intelligence_service
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Provides consolidated, read-only aggregation of case metadata, evidence inventory,
cryptographic integrity status, forensic findings, AI screening results,
explainability records, correlation intelligence, timeline, custody chains,
court reports, verification audits, and overall case readiness.
"""

from typing import Dict, Any, List
from sqlalchemy.orm import Session

from backend.app.services.base import BaseService
from backend.app.services.case_service import CaseService
from backend.app.services.evidence_service import EvidenceService
from backend.app.services.correlation_service import CorrelationService
from backend.app.services.custody_service import CustodyService
from backend.app.services.audit_service import AuditService
from backend.app.models.evidence import EvidenceItem
from backend.app.models.evidence_metadata import EvidenceMetadata
from backend.app.models.analysis_result import AnalysisResult
from backend.app.models.explainability import ExplainabilityRecord
from backend.app.models.report import Report
from backend.app.models.verification import VerificationRecord
from backend.app.utils.logger import get_logger

logger = get_logger("case_intelligence_service")


class CaseIntelligenceService(BaseService):
    """
    Central aggregation service providing a unified, read-only intelligence summary
    for investigative case dockets across 12 distinct domains.
    """

    def __init__(self, db: Session):
        super().__init__(db)
        self.case_service = CaseService(db)
        self.evidence_service = EvidenceService(db)
        self.correlation_service = CorrelationService(db)
        self.custody_service = CustodyService(db)
        self.audit_service = AuditService(db)

    def get_case_intelligence_summary(self, case_id: str) -> Dict[str, Any]:
        """
        Gathers and aggregates existing case data into a consolidated case intelligence summary.

        Zero-Mutation Invariant:
        This method performs only read operations across existing database records
        and never inserts, modifies, or deletes database state.
        """
        # 1. Fetch Case (raises EntityNotFoundException -> 404 if missing)
        case = self.case_service.get_case(case_id)

        case_info = {
            "case_id": case.case_id,
            "case_number": case.case_number,
            "title": case.title,
            "description": case.description,
            "status": case.status,
            "jurisdiction": case.jurisdiction,
            "created_by": case.created_by,
            "created_at": case.created_at.isoformat() if case.created_at else "",
            "updated_at": case.updated_at.isoformat() if case.updated_at else ""
        }

        # 2. Fetch Evidence items for this case
        evidence_records: List[EvidenceItem] = (
            self.db.query(EvidenceItem)
            .filter_by(case_id=case_id)
            .order_by(EvidenceItem.created_at.asc())
            .all()
        )

        by_media_type: Dict[str, int] = {}
        total_size_bytes: int = 0
        evidence_items_data: List[Dict[str, Any]] = []

        for e in evidence_records:
            m_type = (e.media_type or "UNKNOWN").upper()
            by_media_type[m_type] = by_media_type.get(m_type, 0) + 1
            total_size_bytes += (e.file_size or 0)
            evidence_items_data.append({
                "evidence_id": e.evidence_id,
                "original_filename": e.original_filename,
                "media_type": e.media_type,
                "mime_type": e.mime_type,
                "file_size_bytes": e.file_size or 0,
                "sha256_hash": e.sha256_hash,
                "status": e.status,
                "source_description": e.source_description,
                "created_at": e.created_at.isoformat() if e.created_at else None
            })

        evidence_stats = {
            "total_count": len(evidence_records),
            "by_media_type": by_media_type,
            "total_size_bytes": total_size_bytes,
            "items": evidence_items_data
        }

        # 3. Evidence Integrity Summary
        intact_count = sum(1 for e in evidence_records if e.status in ("SECURED", "VERIFIED", "ANALYZED", "VAULTED"))
        compromised_count = sum(1 for e in evidence_records if e.status == "INTEGRITY_COMPROMISED")
        storage_error_count = sum(1 for e in evidence_records if e.status == "STORAGE_ERROR")

        if len(evidence_records) == 0:
            integrity_status = "NO_EVIDENCE"
        elif compromised_count > 0:
            integrity_status = "INTEGRITY_COMPROMISED"
        elif storage_error_count > 0:
            integrity_status = "STORAGE_ERROR"
        else:
            integrity_status = "INTACT"

        integrity_summary = {
            "total_checked": len(evidence_records),
            "intact_count": intact_count,
            "compromised_count": compromised_count,
            "storage_error_count": storage_error_count,
            "integrity_status": integrity_status
        }

        evidence_ids = [e.evidence_id for e in evidence_records]

        # 4. Forensic / Metadata Findings
        metadata_records = (
            self.db.query(EvidenceMetadata)
            .filter(EvidenceMetadata.evidence_id.in_(evidence_ids))
            .all()
        ) if evidence_ids else []

        forensic_items: List[Dict[str, Any]] = []
        anomalies_detected_count = 0
        format_valid_count = 0

        for m in metadata_records:
            anom = m.anomalies or []
            anomalies_detected_count += len(anom)
            if m.format_valid:
                format_valid_count += 1
            forensic_items.append({
                "evidence_id": m.evidence_id,
                "format_valid": bool(m.format_valid),
                "magic_bytes": m.magic_bytes,
                "anomalies_count": len(anom),
                "anomalies": anom
            })

        forensic_summary = {
            "inspected_count": len(metadata_records),
            "anomalies_detected_count": anomalies_detected_count,
            "format_valid_count": format_valid_count,
            "items": forensic_items
        }

        # 5. AI Analysis Findings
        analysis_records = (
            self.db.query(AnalysisResult)
            .filter(AnalysisResult.evidence_id.in_(evidence_ids))
            .all()
        ) if evidence_ids else []

        ai_items: List[Dict[str, Any]] = []
        tamper_detected_count = 0
        total_risk_score = 0.0

        for r in analysis_records:
            pred_str = str(r.prediction).upper() if r.prediction else ""
            if "NO_TAMPER" in pred_str or "AUTHENTIC" in pred_str or "CLEAN" in pred_str:
                is_tamper = False
            else:
                is_tamper = bool(r.tamper_detected or ("TAMPER" in pred_str))
            if is_tamper:
                tamper_detected_count += 1
            total_risk_score += (r.risk_score or 0.0)
            ai_items.append({
                "analysis_id": r.analysis_id,
                "evidence_id": r.evidence_id,
                "analysis_type": r.analysis_type,
                "prediction": r.prediction,
                "confidence": r.confidence or 0.0,
                "risk_score": r.risk_score or 0.0,
                "tamper_detected": is_tamper,
                "findings": r.findings or [],
                "model_name": r.model_name,
                "model_version": r.model_version
            })

        avg_risk_score = round(total_risk_score / len(analysis_records), 4) if analysis_records else 0.0

        ai_summary = {
            "analyzed_count": len(analysis_records),
            "tamper_detected_count": tamper_detected_count,
            "average_risk_score": avg_risk_score,
            "items": ai_items
        }

        # 6. Explainability Records
        explainability_records = (
            self.db.query(ExplainabilityRecord)
            .filter(ExplainabilityRecord.evidence_id.in_(evidence_ids))
            .all()
        ) if evidence_ids else []

        exp_categories: Dict[str, int] = {}
        for exp in explainability_records:
            cat = exp.confidence_category or "UNKNOWN"
            exp_categories[cat] = exp_categories.get(cat, 0) + 1

        explainability_summary = {
            "records_count": len(explainability_records),
            "available": len(explainability_records) > 0,
            "categories": exp_categories
        }

        # 7. Correlation & Timeline Intelligence (Reusing CorrelationService)
        timeline_events: List[Dict[str, Any]] = []
        relationships: List[Dict[str, Any]] = []
        cross_matches: List[Dict[str, Any]] = []
        red_flags: List[Dict[str, Any]] = []

        if evidence_records:
            try:
                corr_resp = self.correlation_service.correlate_case(case_id)
                timeline_events = corr_resp.get("timeline", [])
                relationships = corr_resp.get("relationships", [])
                cross_matches = corr_resp.get("cross_evidence_matches", [])
                red_flags = corr_resp.get("red_flags", [])
            except Exception as ce:
                logger.warning(f"Case correlation extraction error for {case_id}: {ce}")

        correlation_summary = {
            "timeline_events_count": len(timeline_events),
            "relationships_count": len(relationships),
            "cross_matches_count": len(cross_matches),
            "red_flags_count": len(red_flags),
            "red_flags": red_flags
        }

        timeline_summary = {
            "total_events": len(timeline_events),
            "has_timeline": len(timeline_events) > 0,
            "earliest_timestamp": timeline_events[0].get("timestamp") if timeline_events else None,
            "latest_timestamp": timeline_events[-1].get("timestamp") if timeline_events else None
        }

        # 8. Cryptographic Chain of Custody (Reusing CustodyService)
        evidence_chains: List[Dict[str, Any]] = []
        total_custody_events = 0
        broken_chains_count = 0

        for e in evidence_records:
            try:
                c_hist = self.custody_service.get_chronological_history(e.evidence_id)
                chain_intact = bool(c_hist.get("chain_intact", True))
                ev_count = int(c_hist.get("total_events", 0))
            except Exception:
                chain_intact = False
                ev_count = 0

            total_custody_events += ev_count
            if not chain_intact:
                broken_chains_count += 1

            evidence_chains.append({
                "evidence_id": e.evidence_id,
                "chain_intact": chain_intact,
                "total_events": ev_count,
                "broken_at_event_id": None if chain_intact else "EVENT_CHAIN_VERIFICATION_FAILED"
            })

        custody_summary = {
            "total_events": total_custody_events,
            "all_chains_intact": (broken_chains_count == 0),
            "broken_chains_count": broken_chains_count,
            "evidence_chains": evidence_chains
        }

        # 9. Court Reports
        reports = (
            self.db.query(Report)
            .filter_by(case_id=case_id)
            .order_by(Report.created_at.desc())
            .all()
        )

        reports_list = [
            {
                "report_id": r.report_id,
                "report_type": r.report_type,
                "status": r.status,
                "report_sha256": r.report_sha256,
                "verification_code": r.verification_code,
                "created_at": r.created_at.isoformat() if r.created_at else None
            }
            for r in reports
        ]

        reports_summary = {
            "total_reports": len(reports),
            "reports_list": reports_list
        }

        # 10. Public Verification History
        report_ids = [r.report_id for r in reports]
        verifications = (
            self.db.query(VerificationRecord)
            .filter(VerificationRecord.report_id.in_(report_ids))
            .order_by(VerificationRecord.timestamp.desc())
            .all()
        ) if report_ids else []

        valid_verifs = sum(1 for v in verifications if v.status == "VALID")
        tampered_verifs = sum(1 for v in verifications if v.status in ("TAMPER_DETECTED", "INVALID", "TAMPERED"))

        recent_verifs = [
            {
                "verification_id": v.verification_id,
                "report_id": v.report_id,
                "verification_method": v.verification_method,
                "status": v.status,
                "timestamp": v.timestamp.isoformat() if v.timestamp else None
            }
            for v in verifications[:10]
        ]

        verification_summary = {
            "total_verifications": len(verifications),
            "valid_verifications": valid_verifs,
            "tampered_verifications": tampered_verifs,
            "recent_verifications": recent_verifs
        }

        # 11. Audit Trail (Reusing AuditService)
        try:
            audit_resp = self.audit_service.get_case_audit_history(case_id, limit=20, offset=0)
            total_audit_events = audit_resp.get("total", 0)
            recent_audit_events = audit_resp.get("items", [])
        except Exception as ae:
            logger.warning(f"Audit trail query error for case {case_id}: {ae}")
            total_audit_events = 0
            recent_audit_events = []

        audit_summary = {
            "total_audit_events": total_audit_events,
            "recent_events": recent_audit_events
        }

        # 12. Deterministic Overall Case Status Computation
        # Priority rules:
        # 1. NO_EVIDENCE: Case has zero vaulted evidence items.
        # 2. INTEGRITY_COMPROMISED: Any evidence compromised, custody broken, or report tampered.
        # 3. STORAGE_ERROR: Any physical file access/storage error detected.
        # 4. ARCHIVED: Case docket is explicitly archived.
        # 5. READY_FOR_COURT: Evidence exists, integrity unbroken, and court report generated.
        # 6. UNDER_ANALYSIS: Evidence exists and is intact, but final court report not yet generated.
        if len(evidence_records) == 0:
            overall_status = "NO_EVIDENCE"
        elif compromised_count > 0 or broken_chains_count > 0 or tampered_verifs > 0:
            overall_status = "INTEGRITY_COMPROMISED"
        elif storage_error_count > 0:
            overall_status = "STORAGE_ERROR"
        elif str(case.status).upper() == "ARCHIVED":
            overall_status = "ARCHIVED"
        elif len(reports) > 0 and custody_summary["all_chains_intact"] and compromised_count == 0:
            overall_status = "READY_FOR_COURT"
        else:
            overall_status = "UNDER_ANALYSIS"

        return {
            "success": True,
            "case": case_info,
            "evidence": evidence_stats,
            "integrity": integrity_summary,
            "forensic": forensic_summary,
            "ai_analysis": ai_summary,
            "explainability": explainability_summary,
            "correlation": correlation_summary,
            "timeline": timeline_summary,
            "custody": custody_summary,
            "reports": reports_summary,
            "verification": verification_summary,
            "audit": audit_summary,
            "overall_status": overall_status
        }

    def get_operational_case_view(self, case_id: str) -> Dict[str, Any]:
        """
        Derives an actionable investigator operational case view on top of the
        Phase 13 Case Intelligence Summary.

        Computes deterministic:
        1. attention_required (bool)
        2. critical_alerts (list of alerts: INTEGRITY_COMPROMISED, STORAGE_ERROR, BROKEN_CUSTODY_CHAIN, AI_TAMPER_DETECTED, FORENSIC_ANOMALY, CORRELATION_RED_FLAG, TAMPERED_REPORT_VERIFICATION)
        3. pending_actions (list of operational next steps: REVIEW_INTEGRITY_COMPROMISE, VERIFY_CUSTODY_CHAIN, PENDING_FORENSIC_ANALYSIS, PENDING_AI_ANALYSIS, REVIEW_CORRELATION_RED_FLAGS, GENERATE_COURT_REPORT)
        4. findings_summary (validated_findings, anomalous_findings, red_flags)
        5. summary_metrics (total_evidence, verified_evidence, compromised_evidence, analyzed_evidence, active_red_flags, reports_generated)
        6. intelligence_summary (full Phase 13 response)
        """
        summary = self.get_case_intelligence_summary(case_id)

        case_info = summary["case"]
        evidence_sec = summary["evidence"]
        integrity_sec = summary["integrity"]
        forensic_sec = summary["forensic"]
        ai_sec = summary["ai_analysis"]
        correlation_sec = summary["correlation"]
        custody_sec = summary["custody"]
        reports_sec = summary["reports"]
        verif_sec = summary["verification"]

        critical_alerts: List[Dict[str, Any]] = []
        pending_actions: List[Dict[str, Any]] = []

        # 1. Critical Alerts Derivation
        # A. Integrity Compromise & Storage Error Alert
        for e in evidence_sec["items"]:
            if e["status"] == "INTEGRITY_COMPROMISED":
                critical_alerts.append({
                    "alert_type": "INTEGRITY_COMPROMISED",
                    "severity": "HIGH",
                    "resource_id": e["evidence_id"],
                    "description": f"Evidence '{e['original_filename']}' cryptographic integrity is compromised (SHA-256 mismatch)."
                })
            elif e["status"] == "STORAGE_ERROR":
                critical_alerts.append({
                    "alert_type": "STORAGE_ERROR",
                    "severity": "MEDIUM",
                    "resource_id": e["evidence_id"],
                    "description": f"Evidence '{e['original_filename']}' encountered a storage access or missing file error."
                })

        # B. Broken Custody Chain Alert
        for chain in custody_sec["evidence_chains"]:
            if not chain["chain_intact"]:
                critical_alerts.append({
                    "alert_type": "BROKEN_CUSTODY_CHAIN",
                    "severity": "HIGH",
                    "resource_id": chain["evidence_id"],
                    "description": f"Cryptographic chain of custody verification failed for evidence '{chain['evidence_id']}'."
                })

        # C. AI Tamper Detected Alert
        for ai_item in ai_sec["items"]:
            if ai_item.get("tamper_detected"):
                critical_alerts.append({
                    "alert_type": "AI_TAMPER_DETECTED",
                    "severity": "HIGH",
                    "resource_id": ai_item["evidence_id"],
                    "description": f"AI screening detected potential media tampering/splicing on evidence '{ai_item['evidence_id']}'."
                })

        # D. Forensic Anomaly Alert
        for f_item in forensic_sec["items"]:
            if f_item.get("anomalies_count", 0) > 0 or not f_item.get("format_valid", True):
                anom_desc = ", ".join(f_item.get("anomalies", [])) if f_item.get("anomalies") else "Format specification mismatch."
                critical_alerts.append({
                    "alert_type": "FORENSIC_ANOMALY",
                    "severity": "MEDIUM",
                    "resource_id": f_item["evidence_id"],
                    "description": f"Forensic structural anomalies detected in evidence '{f_item['evidence_id']}': {anom_desc}"
                })

        # E. Correlation Red Flags Alert
        for rf in correlation_sec["red_flags"]:
            res_id = rf.get("evidence_id") or (rf.get("evidence_reference", {}).get("evidence_id") if isinstance(rf.get("evidence_reference"), dict) else None) or rf.get("flag_id") or case_id
            critical_alerts.append({
                "alert_type": "CORRELATION_RED_FLAG",
                "severity": "MEDIUM",
                "resource_id": str(res_id),
                "description": rf.get("description", "Correlation anomaly detected.")
            })

        # F. Tampered Report Verification Alert
        for v in verif_sec["recent_verifications"]:
            if v.get("status") in ("TAMPER_DETECTED", "INVALID", "TAMPERED"):
                critical_alerts.append({
                    "alert_type": "TAMPERED_REPORT_VERIFICATION",
                    "severity": "HIGH",
                    "resource_id": v["report_id"],
                    "description": f"Public QR/cryptographic verification detected tampering on report '{v['report_id']}'."
                })

        # 2. Pending Actions Derivation
        inspected_ids = {f["evidence_id"] for f in forensic_sec["items"]}
        analyzed_ids = {a["evidence_id"] for a in ai_sec["items"]}

        for e in evidence_sec["items"]:
            ev_id = e["evidence_id"]
            if e["status"] == "INTEGRITY_COMPROMISED":
                pending_actions.append({
                    "action_type": "REVIEW_INTEGRITY_COMPROMISE",
                    "resource_id": ev_id,
                    "description": f"Review cryptographic hash mismatch and chain breach for evidence '{ev_id}'."
                })
            if ev_id not in inspected_ids:
                pending_actions.append({
                    "action_type": "PENDING_FORENSIC_ANALYSIS",
                    "resource_id": ev_id,
                    "description": f"Evidence '{e['original_filename']}' requires forensic metadata and byte structure inspection."
                })
            if ev_id not in analyzed_ids:
                pending_actions.append({
                    "action_type": "PENDING_AI_ANALYSIS",
                    "resource_id": ev_id,
                    "description": f"Evidence '{e['original_filename']}' requires AI tamper detection and screening."
                })

        for chain in custody_sec["evidence_chains"]:
            if not chain["chain_intact"]:
                pending_actions.append({
                    "action_type": "VERIFY_CUSTODY_CHAIN",
                    "resource_id": chain["evidence_id"],
                    "description": f"Re-audit broken chain of custody blocks for evidence '{chain['evidence_id']}'."
                })

        if correlation_sec["red_flags_count"] > 0:
            pending_actions.append({
                "action_type": "REVIEW_CORRELATION_RED_FLAGS",
                "resource_id": case_id,
                "description": f"{correlation_sec['red_flags_count']} active cross-evidence correlation red flag(s) require investigator review."
            })

        if evidence_sec["total_count"] > 0 and reports_sec["total_reports"] == 0 and integrity_sec["compromised_count"] == 0 and custody_sec["all_chains_intact"]:
            pending_actions.append({
                "action_type": "GENERATE_COURT_REPORT",
                "resource_id": case_id,
                "description": f"All evidence artifacts are intact. Court admissibility certificate (BSA 2023) has not yet been generated for case '{case_id}'."
            })

        # 3. Attention Required Flag
        attention_required = bool(critical_alerts or pending_actions)

        # 4. Findings Summary
        validated_findings = forensic_sec["format_valid_count"] + sum(1 for a in ai_sec["items"] if not a.get("tamper_detected"))
        anomalous_findings = forensic_sec["anomalies_detected_count"] + ai_sec["tamper_detected_count"] + integrity_sec["compromised_count"]
        findings_summary = {
            "validated_findings": validated_findings,
            "anomalous_findings": anomalous_findings,
            "red_flags": correlation_sec["red_flags_count"]
        }

        # 5. Summary Metrics
        summary_metrics = {
            "total_evidence": evidence_sec["total_count"],
            "verified_evidence": integrity_sec["intact_count"],
            "compromised_evidence": integrity_sec["compromised_count"],
            "analyzed_evidence": len(inspected_ids | analyzed_ids),
            "active_red_flags": correlation_sec["red_flags_count"],
            "reports_generated": reports_sec["total_reports"]
        }

        return {
            "success": True,
            "case_id": case_info["case_id"],
            "case_number": case_info["case_number"],
            "title": case_info["title"],
            "overall_status": summary["overall_status"],
            "attention_required": attention_required,
            "critical_alerts": critical_alerts,
            "pending_actions": pending_actions,
            "findings_summary": findings_summary,
            "summary_metrics": summary_metrics,
            "intelligence_summary": summary
        }

