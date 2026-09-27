"""
NYAYAI - Court Admissibility Report Service (Phase 10)
Module: backend.app.services.report_service
Module Lead: Dhananjay Sharma (Backend & System Integration Lead)

Orchestrates court-ready forensic report generation in PDF and DOCX formats,
aggregating evidence inventory, SHA-256 integrity, metadata findings,
forensic analyses, AI screening, explainability references, evidence correlation,
timelines, and immutable cryptographic chains of custody under BSA 2023.
"""

import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List

from backend.app.models.case import Case
from backend.app.models.evidence import EvidenceItem
from backend.app.models.evidence_metadata import EvidenceMetadata
from backend.app.models.analysis_result import AnalysisResult
from backend.app.models.explainability import ExplainabilityRecord
from backend.app.models.custody import CustodyEvent, CustodyEventType
from backend.app.models.report import Report, CourtReport
from backend.app.services.base import BaseService
from backend.app.services.correlation_service import CorrelationService
from backend.app.services.custody_service import CustodyService
from backend.app.utils.exceptions import EntityNotFoundException, ValidationException
from backend.app.utils.logger import get_logger
from reports import CourtAdmissibilityReportGenerator

logger = get_logger("report_service")


def _is_forensic_analysis_type(analysis_type: Optional[str]) -> bool:
    """Classify stored AnalysisResult rows without changing the schema."""
    atype = (analysis_type or "").strip().upper()
    if not atype:
        return False
    if atype in {"FORENSIC", "FORENSIC_INSPECTION", "METADATA_INSPECTION"}:
        return True
    return atype.startswith("FORENSIC")


class ReportService(BaseService):
    """
    Manages end-to-end report synthesis, storage, verification, and artifact downloads.
    """

    def __init__(self, db):
        super().__init__(db)
        self.generator = CourtAdmissibilityReportGenerator()

    def generate_court_ready_report(
        self,
        case_id: str,
        report_format: str = "PDF",
        certifying_officer_name: Optional[str] = None,
        certifying_officer_designation: Optional[str] = None,
        badge_number: Optional[str] = None,
        jurisdiction: Optional[str] = None,
        user_id: str = "USR-SYSTEM-LEAD"
    ) -> Report:
        """
        Synthesizes all 12 evidence intelligence sections from the case docket
        and outputs a court-ready forensic report (PDF or DOCX).
        """
        # 1. Fetch Case
        case = self.db.query(Case).filter_by(case_id=case_id).first()
        if not case:
            raise EntityNotFoundException("Case", case_id)

        # 2. Validate format
        fmt = report_format.upper().strip()
        if fmt not in ("PDF", "DOCX"):
            raise ValidationException(f"Unsupported report format: {report_format}. Must be 'PDF' or 'DOCX'.")

        # 3. Fetch Case Evidence items
        evidence_records = (
            self.db.query(EvidenceItem)
            .filter_by(case_id=case_id)
            .order_by(EvidenceItem.created_at.asc())
            .all()
        )
        evidence_items_data = [
            {
                "evidence_id": e.evidence_id,
                "original_filename": e.original_filename,
                "file_size": e.file_size,
                "file_size_bytes": e.file_size,
                "media_type": e.media_type,
                "mime_type": e.mime_type,
                "sha256_hash": e.sha256_hash,
                "status": e.status,
                "source_description": e.source_description,
                "created_at": e.created_at.isoformat() if e.created_at else None
            }
            for e in evidence_records
        ]

        # 4. Fetch Metadata per evidence
        metadata_map: Dict[str, Dict[str, Any]] = {}
        for e in evidence_records:
            meta = self.db.query(EvidenceMetadata).filter_by(evidence_id=e.evidence_id).first()
            if meta:
                metadata_map[e.evidence_id] = {
                    "format_valid": meta.format_valid,
                    "magic_bytes": meta.magic_bytes,
                    "exif_data": meta.exif_data or {},
                    "timestamps_metadata": meta.timestamps_metadata or {},
                    "anomalies": meta.anomalies or []
                }

        # 5. Fetch Forensic & AI Analysis Results per evidence
        forensic_analysis_map: Dict[str, List[Dict[str, Any]]] = {}
        ai_analysis_map: Dict[str, List[Dict[str, Any]]] = {}
        for e in evidence_records:
            results = self.db.query(AnalysisResult).filter_by(evidence_id=e.evidence_id).all()
            f_list = []
            ai_list = []
            for r in results:
                res_dict = {
                    "analysis_id": r.analysis_id,
                    "analysis_type": r.analysis_type,
                    "status": r.status,
                    "prediction": r.prediction,
                    "confidence": r.confidence,
                    "confidence_score": r.confidence,
                    "risk_score": r.risk_score,
                    "findings": r.findings or [],
                    "explanation": r.explanation,
                    "model_name": r.model_name,
                    "model_version": r.model_version
                }
                if _is_forensic_analysis_type(r.analysis_type):
                    f_list.append(res_dict)
                else:
                    ai_list.append(res_dict)
            if f_list:
                forensic_analysis_map[e.evidence_id] = f_list
            if ai_list:
                ai_analysis_map[e.evidence_id] = ai_list

        # 6. Fetch Explainability records per evidence
        explainability_map: Dict[str, Dict[str, Any]] = {}
        for e in evidence_records:
            exp = self.db.query(ExplainabilityRecord).filter_by(evidence_id=e.evidence_id).first()
            if exp:
                explainability_map[e.evidence_id] = {
                    "record_id": exp.record_id,
                    "reasoning_summary": exp.reasoning_summary,
                    "confidence_category": exp.confidence_category,
                    "feature_attributions": exp.feature_attributions,
                    "limitations_disclaimer": exp.limitations_disclaimer
                }

        # 7. Fetch Custody chains per evidence
        custody_map: Dict[str, List[Dict[str, Any]]] = {}
        for e in evidence_records:
            c_events = (
                self.db.query(CustodyEvent)
                .filter_by(evidence_id=e.evidence_id)
                .order_by(CustodyEvent.sequence_number.asc())
                .all()
            )
            custody_map[e.evidence_id] = [
                {
                    "event_id": c.event_id,
                    "sequence_number": c.sequence_number,
                    "event_type": c.event_type,
                    "action": c.action,
                    "user_id": c.user_id,
                    "actor_id": c.actor_id,
                    "timestamp": c.timestamp,
                    "description": c.description,
                    "previous_hash": c.previous_hash,
                    "event_hash": c.event_hash
                }
                for c in c_events
            ]

        # 8. Fetch Case Correlation intelligence (timeline, relationships, matches, red flags)
        correlation_svc = CorrelationService(self.db)
        try:
            corr_resp = correlation_svc.correlate_case(case_id)
            correlation_data = corr_resp.get("data", corr_resp)
        except Exception as ex:
            logger.warning(f"Correlation intelligence extraction failed for {case_id}: {ex}")
            correlation_data = {}

        # 9. Format package data
        case_data = {
            "case_id": case.case_id,
            "case_number": case.case_number,
            "title": case.title,
            "description": case.description,
            "status": case.status,
            "jurisdiction": jurisdiction or case.jurisdiction,
            "created_at": case.created_at.isoformat() if case.created_at else None
        }

        officer = {
            "name": certifying_officer_name,
            "designation": certifying_officer_designation,
            "badge_number": badge_number,
            "role": certifying_officer_designation
        }

        # 10. Generate court-ready document artifact
        gen_result = self.generator.generate_court_ready_report(
            case_data=case_data,
            evidence_items=evidence_items_data,
            metadata_map=metadata_map,
            forensic_analysis_map=forensic_analysis_map,
            ai_analysis_map=ai_analysis_map,
            explainability_map=explainability_map,
            custody_map=custody_map,
            correlation_data=correlation_data,
            certifying_officer=officer,
            report_format=fmt
        )

        # 11. Persist Report in Database
        db_report = Report(
            report_id=gen_result["report_id"],
            case_id=case.case_id,
            report_type=fmt,
            status="GENERATED",
            storage_reference=gen_result["storage_reference"],
            verification_code=gen_result["verification_code"],
            report_sha256=gen_result["report_sha256"],
            qr_code_data=gen_result.get("qr_verification_url"),
            created_by=user_id,
            created_at=datetime.fromisoformat(gen_result["generated_at"])
        )
        self.db.add(db_report)
        self.db.commit()
        self.db.refresh(db_report)
        logger.info(f"Persisted {fmt} report {db_report.report_id} for case {case_id} [code: {db_report.verification_code}]")

        # 12. Append REPORT_GENERATED custody event to each evidence item in docket
        custody_svc = CustodyService(self.db)
        for e in evidence_records:
            try:
                custody_svc.record_event(
                    evidence_id=e.evidence_id,
                    event_type=CustodyEventType.REPORT_GENERATED,
                    user_id=user_id,
                    description=f"Court-ready {fmt} admissibility report {db_report.report_id} generated by {certifying_officer_name}",
                    details={
                        "report_id": db_report.report_id,
                        "report_type": db_report.report_type,
                        "report_sha256": db_report.report_sha256,
                        "verification_code": db_report.verification_code,
                        "case_id": case.case_id,
                        "compliance_framework": "BSA_2023_SEC_63_65B"
                    }
                )
            except Exception as ce:
                logger.warning(f"Could not append REPORT_GENERATED custody event for {e.evidence_id}: {ce}")

        return db_report

    # -------------------------------------------------------------------------
    # Legacy Method (Backward Compatibility for Phase 0/1 tests)
    # -------------------------------------------------------------------------
    def generate_court_report(
        self,
        case_id: str,
        certifying_officer_name: str,
        badge_number: str,
        jurisdiction: str,
        user_id: str
    ) -> CourtReport:
        case = self.db.query(Case).filter_by(case_id=case_id).first()
        if not case:
            raise EntityNotFoundException("Case", case_id)

        evidence_records = self.db.query(EvidenceItem).filter_by(case_id=case_id).all()
        evidence_items_data = [
            {
                "evidence_id": e.evidence_id,
                "original_filename": e.original_filename,
                "file_size_bytes": e.file_size_bytes,
                "mime_type": e.mime_type,
                "sha256_hash": e.sha256_hash
            }
            for e in evidence_records
        ]

        custody_data = {}
        for e in evidence_records:
            evs = self.db.query(CustodyEvent).filter_by(evidence_id=e.evidence_id).all()
            custody_data[e.evidence_id] = [ev.event_id for ev in evs]

        case_data = {
            "case_id": case.case_id,
            "title": case.title,
            "jurisdiction": jurisdiction or case.jurisdiction
        }

        officer = {
            "name": certifying_officer_name,
            "badge_number": badge_number,
            "role": "Forensic Systems Lead"
        }

        report_result = self.generator.generate_report(
            case_data=case_data,
            evidence_items=evidence_items_data,
            custody_ledgers=custody_data,
            certifying_officer=officer
        )

        db_report = CourtReport(
            report_id=report_result["report_id"],
            case_id=case.case_id,
            certifying_officer_id=user_id,
            compliance_framework="BSA_2023_SEC_63_65B",
            report_sha256=report_result["report_sha256"],
            pdf_path=report_result["report_file_path"],
            qr_code_data=report_result["qr_verification_url"]
        )
        self.db.add(db_report)
        self.db.commit()
        self.db.refresh(db_report)
        logger.info(f"Generated court report {db_report.report_id} for case {case_id}")

        custody_svc = CustodyService(self.db)
        for e in evidence_records:
            try:
                custody_svc.record_event(
                    evidence_id=e.evidence_id,
                    event_type=CustodyEventType.REPORT_GENERATED,
                    user_id=user_id,
                    description=f"Court admissibility certificate {db_report.report_id} issued by {certifying_officer_name}",
                    details={
                        "report_id": db_report.report_id,
                        "report_sha256": db_report.report_sha256,
                        "case_id": case.case_id,
                        "compliance_framework": db_report.compliance_framework
                    }
                )
            except Exception as ce:
                logger.warning(f"Could not append REPORT_GENERATED custody event for {e.evidence_id}: {ce}")

        return db_report

    def get_report(self, report_id: str) -> Report:
        """Fetch report record by report_id."""
        report = self.db.query(Report).filter_by(report_id=report_id).first()
        if not report:
            raise EntityNotFoundException("Report", report_id)
        return report

    def get_report_file(self, report_id: str) -> Tuple[str, str, str]:
        """
        Retrieves local file path, display filename, and media type for streaming downloads.
        """
        report = self.get_report(report_id)
        file_path = report.storage_reference
        if not os.path.exists(file_path):
            raise EntityNotFoundException("ReportFile", file_path)

        fmt = (report.report_type or "PDF").upper()
        if "DOCX" in fmt:
            filename = f"{report.report_id}.docx"
            media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        elif "PDF" in fmt:
            filename = f"{report.report_id}.pdf"
            media_type = "application/pdf"
        else:
            filename = f"{report.report_id}.json"
            media_type = "application/json"

        return file_path, filename, media_type

    def verify_report(self, report_id: str) -> Dict[str, Any]:
        from backend.app.services.verification_service import VerificationService
        return VerificationService(self.db).verify_report(report_id)

