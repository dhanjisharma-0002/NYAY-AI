"""
NYAYAI - Evidence Correlation & Intelligence Service (Phase 9)
Module: backend.app.services.correlation_service
Lead: Ridhi Mashi (Evidence Intelligence & Chain-of-Custody Engineer)
Integration Lead: Dhananjay Sharma (Backend & System Integration Lead)

Aggregates case evidence, metadata, custody blocks, and analysis results to produce:
1. Chronological timeline (no invented timestamps; null/unknown if missing)
2. Evidence relationships (Evidence A related_to Evidence B with reason)
3. Cross-evidence matches
4. Evidence-based red flags (objective anomalies; no criminality claims)
"""

from typing import Dict, Any, List
from sqlalchemy.orm import Session

from backend.app.models.case import Case
from backend.app.models.evidence import EvidenceItem
from backend.app.models.evidence_metadata import EvidenceMetadata
from backend.app.models.custody import CustodyEvent
from backend.app.models.analysis_result import AnalysisResult
from backend.app.services.base import BaseService
from backend.app.utils.exceptions import EntityNotFoundException
from backend.app.utils.logger import get_logger
from correlation import BaselineCorrelationEngine

logger = get_logger("correlation_service")


class CorrelationService(BaseService):
    """
    Orchestrates evidence correlation, multi-evidence timeline synthesis,
    relationship tracking, and red flag extraction for case dockets.
    """

    def __init__(self, db: Session):
        super().__init__(db)
        self.engine = BaselineCorrelationEngine()

    def correlate_case(self, case_id: str) -> Dict[str, Any]:
        """
        Gathers all case evidence artifacts, metadata, analysis results, and custody trails,
        passing them to the Evidence Intelligence Engine.
        """
        case = self.db.query(Case).filter_by(case_id=case_id).first()
        if not case:
            raise EntityNotFoundException("Case", case_id)

        evidence_records = (
            self.db.query(EvidenceItem)
            .filter_by(case_id=case_id)
            .order_by(EvidenceItem.created_at.asc())
            .all()
        )

        items_for_correlation: List[Dict[str, Any]] = []

        for e in evidence_records:
            ev_id = e.evidence_id

            # 1. Fetch metadata if present
            meta_record = self.db.query(EvidenceMetadata).filter_by(evidence_id=ev_id).first()
            metadata_dict = {}
            if meta_record:
                metadata_dict = {
                    "format_valid": meta_record.format_valid,
                    "magic_bytes": meta_record.magic_bytes,
                    "exif_data": meta_record.exif_data or {},
                    "timestamps_metadata": meta_record.timestamps_metadata or {},
                    "anomalies": meta_record.anomalies or []
                }

            # 2. Fetch custody events if present
            custody_records = (
                self.db.query(CustodyEvent)
                .filter_by(evidence_id=ev_id)
                .order_by(CustodyEvent.sequence_number.asc())
                .all()
            )
            custody_events_list = [
                {
                    "event_id": c.event_id,
                    "sequence_number": c.sequence_number,
                    "event_type": c.event_type,
                    "action": c.action,
                    "user_id": c.user_id,
                    "timestamp": c.timestamp,
                    "description": c.description,
                    "previous_hash": c.previous_hash,
                    "event_hash": c.event_hash
                }
                for c in custody_records
            ]

            # 3. Fetch analysis results if present
            analysis_records = (
                self.db.query(AnalysisResult)
                .filter_by(evidence_id=ev_id)
                .all()
            )
            analyses_list = [
                {
                    "analysis_id": a.analysis_id,
                    "analysis_type": a.analysis_type,
                    "status": a.status,
                    "prediction": a.prediction,
                    "confidence": a.confidence,
                    "risk_score": a.risk_score,
                    "findings": a.findings or [],
                    "explanation": a.explanation
                }
                for a in analysis_records
            ]

            # Formulate evidence package
            # Strictly use documented timestamps without inventing
            created_ts = e.created_at.isoformat() if e.created_at else None

            items_for_correlation.append({
                "evidence_id": ev_id,
                "case_id": e.case_id,
                "original_filename": e.original_filename,
                "filename": e.original_filename,
                "media_type": e.media_type,
                "mime_type": e.mime_type,
                "file_size": e.file_size,
                "sha256_hash": e.sha256_hash,
                "status": e.status,
                "uploaded_by": e.uploaded_by,
                "source_description": e.source_description,
                "created_at": created_ts,
                "intake_timestamp": created_ts,
                "metadata": metadata_dict,
                "custody_events": custody_events_list,
                "analysis_results": analyses_list
            })

        # Process through Evidence Intelligence & Correlation Engine
        result = self.engine.correlate_case_evidence(case_id, items_for_correlation)

        # Wrap with top-level and data fields for universal client compatibility
        response_dict = {
            "success": True,
            "case_id": case_id,
            "timeline": result["timeline"],
            "relationships": result["relationships"],
            "links": result["relationships"],  # Legacy synonym
            "cross_evidence_matches": result["cross_evidence_matches"],
            "red_flags": result["red_flags"],
            "total_evidence_count": len(evidence_records),
            "total_red_flags": len(result["red_flags"]),
            "total_items": len(evidence_records),
            "data": result
        }

        logger.info(
            f"Case correlation completed for {case_id}: "
            f"{len(result['timeline'])} timeline events, "
            f"{len(result['relationships'])} relationships, "
            f"{len(result['red_flags'])} red flags."
        )

        return response_dict
