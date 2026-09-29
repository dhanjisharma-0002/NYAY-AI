"""
NYAYAI - Case Docket Batch Pipeline Service (Phase 16)
Module: backend.app.services.pipeline_batch_service
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Coordinates automated, end-to-end evidence pipeline execution across entire case dockets:
1. Filters pending/unanalyzed evidence (avoids redundant re-analysis).
2. Sequentially executes EvidencePipelineOrchestrator per evidence item.
3. Preserves cryptographic SHA-256 pre-analysis verification against vaulted files.
4. On hash tampering or storage failure, marks the individual item without crashing the batch.
5. Preserves custody hash-chain continuity.
6. Updates case status according to existing CaseService/status rules.
7. Logs a single CASE_PIPELINE_BATCH_EXECUTED audit event.
8. Enforces RBAC and role isolation.
"""

import json
import uuid
from typing import Dict, Any, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from backend.app.models.user import User
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.evidence_metadata import EvidenceMetadata
from backend.app.models.analysis_result import AnalysisResult
from backend.app.models.explainability import ExplainabilityRecord
from backend.app.models.custody import CustodyEvent
from backend.app.models.audit import AuditLog
from backend.app.services.base import BaseService
from backend.app.orchestrator.pipeline import EvidencePipelineOrchestrator
from backend.app.utils.exceptions import (
    EntityNotFoundException,
    PermissionDeniedException
)


class PipelineBatchService(BaseService):
    """
    Coordinates batch execution of the forensic, AI, explainability, and custody
    pipeline across all pending evidence artifacts in a case docket.
    """

    def __init__(self, db: Session):
        super().__init__(db)
        self.orchestrator = EvidencePipelineOrchestrator()

    def process_case_pipeline(
        self,
        case_id: str,
        current_user: User,
        force_reanalysis: bool = False
    ) -> Dict[str, Any]:
        """
        Executes end-to-end pipeline on all pending evidence for the given case_id.
        """
        # 1. Verify case existence
        case = self.db.query(Case).filter_by(case_id=case_id).first()
        if not case:
            raise EntityNotFoundException("Case", case_id)

        # 2. Enforce RBAC & Role Isolation
        user_role = (current_user.role or "").strip().upper()
        if user_role == "INVESTIGATOR":
            if case.created_by != current_user.id and case.created_by != current_user.username:
                raise PermissionDeniedException(
                    f"Access forbidden: Investigator '{current_user.username}' is not authorized to process case '{case_id}'."
                )

        # 3. Retrieve all evidence items in case docket
        all_evidences = (
            self.db.query(Evidence)
            .filter_by(case_id=case_id)
            .order_by(Evidence.created_at.asc())
            .all()
        )
        total_items = len(all_evidences)

        # 4. Filter only pending/unanalyzed evidence items (idempotency guarantee)
        pending_evidences: List[Evidence] = []
        for ev in all_evidences:
            if force_reanalysis:
                pending_evidences.append(ev)
            else:
                has_meta = self.db.query(EvidenceMetadata).filter_by(evidence_id=ev.evidence_id).first() is not None
                has_ai = self.db.query(AnalysisResult).filter_by(evidence_id=ev.evidence_id).first() is not None
                if not (has_meta and has_ai):
                    pending_evidences.append(ev)

        # 5. Process items sequentially
        processed_count = 0
        anomalies_detected = 0
        tamper_detected_count = 0
        compromised_count = 0

        for evidence in pending_evidences:
            # Retrieve latest custody event to maintain unbroken hash chain
            last_event = (
                self.db.query(CustodyEvent)
                .filter_by(evidence_id=evidence.evidence_id)
                .order_by(CustodyEvent.sequence_number.desc())
                .first()
            )
            last_hash = last_event.event_hash if last_event else ("0" * 64)
            next_seq = (last_event.sequence_number + 1) if last_event else 1

            vault_path = evidence.storage_reference or evidence.vault_path
            mime = evidence.media_type or evidence.mime_type or "APPLICATION/OCTET-STREAM"

            try:
                pipeline_output = self.orchestrator.run_full_analysis(
                    evidence_id=evidence.evidence_id,
                    vault_path=vault_path,
                    expected_sha256=evidence.sha256_hash,
                    declared_mime=mime,
                    actor_id=current_user.id,
                    last_event_hash=last_hash,
                    next_seq_num=next_seq
                )
            except ValueError as val_err:
                # Vault file hash mismatch / tampering detected
                evidence.status = "INTEGRITY_COMPROMISED"
                compromised_count += 1

                # Record integrity failure custody block
                c_fail = self.orchestrator.custody_ledger.create_event(
                    evidence_id=evidence.evidence_id,
                    sequence_number=next_seq,
                    action="INTEGRITY_VERIFICATION_FAILED",
                    actor_id=current_user.id,
                    details={"error": str(val_err), "status": "INTEGRITY_COMPROMISED"},
                    previous_event_hash=last_hash
                )
                db_fail_evt = CustodyEvent(
                    event_id=c_fail["event_id"],
                    evidence_id=evidence.evidence_id,
                    sequence_number=c_fail["sequence_number"],
                    action=c_fail["action"],
                    actor_id=c_fail["actor_id"],
                    timestamp=c_fail["timestamp"],
                    previous_event_hash=c_fail["previous_event_hash"],
                    event_hash=c_fail["event_hash"],
                    payload_json=json.dumps(c_fail["payload_json"])
                )
                self.db.add(db_fail_evt)
                self.db.commit()
                continue
            except (FileNotFoundError, OSError):
                # Physical vault file inaccessible or missing
                evidence.status = "STORAGE_ERROR"
                self.db.commit()
                continue
            except Exception as ex:
                self.logger.error(f"Unexpected error analyzing evidence '{evidence.evidence_id}': {ex}")
                continue

            # Extract pipeline results
            forensic = pipeline_output["forensic_report"]
            ai_res = pipeline_output["ai_analysis"]
            exp_res = pipeline_output["explainability"]
            c_evt = pipeline_output["custody_event"]

            # Anomaly tally
            has_anomaly = (
                not forensic.get("format_valid", True) or
                bool(forensic.get("anomalies") and len(forensic.get("anomalies")) > 0)
            )
            if has_anomaly:
                anomalies_detected += 1

            # AI tamper tally
            pred_str = str(ai_res.get("prediction", "")).upper()
            is_tamper = False
            if "NO_TAMPER" not in pred_str and "AUTHENTIC" not in pred_str and "CLEAN" not in pred_str:
                if ai_res.get("tamper_detected") or "TAMPER" in pred_str:
                    is_tamper = True
                    tamper_detected_count += 1

            # Upsert EvidenceMetadata (Forensic Artifacts)
            meta_rec = self.db.query(EvidenceMetadata).filter_by(evidence_id=evidence.evidence_id).first()
            if meta_rec:
                meta_rec.format_valid = forensic.get("format_valid", True)
                meta_rec.magic_bytes = forensic.get("magic_bytes", "") or "UNKNOWN"
                meta_rec.exif_data = forensic.get("exif_metadata", {})
                meta_rec.timestamps_metadata = forensic.get("filesystem_metadata", {})
                meta_rec.anomalies = forensic.get("anomalies", [])
            else:
                meta_rec = EvidenceMetadata(
                    metadata_id=f"META-{uuid.uuid4().hex[:12].upper()}",
                    evidence_id=evidence.evidence_id,
                    format_valid=forensic.get("format_valid", True),
                    magic_bytes=forensic.get("magic_bytes", "") or "UNKNOWN",
                    exif_data=forensic.get("exif_metadata", {}),
                    timestamps_metadata=forensic.get("filesystem_metadata", {}),
                    anomalies=forensic.get("anomalies", [])
                )
                self.db.add(meta_rec)

            # Upsert AnalysisResult (AI Findings)
            ai_rec = self.db.query(AnalysisResult).filter_by(evidence_id=evidence.evidence_id).first()
            if ai_rec:
                ai_rec.prediction = "TAMPER_DETECTED" if is_tamper else "AUTHENTIC"
                ai_rec.confidence = ai_res.get("confidence_score", 0.0)
                ai_rec.risk_score = 0.85 if is_tamper else 0.05
                ai_rec.findings = ai_res.get("findings", [])
            else:
                ai_rec = AnalysisResult(
                    analysis_id=f"AIR-{uuid.uuid4().hex[:12].upper()}",
                    evidence_id=evidence.evidence_id,
                    analysis_type="TAMPER_DETECTION",
                    status="COMPLETED",
                    prediction="TAMPER_DETECTED" if is_tamper else "AUTHENTIC",
                    confidence=ai_res.get("confidence_score", 0.0),
                    risk_score=0.85 if is_tamper else 0.05,
                    findings=ai_res.get("findings", []),
                    model_name=ai_res.get("model_name", "TamperScreener"),
                    model_version=ai_res.get("model_version", "0.1.0")
                )
                self.db.add(ai_rec)

            # Upsert ExplainabilityRecord
            exp_rec = self.db.query(ExplainabilityRecord).filter_by(evidence_id=evidence.evidence_id).first()
            if not exp_rec:
                exp_rec = ExplainabilityRecord(
                    record_id=f"EXP-{uuid.uuid4().hex[:12].upper()}",
                    evidence_id=evidence.evidence_id,
                    reasoning_summary=exp_res.get("reasoning_summary", ""),
                    confidence_category=exp_res.get("confidence_category", "MEDIUM"),
                    feature_attributions=json.dumps(exp_res.get("contributing_factors", [])),
                    limitations_disclaimer=exp_res.get("limitations_disclaimer", "")
                )
                self.db.add(exp_rec)

            # Record Chained Custody Event
            db_cust_event = CustodyEvent(
                event_id=c_evt["event_id"],
                evidence_id=evidence.evidence_id,
                sequence_number=c_evt["sequence_number"],
                action=c_evt["action"],
                actor_id=c_evt["actor_id"],
                timestamp=c_evt["timestamp"],
                previous_event_hash=c_evt["previous_event_hash"],
                event_hash=c_evt["event_hash"],
                payload_json=json.dumps(c_evt["payload_json"])
            )
            self.db.add(db_cust_event)

            # Update evidence status
            evidence.status = "ANALYZED"
            processed_count += 1
            self.db.commit()

        # 6. Update case lifecycle status if transitioning from OPEN
        now = datetime.now(timezone.utc)
        if case.status == "OPEN" and processed_count > 0:
            case.status = "UNDER_ANALYSIS"
            case.updated_at = now
            self.db.commit()

        # 7. Record single audit entry for the batch execution
        audit_entry = AuditLog(
            audit_id=f"AUD-{uuid.uuid4().hex[:12].upper()}",
            user_id=current_user.id,
            action="CASE_PIPELINE_BATCH_EXECUTED",
            resource_type="CASE",
            resource_id=case.case_id,
            meta_data={
                "processed_count": processed_count,
                "total_items": total_items,
                "anomalies_detected": anomalies_detected,
                "tamper_detected_count": tamper_detected_count,
                "compromised_count": compromised_count,
                "new_case_status": case.status
            }
        )
        self.db.add(audit_entry)
        self.db.commit()

        return {
            "case_id": case.case_id,
            "total_items": total_items,
            "processed_count": processed_count,
            "anomalies_detected": anomalies_detected,
            "tamper_detected_count": tamper_detected_count,
            "compromised_count": compromised_count,
            "new_case_status": case.status
        }
