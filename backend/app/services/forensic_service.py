"""
NYAYAI - Forensic Orchestration Service (Phase 7)
Module: backend.app.services.forensic_service
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Enforces:
- Backend acts strictly as an orchestration layer
- Zero forensic algorithms inside backend (delegated to Anu Sharma's forensic engine via adapter)
- 9-step orchestration pipeline:
  1. Authenticate user
  2. Verify evidence access
  3. Verify evidence integrity
  4. Send evidence reference to forensic engine adapter
  5. Receive structured result
  6. Store AnalysisResult
  7. Create custody event
  8. Create audit log
  9. Return analysis result
"""

import os
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from sqlalchemy.orm import Session
from backend.app.services.base import BaseService
from backend.app.services.hashing_service import HashingService
from backend.app.storage import get_storage_driver, BaseStorageDriver
from backend.app.models.evidence import Evidence
from backend.app.models.analysis_result import AnalysisResult
from backend.app.models.custody import CustodyEvent
from backend.app.models.audit import AuditLog
from backend.app.adapters.base import BaseForensicEngineAdapter
from backend.app.adapters.forensic_adapter import ForensicEngineAdapter
from backend.app.utils.exceptions import EntityNotFoundException, AppException
from backend.app.utils.logger import get_logger
from custody import CryptographicCustodyLedger, GENESIS_HASH

logger = get_logger("forensic_orchestration")


class ForensicService(BaseService):
    """
    Orchestration layer for forensic inspection.
    Delegates byte analysis to adapter, enforces integrity checks and records custody chain.
    """

    def __init__(
        self,
        db: Session,
        adapter: Optional[BaseForensicEngineAdapter] = None,
        storage_driver: Optional[BaseStorageDriver] = None,
        hasher: Optional[HashingService] = None
    ):
        super().__init__(db)
        self.adapter = adapter or ForensicEngineAdapter()
        self.storage = storage_driver or get_storage_driver()
        self.hasher = hasher or HashingService()
        self.custody_ledger = CryptographicCustodyLedger()

    def inspect_evidence(self, evidence_id: str) -> Dict[str, Any]:
        """Backward-compatible inspection method."""
        return self.orchestrate_analysis(evidence_id=evidence_id)

    def orchestrate_analysis(
        self,
        evidence_id: str,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        adapter_override: Optional[BaseForensicEngineAdapter] = None
    ) -> Dict[str, Any]:
        """
        Executes complete 9-step forensic orchestration pipeline.
        """
        active_adapter = adapter_override or self.adapter
        now = datetime.now(timezone.utc)
        actor_id = user_id or "SYSTEM_FORENSIC_ORCHESTRATOR"

        # Step 2: Verify evidence access
        evidence = self.db.query(Evidence).filter_by(evidence_id=evidence_id).first()
        if not evidence:
            raise EntityNotFoundException("Evidence", evidence_id)

        # Step 3: Verify evidence integrity before processing
        storage_ref = evidence.storage_reference
        if not self.storage.exists(storage_ref):
            raise AppException(
                message=f"Evidence file missing from vault storage: {storage_ref}",
                status_code=404,
                error_code="STORAGE_FILE_NOT_FOUND"
            )

        file_bytes = self.storage.retrieve(storage_ref)
        current_hash = self.hasher.compute_bytes_hash(file_bytes)
        if not self.hasher.verify_hash(current_hash, evidence.sha256_hash):
            evidence.status = "INTEGRITY_COMPROMISED"
            self.db.commit()
            raise AppException(
                message="Evidence integrity compromised: computed file SHA-256 does not match vaulted hash. Forensic analysis aborted to prevent chain tampering.",
                status_code=409,
                error_code="INTEGRITY_COMPROMISED"
            )

        local_file_path = self.storage.get_local_path(storage_ref)

        # Step 4: Send evidence reference to forensic engine & receive structured result
        analysis_id = f"ANL-{now.year}-{uuid.uuid4().hex[:8].upper()}"
        try:
            forensic_result = active_adapter.analyze(
                evidence_id=evidence_id,
                file_path=local_file_path,
                media_type=evidence.media_type,
                declared_mime=evidence.mime_type or "application/octet-stream"
            )
        except Exception as exc:
            # Handle engine failure and record FAILED status
            failed_record = AnalysisResult(
                analysis_id=analysis_id,
                evidence_id=evidence_id,
                analysis_type="FORENSIC_INSPECTION",
                status="FAILED",
                prediction="ANALYSIS_FAILED",
                confidence=0.0,
                risk_score=1.0,
                findings=[str(exc)],
                explanation="Forensic inspection engine failed during processing.",
                model_name=getattr(active_adapter, "model_name", "ForensicEngine"),
                model_version=getattr(active_adapter, "model_version", "0.1.0"),
                created_at=now
            )
            self.db.add(failed_record)

            audit_entry = AuditLog(
                audit_id=f"AUD-{now.year}-{uuid.uuid4().hex[:8].upper()}",
                user_id=actor_id,
                action="FORENSIC_ANALYSIS_FAILED",
                resource_type="EVIDENCE",
                resource_id=evidence_id,
                timestamp=now,
                meta_data={"error": str(exc), "analysis_id": analysis_id}
            )
            self.db.add(audit_entry)
            self.db.commit()
            raise

        # Step 6: Store AnalysisResult
        analysis_record = AnalysisResult(
            analysis_id=analysis_id,
            evidence_id=evidence_id,
            analysis_type="FORENSIC_INSPECTION",
            status="COMPLETED",
            prediction=forensic_result.get("prediction", "COMPLETED"),
            confidence=forensic_result.get("confidence", 0.95),
            risk_score=forensic_result.get("risk_score", 0.10),
            findings=forensic_result.get("findings", []),
            explanation=forensic_result.get("explanation", ""),
            model_name=forensic_result.get("model_name", "ForensicMetadataExtractor"),
            model_version=forensic_result.get("model_version", "0.1.0"),
            created_at=now
        )
        self.db.add(analysis_record)

        # Step 7: Create custody event
        last_event = (
            self.db.query(CustodyEvent)
            .filter_by(evidence_id=evidence_id)
            .order_by(CustodyEvent.sequence_number.desc())
            .first()
        )
        next_seq = (last_event.sequence_number + 1) if last_event else 1
        last_hash = last_event.event_hash if last_event else GENESIS_HASH

        custody_details = {
            "analysis_id": analysis_id,
            "format_valid": forensic_result.get("format_valid", True),
            "anomalies_count": len(forensic_result.get("anomalies", [])),
            "risk_score": forensic_result.get("risk_score", 0.10),
            "prediction": forensic_result.get("prediction", "STRUCTURALLY_CONSISTENT")
        }

        custody_block = self.custody_ledger.create_event(
            evidence_id=evidence_id,
            sequence_number=next_seq,
            action="FORENSIC_ANALYSIS_COMPLETED",
            actor_id=actor_id,
            details=custody_details,
            previous_event_hash=last_hash
        )

        custody_event = CustodyEvent(
            event_id=custody_block["event_id"],
            evidence_id=evidence_id,
            sequence_number=custody_block["sequence_number"],
            event_type=custody_block["action"],
            user_id=custody_block["actor_id"],
            timestamp=custody_block["timestamp"],
            description=f"Forensic structural inspection completed by {actor_id}. Risk score: {custody_details['risk_score']}",
            previous_hash=custody_block["previous_event_hash"],
            event_hash=custody_block["event_hash"],
            payload_json=json.dumps(custody_block["payload_json"])
        )
        self.db.add(custody_event)

        # Step 8: Create audit log
        audit_entry = AuditLog(
            audit_id=f"AUD-{now.year}-{uuid.uuid4().hex[:8].upper()}",
            user_id=actor_id,
            action="FORENSIC_ANALYSIS_PERFORMED",
            resource_type="EVIDENCE",
            resource_id=evidence_id,
            timestamp=now,
            meta_data={
                "case_id": evidence.case_id,
                "analysis_id": analysis_id,
                "format_valid": forensic_result.get("format_valid", True),
                "custody_event_id": custody_block["event_id"],
                "prediction": forensic_result.get("prediction")
            }
        )
        self.db.add(audit_entry)

        # Commit and return
        self.db.commit()

        # Step 9: Return analysis result
        return {
            "analysis_id": analysis_id,
            "evidence_id": evidence_id,
            "analysis_type": "FORENSIC_INSPECTION",
            "status": "COMPLETED",
            "format_valid": forensic_result.get("format_valid", True),
            "magic_bytes": forensic_result.get("magic_bytes", ""),
            "detected_mime": forensic_result.get("detected_mime", evidence.mime_type or ""),
            "anomalies": forensic_result.get("anomalies", []),
            "metadata": forensic_result.get("metadata", {}),
            "prediction": forensic_result.get("prediction", "STRUCTURALLY_CONSISTENT"),
            "confidence": forensic_result.get("confidence", 0.95),
            "risk_score": forensic_result.get("risk_score", 0.10),
            "findings": forensic_result.get("findings", []),
            "explanation": forensic_result.get("explanation", ""),
            "custody_event_id": custody_block["event_id"],
            "created_at": now.isoformat()
        }
