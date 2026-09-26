"""
NYAYAI - Evidence Integrity Verification Service
Module: backend.app.services.integrity_service
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Enforces:
- Rule 7: Digital evidence integrity must use SHA-256
- Rule 2: Zero mutation guarantee on original vaulted artifacts
- Chain of Custody continuous cryptographic auditing
- Non-repudiation and tamper detection
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from sqlalchemy.orm import Session
from backend.app.services.base import BaseService
from backend.app.services.hashing_service import HashingService
from backend.app.storage import get_storage_driver, BaseStorageDriver
from backend.app.storage.exceptions import StorageFileNotFoundException, StorageException
from backend.app.models.evidence import Evidence
from backend.app.models.custody import CustodyEvent
from backend.app.models.audit import AuditLog
from backend.app.utils.exceptions import EntityNotFoundException
from backend.app.utils.logger import get_logger
from custody import CryptographicCustodyLedger, GENESIS_HASH

logger = get_logger("integrity_service")


class EvidenceIntegrityService(BaseService):
    """
    Core integrity verification service for NYAYAI digital evidence.
    Verifies that the vaulted physical file matches its recorded SHA-256 digest
    without modifying the original evidence or overwriting the original hash.
    """

    def __init__(
        self,
        db: Session,
        storage_driver: Optional[BaseStorageDriver] = None,
        hasher: Optional[HashingService] = None
    ):
        super().__init__(db)
        self.storage = storage_driver or get_storage_driver()
        self.hasher = hasher or HashingService()
        self.custody_ledger = CryptographicCustodyLedger()

    def verify_evidence_integrity(
        self,
        evidence_id: str,
        actor_user_id: Optional[str] = None,
        actor_username: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes complete cryptographic evidence integrity verification:
        1. Retrieves original stored file from storage abstraction.
        2. Calculates current SHA-256 hash using reusable HashingService.
        3. Compares current hash with stored hash (constant-time).
        4. If mismatch occurs:
           - NEVER overwrites the stored hash.
           - Updates evidence status to 'INTEGRITY_COMPROMISED'.
        5. If storage or file missing occurs:
           - Returns ERROR status.
           - Records storage error.
        6. Appends a tamper-evident event to the Custody Ledger.
        7. Records an audit log event.
        8. Returns verification report.
        """
        # Step 1: Look up evidence record
        evidence = self.db.query(Evidence).filter_by(evidence_id=evidence_id).first()
        if not evidence:
            raise EntityNotFoundException("Evidence", evidence_id)

        stored_hash = evidence.sha256_hash
        storage_ref = evidence.storage_reference
        now = datetime.now(timezone.utc)
        verified_at_iso = now.isoformat()

        actor_id = actor_user_id or "SYSTEM_VERIFICATION_DAEMON"
        actor_name = actor_username or actor_id

        current_hash: Optional[str] = None
        integrity_status: str = "ERROR"
        error_message: Optional[str] = None
        custody_action: str = "EVIDENCE_INTEGRITY_CHECK_FAILED"
        audit_action: str = "EVIDENCE_STORAGE_ERROR"

        # Step 2: Retrieve original stored file & calculate current SHA-256
        try:
            if not self.storage.exists(storage_ref):
                integrity_status = "ERROR"
                error_message = f"Evidence file missing from vault storage: {storage_ref}"
                custody_action = "EVIDENCE_FILE_MISSING_ERROR"
                audit_action = "EVIDENCE_STORAGE_ERROR"
                logger.error(f"Integrity check failed: {error_message}")
            else:
                # Read content in strict read-only mode
                file_bytes = self.storage.retrieve(storage_ref)
                current_hash = self.hasher.compute_bytes_hash(file_bytes)

                # Step 3: Compare with stored hash
                if self.hasher.verify_hash(current_hash, stored_hash):
                    integrity_status = "VERIFIED"
                    error_message = None
                    custody_action = "EVIDENCE_INTEGRITY_VERIFIED"
                    audit_action = "EVIDENCE_INTEGRITY_VERIFIED"
                    logger.info(
                        f"Evidence integrity VERIFIED for {evidence_id} (hash: {stored_hash})"
                    )
                else:
                    # TAMPER DETECTED / HASH MISMATCH
                    integrity_status = "MISMATCH"
                    error_message = (
                        f"Cryptographic hash mismatch! Vaulted file hash ({current_hash}) "
                        f"does not match registered hash ({stored_hash})."
                    )
                    custody_action = "EVIDENCE_INTEGRITY_TAMPER_DETECTED"
                    audit_action = "EVIDENCE_INTEGRITY_MISMATCH"
                    logger.warning(
                        f"CRITICAL: Integrity MISMATCH detected on evidence {evidence_id}! "
                        f"Expected {stored_hash}, got {current_hash}"
                    )

        except StorageFileNotFoundException as fnf:
            integrity_status = "ERROR"
            error_message = str(fnf)
            custody_action = "EVIDENCE_FILE_MISSING_ERROR"
            audit_action = "EVIDENCE_STORAGE_ERROR"
            logger.error(f"Storage file not found: {fnf}")

        except Exception as exc:
            integrity_status = "ERROR"
            error_message = f"Storage access error during integrity check: {str(exc)}"
            custody_action = "STORAGE_ACCESS_ERROR"
            audit_action = "EVIDENCE_STORAGE_ERROR"
            logger.error(f"Integrity check exception on {evidence_id}: {exc}")

        # Step 4: Update evidence status appropriately WITHOUT overwriting stored hash
        if integrity_status == "MISMATCH":
            # Rule: Original evidence must never be modified.
            # Do NOT overwrite stored hash. Mark status appropriately.
            evidence.status = "INTEGRITY_COMPROMISED"
        elif integrity_status == "ERROR" and evidence.status != "INTEGRITY_COMPROMISED":
            evidence.status = "STORAGE_ERROR"

        # Step 5: Create next Custody Event
        last_event = (
            self.db.query(CustodyEvent)
            .filter_by(evidence_id=evidence_id)
            .order_by(CustodyEvent.sequence_number.desc())
            .first()
        )
        next_seq = (last_event.sequence_number + 1) if last_event else 1
        last_hash = last_event.event_hash if last_event else GENESIS_HASH

        custody_details = {
            "evidence_id": evidence_id,
            "case_id": evidence.case_id,
            "stored_hash": stored_hash,
            "current_hash": current_hash,
            "integrity_status": integrity_status,
            "verified_at": verified_at_iso,
            "storage_reference": storage_ref,
            "error_message": error_message
        }

        sealed_block = self.custody_ledger.create_event(
            evidence_id=evidence_id,
            sequence_number=next_seq,
            action=custody_action,
            actor_id=actor_id,
            details=custody_details,
            previous_event_hash=last_hash
        )

        custody_event_record = CustodyEvent(
            event_id=sealed_block["event_id"],
            evidence_id=evidence_id,
            sequence_number=sealed_block["sequence_number"],
            event_type=sealed_block["action"],
            user_id=sealed_block["actor_id"],
            timestamp=sealed_block["timestamp"],
            description=(
                f"Integrity check completed: status={integrity_status}. "
                f"Stored={stored_hash[:16]}..., Current={(current_hash or 'None')[:16]}..."
            ),
            previous_hash=sealed_block["previous_event_hash"],
            event_hash=sealed_block["event_hash"],
            payload_json=json.dumps(sealed_block["payload_json"])
        )
        self.db.add(custody_event_record)

        # Step 6: Create Audit Log entry
        audit_id = f"AUD-{now.year}-{uuid.uuid4().hex[:8].upper()}"
        audit_entry = AuditLog(
            audit_id=audit_id,
            user_id=actor_user_id,
            action=audit_action,
            resource_type="EVIDENCE",
            resource_id=evidence_id,
            timestamp=now,
            meta_data={
                "case_id": evidence.case_id,
                "stored_hash": stored_hash,
                "current_hash": current_hash,
                "integrity_status": integrity_status,
                "custody_event_id": sealed_block["event_id"],
                "error_message": error_message
            }
        )
        self.db.add(audit_entry)

        # Commit and preserve history
        self.db.commit()

        # Step 7: Return verification information matching Phase 6 response specification
        return {
            "evidence_id": evidence_id,
            "stored_hash": stored_hash,
            "current_hash": current_hash,
            "integrity_status": integrity_status,
            "verified_at": verified_at_iso,
            "error_message": error_message,
            "custody_event_id": sealed_block["event_id"]
        }
