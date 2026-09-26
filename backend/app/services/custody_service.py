"""
NYAYAI - Chain of Custody Service (Phase 8)
Module: backend.app.services.custody_service
Lead: Ridhi Mashi (Evidence Intelligence & Chain-of-Custody Engineer)
Integration Lead: Dhananjay Sharma (Backend & System Integration Lead)

Enforces:
- Append-only, hash-linked cryptographic event chain:
  Current Event -> previous event hash -> current event hash
- Strict prohibition against deleting or silently modifying historical events
- Chronological event ordering by sequence number
- Full event structure:
  event_id, evidence_id, user_id, event_type, timestamp, description, previous_hash, event_hash
"""

import json
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from backend.app.models.evidence import EvidenceItem
from backend.app.models.custody import CustodyEvent, CustodyEventType
from backend.app.services.base import BaseService
from backend.app.utils.exceptions import EntityNotFoundException
from backend.app.utils.logger import get_logger
from custody import CryptographicCustodyLedger, GENESIS_HASH

logger = get_logger("custody_service")


class CustodyService(BaseService):
    """
    Manages cryptographic Chain of Custody operations, chronological history retrieval,
    and append-only event verification.
    """

    def __init__(self, db: Session):
        super().__init__(db)
        self.ledger = CryptographicCustodyLedger()

    @staticmethod
    def _sanitize_payload(payload: Any) -> Any:
        """
        Sanitizes sensitive internal server storage paths or secrets from custody payload
        before presenting to client, complying with security requirement:
        'Do not expose sensitive internal information unnecessarily'.
        """
        if isinstance(payload, dict):
            sanitized = {}
            for k, v in payload.items():
                k_lower = str(k).lower()
                if any(s in k_lower for s in ["vault_path", "storage_reference", "file_path", "absolute_path", "secret", "password", "token"]):
                    continue
                sanitized[k] = CustodyService._sanitize_payload(v)
            return sanitized
        elif isinstance(payload, list):
            return [CustodyService._sanitize_payload(item) for item in payload]
        return payload

    def get_chronological_history(self, evidence_id: str) -> Dict[str, Any]:
        """
        Retrieves full chronological custody history for evidence artifact.
        Verifies cryptographic SHA-256 chain integrity on every read.
        Enforces:
        - Chronological ordering by sequence number
        - Continuous hash-linked event chain
        - Sensitive information redaction
        """
        evidence = self.db.query(EvidenceItem).filter_by(evidence_id=evidence_id).first()
        if not evidence:
            raise EntityNotFoundException("Evidence", evidence_id)

        # Chronological retrieval ordered by monotonic sequence
        events = (
            self.db.query(CustodyEvent)
            .filter_by(evidence_id=evidence_id)
            .order_by(CustodyEvent.sequence_number.asc())
            .all()
        )

        formatted_events = []
        blocks_for_verification = []

        for ev in events:
            try:
                payload = json.loads(ev.payload_json) if isinstance(ev.payload_json, str) else ev.payload_json
            except Exception:
                payload = {"raw": ev.payload_json}

            ts_str = ev.timestamp if isinstance(ev.timestamp, str) else ev.timestamp.isoformat()
            desc = ev.description or f"{ev.event_type} recorded by {ev.user_id}"

            event_dict = {
                "event_id": ev.event_id,
                "evidence_id": ev.evidence_id,
                "user_id": ev.user_id,
                "event_type": ev.event_type,
                "timestamp": ts_str,
                "description": desc,
                "previous_hash": ev.previous_hash,
                "event_hash": ev.event_hash,
                # Backward compatibility aliases
                "sequence_number": ev.sequence_number,
                "action": ev.action,
                "actor_id": ev.actor_id,
                "previous_event_hash": ev.previous_event_hash,
                "payload_json": self._sanitize_payload(payload)
            }
            formatted_events.append(event_dict)

            # Raw un-sanitized block structure required for cryptographic SHA-256 verifier
            blocks_for_verification.append({
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

        verification = self.ledger.verify_chain(blocks_for_verification)

        return {
            "success": True,
            "evidence_id": evidence_id,
            "chain_intact": verification["is_valid"],
            "total_events": len(formatted_events),
            "history": formatted_events,
            "events": formatted_events,
            "ledger": formatted_events
        }

    # Backward compatibility alias
    get_ledger = get_chronological_history

    def record_event(
        self,
        evidence_id: str,
        event_type: str,
        user_id: str,
        description: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Appends a verifiable, hash-linked event block to the evidence custody chain:
        Current Event -> previous event hash -> current event hash
        """
        evidence = self.db.query(EvidenceItem).filter_by(evidence_id=evidence_id).first()
        if not evidence:
            raise EntityNotFoundException("Evidence", evidence_id)

        last_event = (
            self.db.query(CustodyEvent)
            .filter_by(evidence_id=evidence_id)
            .order_by(CustodyEvent.sequence_number.desc())
            .first()
        )
        next_seq = (last_event.sequence_number + 1) if last_event else 1
        prev_hash = last_event.event_hash if last_event else GENESIS_HASH

        payload_details = details or {}
        desc = description or f"Custody event '{event_type}' recorded by {user_id}"

        # Seal cryptographic block
        sealed_block = self.ledger.create_event(
            evidence_id=evidence_id,
            sequence_number=next_seq,
            action=event_type,
            actor_id=user_id,
            details=payload_details,
            previous_event_hash=prev_hash
        )

        custody_event = CustodyEvent(
            event_id=sealed_block["event_id"],
            evidence_id=evidence_id,
            sequence_number=next_seq,
            event_type=event_type,
            user_id=user_id,
            timestamp=sealed_block["timestamp"],
            description=desc,
            previous_hash=prev_hash,
            event_hash=sealed_block["event_hash"],
            payload_json=json.dumps(sealed_block["payload_json"])
        )
        self.db.add(custody_event)
        self.db.commit()
        self.db.refresh(custody_event)

        logger.info(
            f"Sealed custody block {next_seq} ({event_type}) for evidence {evidence_id}: {sealed_block['event_hash']}"
        )

        return {
            "event_id": custody_event.event_id,
            "evidence_id": custody_event.evidence_id,
            "user_id": custody_event.user_id,
            "event_type": custody_event.event_type,
            "timestamp": custody_event.timestamp,
            "description": custody_event.description,
            "previous_hash": custody_event.previous_hash,
            "event_hash": custody_event.event_hash,
            "sequence_number": custody_event.sequence_number
        }

    def verify_ledger(self, evidence_id: str) -> Dict[str, Any]:
        """
        Verifies entire cryptographic custody chain from genesis to head block
        using raw un-sanitized blocks directly from database.
        """
        evidence = self.db.query(EvidenceItem).filter_by(evidence_id=evidence_id).first()
        if not evidence:
            raise EntityNotFoundException("Evidence", evidence_id)

        events = (
            self.db.query(CustodyEvent)
            .filter_by(evidence_id=evidence_id)
            .order_by(CustodyEvent.sequence_number.asc())
            .all()
        )

        blocks_for_verification = []
        for ev in events:
            try:
                payload = json.loads(ev.payload_json) if isinstance(ev.payload_json, str) else ev.payload_json
            except Exception:
                payload = {"raw": ev.payload_json}

            ts_str = ev.timestamp if isinstance(ev.timestamp, str) else ev.timestamp.isoformat()
            blocks_for_verification.append({
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

        verification = self.ledger.verify_chain(blocks_for_verification)
        return {
            "evidence_id": evidence_id,
            "is_valid": verification["is_valid"],
            "verified_blocks": verification["verified_count"],
            "broken_at_event_id": verification.get("broken_at_event_id"),
            "diagnostic_message": verification.get("reason", "Chain verified.")
        }

