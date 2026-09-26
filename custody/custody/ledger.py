"""
NYAYAI - Cryptographic Chain of Custody Ledger
Module Lead: Ridhi Mashi (Evidence Intelligence & Chain-of-Custody Engineer)

Implements continuous SHA-256 hash chaining:
event_hash = SHA256(previous_event_hash | sequence_number | evidence_id | action | actor_id | timestamp | payload)
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List
from .base import BaseCustodyLedger

GENESIS_HASH = "0" * 64


class CryptographicCustodyLedger(BaseCustodyLedger):
    """
    Tamper-evident custody ledger implementation.
    """

    @staticmethod
    def _compute_hash(
        previous_event_hash: str,
        sequence_number: int,
        evidence_id: str,
        action: str,
        actor_id: str,
        timestamp_iso: str,
        payload_dict: Dict[str, Any]
    ) -> str:
        # Sort keys to ensure deterministic canonical serialization
        serialized_payload = json.dumps(payload_dict, sort_keys=True)
        canonical_content = (
            f"{previous_event_hash}|"
            f"{sequence_number}|"
            f"{evidence_id}|"
            f"{action}|"
            f"{actor_id}|"
            f"{timestamp_iso}|"
            f"{serialized_payload}"
        )
        return hashlib.sha256(canonical_content.encode("utf-8")).hexdigest().lower()

    def create_event(
        self,
        evidence_id: str,
        sequence_number: int,
        action: str,
        actor_id: str,
        details: Dict[str, Any],
        previous_event_hash: str = GENESIS_HASH,
        timestamp_override: str = None
    ) -> Dict[str, Any]:
        """
        Creates and seals a new custody block.
        """
        timestamp = timestamp_override or datetime.now(timezone.utc).isoformat()
        event_id = f"EVT-{uuid.uuid4().hex[:12].upper()}"

        event_hash = self._compute_hash(
            previous_event_hash=previous_event_hash,
            sequence_number=sequence_number,
            evidence_id=evidence_id,
            action=action,
            actor_id=actor_id,
            timestamp_iso=timestamp,
            payload_dict=details
        )

        return {
            "event_id": event_id,
            "evidence_id": evidence_id,
            "sequence_number": sequence_number,
            "action": action,
            "actor_id": actor_id,
            "timestamp": timestamp,
            "previous_event_hash": previous_event_hash,
            "event_hash": event_hash,
            "payload_json": details
        }

    def verify_chain(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validates the integrity of an ordered list of custody events.
        Checks:
        1. Monotonic sequence numbers.
        2. Genesis link for block 1.
        3. previous_event_hash linkage to prior block's event_hash.
        4. Recalculated event_hash matches recorded event_hash.
        """
        if not events:
            return {
                "is_valid": True,
                "verified_count": 0,
                "broken_at_event_id": None,
                "reason": "Empty chain is trivially valid."
            }

        expected_prev_hash = GENESIS_HASH

        for idx, event in enumerate(events):
            expected_seq = idx + 1
            if event.get("sequence_number") != expected_seq:
                return {
                    "is_valid": False,
                    "verified_count": idx,
                    "broken_at_event_id": event.get("event_id"),
                    "reason": f"Sequence break: Expected sequence {expected_seq}, found {event.get('sequence_number')}"
                }

            if event.get("previous_event_hash") != expected_prev_hash:
                return {
                    "is_valid": False,
                    "verified_count": idx,
                    "broken_at_event_id": event.get("event_id"),
                    "reason": f"Hash chain break: Block {expected_seq} previous_event_hash mismatch."
                }

            recalculated_hash = self._compute_hash(
                previous_event_hash=event.get("previous_event_hash"),
                sequence_number=event.get("sequence_number"),
                evidence_id=event.get("evidence_id"),
                action=event.get("action"),
                actor_id=event.get("actor_id"),
                timestamp_iso=event.get("timestamp"),
                payload_dict=event.get("payload_json") if isinstance(event.get("payload_json"), dict) else json.loads(event.get("payload_json", "{}"))
            )

            if recalculated_hash != event.get("event_hash"):
                return {
                    "is_valid": False,
                    "verified_count": idx,
                    "broken_at_event_id": event.get("event_id"),
                    "reason": f"Content tampering detected: Block {expected_seq} hash mismatch."
                }

            expected_prev_hash = event.get("event_hash")

        return {
            "is_valid": True,
            "verified_count": len(events),
            "broken_at_event_id": None,
            "reason": "Chain cryptographically verified and unbroken."
        }
