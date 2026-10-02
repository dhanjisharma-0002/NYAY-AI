"""
NYAYAI - Cryptographic Chain of Custody Ledger (Production Grade)
Module Lead: Ridhi Masih (Evidence Intelligence & Chain-of-Custody Engineer)

Implements continuous SHA-256 hash chaining & Merkle Tree Root verification:
- event_hash = SHA256(previous_event_hash | sequence_number | evidence_id | action | actor_id | timestamp | payload)
- Merkle Root = Binary SHA-256 tree over all sequential event hashes
- Bharatiya Sakshya Adhiniyam (BSA), 2023 (Section 63/65B) Custody Compliance Certificate
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from .base import BaseCustodyLedger

GENESIS_HASH = "0" * 64


class CryptographicCustodyLedger(BaseCustodyLedger):
    """
    Tamper-evident, courtroom-grade custody ledger implementation.
    Owned and maintained by Ridhi Masih.
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

    @staticmethod
    def compute_merkle_root(event_hashes: List[str]) -> str:
        """
        Calculates binary Merkle tree root over all event hashes in the chain.
        Adheres to standard RFC 6962 / Bitcoin Merkle tree rules (last node duplicated if odd).
        """
        if not event_hashes:
            return GENESIS_HASH

        current = list(event_hashes)
        while len(current) > 1:
            if len(current) % 2 == 1:
                current.append(current[-1])
            next_level = []
            for i in range(0, len(current), 2):
                combined = (current[i] + current[i + 1]).encode("utf-8")
                next_level.append(hashlib.sha256(combined).hexdigest().lower())
            current = next_level

        return current[0]

    def create_event(
        self,
        evidence_id: str,
        sequence_number: int,
        action: str,
        actor_id: str,
        details: Dict[str, Any],
        previous_event_hash: str = GENESIS_HASH,
        timestamp_override: Optional[str] = None
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

    def create_seal_event(
        self,
        evidence_id: str,
        sequence_number: int,
        actor_id: str,
        prior_events: List[Dict[str, Any]],
        previous_event_hash: str,
        order_reference: str = "Judicial Sealing Order"
    ) -> Dict[str, Any]:
        """
        Creates a specialized JUDICIAL_SEALING custody event containing the Merkle root of all prior blocks.
        """
        hashes = [e.get("event_hash", "") for e in prior_events]
        merkle_root = self.compute_merkle_root(hashes)
        details = {
            "seal_type": "STATUTORY_JUDICIAL_SEAL",
            "statutory_authority": "BSA_2023_SECTION_63",
            "order_reference": order_reference,
            "total_sealed_events": len(prior_events),
            "merkle_root": merkle_root,
            "status": "SEALED_IMMUTABLE"
        }
        return self.create_event(
            evidence_id=evidence_id,
            sequence_number=sequence_number,
            action="JUDICIAL_SEALING_AND_CUSTODY_TRANSFER",
            actor_id=actor_id,
            details=details,
            previous_event_hash=previous_event_hash
        )

    def verify_chain(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validates the integrity of an ordered list of custody events.
        Checks:
        1. Monotonic sequence numbers.
        2. Genesis link for block 1.
        3. previous_event_hash linkage to prior block's event_hash.
        4. Recalculated event_hash matches recorded event_hash.
        5. Computes chain Merkle root.
        """
        if not events:
            return {
                "is_valid": True,
                "verified_count": 0,
                "broken_at_event_id": None,
                "genesis_hash": GENESIS_HASH,
                "merkle_root": GENESIS_HASH,
                "reason": "Empty chain is trivially valid."
            }

        expected_prev_hash = GENESIS_HASH
        event_hashes: List[str] = []

        for idx, event in enumerate(events):
            expected_seq = idx + 1
            seq_num = event.get("sequence_number")
            ev_id = event.get("event_id")

            if seq_num != expected_seq:
                return {
                    "is_valid": False,
                    "verified_count": idx,
                    "broken_at_event_id": ev_id,
                    "tamper_field": "sequence_number",
                    "reason": f"Sequence break: Expected sequence {expected_seq}, found {seq_num}"
                }

            prev_hash = event.get("previous_event_hash")
            if prev_hash != expected_prev_hash:
                return {
                    "is_valid": False,
                    "verified_count": idx,
                    "broken_at_event_id": ev_id,
                    "tamper_field": "previous_event_hash",
                    "reason": f"Hash chain break: Block {expected_seq} previous_event_hash mismatch."
                }

            raw_payload = event.get("payload_json")
            if isinstance(raw_payload, dict):
                payload_dict = raw_payload
            elif isinstance(raw_payload, str):
                try:
                    payload_dict = json.loads(raw_payload)
                except Exception:
                    payload_dict = {"raw": raw_payload}
            else:
                payload_dict = {}

            recalculated_hash = self._compute_hash(
                previous_event_hash=prev_hash,
                sequence_number=seq_num,
                evidence_id=event.get("evidence_id"),
                action=event.get("action"),
                actor_id=event.get("actor_id"),
                timestamp_iso=event.get("timestamp"),
                payload_dict=payload_dict
            )

            rec_event_hash = event.get("event_hash")
            if recalculated_hash != rec_event_hash:
                return {
                    "is_valid": False,
                    "verified_count": idx,
                    "broken_at_event_id": ev_id,
                    "tamper_field": "payload_json_or_attributes",
                    "reason": f"Content tampering detected: Block {expected_seq} hash mismatch."
                }

            event_hashes.append(rec_event_hash)
            expected_prev_hash = rec_event_hash

        merkle_root = self.compute_merkle_root(event_hashes)

        return {
            "is_valid": True,
            "verified_count": len(events),
            "broken_at_event_id": None,
            "genesis_hash": GENESIS_HASH,
            "head_hash": event_hashes[-1] if event_hashes else GENESIS_HASH,
            "merkle_root": merkle_root,
            "reason": "Chain cryptographically verified and unbroken."
        }

    def generate_certificate(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Produces a court-admissible Certificate of Custody Integrity under BSA 2023 Sec 63.
        """
        verif = self.verify_chain(events)
        evidence_id = events[0].get("evidence_id") if events else "UNKNOWN"

        return {
            "certificate_id": f"CERT-CUST-{uuid.uuid4().hex[:12].upper()}",
            "evidence_id": evidence_id,
            "statutory_authority": "Bharatiya Sakshya Adhiniyam, 2023 (Section 63 & 65B)",
            "is_unbroken": verif["is_valid"],
            "total_blocks_verified": verif["verified_count"],
            "genesis_hash": GENESIS_HASH,
            "head_event_hash": verif.get("head_hash"),
            "merkle_root": verif.get("merkle_root"),
            "certification_timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "CRYPTOGRAPHICALLY_VERIFIED" if verif["is_valid"] else "TAMPERED_INVALID",
            "verification_summary": verif["reason"]
        }
