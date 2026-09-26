"""
NYAYAI - Test Suite: Chain of Custody Cryptographic Ledger
Tests adherence to Rule 8 (Auditable Ledger) & Rule 7 (Cryptographic Chaining)
"""

import pytest
import sys
import os

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for d in ["custody"]:
    p = os.path.join(ROOT_DIR, d)
    if p not in sys.path:
        sys.path.insert(0, p)

from custody.ledger import CryptographicCustodyLedger, GENESIS_HASH


def test_custody_ledger_unbroken_chain():
    """Verify that sequentially chained blocks pass cryptographic verification."""
    ledger = CryptographicCustodyLedger()
    evidence_id = "EVD-2026-TEST01"

    # Block 1: Intake
    b1 = ledger.create_event(
        evidence_id=evidence_id,
        sequence_number=1,
        action="EVIDENCE_INTAKE",
        actor_id="USR-OFFICER-01",
        details={"sha256": "abc12345"},
        previous_event_hash=GENESIS_HASH
    )

    # Block 2: Analysis
    b2 = ledger.create_event(
        evidence_id=evidence_id,
        sequence_number=2,
        action="FORENSIC_ANALYSIS_RUN",
        actor_id="SYSTEM_ORCHESTRATOR",
        details={"tamper_detected": False},
        previous_event_hash=b1["event_hash"]
    )

    # Block 3: Verification
    b3 = ledger.create_event(
        evidence_id=evidence_id,
        sequence_number=3,
        action="COURT_CERTIFICATE_ISSUED",
        actor_id="USR-SYSTEM-LEAD",
        details={"report_id": "REP-001"},
        previous_event_hash=b2["event_hash"]
    )

    chain = [b1, b2, b3]
    result = ledger.verify_chain(chain)

    assert result["is_valid"] is True
    assert result["verified_count"] == 3
    assert result["broken_at_event_id"] is None


def test_custody_ledger_detects_payload_tampering():
    """Verify that tampering with an event's details payload invalidates the chain."""
    ledger = CryptographicCustodyLedger()
    evidence_id = "EVD-2026-TEST02"

    b1 = ledger.create_event(
        evidence_id=evidence_id,
        sequence_number=1,
        action="EVIDENCE_INTAKE",
        actor_id="USR-OFFICER-01",
        details={"sha256": "authentic_hash"},
        previous_event_hash=GENESIS_HASH
    )

    b2 = ledger.create_event(
        evidence_id=evidence_id,
        sequence_number=2,
        action="FORENSIC_ANALYSIS",
        actor_id="SYSTEM",
        details={"tamper_detected": True},
        previous_event_hash=b1["event_hash"]
    )

    # Malicious actor tampers with Block 1 details (e.g. altering recorded sha256)
    b1_tampered = dict(b1)
    b1_tampered["payload_json"] = {"sha256": "malicious_fake_hash"}

    chain = [b1_tampered, b2]
    result = ledger.verify_chain(chain)

    assert result["is_valid"] is False
    assert result["broken_at_event_id"] == b1["event_id"]
    assert "Content tampering detected" in result["reason"]


def test_custody_ledger_detects_broken_hash_link():
    """Verify that tampering with previous_event_hash invalidates the chain."""
    ledger = CryptographicCustodyLedger()
    evidence_id = "EVD-2026-TEST03"

    b1 = ledger.create_event(
        evidence_id=evidence_id,
        sequence_number=1,
        action="EVIDENCE_INTAKE",
        actor_id="USR-OFFICER-01",
        details={"status": "initial"},
        previous_event_hash=GENESIS_HASH
    )

    b2 = ledger.create_event(
        evidence_id=evidence_id,
        sequence_number=2,
        action="ANALYSIS",
        actor_id="SYSTEM",
        details={"status": "analyzed"},
        previous_event_hash=b1["event_hash"]
    )

    # Corrupt link in b2
    b2_corrupted = dict(b2)
    b2_corrupted["previous_event_hash"] = "deadbeef" * 8

    chain = [b1, b2_corrupted]
    result = ledger.verify_chain(chain)

    assert result["is_valid"] is False
    assert result["broken_at_event_id"] == b2["event_id"]
    assert "Hash chain break" in result["reason"]
