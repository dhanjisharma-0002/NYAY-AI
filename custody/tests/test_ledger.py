"""
NYAYAI - Local Module Unit Tests: Chain of Custody Ledger
Module Lead: Ridhi Masih (Evidence Intelligence Lead)
"""

import pytest
from custody.base import BaseCustodyLedger
from custody.ledger import CryptographicCustodyLedger, GENESIS_HASH


def test_custody_ledger_inheritance():
    """Verify CryptographicCustodyLedger implements BaseCustodyLedger."""
    ledger = CryptographicCustodyLedger()
    assert isinstance(ledger, BaseCustodyLedger)


def test_custody_ledger_mandatory_identifiers():
    """Test validation of mandatory case_id and evidence_id."""
    ledger = CryptographicCustodyLedger()

    with pytest.raises(ValueError, match="evidence_id is required"):
        ledger.create_event(case_id="CASE-001", evidence_id="", action="INTAKE")

    with pytest.raises(ValueError, match="case_id is required"):
        ledger.create_event(case_id="", evidence_id="EVID-001", action="INTAKE")


def test_custody_ledger_sha256_chaining():
    """Test sequential event logging and continuous SHA-256 hash chaining."""
    ledger = CryptographicCustodyLedger()

    # Block 1
    evt1 = ledger.create_event(
        case_id="CASE-2026-UNIT",
        evidence_id="EVID-CUST-01",
        sequence_number=1,
        action="EVIDENCE_INTAKE",
        actor_id="OFFICER_A",
        details={"sha256": "4" * 64, "item": "Hard Drive"},
        previous_event_hash=GENESIS_HASH
    )
    assert evt1["previous_event_hash"] == GENESIS_HASH
    assert len(evt1["event_hash"]) == 64

    # Block 2
    evt2 = ledger.create_event(
        case_id="CASE-2026-UNIT",
        evidence_id="EVID-CUST-01",
        sequence_number=2,
        action="FORENSIC_ACQUISITION",
        actor_id="EXAMINER_B",
        details={"sha256": "4" * 64, "tool": "EnCase"},
        previous_event_hash=evt1["event_hash"]
    )
    assert evt2["previous_event_hash"] == evt1["event_hash"]

    # Verify unbroken chain
    verif = ledger.verify_chain([evt1, evt2])
    assert verif["is_valid"] is True
    assert verif["verified_count"] == 2
    assert verif["merkle_root"] != GENESIS_HASH


def test_custody_ledger_tamper_detection():
    """Test that payload mutation breaks chain verification and is localized."""
    ledger = CryptographicCustodyLedger()

    evt1 = ledger.create_event(
        case_id="CASE-T", evidence_id="E-01", sequence_number=1, action="INTAKE"
    )
    evt2 = ledger.create_event(
        case_id="CASE-T", evidence_id="E-01", sequence_number=2, action="SEAL",
        previous_event_hash=evt1["event_hash"], details={"original": True}
    )

    tampered_evt2 = dict(evt2)
    tampered_evt2["payload_json"] = {"original": False}

    verif = ledger.verify_chain([evt1, tampered_evt2])
    assert verif["is_valid"] is False
    assert verif["broken_at_event_id"] == evt2["event_id"]


def test_custody_statutory_certificate():
    """Test statutory BSA 2023 certificate generation."""
    ledger = CryptographicCustodyLedger()
    evt = ledger.create_event(case_id="CASE-CERT", evidence_id="EVID-CERT")
    cert = ledger.generate_certificate([evt])

    assert cert["case_id"] == "CASE-CERT"
    assert cert["evidence_id"] == "EVID-CERT"
    assert cert["is_unbroken"] is True
    assert "Bharatiya Sakshya Adhiniyam" in cert["statutory_authority"]
