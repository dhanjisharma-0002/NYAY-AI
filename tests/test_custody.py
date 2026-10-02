import pytest
from custody.ledger import CryptographicCustodyLedger, GENESIS_HASH
from custody.base import BaseCustodyLedger

def test_custody_ledger_inheritance():
    """Verify CryptographicCustodyLedger implements BaseCustodyLedger."""
    ledger = CryptographicCustodyLedger()
    assert isinstance(ledger, BaseCustodyLedger)

def test_custody_ledger_validation():
    """Verify validation of mandatory case_id and evidence_id."""
    ledger = CryptographicCustodyLedger()

    with pytest.raises(ValueError, match="evidence_id is required"):
        ledger.create_event(case_id="CASE-001", evidence_id="", action="INTAKE")

    with pytest.raises(ValueError, match="case_id is required"):
        ledger.create_event(case_id="", evidence_id="EVID-001", action="INTAKE")

def test_custody_chain_creation_and_verification():
    """Test sequential event logging and continuous SHA-256 chain verification."""
    ledger = CryptographicCustodyLedger()
    
    events = []
    # Block 1: Intake
    evt1 = ledger.create_event(
        case_id="CASE-2026-DEL-101",
        evidence_id="EVID-101",
        sequence_number=1,
        action="EVIDENCE_INTAKE",
        actor_id="OFFICER_A",
        details={"sha256": "aaaa" * 16, "device": "iPhone 13"},
        previous_event_hash=GENESIS_HASH
    )
    events.append(evt1)
    
    # Block 2: Transfer to Forensic Lab
    evt2 = ledger.create_event(
        case_id="CASE-2026-DEL-101",
        evidence_id="EVID-101",
        sequence_number=2,
        action="TRANSFER_TO_LAB",
        actor_id="OFFICER_B",
        details={"courier": "Tamper-Evident Bag #8821"},
        previous_event_hash=evt1["event_hash"]
    )
    events.append(evt2)
    
    # Block 3: Forensic Extraction
    evt3 = ledger.create_event(
        case_id="CASE-2026-DEL-101",
        evidence_id="EVID-101",
        sequence_number=3,
        action="FORENSIC_ACQUISITION",
        actor_id="EXAMINER_C",
        details={"tool": "Cellebrite UFED", "image_type": "physical"},
        previous_event_hash=evt2["event_hash"]
    )
    events.append(evt3)

    verif = ledger.verify_chain(events)
    assert verif["is_valid"] is True
    assert verif["verified_count"] == 3
    assert verif["broken_at_event_id"] is None
    assert verif["merkle_root"] != GENESIS_HASH
    assert verif["head_hash"] == evt3["event_hash"]

def test_custody_chain_tamper_localization_payload():
    """Test that tampering with payload data is detected and pinpointed."""
    ledger = CryptographicCustodyLedger()
    
    evt1 = ledger.create_event(
        case_id="CASE-TAMPER",
        evidence_id="EVID-001",
        sequence_number=1,
        action="INTAKE",
        actor_id="OFFICER_1",
        details={"original_note": "Unopened evidence bag"},
        previous_event_hash=GENESIS_HASH
    )
    evt2 = ledger.create_event(
        case_id="CASE-TAMPER",
        evidence_id="EVID-001",
        sequence_number=2,
        action="ANALYSIS",
        actor_id="OFFICER_2",
        details={"result": "negative"},
        previous_event_hash=evt1["event_hash"]
    )
    
    # Tamper with block 2 payload
    evt2_tampered = dict(evt2)
    evt2_tampered["payload_json"] = {"result": "altered_positive"}
    
    chain = [evt1, evt2_tampered]
    verif = ledger.verify_chain(chain)
    
    assert verif["is_valid"] is False
    assert verif["broken_at_event_id"] == evt2["event_id"]
    assert verif["tamper_field"] == "payload_json_or_attributes"
    assert "tampering detected" in verif["reason"].lower()

def test_custody_chain_tamper_localization_hash_break():
    """Test that broken previous_event_hash linkage is detected and pinpointed."""
    ledger = CryptographicCustodyLedger()
    
    evt1 = ledger.create_event(
        case_id="CASE-TAMPER-2",
        evidence_id="EVID-002",
        sequence_number=1,
        action="INTAKE",
        actor_id="OFFICER_1",
        previous_event_hash=GENESIS_HASH
    )
    evt2 = ledger.create_event(
        case_id="CASE-TAMPER-2",
        evidence_id="EVID-002",
        sequence_number=2,
        action="INSPECTION",
        actor_id="OFFICER_2",
        previous_event_hash="f" * 64  # Fake previous hash
    )
    
    chain = [evt1, evt2]
    verif = ledger.verify_chain(chain)
    assert verif["is_valid"] is False
    assert verif["broken_at_event_id"] == evt2["event_id"]
    assert verif["tamper_field"] == "previous_event_hash"

def test_merkle_root_computation():
    """Verify Merkle root computation over event hashes."""
    ledger = CryptographicCustodyLedger()
    
    # Empty
    assert ledger.compute_merkle_root([]) == GENESIS_HASH
    
    # Single
    h1 = "a" * 64
    assert ledger.compute_merkle_root([h1]) == h1
    
    # Two items
    h2 = "b" * 64
    root2 = ledger.compute_merkle_root([h1, h2])
    assert isinstance(root2, str)
    assert len(root2) == 64
    
    # Deterministic
    assert ledger.compute_merkle_root([h1, h2]) == root2

def test_statutory_custody_certificate():
    """Verify court-admissible certificate generation under BSA 2023 Sec 63."""
    ledger = CryptographicCustodyLedger()
    
    evt = ledger.create_event(
        case_id="CASE-CERT-01",
        evidence_id="EVID-PHONE-01",
        sequence_number=1,
        action="SEIZED_AT_SCENE",
        actor_id="INSPECTOR_SHARMA",
        details={"location": "Connaught Place, New Delhi"},
        previous_event_hash=GENESIS_HASH
    )
    
    cert = ledger.generate_certificate([evt])
    assert cert["case_id"] == "CASE-CERT-01"
    assert cert["evidence_id"] == "EVID-PHONE-01"
    assert "Bharatiya Sakshya Adhiniyam" in cert["statutory_authority"]
    assert cert["is_unbroken"] is True
    assert cert["status"] == "CRYPTOGRAPHICALLY_VERIFIED"
    assert cert["total_blocks_verified"] == 1
    assert cert["head_event_hash"] == evt["event_hash"]
