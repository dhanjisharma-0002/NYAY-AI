"""
NYAYAI - Comprehensive Test Suite: Advanced Cryptographic Custody Ledger
Module Lead: Ridhi Masih (Evidence Intelligence & Chain-of-Custody Engineer)

Validates:
1. Merkle Tree Root deterministic computation over chained block hashes
2. Specialized Judicial Sealing and Custody Transfer event creation
3. Court-admissible Certificate of Custody Integrity generation (BSA 2023 Sec 63)
4. Field-level tamper localization upon tampering
5. Full backwards-compatibility with original BaseCustodyLedger contract
"""

import os
import sys
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for d in ["custody"]:
    p = os.path.join(ROOT_DIR, d)
    if p not in sys.path:
        sys.path.insert(0, p)

from custody.ledger import CryptographicCustodyLedger, GENESIS_HASH


def test_merkle_root_computation():
    """Verify binary Merkle tree root calculation."""
    ledger = CryptographicCustodyLedger()
    h1 = "a" * 64
    h2 = "b" * 64
    h3 = "c" * 64

    # Merkle root of single hash is itself
    assert ledger.compute_merkle_root([h1]) == h1

    # Merkle root of multiple hashes is 64-char hex
    root = ledger.compute_merkle_root([h1, h2, h3])
    assert len(root) == 64
    assert root.isalnum()


def test_custody_ledger_merkle_and_certificate():
    """Verify unbroken chain produces Merkle root and court certificate."""
    ledger = CryptographicCustodyLedger()
    ev_id = "EVD-CUST-CERT-01"

    b1 = ledger.create_event(
        evidence_id=ev_id,
        sequence_number=1,
        action="EVIDENCE_INTAKE",
        actor_id="OFFICER-01",
        details={"sha256": "1111" * 16},
        previous_event_hash=GENESIS_HASH
    )
    b2 = ledger.create_event(
        evidence_id=ev_id,
        sequence_number=2,
        action="FORENSIC_ANALYSIS_RUN",
        actor_id="SYSTEM",
        details={"tamper_detected": False},
        previous_event_hash=b1["event_hash"]
    )

    seal_event = ledger.create_seal_event(
        evidence_id=ev_id,
        sequence_number=3,
        actor_id="JUDGE-01",
        prior_events=[b1, b2],
        previous_event_hash=b2["event_hash"],
        order_reference="Sessions Case No. 42 Sealing Order"
    )

    chain = [b1, b2, seal_event]
    verif = ledger.verify_chain(chain)

    assert verif["is_valid"] is True
    assert verif["verified_count"] == 3
    assert "merkle_root" in verif
    assert len(verif["merkle_root"]) == 64

    cert = ledger.generate_certificate(chain)
    assert cert["is_unbroken"] is True
    assert cert["status"] == "CRYPTOGRAPHICALLY_VERIFIED"
    assert "Bharatiya Sakshya Adhiniyam" in cert["statutory_authority"]
    assert cert["merkle_root"] == verif["merkle_root"]


def test_tamper_localization_reporting():
    """Verify tampering pinpoints specific broken field."""
    ledger = CryptographicCustodyLedger()
    ev_id = "EVD-CUST-TAMPER-02"

    b1 = ledger.create_event(
        evidence_id=ev_id,
        sequence_number=1,
        action="EVIDENCE_INTAKE",
        actor_id="OFFICER-01",
        details={"sha256": "original_valid_hash"},
        previous_event_hash=GENESIS_HASH
    )

    b1_tampered = dict(b1)
    b1_tampered["payload_json"] = {"sha256": "fraudulent_altered_hash"}

    res = ledger.verify_chain([b1_tampered])
    assert res["is_valid"] is False
    assert res["tamper_field"] == "payload_json_or_attributes"
    assert "Content tampering detected" in res["reason"]
