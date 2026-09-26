"""
NYAYAI - Test Suite: Chain of Custody Integration (Phase 8)
Lead: Ridhi Mashi (Evidence Intelligence & Chain-of-Custody Engineer)
Integration Lead: Dhananjay Sharma (Backend & System Integration Lead)

Comprehensive Test Suite Verifying:
1. upload event: Genesis block created on evidence intake with required fields and EVIDENCE_UPLOADED type.
2. analysis event: Forensic and AI analysis events appended with strict hash linking.
3. verification event: Cryptographic integrity verification events appended to the chain.
4. transfer & access events: EVIDENCE_TRANSFERRED, EVIDENCE_VIEWED, EVIDENCE_DOWNLOADED recording.
5. chronological ordering: Monotonically increasing sequence numbers and chronological event order.
6. hash chain consistency: Continuous SHA-256 hash linking (Current Event -> previous event hash -> current event hash) and tamper detection.
7. unauthorized access: Strict RBAC enforcement (Unauthenticated -> 401, Unauthorized role -> 403, Authorized roles -> 200).
8. sensitive information protection: Internal server storage paths (vault_path) are redacted from custody history.
"""

import os
import sys
import uuid
import hashlib
import json
import pytest
from fastapi.testclient import TestClient

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for d in ["forensic-engine", "ai-engine", "custody", "correlation", "explainability", "reports"]:
    p = os.path.join(ROOT_DIR, d)
    if p not in sys.path:
        sys.path.insert(0, p)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.app.main import app
from backend.app.database import SessionLocal
from backend.app.models.user import User
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.custody import CustodyEvent, CustodyEventType
from database.init_db import init_database
from custody import GENESIS_HASH

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_environment():
    """Initializes the database schema before test execution."""
    init_database()


@pytest.fixture
def auth_fixtures():
    """Sets up authenticated test actors with various platform roles."""
    suffix = uuid.uuid4().hex[:8]
    actors = {}

    roles = ["INVESTIGATOR", "JUDGE", "LAWYER", "ADMIN", "AUDITOR"]
    for role in roles:
        username = f"{role.lower()}_{suffix}"
        email = f"{username}@nyayai.gov.in"
        password = "Password123!"

        reg_payload = {
            "username": username,
            "email": email,
            "password": password,
            "full_name": f"Test {role.title()}",
            "role": role,
            "badge_number": f"{role[:3]}-{suffix}"
        }
        client.post("/api/auth/register", json=reg_payload)
        login_res = client.post("/api/auth/login", json={"username": username, "password": password})
        assert login_res.status_code == 200, f"Failed login for {username}"

        token = login_res.json()["access_token"]
        user_id = login_res.json()["user"]["user_id"]
        actors[role] = {
            "headers": {"Authorization": f"Bearer {token}"},
            "user_id": user_id,
            "username": username
        }

    return actors


@pytest.fixture
def test_case(auth_fixtures):
    """Creates a fresh test case docket."""
    inv = auth_fixtures["INVESTIGATOR"]
    res = client.post(
        "/api/cases",
        json={"title": "State vs Cyber Syndicate", "description": "Custody chain verification docket"},
        headers=inv["headers"]
    )
    assert res.status_code == 201
    return res.json()["data"]["case_id"]


@pytest.fixture
def uploaded_evidence(auth_fixtures, test_case):
    """Uploads a test evidence artifact and returns its metadata."""
    inv = auth_fixtures["INVESTIGATOR"]
    raw_content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR_CUSTODY_INTEGRATION_TEST"
    expected_hash = hashlib.sha256(raw_content).hexdigest()

    files = {"file": ("cctv_secure_frame.png", raw_content, "image/png")}
    data = {
        "case_id": test_case,
        "source_description": "Traffic junction camera #42 seizure"
    }

    upload_res = client.post("/api/evidence/upload", files=files, data=data, headers=inv["headers"])
    assert upload_res.status_code == 201
    body = upload_res.json()

    return {
        "evidence_id": body["evidence_id"],
        "case_id": test_case,
        "filename": body["filename"],
        "sha256_hash": expected_hash,
        "raw_content": raw_content
    }


# ==============================================================================
# 1. Upload Event (Genesis Block) Tests
# ==============================================================================

def test_upload_event_creates_genesis_block(auth_fixtures, uploaded_evidence):
    """
    Test 1: Upload Event
    - Verifies genesis block created automatically on evidence intake
    - Confirms all 8 required fields:
      event_id, evidence_id, user_id, event_type, timestamp, description, previous_hash, event_hash
    - Confirms event_type is EVIDENCE_UPLOADED
    - Confirms previous_hash is GENESIS_HASH (64 zeros)
    """
    inv = auth_fixtures["INVESTIGATOR"]
    evidence_id = uploaded_evidence["evidence_id"]

    res = client.get(f"/api/custody/evidence/{evidence_id}", headers=inv["headers"])
    assert res.status_code == 200
    data = res.json()

    assert data["success"] is True
    assert data["evidence_id"] == evidence_id
    assert data["chain_intact"] is True
    assert data["total_events"] >= 1
    assert len(data["history"]) >= 1

    genesis = data["history"][0]

    # Required 8 fields verification
    required_fields = [
        "event_id", "evidence_id", "user_id", "event_type",
        "timestamp", "description", "previous_hash", "event_hash"
    ]
    for field in required_fields:
        assert field in genesis, f"Missing required field: {field}"
        assert genesis[field] is not None, f"Field {field} is None"

    assert genesis["evidence_id"] == evidence_id
    assert genesis["user_id"] == inv["user_id"]
    assert genesis["event_type"] in [CustodyEventType.EVIDENCE_UPLOADED, "EVIDENCE_INTAKE_RECORDED"]
    assert genesis["previous_hash"] == GENESIS_HASH
    assert len(genesis["event_hash"]) == 64


# ==============================================================================
# 2. Analysis Event Tests
# ==============================================================================

def test_analysis_event_appends_to_chain(auth_fixtures, uploaded_evidence):
    """
    Test 2: Analysis Event
    - Executes forensic analysis & AI analysis
    - Verifies analysis custody blocks are appended to the chain
    - Confirms previous_hash links directly to the preceding block's event_hash
    """
    inv = auth_fixtures["INVESTIGATOR"]
    evidence_id = uploaded_evidence["evidence_id"]

    # 1. Trigger forensic analysis
    f_res = client.post(f"/api/forensics/analyze/{evidence_id}", headers=inv["headers"])
    assert f_res.status_code == 200

    # 2. Trigger AI tamper detection analysis
    ai_res = client.post(f"/api/ai/analyze/{evidence_id}", headers=inv["headers"])
    assert ai_res.status_code == 200

    # 3. Retrieve custody history
    custody_res = client.get(f"/api/custody/evidence/{evidence_id}", headers=inv["headers"])
    assert custody_res.status_code == 200
    data = custody_res.json()

    assert data["chain_intact"] is True
    assert data["total_events"] >= 3  # Genesis + Forensic + AI

    history = data["history"]
    event_types = [e["event_type"] for e in history]

    assert "FORENSIC_ANALYSIS_COMPLETED" in event_types
    assert "AI_ANALYSIS_COMPLETED" in event_types

    # Verify cryptographic hash linking between blocks
    for i in range(1, len(history)):
        curr_block = history[i]
        prev_block = history[i - 1]
        assert curr_block["previous_hash"] == prev_block["event_hash"], (
            f"Hash link broken at index {i}: {curr_block['previous_hash']} != {prev_block['event_hash']}"
        )


# ==============================================================================
# 3. Verification Event Tests
# ==============================================================================

def test_verification_event_appends_to_chain(auth_fixtures, uploaded_evidence):
    """
    Test 3: Verification Event
    - Executes evidence integrity verification
    - Verifies integrity verification event block is appended
    - Confirms continuous hash chain integrity
    """
    inv = auth_fixtures["INVESTIGATOR"]
    evidence_id = uploaded_evidence["evidence_id"]

    # 1. Perform integrity verification
    verify_res = client.post(f"/api/evidence/{evidence_id}/verify-integrity", headers=inv["headers"])
    assert verify_res.status_code == 200
    assert verify_res.json()["integrity_status"] == "VERIFIED"

    # 2. Retrieve custody history
    custody_res = client.get(f"/api/custody/evidence/{evidence_id}", headers=inv["headers"])
    assert custody_res.status_code == 200
    data = custody_res.json()

    assert data["chain_intact"] is True
    history = data["history"]
    latest_event = history[-1]

    # Verify event type matches verification
    assert latest_event["event_type"] in [
        CustodyEventType.INTEGRITY_VERIFIED,
        "EVIDENCE_INTEGRITY_VERIFIED"
    ]
    # Verify hash linking
    assert latest_event["previous_hash"] == history[-2]["event_hash"]


# ==============================================================================
# 4. Transfer, View, Download & Report Custody Events
# ==============================================================================

def test_transfer_view_and_download_events(auth_fixtures, uploaded_evidence):
    """
    Test 4: Custody Transfer, View, and Download Events
    - Appends EVIDENCE_TRANSFERRED, EVIDENCE_VIEWED, and EVIDENCE_DOWNLOADED
    - Verifies continuous chain growth and hash link integrity
    """
    inv = auth_fixtures["INVESTIGATOR"]
    evidence_id = uploaded_evidence["evidence_id"]

    # 1. Record EVIDENCE_TRANSFERRED
    transfer_res = client.post(
        f"/api/custody/evidence/{evidence_id}/events",
        json={
            "event_type": CustodyEventType.EVIDENCE_TRANSFERRED,
            "description": "Evidence transferred to Cyber Crime Forensic Division, New Delhi",
            "details": {
                "transferred_to": "Dr. Anu Sharma",
                "department": "Digital Forensics Lab",
                "dispatch_id": "DSP-DL-2026-99"
            }
        },
        headers=inv["headers"]
    )
    assert transfer_res.status_code == 201

    # 2. Record EVIDENCE_VIEWED
    view_res = client.post(
        f"/api/custody/evidence/{evidence_id}/events",
        json={
            "event_type": CustodyEventType.EVIDENCE_VIEWED,
            "description": "Evidence inspected in high-security viewer console",
            "details": {"terminal_id": "TERM-SEC-01", "mode": "READ_ONLY"}
        },
        headers=inv["headers"]
    )
    assert view_res.status_code == 201

    # 3. Record EVIDENCE_DOWNLOADED
    dl_res = client.post(
        f"/api/custody/evidence/{evidence_id}/events",
        json={
            "event_type": CustodyEventType.EVIDENCE_DOWNLOADED,
            "description": "Encrypted forensic clone exported for judicial presentation",
            "details": {"export_format": "RAW_ENCRYPTED", "destination": "Court Evidence Vault"}
        },
        headers=inv["headers"]
    )
    assert dl_res.status_code == 201

    # Verify history
    custody_res = client.get(f"/api/custody/evidence/{evidence_id}", headers=inv["headers"])
    assert custody_res.status_code == 200
    data = custody_res.json()

    assert data["chain_intact"] is True
    event_types = [e["event_type"] for e in data["history"]]
    assert CustodyEventType.EVIDENCE_TRANSFERRED in event_types
    assert CustodyEventType.EVIDENCE_VIEWED in event_types
    assert CustodyEventType.EVIDENCE_DOWNLOADED in event_types


# ==============================================================================
# 5. Chronological Ordering Tests
# ==============================================================================

def test_chronological_ordering_guarantee(auth_fixtures, uploaded_evidence):
    """
    Test 5: Chronological Ordering
    - Verifies that custody history is returned in strict monotonic order
    - Confirms sequence numbers are 1, 2, 3... without gaps or reversals
    """
    inv = auth_fixtures["INVESTIGATOR"]
    evidence_id = uploaded_evidence["evidence_id"]

    # Append a few events
    for action in ["EVIDENCE_VIEWED", "EVIDENCE_TRANSFERRED"]:
        client.post(
            f"/api/custody/evidence/{evidence_id}/events",
            json={"event_type": action, "description": f"Testing sequence for {action}"},
            headers=inv["headers"]
        )

    res = client.get(f"/api/custody/evidence/{evidence_id}", headers=inv["headers"])
    assert res.status_code == 200
    history = res.json()["history"]

    for idx, ev in enumerate(history):
        expected_seq = idx + 1
        assert ev["sequence_number"] == expected_seq, (
            f"Chronological ordering violation: expected sequence {expected_seq}, found {ev['sequence_number']}"
        )


# ==============================================================================
# 6. Hash Chain Consistency & Tamper Detection Tests
# ==============================================================================

def test_hash_chain_consistency_and_tamper_detection(auth_fixtures, uploaded_evidence):
    """
    Test 6: Hash Chain Consistency & Tampering Detection
    - Verifies that CryptographicCustodyLedger detects historical tampering
    - Simulates silent modification of a historical event
    - Confirms that chain_intact immediately becomes False
    """
    inv = auth_fixtures["INVESTIGATOR"]
    evidence_id = uploaded_evidence["evidence_id"]

    # Append an event so there are at least 2 events
    client.post(
        f"/api/custody/evidence/{evidence_id}/events",
        json={"event_type": CustodyEventType.EVIDENCE_VIEWED, "description": "Legitimate view"},
        headers=inv["headers"]
    )

    # Verify initial integrity
    init_res = client.get(f"/api/custody/evidence/{evidence_id}", headers=inv["headers"])
    assert init_res.status_code == 200
    assert init_res.json()["chain_intact"] is True

    # Also verify via POST /api/custody/{evidence_id}/verify
    verify_api_res = client.post(f"/api/custody/{evidence_id}/verify", headers=inv["headers"])
    assert verify_api_res.status_code == 200
    assert verify_api_res.json()["is_valid"] is True

    # Tamper with the genesis event directly in the database (silent modification)
    db = SessionLocal()
    try:
        first_event = (
            db.query(CustodyEvent)
            .filter_by(evidence_id=evidence_id, sequence_number=1)
            .first()
        )
        # Silently alter the historical event payload to simulate unauthorized data modification
        first_event.payload_json = json.dumps({"tampered": True, "altered_by": "malicious_actor"})
        db.commit()
    finally:
        db.close()

    # Re-query custody history: must detect chain tampering
    tampered_res = client.get(f"/api/custody/evidence/{evidence_id}", headers=inv["headers"])
    assert tampered_res.status_code == 200
    assert tampered_res.json()["chain_intact"] is False, "Tampering was NOT detected by custody ledger!"

    # Verify verification endpoint also reports tampering
    verify_tampered = client.post(f"/api/custody/{evidence_id}/verify", headers=inv["headers"])
    assert verify_tampered.status_code == 200
    assert verify_tampered.json()["is_valid"] is False


# ==============================================================================
# 7. Unauthorized Access & RBAC Enforcement Tests
# ==============================================================================

def test_unauthorized_access_enforcement(auth_fixtures, uploaded_evidence):
    """
    Test 7: Unauthorized Access
    - Unauthenticated request (no Authorization header) -> 401 Unauthorized
    - Unauthorized role (LAWYER) -> 403 Forbidden
    - Authorized role (JUDGE, INVESTIGATOR, ADMIN, AUDITOR) -> 200 OK
    """
    evidence_id = uploaded_evidence["evidence_id"]
    inv = auth_fixtures["INVESTIGATOR"]
    judge = auth_fixtures["JUDGE"]
    lawyer = auth_fixtures["LAWYER"]
    admin = auth_fixtures["ADMIN"]
    auditor = auth_fixtures["AUDITOR"]

    # 1. Unauthenticated request -> 401
    unauth_res = client.get(f"/api/custody/evidence/{evidence_id}")
    assert unauth_res.status_code == 401, f"Expected 401, got {unauth_res.status_code}"

    # 2. Unauthorized role (LAWYER) -> 403 Forbidden
    lawyer_res = client.get(f"/api/custody/evidence/{evidence_id}", headers=lawyer["headers"])
    assert lawyer_res.status_code == 403, f"Expected 403, got {lawyer_res.status_code}"

    # Unauthorized role attempting to append events -> 403 Forbidden
    lawyer_post = client.post(
        f"/api/custody/evidence/{evidence_id}/events",
        json={"event_type": "EVIDENCE_VIEWED", "description": "Unauthorized attempt"},
        headers=lawyer["headers"]
    )
    assert lawyer_post.status_code == 403

    # 3. Authorized roles -> 200 OK
    for authorized_actor in [inv, judge, admin, auditor]:
        ok_res = client.get(f"/api/custody/evidence/{evidence_id}", headers=authorized_actor["headers"])
        assert ok_res.status_code == 200, f"Role failed to access custody: {ok_res.status_code}"
        assert ok_res.json()["success"] is True


# ==============================================================================
# 8. Sensitive Internal Information Redaction Tests
# ==============================================================================

def test_sensitive_internal_information_redacted(auth_fixtures, uploaded_evidence):
    """
    Test 8: Sensitive Information Protection
    - Verifies that internal filesystem paths (vault_path, storage_reference) are
      never exposed in the custody history API response.
    """
    inv = auth_fixtures["INVESTIGATOR"]
    evidence_id = uploaded_evidence["evidence_id"]

    res = client.get(f"/api/custody/evidence/{evidence_id}", headers=inv["headers"])
    assert res.status_code == 200
    history = res.json()["history"]

    for ev in history:
        payload = ev.get("payload_json") or {}
        # Ensure vault_path or internal storage paths are NOT exposed
        assert "vault_path" not in payload, "Internal vault_path was exposed in custody payload!"
        assert "storage_reference" not in payload, "Internal storage_reference was exposed in custody payload!"
        assert "password" not in payload
        assert "secret" not in payload
