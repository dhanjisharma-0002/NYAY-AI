"""
NYAYAI - Test Suite: Phase 18 Case Docket Judicial Admissibility & Verification Gateway
Module: tests.test_case_admissibility_verification
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Comprehensive focused test suite verifying:
1. Successful sealed case judicial verification (ADMISSIBLE under BSA 2023).
2. Physical vault file tampering detection (INADMISSIBLE_TAMPERED).
3. Chain of custody breach detection (CHAIN_OF_CUSTODY_BREACHED).
4. Sealing manifest hash mismatch detection (SEALING_HASH_MISMATCH).
5. Unsealed / pending case docket verification (UNSEALED).
6. Missing court report detection (MISSING_COURT_REPORT).
7. Empty case docket handling (EMPTY_CASE).
8. Deterministic sealing hash recalculation parity with Phase 17 finalization.
9. RBAC: Judge/Admin/Lawyer/Owner permitted (200), Foreign Investigator blocked (403), Anonymous (401/403).
10. Non-existent case docket handling (HTTP 404).
11. Exactly one CASE_ADMISSIBILITY_VERIFIED audit event recorded per run.
12. Alias endpoint POST /api/cases/{case_id}/judicial-verification parity.
13. Certificate retrieval endpoint GET /api/cases/{case_id}/admissibility-certificate.
"""

import os
import sys
import uuid
import json
import hashlib
from datetime import datetime, timezone
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
from database.connection import Base, engine, SessionLocal
from database.models import (
    User,
    Case,
    Evidence,
    CustodyEvent,
    Report,
    AuditLog
)
from backend.app.core.security import create_access_token

Base.metadata.create_all(bind=engine)
client = TestClient(app)


@pytest.fixture(scope="module")
def rbac_setup():
    """Provisions investigator, admin, judge, and lawyer users with auth headers."""
    db = SessionLocal()
    try:
        def get_or_create(username: str, role: str) -> User:
            u = db.query(User).filter_by(username=username).first()
            if not u:
                u = User(
                    id=str(uuid.uuid4()),
                    username=username,
                    email=f"{username}@nyayai.gov.in",
                    hashed_password="hashed_placeholder_p18",
                    role=role,
                    full_name=f"Official {username.title()}",
                    badge_number=f"BADGE-{username[:4].upper()}-99",
                    is_active=True
                )
                db.add(u)
                db.commit()
                db.refresh(u)
            return u

        inv1 = get_or_create("p18_inv_lead", "INVESTIGATOR")
        inv2 = get_or_create("p18_inv_other", "INVESTIGATOR")
        admin = get_or_create("p18_admin_lead", "ADMIN")
        judge = get_or_create("p18_hon_judge", "JUDGE")
        lawyer = get_or_create("p18_advocate", "LAWYER")

        def headers_for(user: User):
            token = create_access_token({"sub": user.id, "username": user.username, "role": user.role, "id": user.id})
            return {"Authorization": f"Bearer {token}"}

        return {
            "inv1": inv1,
            "inv2": inv2,
            "admin": admin,
            "judge": judge,
            "lawyer": lawyer,
            "headers_inv1": headers_for(inv1),
            "headers_inv2": headers_for(inv2),
            "headers_admin": headers_for(admin),
            "headers_judge": headers_for(judge),
            "headers_lawyer": headers_for(lawyer),
        }
    finally:
        db.close()


def create_sealed_case_helper(rbac_setup, suffix=None):
    """Creates, analyzes, generates report, and finalizes a case docket."""
    if not suffix:
        suffix = uuid.uuid4().hex[:6].upper()
    headers = rbac_setup["headers_inv1"]

    # 1. Create Case Docket
    c_res = client.post(
        "/api/cases",
        json={
            "title": f"Sealed Trial Case {suffix}",
            "description": "Evidence docket prepared for court submission",
            "jurisdiction": "High Court of Delhi"
        },
        headers=headers
    )
    assert c_res.status_code == 201, c_res.text
    case_id = c_res.json()["data"]["case_id"]

    # 2. Upload Evidence 1
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRP18_EVD1_BYTES"
    up1 = client.post(
        "/api/evidence/upload",
        files={"file": ("evidence1.png", png_bytes, "image/png")},
        data={"case_id": case_id, "source_description": "CCTV Camera 1"},
        headers=headers
    )
    assert up1.status_code == 201, up1.text
    ev1_id = up1.json()["evidence_id"]

    # 3. Upload Evidence 2
    wav_bytes = b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00P18_AUDIO"
    up2 = client.post(
        "/api/evidence/upload",
        files={"file": ("evidence2.wav", wav_bytes, "audio/wav")},
        data={"case_id": case_id, "source_description": "Audio Intercept 1"},
        headers=headers
    )
    assert up2.status_code == 201, up2.text
    ev2_id = up2.json()["evidence_id"]

    # 4. Run Batch Pipeline
    pipe_res = client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers)
    assert pipe_res.status_code == 200, pipe_res.text

    # 5. Generate Court Admissibility Report
    rep_res = client.post(
        f"/api/reports/generate/{case_id}",
        json={
            "certifying_officer_name": "Official Lead Investigator",
            "certifying_officer_designation": "Forensic Investigator",
            "badge_number": "BADGE-INV-99",
            "jurisdiction": "High Court of Delhi"
        },
        headers=headers
    )
    assert rep_res.status_code in (200, 201), rep_res.text

    # 6. Finalize & Seal Case Docket
    fin_res = client.post(
        f"/api/cases/{case_id}/finalize",
        json={
            "certification_notes": "Forensic pipeline and custody verified.",
            "certifying_officer_name": "Official Lead Investigator",
            "badge_number": "BADGE-INV-99"
        },
        headers=headers
    )
    assert fin_res.status_code == 200, fin_res.text
    sealing_data = fin_res.json()

    return {
        "case_id": case_id,
        "evidence_ids": [ev1_id, ev2_id],
        "sealing_hash": sealing_data["docket_sealing_hash"],
        "headers": headers
    }


# =============================================================================
# TESTS
# =============================================================================

def test_successful_sealed_verification(rbac_setup):
    """1. Fully sealed case passes judicial verification with ADMISSIBLE status."""
    fixture = create_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    payload = {
        "court_bench": "Courtroom 3A, High Court of Delhi",
        "judicial_officer_name": "Hon'ble Justice S. K. Gupta",
        "verification_notes": "Judicial inspection under BSA 2023 Section 63."
    }

    res = client.post(f"/api/cases/{case_id}/verify-admissibility", json=payload, headers=headers)
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["case_id"] == case_id
    assert data["case_status"] == "COMPLETED"
    assert data["admissibility_status"] == "ADMISSIBLE"
    assert data["is_admissible"] is True
    assert data["statutory_framework"] == "BSA_2023_SECTION_63"
    assert data["verifier"]["role"] == "JUDGE"
    assert data["verifier"]["judicial_officer_name"] == "Hon'ble Justice S. K. Gupta"
    assert data["verifier"]["court_bench"] == "Courtroom 3A, High Court of Delhi"

    checks = data["checks"]
    assert checks["vault_integrity_passed"] is True
    assert checks["custody_chains_intact"] is True
    assert checks["sealing_hash_verified"] is True
    assert checks["court_reports_valid"] is True
    assert checks["total_evidence_verified"] == 2
    assert checks["compromised_evidence_count"] == 0
    assert checks["broken_custody_chains_count"] == 0

    sealing = data["sealing_verification"]
    assert sealing["is_sealed"] is True
    assert sealing["hashes_match"] is True
    assert sealing["expected_sealing_hash"] == fixture["sealing_hash"]
    assert sealing["recalculated_sealing_hash"] == fixture["sealing_hash"]


def test_vault_tamper_detection(rbac_setup):
    """2. Vault file alteration detected as INADMISSIBLE_TAMPERED without mutating DB baseline."""
    fixture = create_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    ev1_id = fixture["evidence_ids"][0]

    # Tamper with evidence 1 file in storage
    db = SessionLocal()
    try:
        ev1 = db.query(Evidence).filter_by(evidence_id=ev1_id).first()
        assert ev1 is not None
        original_db_hash = ev1.sha256_hash
        assert os.path.exists(ev1.storage_reference)

        # Corrupt vault file content on disk (temporarily allow write on WORM-protected file)
        import stat
        os.chmod(ev1.storage_reference, stat.S_IWRITE)
        with open(ev1.storage_reference, "wb") as f:
            f.write(b"CORRUPTED_FILE_CONTENT_TAMPERED_VAULT")
    finally:
        db.close()

    # Perform judicial verification
    res = client.post(
        f"/api/cases/{case_id}/verify-admissibility",
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["admissibility_status"] == "INADMISSIBLE_TAMPERED"
    assert data["is_admissible"] is False
    assert data["checks"]["vault_integrity_passed"] is False
    assert data["checks"]["compromised_evidence_count"] >= 1
    assert ev1_id in data["checks"]["compromised_evidence_ids"]

    # Verify baseline hash in database was NOT altered
    db2 = SessionLocal()
    try:
        ev1_after = db2.query(Evidence).filter_by(evidence_id=ev1_id).first()
        assert ev1_after.sha256_hash == original_db_hash
        # Case status should still be COMPLETED
        case_after = db2.query(Case).filter_by(case_id=case_id).first()
        assert case_after.status == "COMPLETED"
    finally:
        db2.close()


def test_custody_chain_breach_detection(rbac_setup):
    """3. Altered custody event block triggers CHAIN_OF_CUSTODY_BREACHED."""
    fixture = create_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    ev1_id = fixture["evidence_ids"][0]

    # Tamper with an event in custody ledger for ev1
    db = SessionLocal()
    try:
        first_event = (
            db.query(CustodyEvent)
            .filter_by(evidence_id=ev1_id)
            .order_by(CustodyEvent.sequence_number.asc())
            .first()
        )
        assert first_event is not None
        # Invalidate event hash with unique dummy hex to break cryptographic custody chain
        first_event.event_hash = "deadbeef" + uuid.uuid4().hex[:56]
        db.commit()
    finally:
        db.close()

    res = client.post(
        f"/api/cases/{case_id}/verify-admissibility",
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["admissibility_status"] == "CHAIN_OF_CUSTODY_BREACHED"
    assert data["is_admissible"] is False
    assert data["checks"]["custody_chains_intact"] is False
    assert ev1_id in data["checks"]["broken_chain_evidence_ids"]


def test_sealing_hash_mismatch_detection(rbac_setup):
    """4. Inconsistent sealing audit hash triggers SEALING_HASH_MISMATCH."""
    fixture = create_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]

    # Modify CASE_FINALIZED audit log sealing hash in DB
    db = SessionLocal()
    try:
        audit = (
            db.query(AuditLog)
            .filter_by(resource_id=case_id, action="CASE_FINALIZED")
            .first()
        )
        assert audit is not None
        # Corrupt expected sealing hash
        m = dict(audit.meta_data)
        m["docket_sealing_hash"] = "deadbeef" * 8
        audit.meta_data = m
        db.commit()
    finally:
        db.close()

    res = client.post(
        f"/api/cases/{case_id}/verify-admissibility",
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["admissibility_status"] == "SEALING_HASH_MISMATCH"
    assert data["is_admissible"] is False
    assert data["checks"]["sealing_hash_verified"] is False
    assert data["sealing_verification"]["hashes_match"] is False


def test_unsealed_case_detection(rbac_setup):
    """5. Non-finalized case docket returns UNSEALED status."""
    headers = rbac_setup["headers_inv1"]
    # Create case docket without finalizing
    c_res = client.post(
        "/api/cases",
        json={"title": "Unsealed Case Testing", "jurisdiction": "High Court of Delhi"},
        headers=headers
    )
    assert c_res.status_code == 201
    case_id = c_res.json()["data"]["case_id"]

    # Upload one evidence item
    up = client.post(
        "/api/evidence/upload",
        files={"file": ("unsealed.png", b"\x89PNG\r\n\x1a\nUNSEALED", "image/png")},
        data={"case_id": case_id},
        headers=headers
    )
    assert up.status_code == 201

    res = client.post(
        f"/api/cases/{case_id}/verify-admissibility",
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["admissibility_status"] == "UNSEALED"
    assert data["is_admissible"] is False
    assert data["sealing_verification"]["is_sealed"] is False


def test_missing_court_report_detection(rbac_setup):
    """6. Completed case lacking an official court report returns MISSING_COURT_REPORT."""
    headers = rbac_setup["headers_inv1"]
    suffix = uuid.uuid4().hex[:6].upper()

    # Create and analyze case
    c_res = client.post(
        "/api/cases",
        json={"title": f"No Report Case {suffix}", "jurisdiction": "High Court of Delhi"},
        headers=headers
    )
    assert c_res.status_code == 201
    case_id = c_res.json()["data"]["case_id"]

    up = client.post(
        "/api/evidence/upload",
        files={"file": ("noreport.png", b"\x89PNG\r\n\x1a\nNOREPORT", "image/png")},
        data={"case_id": case_id},
        headers=headers
    )
    assert up.status_code == 201

    client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers)

    # Artificially set case status to COMPLETED in DB without generating report
    db = SessionLocal()
    try:
        case = db.query(Case).filter_by(case_id=case_id).first()
        case.status = "COMPLETED"
        db.commit()
    finally:
        db.close()

    res = client.post(
        f"/api/cases/{case_id}/verify-admissibility",
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["admissibility_status"] == "MISSING_COURT_REPORT"
    assert data["is_admissible"] is False
    assert data["checks"]["court_reports_valid"] is False


def test_empty_case_detection(rbac_setup):
    """7. Case docket with zero evidence returns EMPTY_CASE."""
    headers = rbac_setup["headers_inv1"]
    c_res = client.post(
        "/api/cases",
        json={"title": "Empty Docket For Verification", "jurisdiction": "Delhi"},
        headers=headers
    )
    assert c_res.status_code == 201
    case_id = c_res.json()["data"]["case_id"]

    res = client.post(
        f"/api/cases/{case_id}/verify-admissibility",
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["admissibility_status"] == "EMPTY_CASE"
    assert data["is_admissible"] is False
    assert data["checks"]["total_evidence_verified"] == 0


def test_deterministic_sealing_hash_parity(rbac_setup):
    """8. Sealing manifest hash recalculated during verification exactly matches Phase 17 sealing hash."""
    fixture = create_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]

    res = client.post(
        f"/api/cases/{case_id}/verify-admissibility",
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 200
    data = res.json()

    assert data["sealing_verification"]["hashes_match"] is True
    assert data["sealing_verification"]["recalculated_sealing_hash"] == fixture["sealing_hash"]
    assert len(data["sealing_verification"]["recalculated_sealing_hash"]) == 64


def test_role_based_access_control(rbac_setup):
    """9. Strict RBAC: Judge, Admin, Lawyer, Owning Investigator permitted; Other Investigator forbidden."""
    fixture = create_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]

    # 1. JUDGE - Permitted (200)
    res_judge = client.post(
        f"/api/cases/{case_id}/verify-admissibility",
        headers=rbac_setup["headers_judge"]
    )
    assert res_judge.status_code == 200

    # 2. ADMIN - Permitted (200)
    res_admin = client.post(
        f"/api/cases/{case_id}/verify-admissibility",
        headers=rbac_setup["headers_admin"]
    )
    assert res_admin.status_code == 200

    # 3. LAWYER - Permitted (200)
    res_lawyer = client.post(
        f"/api/cases/{case_id}/verify-admissibility",
        headers=rbac_setup["headers_lawyer"]
    )
    assert res_lawyer.status_code == 200

    # 4. Owning INVESTIGATOR (inv1) - Permitted (200)
    res_inv1 = client.post(
        f"/api/cases/{case_id}/verify-admissibility",
        headers=rbac_setup["headers_inv1"]
    )
    assert res_inv1.status_code == 200

    # 5. Non-owning INVESTIGATOR (inv2) - Forbidden (403)
    res_inv2 = client.post(
        f"/api/cases/{case_id}/verify-admissibility",
        headers=rbac_setup["headers_inv2"]
    )
    assert res_inv2.status_code == 403

    # 6. Anonymous (No token) - Unauthorized (401 or 403)
    res_anon = client.post(f"/api/cases/{case_id}/verify-admissibility")
    assert res_anon.status_code in (401, 403)


def test_case_not_found_404(rbac_setup):
    """10. Requesting non-existent case returns HTTP 404."""
    non_existent_id = f"CASE-DOESNOTEXIST-{uuid.uuid4().hex[:6]}"
    res = client.post(
        f"/api/cases/{non_existent_id}/verify-admissibility",
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 404


def test_single_audit_event_recorded(rbac_setup):
    """11. Exactly one CASE_ADMISSIBILITY_VERIFIED audit event is recorded per verification run."""
    fixture = create_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]

    db = SessionLocal()
    try:
        initial_audits = (
            db.query(AuditLog)
            .filter_by(resource_id=case_id, action="CASE_ADMISSIBILITY_VERIFIED")
            .count()
        )
    finally:
        db.close()

    assert initial_audits == 0

    # Execute verification run
    payload = {
        "court_bench": "Division Bench II, High Court of Delhi",
        "judicial_officer_name": "Justice Mehra",
        "verification_notes": "Admissibility audit for trial record."
    }
    res = client.post(
        f"/api/cases/{case_id}/verify-admissibility",
        json=payload,
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 200

    db2 = SessionLocal()
    try:
        logs = (
            db2.query(AuditLog)
            .filter_by(resource_id=case_id, action="CASE_ADMISSIBILITY_VERIFIED")
            .all()
        )
        assert len(logs) == 1
        log = logs[0]
        assert log.meta_data["admissibility_status"] == "ADMISSIBLE"
        assert log.meta_data["is_admissible"] is True
        assert log.meta_data["court_bench"] == "Division Bench II, High Court of Delhi"
        assert log.meta_data["judicial_officer_name"] == "Justice Mehra"
        assert log.meta_data["vault_integrity_passed"] is True
        assert log.meta_data["sealing_hash_verified"] is True
    finally:
        db2.close()


def test_judicial_verification_alias_parity(rbac_setup):
    """12. Alias POST /api/cases/{case_id}/judicial-verification returns identical response."""
    fixture = create_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    res_canon = client.post(f"/api/cases/{case_id}/verify-admissibility", headers=headers)
    assert res_canon.status_code == 200
    data_canon = res_canon.json()

    res_alias = client.post(f"/api/cases/{case_id}/judicial-verification", headers=headers)
    assert res_alias.status_code == 200
    data_alias = res_alias.json()

    assert data_alias["case_id"] == data_canon["case_id"]
    assert data_alias["admissibility_status"] == data_canon["admissibility_status"]
    assert data_alias["is_admissible"] == data_canon["is_admissible"]
    assert data_alias["checks"]["sealing_hash_verified"] == data_canon["checks"]["sealing_hash_verified"]


def test_admissibility_certificate_endpoint(rbac_setup):
    """13. GET /api/cases/{case_id}/admissibility-certificate retrieves recorded certificate."""
    fixture = create_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    # 1. Run verification first
    client.post(
        f"/api/cases/{case_id}/verify-admissibility",
        json={"court_bench": "Courtroom 5", "judicial_officer_name": "Justice Roy"},
        headers=headers
    )

    # 2. Query certificate
    cert_res = client.get(
        f"/api/cases/{case_id}/admissibility-certificate",
        headers=headers
    )
    assert cert_res.status_code == 200, cert_res.text
    cert = cert_res.json()

    assert cert["case_id"] == case_id
    assert cert["admissibility_status"] == "ADMISSIBLE"
    assert cert["is_admissible"] is True
    assert cert["statutory_framework"] == "BSA_2023_SECTION_63"
    assert cert["checks"]["sealing_hash_verified"] is True
    assert cert["verifier"]["judicial_officer_name"] == "Justice Roy"
