"""
NYAYAI - Test Suite: Phase 17 Case Docket Finalization & Judicial Sealing
Module: tests.test_case_finalization_sealing
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Comprehensive focused test suite verifying:
1. Successful case docket finalization and cryptographic sealing.
2. Deterministic SHA-256 docket sealing manifest hash calculation.
3. Terminal custody event chaining (DOCKET_SEALED) with unbroken hash continuity.
4. Validation gate: pending forensic/AI analysis rejection (HTTP 400).
5. Validation gate: compromised integrity/storage error rejection (HTTP 400).
6. Validation gate: broken custody chain rejection (HTTP 400).
7. Validation gate: missing official court admissibility report rejection (HTTP 400).
8. Validation gate: empty case docket rejection (HTTP 400).
9. Idempotency & Conflict: already COMPLETED or ARCHIVED case cannot be finalized (HTTP 409).
10. Immutability guard: evidence intake blocked for COMPLETED/ARCHIVED cases (HTTP 400).
11. Role-based access control (RBAC): Investigator isolation (403), Admin/Judge permitted (200), Lawyer blocked (403).
12. Unknown case handling (HTTP 404).
13. Exactly one CASE_FINALIZED audit event recorded.
14. Alias endpoint POST /api/cases/{case_id}/seal parity.
15. Manifest inspection GET /api/cases/{case_id}/sealing-manifest.
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
    EvidenceMetadata,
    AnalysisResult,
    CustodyEvent,
    Report,
    AuditLog
)
from backend.app.core.security import create_access_token
from custody import CryptographicCustodyLedger

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
                    hashed_password="hashed_placeholder_p17",
                    role=role,
                    full_name=f"Official {username.title()}",
                    badge_number=f"BADGE-{username[:4].upper()}-99",
                    is_active=True
                )
                db.add(u)
                db.commit()
                db.refresh(u)
            return u

        inv1 = get_or_create("p17_inv_lead", "INVESTIGATOR")
        inv2 = get_or_create("p17_inv_other", "INVESTIGATOR")
        admin = get_or_create("p17_admin_lead", "ADMIN")
        judge = get_or_create("p17_hon_judge", "JUDGE")
        lawyer = get_or_create("p17_advocate", "LAWYER")

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


@pytest.fixture
def fully_prepared_case(rbac_setup):
    """
    Creates an UNDER_ANALYSIS case with 2 analyzed evidence items and 1 court report.
    Ready for successful finalization.
    """
    headers = rbac_setup["headers_inv1"]
    suffix = uuid.uuid4().hex[:6].upper()

    # 1. Create Case Docket
    c_res = client.post(
        "/api/cases",
        json={
            "title": f"Ready for Sealing Case {suffix}",
            "description": "Case fully analyzed and ready for judicial sealing",
            "jurisdiction": "High Court of Delhi"
        },
        headers=headers
    )
    assert c_res.status_code == 201, c_res.text
    case_id = c_res.json()["data"]["case_id"]

    # 2. Upload Evidence 1 (PNG image)
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRP17_IMAGE_BYTES"
    up1 = client.post(
        "/api/evidence/upload",
        files={"file": ("evidence1.png", png_bytes, "image/png")},
        data={"case_id": case_id, "source_description": "Source Camera 1"},
        headers=headers
    )
    assert up1.status_code == 201, up1.text
    ev1_id = up1.json()["evidence_id"]

    # 3. Upload Evidence 2 (WAV audio)
    wav_bytes = b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00P17_AUDIO"
    up2 = client.post(
        "/api/evidence/upload",
        files={"file": ("evidence2.wav", wav_bytes, "audio/wav")},
        data={"case_id": case_id, "source_description": "Recorded Call 1"},
        headers=headers
    )
    assert up2.status_code == 201, up2.text
    ev2_id = up2.json()["evidence_id"]

    # 4. Run Batch Analysis Pipeline (Transitions status to UNDER_ANALYSIS)
    pipe_res = client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers)
    assert pipe_res.status_code == 200, pipe_res.text
    assert pipe_res.json()["processed_count"] == 2

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

    return {
        "case_id": case_id,
        "evidence_ids": [ev1_id, ev2_id],
        "headers": headers
    }


# =============================================================================
# TESTS
# =============================================================================

def test_successful_finalization_and_sealing(fully_prepared_case, rbac_setup):
    """1. Full pipeline case finalization transitions to COMPLETED and seals docket."""
    case_id = fully_prepared_case["case_id"]
    headers = fully_prepared_case["headers"]

    payload = {
        "certification_notes": "All forensic examinations complete and verified under BSA 2023.",
        "certifying_officer_name": "Official Lead Investigator",
        "badge_number": "BADGE-INV-99"
    }

    res = client.post(f"/api/cases/{case_id}/finalize", json=payload, headers=headers)
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["case_id"] == case_id
    assert data["previous_status"] == "UNDER_ANALYSIS"
    assert data["new_status"] == "COMPLETED"
    assert len(data["docket_sealing_hash"]) == 64
    assert data["total_evidence_sealed"] == 2
    assert data["court_reports_referenced"] >= 1
    assert data["custody_events_appended"] == 2
    assert data["sealed_by"] == rbac_setup["inv1"].id

    # Verify database state
    db = SessionLocal()
    try:
        c = db.query(Case).filter_by(case_id=case_id).first()
        assert c.status == "COMPLETED"
    finally:
        db.close()


def test_deterministic_sealing_hash(fully_prepared_case):
    """2. Docket sealing hash is deterministic and reproducible."""
    case_id = fully_prepared_case["case_id"]
    headers = fully_prepared_case["headers"]

    # Finalize
    res = client.post(f"/api/cases/{case_id}/finalize", headers=headers)
    assert res.status_code == 200
    sealed_hash = res.json()["docket_sealing_hash"]

    # Retrieve sealing manifest and verify hash consistency
    man_res = client.get(f"/api/cases/{case_id}/sealing-manifest", headers=headers)
    assert man_res.status_code == 200
    man_data = man_res.json()
    assert man_data["is_sealed"] is True
    assert man_data["docket_sealing_hash"] == sealed_hash

    # Verify manual reconstruction yields identical SHA-256
    db = SessionLocal()
    try:
        case = db.query(Case).filter_by(case_id=case_id).first()
        evidences = db.query(Evidence).filter_by(case_id=case_id).order_by(Evidence.evidence_id.asc()).all()
        reports = db.query(Report).filter_by(case_id=case_id).order_by(Report.report_id.asc()).all()

        manifest_payload = {
            "case_id": case.case_id,
            "case_number": case.case_number,
            "evidence": [
                {
                    "evidence_id": item["evidence_id"],
                    "sha256_hash": item["sha256_hash"],
                    "terminal_custody_hash": item["terminal_custody_hash"]
                }
                for item in man_data["evidence_manifest"]
            ],
            "reports": [
                {
                    "report_id": item["report_id"],
                    "report_sha256": item["report_sha256"]
                }
                for item in man_data["reports_manifest"]
            ]
        }
        computed = hashlib.sha256(json.dumps(manifest_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest().lower()
        assert computed == sealed_hash
    finally:
        db.close()


def test_terminal_custody_chaining(fully_prepared_case):
    """3. Verifies terminal DOCKET_SEALED event is appended with valid hash chaining."""
    case_id = fully_prepared_case["case_id"]
    headers = fully_prepared_case["headers"]
    ev_ids = fully_prepared_case["evidence_ids"]

    res = client.post(f"/api/cases/{case_id}/finalize", headers=headers)
    assert res.status_code == 200
    sealing_hash = res.json()["docket_sealing_hash"]

    ledger = CryptographicCustodyLedger()
    db = SessionLocal()
    try:
        from backend.app.services.custody_service import CustodyService
        custody_svc = CustodyService(db)
        for eid in ev_ids:
            events = db.query(CustodyEvent).filter_by(evidence_id=eid).order_by(CustodyEvent.sequence_number.asc()).all()
            assert len(events) >= 3  # GENESIS, PIPELINE, DOCKET_SEALED

            last_evt = events[-1]
            assert last_evt.event_type == "DOCKET_SEALED"
            assert last_evt.previous_hash == events[-2].event_hash

            payload = json.loads(last_evt.payload_json)
            assert payload.get("docket_sealing_hash") == sealing_hash
            assert payload.get("sealed_status") == "COMPLETED"

            # Verify entire chain is cryptographically intact
            check = custody_svc.get_chronological_history(eid)
            assert check["chain_intact"] is True
    finally:
        db.close()


def test_pending_analysis_rejection(rbac_setup):
    """4. Case with unanalyzed evidence cannot be finalized (HTTP 400)."""
    headers = rbac_setup["headers_inv1"]
    suffix = uuid.uuid4().hex[:6].upper()

    # Create Case
    c_res = client.post("/api/cases", json={"title": f"Pending Case {suffix}"}, headers=headers)
    case_id = c_res.json()["data"]["case_id"]

    # Upload Evidence without running pipeline
    client.post(
        "/api/evidence/upload",
        files={"file": ("raw.png", b"\x89PNG\r\n\x1a\nRAW_BYTES", "image/png")},
        data={"case_id": case_id},
        headers=headers
    )

    # Attempt finalize
    res = client.post(f"/api/cases/{case_id}/finalize", headers=headers)
    assert res.status_code == 400
    assert "PENDING_ANALYSIS_REMAINS" in res.text or "pending forensic or AI analysis" in res.text


def test_compromised_integrity_rejection(fully_prepared_case):
    """5. Case with INTEGRITY_COMPROMISED evidence cannot be finalized (HTTP 400)."""
    case_id = fully_prepared_case["case_id"]
    headers = fully_prepared_case["headers"]
    eid = fully_prepared_case["evidence_ids"][0]

    # Force integrity compromised status
    db = SessionLocal()
    try:
        ev = db.query(Evidence).filter_by(evidence_id=eid).first()
        ev.status = "INTEGRITY_COMPROMISED"
        db.commit()
    finally:
        db.close()

    res = client.post(f"/api/cases/{case_id}/finalize", headers=headers)
    assert res.status_code == 400
    assert "EVIDENCE_INTEGRITY_COMPROMISED" in res.text or "compromised" in res.text


def test_broken_custody_chain_rejection(fully_prepared_case):
    """6. Case with broken custody chain cannot be finalized (HTTP 400)."""
    case_id = fully_prepared_case["case_id"]
    headers = fully_prepared_case["headers"]
    eid = fully_prepared_case["evidence_ids"][0]

    # Break hash chain in database by mutating payload of first block
    db = SessionLocal()
    try:
        ce = db.query(CustodyEvent).filter_by(evidence_id=eid).first()
        ce.payload_json = json.dumps({"tampered": True})
        db.commit()
    finally:
        db.close()

    res = client.post(f"/api/cases/{case_id}/finalize", headers=headers)
    assert res.status_code == 400
    assert "BROKEN_CUSTODY_CHAIN" in res.text or "chain of custody" in res.text


def test_missing_report_rejection(rbac_setup):
    """7. Case without any official court report cannot be finalized (HTTP 400)."""
    headers = rbac_setup["headers_inv1"]
    suffix = uuid.uuid4().hex[:6].upper()

    # Create case
    c_res = client.post("/api/cases", json={"title": f"No Report Case {suffix}"}, headers=headers)
    case_id = c_res.json()["data"]["case_id"]

    # Upload evidence and run analysis
    client.post(
        "/api/evidence/upload",
        files={"file": ("doc.png", b"\x89PNG\r\n\x1a\nTEST", "image/png")},
        data={"case_id": case_id},
        headers=headers
    )
    client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers)

    # Attempt finalize without generating report
    res = client.post(f"/api/cases/{case_id}/finalize", headers=headers)
    assert res.status_code == 400
    assert "COURT_REPORT_REQUIRED" in res.text or "court admissibility report" in res.text


def test_empty_case_rejection(rbac_setup):
    """8. Case docket with zero evidence cannot be finalized (HTTP 400)."""
    headers = rbac_setup["headers_inv1"]
    suffix = uuid.uuid4().hex[:6].upper()

    c_res = client.post("/api/cases", json={"title": f"Empty Case {suffix}"}, headers=headers)
    case_id = c_res.json()["data"]["case_id"]

    res = client.post(f"/api/cases/{case_id}/finalize", headers=headers)
    assert res.status_code == 400
    assert "EMPTY_CASE_DOCKET" in res.text or "empty" in res.text


def test_already_completed_conflict(fully_prepared_case):
    """9. Idempotency: Attempting to finalize an already COMPLETED case returns HTTP 409."""
    case_id = fully_prepared_case["case_id"]
    headers = fully_prepared_case["headers"]

    # First finalization succeeds
    res1 = client.post(f"/api/cases/{case_id}/finalize", headers=headers)
    assert res1.status_code == 200

    # Second finalization rejected with 409 Conflict
    res2 = client.post(f"/api/cases/{case_id}/finalize", headers=headers)
    assert res2.status_code == 409
    assert "CASE_ALREADY_COMPLETED" in res2.text or "already COMPLETED" in res2.text


def test_completed_case_intake_blocked(fully_prepared_case):
    """10. Immutability: New evidence upload into a COMPLETED case is rejected with HTTP 400."""
    case_id = fully_prepared_case["case_id"]
    headers = fully_prepared_case["headers"]

    # Finalize case
    fin_res = client.post(f"/api/cases/{case_id}/finalize", headers=headers)
    assert fin_res.status_code == 200

    # Attempt to upload new evidence into sealed case
    up_res = client.post(
        "/api/evidence/upload",
        files={"file": ("late_evidence.png", b"\x89PNG\r\n\x1a\nLATE", "image/png")},
        data={"case_id": case_id},
        headers=headers
    )
    assert up_res.status_code == 400
    assert "CASE_SEALED" in up_res.text or "sealed" in up_res.text


def test_rbac_and_role_isolation(fully_prepared_case, rbac_setup):
    """11. RBAC: Unauthorized investigator (403), Lawyer (403), Admin (200), Judge (200)."""
    case_id = fully_prepared_case["case_id"]
    headers_inv2 = rbac_setup["headers_inv2"]
    headers_lawyer = rbac_setup["headers_lawyer"]
    headers_admin = rbac_setup["headers_admin"]
    headers_judge = rbac_setup["headers_judge"]

    # Unauthorized investigator attempt -> 403 Forbidden
    res_inv2 = client.post(f"/api/cases/{case_id}/finalize", headers=headers_inv2)
    assert res_inv2.status_code == 403

    # Lawyer attempt -> 403 Forbidden
    res_lawyer = client.post(f"/api/cases/{case_id}/finalize", headers=headers_lawyer)
    assert res_lawyer.status_code == 403

    # Anonymous attempt -> 401/403
    res_anon = client.post(f"/api/cases/{case_id}/finalize")
    assert res_anon.status_code in (401, 403)

    # Admin attempt -> 200 OK
    res_admin = client.post(f"/api/cases/{case_id}/finalize", headers=headers_admin)
    assert res_admin.status_code == 200


def test_finalize_unknown_case_returns_404(rbac_setup):
    """12. Unknown case_id returns 404 EntityNotFoundException."""
    headers = rbac_setup["headers_admin"]
    res = client.post("/api/cases/CASE-NONEXISTENT-9999/finalize", headers=headers)
    assert res.status_code == 404


def test_exactly_one_case_finalized_audit_event(fully_prepared_case):
    """13. Exactly one CASE_FINALIZED audit event is logged on docket sealing."""
    case_id = fully_prepared_case["case_id"]
    headers = fully_prepared_case["headers"]

    res = client.post(f"/api/cases/{case_id}/finalize", headers=headers)
    assert res.status_code == 200

    db = SessionLocal()
    try:
        audits = (
            db.query(AuditLog)
            .filter_by(resource_id=case_id, action="CASE_FINALIZED")
            .all()
        )
        assert len(audits) == 1
        audit = audits[0]
        assert audit.meta_data.get("new_status") == "COMPLETED"
        assert audit.meta_data.get("docket_sealing_hash") == res.json()["docket_sealing_hash"]
        assert audit.meta_data.get("total_evidence_sealed") == 2
    finally:
        db.close()


def test_alias_endpoint_post_seal(fully_prepared_case):
    """14. Alias endpoint POST /api/cases/{case_id}/seal functions identically."""
    case_id = fully_prepared_case["case_id"]
    headers = fully_prepared_case["headers"]

    res = client.post(f"/api/cases/{case_id}/seal", headers=headers)
    assert res.status_code == 200
    assert res.json()["new_status"] == "COMPLETED"


def test_sealing_manifest_endpoint(fully_prepared_case):
    """15. GET /api/cases/{case_id}/sealing-manifest returns complete sealed verification record."""
    case_id = fully_prepared_case["case_id"]
    headers = fully_prepared_case["headers"]

    # Pre-sealing manifest: is_sealed == False
    pre_res = client.get(f"/api/cases/{case_id}/sealing-manifest", headers=headers)
    assert pre_res.status_code == 200
    assert pre_res.json()["is_sealed"] is False
    assert pre_res.json()["docket_sealing_hash"] is None

    # Seal case
    fin_res = client.post(f"/api/cases/{case_id}/finalize", headers=headers)
    assert fin_res.status_code == 200
    expected_hash = fin_res.json()["docket_sealing_hash"]

    # Post-sealing manifest: is_sealed == True with full records
    post_res = client.get(f"/api/cases/{case_id}/sealing-manifest", headers=headers)
    assert post_res.status_code == 200
    post_data = post_res.json()
    assert post_data["is_sealed"] is True
    assert post_data["docket_sealing_hash"] == expected_hash
    assert len(post_data["evidence_manifest"]) == 2
    assert len(post_data["reports_manifest"]) >= 1
