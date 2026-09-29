"""
NYAYAI - Test Suite: Phase 16 Case Docket Batch Pipeline Orchestrator
Module: tests.test_case_pipeline_batch
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Comprehensive focused test suite verifying:
1. All pending evidence processed across docket.
2. Idempotency guarantee: already analyzed evidence is not redundantly re-analyzed.
3. Fault-tolerant hash tampering: tampered evidence marked INTEGRITY_COMPROMISED without crashing batch.
4. Case status transition: OPEN case transitions to UNDER_ANALYSIS.
5. Pending actions reduced: Phase 14 operational view shows 0 pending forensic/AI actions post-run.
6. RBAC and role isolation: Investigator only processes owned/assigned cases; unauthorized gets 403.
7. Unknown case returns 404.
8. Empty case docket (0 evidence) returns clean 200 OK without errors.
9. Alias endpoint POST /api/cases/{case_id}/run-analysis functions identically.
10. Single CASE_PIPELINE_BATCH_EXECUTED audit event recorded.
"""

import os
import sys
import stat
import uuid
import pytest
from datetime import datetime, timezone
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
    ExplainabilityRecord,
    CustodyEvent,
    AuditLog
)
from backend.app.core.security import create_access_token

Base.metadata.create_all(bind=engine)
client = TestClient(app)


@pytest.fixture(scope="module")
def rbac_setup():
    """Provisions investigator and admin users with auth headers."""
    db = SessionLocal()
    try:
        def get_or_create(username: str, role: str) -> User:
            u = db.query(User).filter_by(username=username).first()
            if not u:
                u = User(
                    id=str(uuid.uuid4()),
                    username=username,
                    email=f"{username}@nyayai.gov.in",
                    hashed_password="hashed_placeholder_p16",
                    full_name=f"{role} Officer",
                    role=role,
                    is_active=True
                )
                db.add(u)
                db.commit()
                db.refresh(u)
            return u

        suffix = uuid.uuid4().hex[:6]
        inv1 = get_or_create(f"inv1_p16_{suffix}", "INVESTIGATOR")
        inv2 = get_or_create(f"inv2_p16_{suffix}", "INVESTIGATOR")
        admin = get_or_create(f"admin_p16_{suffix}", "ADMIN")

        return {
            "inv1": inv1,
            "inv2": inv2,
            "admin": admin,
            "headers_inv1": {"Authorization": f"Bearer {create_access_token({'sub': inv1.id, 'username': inv1.username, 'role': 'INVESTIGATOR'})}"},
            "headers_inv2": {"Authorization": f"Bearer {create_access_token({'sub': inv2.id, 'username': inv2.username, 'role': 'INVESTIGATOR'})}"},
            "headers_admin": {"Authorization": f"Bearer {create_access_token({'sub': admin.id, 'username': admin.username, 'role': 'ADMIN'})}"}
        }
    finally:
        db.close()


@pytest.fixture
def docket_with_evidence(rbac_setup):
    """
    Creates an OPEN case with 2 vaulted unanalyzed evidence items.
    """
    inv1 = rbac_setup["inv1"]
    headers = rbac_setup["headers_inv1"]
    suffix = uuid.uuid4().hex[:6].upper()

    # 1. Create Case Docket
    c_res = client.post(
        "/api/cases",
        json={
            "title": f"Batch Processing Test Case {suffix}",
            "description": "Case created for batch pipeline testing",
            "jurisdiction": "High Court of Delhi"
        },
        headers=headers
    )
    assert c_res.status_code == 201, c_res.text
    case_id = c_res.json()["data"]["case_id"]

    # 2. Upload Evidence 1 (PNG image)
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRP16_TEST_IMAGE_1_BYTES"
    up1 = client.post(
        "/api/evidence/upload",
        files={"file": ("evidence1.png", png_bytes, "image/png")},
        data={"case_id": case_id, "source_description": "Mobile Camera 1"},
        headers=headers
    )
    assert up1.status_code == 201, up1.text
    ev1_id = up1.json()["evidence_id"]

    # 3. Upload Evidence 2 (WAV audio)
    wav_bytes = b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00P16_AUDIO"
    up2 = client.post(
        "/api/evidence/upload",
        files={"file": ("evidence2.wav", wav_bytes, "audio/wav")},
        data={"case_id": case_id, "source_description": "Call Recording 1"},
        headers=headers
    )
    assert up2.status_code == 201, up2.text
    ev2_id = up2.json()["evidence_id"]

    return {
        "case_id": case_id,
        "evidence_ids": [ev1_id, ev2_id],
        "headers": headers
    }


# =============================================================================
# TESTS
# =============================================================================

def test_process_pipeline_executes_all_pending_evidence(docket_with_evidence):
    """1. Batch pipeline executes forensic, AI, explainability, and custody logging across all pending items."""
    case_id = docket_with_evidence["case_id"]
    headers = docket_with_evidence["headers"]
    ev_ids = docket_with_evidence["evidence_ids"]

    res = client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers)
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["case_id"] == case_id
    assert data["total_items"] == 2
    assert data["processed_count"] == 2
    assert data["compromised_count"] == 0
    assert data["new_case_status"] == "UNDER_ANALYSIS"

    # Verify database persistence for each evidence item
    db = SessionLocal()
    try:
        for eid in ev_ids:
            ev = db.query(Evidence).filter_by(evidence_id=eid).first()
            assert ev.status == "ANALYZED"

            meta = db.query(EvidenceMetadata).filter_by(evidence_id=eid).first()
            assert meta is not None
            assert meta.magic_bytes is not None

            ai_res = db.query(AnalysisResult).filter_by(evidence_id=eid).first()
            assert ai_res is not None
            assert ai_res.status == "COMPLETED"

            exp = db.query(ExplainabilityRecord).filter_by(evidence_id=eid).first()
            assert exp is not None

            # Custody event: genesis block (1) + pipeline execution block (2)
            events = db.query(CustodyEvent).filter_by(evidence_id=eid).order_by(CustodyEvent.sequence_number.asc()).all()
            assert len(events) >= 2
            pipeline_evt = next((e for e in events if e.action == "ANALYSIS_PIPELINE_EXECUTED"), None)
            assert pipeline_evt is not None
            assert pipeline_evt.previous_event_hash == events[0].event_hash
    finally:
        db.close()


def test_process_pipeline_idempotency(docket_with_evidence):
    """2. Idempotency: Running process-pipeline a second time skips already analyzed items."""
    case_id = docket_with_evidence["case_id"]
    headers = docket_with_evidence["headers"]

    # First run processes 2 items
    res1 = client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers)
    assert res1.status_code == 200
    assert res1.json()["processed_count"] == 2

    # Second run should skip and process 0 items
    res2 = client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers)
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["total_items"] == 2
    assert data2["processed_count"] == 0


def test_process_pipeline_detects_hash_tampering(rbac_setup):
    """3. Fault tolerance: Tampered evidence is marked INTEGRITY_COMPROMISED without crashing batch."""
    headers = rbac_setup["headers_inv1"]
    suffix = uuid.uuid4().hex[:6].upper()

    # 1. Create Case Docket
    c_res = client.post(
        "/api/cases",
        json={"title": f"Tamper Test Docket {suffix}", "jurisdiction": "High Court of Delhi"},
        headers=headers
    )
    case_id = c_res.json()["data"]["case_id"]

    # 2. Upload Authentic Evidence 1
    up1 = client.post(
        "/api/evidence/upload",
        files={"file": ("good.png", b"\x89PNG\r\n\x1a\nGOOD_IMAGE_BYTES", "image/png")},
        data={"case_id": case_id},
        headers=headers
    )
    ev1_id = up1.json()["evidence_id"]

    # 3. Upload Evidence 2 that will be physically tampered on disk
    up2 = client.post(
        "/api/evidence/upload",
        files={"file": ("tampered.png", b"\x89PNG\r\n\x1a\nORIGINAL_IMAGE_BYTES", "image/png")},
        data={"case_id": case_id},
        headers=headers
    )
    ev2_id = up2.json()["evidence_id"]

    # Physically mutate file bytes in vault to simulate post-upload tampering
    db = SessionLocal()
    try:
        ev2 = db.query(Evidence).filter_by(evidence_id=ev2_id).first()
        vault_path = ev2.storage_reference
        os.chmod(vault_path, stat.S_IWRITE | stat.S_IREAD)
        with open(vault_path, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\nMALICIOUS_CORRUPTED_BYTES_HERE")
        os.chmod(vault_path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    finally:
        db.close()

    # 4. Execute Batch Pipeline
    res = client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["total_items"] == 2
    assert data["processed_count"] == 1       # Evidence 1 processed successfully
    assert data["compromised_count"] == 1     # Evidence 2 flagged as compromised

    # Verify statuses in database
    db = SessionLocal()
    try:
        e1 = db.query(Evidence).filter_by(evidence_id=ev1_id).first()
        e2 = db.query(Evidence).filter_by(evidence_id=ev2_id).first()
        assert e1.status == "ANALYZED"
        assert e2.status == "INTEGRITY_COMPROMISED"

        # Verify failure custody event was appended to e2
        e2_events = db.query(CustodyEvent).filter_by(evidence_id=ev2_id).all()
        actions = [ev.action for ev in e2_events]
        assert "INTEGRITY_VERIFICATION_FAILED" in actions
    finally:
        db.close()


def test_process_pipeline_case_status_transition(docket_with_evidence):
    """4. Case status transitions from OPEN to UNDER_ANALYSIS when pipeline runs."""
    case_id = docket_with_evidence["case_id"]
    headers = docket_with_evidence["headers"]

    # Verify initial status is OPEN
    db = SessionLocal()
    try:
        c_before = db.query(Case).filter_by(case_id=case_id).first()
        assert c_before.status == "OPEN"
    finally:
        db.close()

    # Execute batch pipeline
    res = client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers)
    assert res.status_code == 200
    assert res.json()["new_case_status"] == "UNDER_ANALYSIS"

    db = SessionLocal()
    try:
        c_after = db.query(Case).filter_by(case_id=case_id).first()
        assert c_after.status == "UNDER_ANALYSIS"
    finally:
        db.close()


def test_process_pipeline_resolves_pending_actions(docket_with_evidence):
    """5. Post-execution, Phase 14 operational view shows pending forensic/AI actions reduced to zero."""
    case_id = docket_with_evidence["case_id"]
    headers = docket_with_evidence["headers"]

    # Delete metadata for item 1 to trigger PENDING_FORENSIC_ANALYSIS
    db = SessionLocal()
    try:
        db.query(EvidenceMetadata).filter_by(evidence_id=docket_with_evidence["evidence_ids"][0]).delete()
        db.commit()
    finally:
        db.close()

    # Check Phase 14 operational view BEFORE running pipeline
    op_before = client.get(f"/api/cases/{case_id}/operational-view", headers=headers).json()
    action_types_before = [a["action_type"] for a in op_before["pending_actions"]]
    assert "PENDING_FORENSIC_ANALYSIS" in action_types_before
    assert "PENDING_AI_ANALYSIS" in action_types_before

    # Run batch pipeline
    res = client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers)
    assert res.status_code == 200

    # Check Phase 14 operational view AFTER running pipeline
    op_after = client.get(f"/api/cases/{case_id}/operational-view", headers=headers).json()
    action_types_after = [a["action_type"] for a in op_after["pending_actions"]]
    assert "PENDING_FORENSIC_ANALYSIS" not in action_types_after
    assert "PENDING_AI_ANALYSIS" not in action_types_after


def test_process_pipeline_rbac_and_role_isolation(docket_with_evidence, rbac_setup):
    """6. Role isolation: Investigator 2 cannot process Investigator 1's case (403); Admin can process."""
    case_id = docket_with_evidence["case_id"]
    headers_inv2 = rbac_setup["headers_inv2"]
    headers_admin = rbac_setup["headers_admin"]

    # Unauthorized investigator attempt -> 403 Forbidden
    resp_unauth = client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers_inv2)
    assert resp_unauth.status_code in (401, 403)

    # Unauthenticated attempt -> 401/403
    resp_anon = client.post(f"/api/cases/{case_id}/process-pipeline")
    assert resp_anon.status_code in (401, 403)

    # Admin attempt -> 200 OK
    resp_admin = client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers_admin)
    assert resp_admin.status_code == 200


def test_process_pipeline_unknown_case_returns_404(rbac_setup):
    """7. Unknown case_id returns 404 EntityNotFoundException."""
    headers = rbac_setup["headers_inv1"]
    res = client.post("/api/cases/CASE-NONEXISTENT-9999/process-pipeline", headers=headers)
    assert res.status_code == 404


def test_process_pipeline_empty_case(rbac_setup):
    """8. Case with zero evidence items returns 200 OK with total_items = 0 and processed_count = 0."""
    headers = rbac_setup["headers_inv1"]
    suffix = uuid.uuid4().hex[:6].upper()

    c_res = client.post(
        "/api/cases",
        json={"title": f"Empty Case {suffix}", "jurisdiction": "High Court of Delhi"},
        headers=headers
    )
    case_id = c_res.json()["data"]["case_id"]

    res = client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total_items"] == 0
    assert data["processed_count"] == 0


def test_process_pipeline_alias_endpoint(docket_with_evidence):
    """9. Alias endpoint POST /api/cases/{case_id}/run-analysis functions equivalently."""
    case_id = docket_with_evidence["case_id"]
    headers = docket_with_evidence["headers"]

    res = client.post(f"/api/cases/{case_id}/run-analysis", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["case_id"] == case_id
    assert "processed_count" in data


def test_process_pipeline_creates_single_audit_event(docket_with_evidence):
    """10. Single CASE_PIPELINE_BATCH_EXECUTED audit event is logged per batch execution."""
    case_id = docket_with_evidence["case_id"]
    headers = docket_with_evidence["headers"]

    db = SessionLocal()
    try:
        aud_count_before = (
            db.query(AuditLog)
            .filter_by(resource_id=case_id, action="CASE_PIPELINE_BATCH_EXECUTED")
            .count()
        )
    finally:
        db.close()

    res = client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers)
    assert res.status_code == 200

    db = SessionLocal()
    try:
        aud_count_after = (
            db.query(AuditLog)
            .filter_by(resource_id=case_id, action="CASE_PIPELINE_BATCH_EXECUTED")
            .count()
        )
        assert aud_count_after == aud_count_before + 1
    finally:
        db.close()
