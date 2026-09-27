"""
NYAYAI - Test Suite: Phase 12 Audit Trail & Audit History
Module: tests.test_phase12_audit_trail
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Comprehensive focused test suite verifying:
1. ADMIN can read global audit history
2. AUDITOR can read audit history
3. SYSTEM_LEAD can read audit history
4. INVESTIGATOR gets 403
5. LAWYER gets 403
6. JUDGE gets 403
7. Action filtering works
8. Resource type filtering works
9. Pagination works (limit, offset)
10. Case audit history works
11. Evidence audit history works
12. Report audit history works
13. Sensitive metadata is not exposed
14. CASE_CREATED is logged
15. CASE_UPDATED is logged
16. REPORT_GENERATED is logged
"""

import os
import sys
import uuid
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
from database.models import User, Case, Evidence, Report, AuditLog
from backend.app.core.security import create_access_token

Base.metadata.create_all(bind=engine)
client = TestClient(app)


@pytest.fixture(scope="module")
def setup_rbac_tokens():
    """Generates valid JWTs for each platform role."""
    db = SessionLocal()
    try:
        def get_or_create_user(role_name: str) -> User:
            u = db.query(User).filter_by(role=role_name).first()
            if not u:
                u = User(
                    id=str(uuid.uuid4()),
                    username=f"test_p12_{role_name.lower()}_{uuid.uuid4().hex[:6]}",
                    email=f"{role_name.lower()}_{uuid.uuid4().hex[:6]}@nyayai.gov.in",
                    hashed_password="hashed_placeholder_p12",
                    role=role_name,
                    is_active=True
                )
                db.add(u)
                db.commit()
                db.refresh(u)
            return u

        admin_u = get_or_create_user("ADMIN")
        auditor_u = get_or_create_user("AUDITOR")
        system_lead_u = get_or_create_user("SYSTEM_LEAD")
        inv_u = get_or_create_user("INVESTIGATOR")
        lawyer_u = get_or_create_user("LAWYER")
        judge_u = get_or_create_user("JUDGE")

        return {
            "ADMIN": {"Authorization": f"Bearer {create_access_token({'sub': admin_u.id, 'username': admin_u.username, 'role': 'ADMIN'})}"},
            "AUDITOR": {"Authorization": f"Bearer {create_access_token({'sub': auditor_u.id, 'username': auditor_u.username, 'role': 'AUDITOR'})}"},
            "SYSTEM_LEAD": {"Authorization": f"Bearer {create_access_token({'sub': system_lead_u.id, 'username': system_lead_u.username, 'role': 'SYSTEM_LEAD'})}"},
            "INVESTIGATOR": {"Authorization": f"Bearer {create_access_token({'sub': inv_u.id, 'username': inv_u.username, 'role': 'INVESTIGATOR'})}"},
            "LAWYER": {"Authorization": f"Bearer {create_access_token({'sub': lawyer_u.id, 'username': lawyer_u.username, 'role': 'LAWYER'})}"},
            "JUDGE": {"Authorization": f"Bearer {create_access_token({'sub': judge_u.id, 'username': judge_u.username, 'role': 'JUDGE'})}"}
        }
    finally:
        db.close()


@pytest.fixture(scope="module")
def setup_audit_entities(setup_rbac_tokens):
    """Pre-seeds test entities and triggers actions to guarantee audit log records."""
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(role="ADMIN").first()

        # 1. Create a test case via API (triggers CASE_CREATED)
        case_res = client.post(
            "/api/v1/cases",
            json={
                "title": "Phase 12 Audit Inspection Docket",
                "description": "Verifying end-to-end system audit trails",
                "jurisdiction": "High Court of Delhi"
            },
            headers=setup_rbac_tokens["ADMIN"]
        )
        assert case_res.status_code == 201
        case_id = case_res.json()["data"]["case_id"]

        # 2. Update the case (triggers CASE_UPDATED)
        patch_res = client.patch(
            f"/api/v1/cases/{case_id}",
            json={"status": "UNDER_ANALYSIS"},
            headers=setup_rbac_tokens["ADMIN"]
        )
        assert patch_res.status_code == 200

        # 3. Create dummy evidence in DB
        ev_id = f"EVD-{uuid.uuid4().hex[:8].upper()}"
        ev = Evidence(
            evidence_id=ev_id,
            case_id=case_id,
            original_filename="seized_ledger.csv",
            media_type="text/csv",
            file_size=1024,
            sha256_hash=f"hash_{uuid.uuid4().hex[:56]}",
            storage_reference=f"./storage/vault/{case_id}/{ev_id}/seized_ledger.csv",
            uploaded_by=user.id
        )
        db.add(ev)

        # 4. Generate report via API (triggers REPORT_GENERATED)
        rep_res = client.post(
            f"/api/v1/cases/{case_id}/report",
            json={
                "certifying_officer_name": "Senior Auditor Verma",
                "certifying_officer_designation": "Forensic Systems Lead",
                "badge_number": "INV-AUD-01",
                "jurisdiction": "High Court of Delhi"
            }
        )
        assert rep_res.status_code == 201
        rep_id = rep_res.json()["data"]["report_id"]

        # 5. Insert an explicit evidence audit log for testing
        audit_ev = AuditLog(
            audit_id=f"AUD-{uuid.uuid4().hex[:12].upper()}",
            user_id=user.id,
            action="EVIDENCE_MANUALLY_INSPECTED",
            resource_type="EVIDENCE",
            resource_id=ev_id,
            meta_data={"inspector": "Auditor Verma", "password_leak": "SHOULD_BE_FILTERED"}
        )
        db.add(audit_ev)
        db.commit()

        return {
            "case_id": case_id,
            "evidence_id": ev_id,
            "report_id": rep_id
        }
    finally:
        db.close()


# -------------------------------------------------------------------------
# RBAC Tests (1 - 6)
# -------------------------------------------------------------------------

def test_admin_can_read_audit_history(setup_rbac_tokens, setup_audit_entities):
    res = client.get("/api/v1/audit", headers=setup_rbac_tokens["ADMIN"])
    assert res.status_code == 200
    assert res.json()["success"] is True
    assert isinstance(res.json()["items"], list)


def test_auditor_can_read_audit_history(setup_rbac_tokens, setup_audit_entities):
    res = client.get("/api/v1/audit", headers=setup_rbac_tokens["AUDITOR"])
    assert res.status_code == 200
    assert res.json()["success"] is True
    assert res.json()["total"] >= 1


def test_system_lead_can_read_audit_history(setup_rbac_tokens, setup_audit_entities):
    res = client.get("/api/v1/audit", headers=setup_rbac_tokens["SYSTEM_LEAD"])
    assert res.status_code == 200
    assert res.json()["success"] is True


def test_investigator_gets_403(setup_rbac_tokens):
    res = client.get("/api/v1/audit", headers=setup_rbac_tokens["INVESTIGATOR"])
    assert res.status_code == 403


def test_lawyer_gets_403(setup_rbac_tokens):
    res = client.get("/api/v1/audit", headers=setup_rbac_tokens["LAWYER"])
    assert res.status_code == 403


def test_judge_gets_403(setup_rbac_tokens):
    res = client.get("/api/v1/audit", headers=setup_rbac_tokens["JUDGE"])
    assert res.status_code == 403


# -------------------------------------------------------------------------
# Querying & Filtering Tests (7 - 9)
# -------------------------------------------------------------------------

def test_action_filtering_works(setup_rbac_tokens, setup_audit_entities):
    res = client.get("/api/v1/audit?action=CASE_CREATED", headers=setup_rbac_tokens["ADMIN"])
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) >= 1
    for item in items:
        assert item["action"] == "CASE_CREATED"


def test_resource_type_filtering_works(setup_rbac_tokens, setup_audit_entities):
    res = client.get("/api/v1/audit?resource_type=REPORT", headers=setup_rbac_tokens["ADMIN"])
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) >= 1
    for item in items:
        assert item["resource_type"] == "REPORT"


def test_pagination_works(setup_rbac_tokens, setup_audit_entities):
    res = client.get("/api/v1/audit?limit=2&offset=0", headers=setup_rbac_tokens["ADMIN"])
    assert res.status_code == 200
    data = res.json()
    assert data["limit"] == 2
    assert data["offset"] == 0
    assert len(data["items"]) <= 2


# -------------------------------------------------------------------------
# Entity Audit History Endpoints (10 - 12)
# -------------------------------------------------------------------------

def test_case_audit_history_works(setup_rbac_tokens, setup_audit_entities):
    cid = setup_audit_entities["case_id"]
    res = client.get(f"/api/v1/audit/cases/{cid}", headers=setup_rbac_tokens["ADMIN"])
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) >= 1
    actions = [item["action"] for item in items]
    assert "CASE_CREATED" in actions


def test_evidence_audit_history_works(setup_rbac_tokens, setup_audit_entities):
    eid = setup_audit_entities["evidence_id"]
    res = client.get(f"/api/v1/audit/evidence/{eid}", headers=setup_rbac_tokens["ADMIN"])
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) >= 1
    assert items[0]["resource_id"] == eid


def test_report_audit_history_works(setup_rbac_tokens, setup_audit_entities):
    rid = setup_audit_entities["report_id"]
    res = client.get(f"/api/v1/audit/reports/{rid}", headers=setup_rbac_tokens["ADMIN"])
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) >= 1
    assert items[0]["resource_id"] == rid


# -------------------------------------------------------------------------
# Security & Logging Verification (13 - 16)
# -------------------------------------------------------------------------

def test_sensitive_metadata_is_not_exposed(setup_rbac_tokens, setup_audit_entities):
    res = client.get("/api/v1/audit", headers=setup_rbac_tokens["ADMIN"])
    assert res.status_code == 200
    for item in res.json()["items"]:
        meta = item["metadata"]
        for k in meta.keys():
            k_lower = str(k).lower()
            assert "password" not in k_lower
            assert "secret" not in k_lower
            assert "token" not in k_lower
            assert "credential" not in k_lower


def test_case_created_is_logged(setup_audit_entities):
    cid = setup_audit_entities["case_id"]
    db = SessionLocal()
    try:
        log = db.query(AuditLog).filter_by(action="CASE_CREATED", resource_id=cid).first()
        assert log is not None
        assert log.resource_type == "CASE"
        assert log.audit_id.startswith("AUD-")
    finally:
        db.close()


def test_case_updated_is_logged(setup_audit_entities):
    cid = setup_audit_entities["case_id"]
    db = SessionLocal()
    try:
        log = db.query(AuditLog).filter_by(action="CASE_UPDATED", resource_id=cid).first()
        assert log is not None
        assert log.resource_type == "CASE"
    finally:
        db.close()


def test_report_generated_is_logged(setup_audit_entities):
    rid = setup_audit_entities["report_id"]
    db = SessionLocal()
    try:
        log = db.query(AuditLog).filter_by(action="REPORT_GENERATED", resource_id=rid).first()
        assert log is not None
        assert log.resource_type == "REPORT"
        assert "compliance_framework" in log.meta_data
    finally:
        db.close()
