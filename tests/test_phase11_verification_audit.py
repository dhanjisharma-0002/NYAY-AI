"""
NYAYAI - Test Suite: Phase 11 Public Verification & Verification Audit
Module: tests.test_phase11_verification_audit
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Comprehensive focused test suite verifying:
1. Valid verification by report_id
2. Valid verification by verification_code
3. VerificationRecord persistence in database
4. AuditLog creation on verification (both success and failed lookups)
5. Safe public response with zero sensitive data leakage (no filesystem paths, no credentials)
6. Non-existent / invalid report verification failure handling (controlled 404)
7. Dual-path compatibility (/api/v1/reports/verify, /api/reports/verify, /api/verification)
8. Verification audit history retrieval
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
from database.models import User, Case, Report, VerificationRecord, AuditLog

Base.metadata.create_all(bind=engine)
client = TestClient(app)


@pytest.fixture(scope="module")
def setup_test_report():
    """Sets up an isolated Case and Report for Phase 11 verification testing."""
    db = SessionLocal()
    try:
        # 1. Ensure test user
        user = db.query(User).first()
        if not user:
            user = User(
                id=str(uuid.uuid4()),
                username="test_verifier_admin",
                email="verifier_admin@nyayai.gov.in",
                hashed_password="hashed_placeholder_2026",
                role="ADMIN"
            )
            db.add(user)
            db.commit()
            db.refresh(user)

        # 2. Create test case
        case_id = f"CASE-2026-{uuid.uuid4().hex[:8].upper()}"
        case = Case(
            case_id=case_id,
            case_number=f"FIR-{uuid.uuid4().hex[:6].upper()}/2026",
            title="State vs. Digital Forgery Syndicate",
            description="High-profile electronic evidence tampering matter",
            jurisdiction="High Court of Delhi",
            created_by=user.id
        )
        db.add(case)

        # 3. Create test report
        report_id = f"REP-{uuid.uuid4().hex[:10].upper()}"
        verification_code = f"VERIFY-{uuid.uuid4().hex[:12].upper()}"
        report_sha256 = f"sha256_{uuid.uuid4().hex}{uuid.uuid4().hex[:32]}"[:64]

        report = Report(
            report_id=report_id,
            case_id=case.case_id,
            report_type="BSA_2023_SEC_63_65B",
            status="GENERATED",
            storage_reference=f"./storage/reports/{report_id}.pdf",
            verification_code=verification_code,
            report_sha256=report_sha256,
            qr_code_data=f"http://localhost:8000/api/v1/reports/verify/{verification_code}",
            created_by=user.id
        )
        db.add(report)
        db.commit()

        return {
            "case_id": case.case_id,
            "report_id": report.report_id,
            "verification_code": report.verification_code,
            "report_sha256": report.report_sha256
        }
    finally:
        db.close()


def test_valid_verification_by_report_id(setup_test_report):
    """Verifies that a court report is authenticated by report_id."""
    rep_id = setup_test_report["report_id"]
    response = client.get(f"/api/v1/reports/verify/{rep_id}", headers={"user-agent": "CourtRoom-Scanner/1.0"})
    assert response.status_code == 200

    data = response.json()
    assert data["verified"] is True
    assert data["report_id"] == rep_id
    assert data["official_report_sha256"] == setup_test_report["report_sha256"]
    assert data["integrity_status"] == "AUTHENTIC_AND_UNCOMPROMISED"
    assert data["compliance_framework"] == "BSA_2023_SEC_63_65B"
    assert data["case_id"] == setup_test_report["case_id"]
    assert "verification_id" in data
    assert data["verification_id"].startswith("VER-")


def test_valid_verification_by_verification_code(setup_test_report):
    """Verifies that a court report is authenticated by its unique verification_code."""
    code = setup_test_report["verification_code"]
    response = client.get(f"/api/reports/verify/{code}", headers={"user-agent": "PublicCitizenPortal/2.0"})
    assert response.status_code == 200

    data = response.json()
    assert data["verified"] is True
    assert data["report_id"] == setup_test_report["report_id"]
    assert data["verification_code"] == code
    assert data["integrity_status"] == "AUTHENTIC_AND_UNCOMPROMISED"


def test_verification_record_persisted_in_database(setup_test_report):
    """Verifies that every verification query writes a persistent VerificationRecord row."""
    rep_id = setup_test_report["report_id"]
    db = SessionLocal()
    try:
        records = (
            db.query(VerificationRecord)
            .filter_by(report_id=rep_id)
            .all()
        )
        assert len(records) >= 1
        record = records[-1]
        assert record.report_id == rep_id
        assert record.status == "VALID"
        assert record.verification_method == "QR_CODE"
        assert record.verification_id.startswith("VER-")
        assert record.timestamp is not None
    finally:
        db.close()


def test_audit_log_created_on_verification(setup_test_report):
    """Verifies that an immutable AuditLog entry is appended for verification."""
    rep_id = setup_test_report["report_id"]
    db = SessionLocal()
    try:
        logs = (
            db.query(AuditLog)
            .filter_by(resource_type="REPORT", resource_id=rep_id, action="REPORT_VERIFIED")
            .all()
        )
        assert len(logs) >= 1
        audit = logs[-1]
        assert audit.action == "REPORT_VERIFIED"
        assert audit.resource_id == rep_id
        assert audit.audit_id.startswith("AUD-")
        assert "verification_id" in audit.meta_data
    finally:
        db.close()


def test_safe_public_response_no_sensitive_leakage(setup_test_report):
    """Guarantees zero leakage of server secrets, passwords, tokens, or filesystem paths."""
    rep_id = setup_test_report["report_id"]
    response = client.get(f"/api/v1/reports/verify/{rep_id}")
    assert response.status_code == 200
    data = response.json()

    # Forbidden sensitive keys
    forbidden_keys = [
        "storage_reference",
        "pdf_path",
        "password",
        "hashed_password",
        "token",
        "access_token",
        "secret",
        "secret_key",
        "created_by",
        "database_url",
        "server_path"
    ]
    for key in forbidden_keys:
        assert key not in data, f"Sensitive key '{key}' leaked in public verification response!"

    # Ensure no internal filesystem paths appear in any string values
    for k, v in data.items():
        if isinstance(v, str):
            assert "storage/reports" not in v, f"Internal storage path leaked in key '{k}': {v}"
            assert "C:\\" not in v, f"Windows filesystem path leaked in key '{k}': {v}"
            assert "/var/" not in v, f"Server path leaked in key '{k}': {v}"


def test_invalid_verification_returns_404_and_logs_audit():
    """Verifies controlled 404 response on non-existent identifier and audit logging of failed attempt."""
    bogus_id = f"INVALID-{uuid.uuid4().hex[:10].upper()}"
    response = client.get(f"/api/v1/reports/verify/{bogus_id}")
    assert response.status_code == 404

    err_body = response.json()
    assert err_body["success"] is False
    assert err_body["status"] == 404
    assert "error" in err_body
    assert err_body["error"]["code"] == "REPORT_NOT_FOUND"

    # Verify that an audit record of the failed attempt was logged
    db = SessionLocal()
    try:
        failed_audits = (
            db.query(AuditLog)
            .filter_by(action="REPORT_VERIFICATION_FAILED", resource_id=bogus_id)
            .all()
        )
        assert len(failed_audits) >= 1
        fa = failed_audits[-1]
        assert fa.meta_data["status"] == "NOT_FOUND"
        assert fa.meta_data["attempted_identifier"] == bogus_id
    finally:
        db.close()


def test_dual_path_and_versioned_routing_compatibility(setup_test_report):
    """Verifies routing equivalence across /api/v1/reports/verify, /api/reports/verify, and /api/verification."""
    rep_id = setup_test_report["report_id"]

    res1 = client.get(f"/api/v1/reports/verify/{rep_id}")
    res2 = client.get(f"/api/reports/verify/{rep_id}")
    res3 = client.get(f"/api/verification/{rep_id}")

    assert res1.status_code == 200
    assert res2.status_code == 200
    assert res3.status_code == 200

    d1 = res1.json()
    d2 = res2.json()
    d3 = res3.json()

    assert d1["verified"] == d2["verified"] == d3["verified"] == True
    assert d1["report_id"] == d2["report_id"] == d3["report_id"] == rep_id
    assert d1["official_report_sha256"] == d2["official_report_sha256"] == d3["official_report_sha256"]


def test_verification_history_endpoint(setup_test_report):
    """Verifies retrieval of verification audit history for court report dockets."""
    rep_id = setup_test_report["report_id"]
    response = client.get(f"/api/v1/reports/{rep_id}/verifications")
    assert response.status_code == 200

    records = response.json()
    assert isinstance(records, list)
    assert len(records) >= 1
    first_record = records[0]
    assert first_record["report_id"] == rep_id
    assert first_record["status"] == "VALID"
    assert first_record["verification_method"] == "QR_CODE"
    assert "timestamp" in first_record
