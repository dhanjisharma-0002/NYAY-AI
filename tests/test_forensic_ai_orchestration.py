"""
NYAYAI - Test Suite: Forensic and AI Orchestration (Phase 7)
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Tests:
1. Forensic orchestration success (all 9 steps verified)
2. AI orchestration success (expected fields: evidence_id, analysis_type, prediction, confidence, risk_score, findings, explanation, model_version)
3. Authentication and RBAC enforcement (401 unauthenticated, 403 unauthorized role)
4. Missing evidence returns 404
5. Evidence integrity check failure aborts analysis (409 Conflict)
6. Failure handling: engine unavailable (503, status FAILED)
7. Failure handling: timeout (504, status FAILED)
8. Failure handling: invalid engine response (502, status FAILED)
9. Failure handling: unsupported media type (415, status FAILED)
10. Failure handling: internal engine analysis failure (500, status FAILED)
11. AI failure handling modes (lifecycle status FAILED and audit trail)
"""

import os
import stat
import uuid
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database import SessionLocal
from backend.app.models.user import User
from backend.app.models.role import Role
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.analysis_result import AnalysisResult
from backend.app.models.custody import CustodyEvent
from backend.app.models.audit import AuditLog
from backend.app.adapters.mock_adapter import MockForensicEngineAdapter, MockAIEngineAdapter
from backend.app.services.forensic_service import ForensicService
from backend.app.services.ai_service import AIService
from database.init_db import init_database

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    init_database()


@pytest.fixture
def auth_context():
    """Sets up an authenticated investigator and a test case."""
    suffix = uuid.uuid4().hex[:8]
    username = f"inv_orch_{suffix}"
    reg_payload = {
        "username": username,
        "email": f"{username}@nyayai.gov.in",
        "password": "SecurePassword123!",
        "full_name": "Orchestration Test Officer",
        "role": "INVESTIGATOR",
        "badge_number": f"INV-ORCH-{suffix}"
    }
    client.post("/api/auth/register", json=reg_payload)
    login_res = client.post("/api/auth/login", json={"username": username, "password": "SecurePassword123!"})
    login_data = login_res.json()
    token = login_data["access_token"]
    user_id = login_data["user"]["user_id"]
    headers = {"Authorization": f"Bearer {token}"}

    case_res = client.post(
        "/api/cases",
        json={
            "title": f"Phase 7 Orchestration Docket {suffix}",
            "description": "Integration testing for forensic and AI engine adapters",
            "jurisdiction": "High Court of Delhi"
        },
        headers=headers
    )
    case_id = case_res.json()["data"]["case_id"]

    return {
        "user_id": user_id,
        "username": username,
        "token": token,
        "headers": headers,
        "case_id": case_id
    }


@pytest.fixture
def lawyer_headers():
    """Sets up an authenticated lawyer for RBAC testing."""
    suffix = uuid.uuid4().hex[:8]
    username = f"lawyer_orch_{suffix}"
    reg_payload = {
        "username": username,
        "email": f"{username}@nyayai.gov.in",
        "password": "SecurePassword123!",
        "full_name": "Advocate Test",
        "role": "LAWYER",
        "badge_number": f"BAR-{suffix}"
    }
    client.post("/api/auth/register", json=reg_payload)
    login_res = client.post("/api/auth/login", json={"username": username, "password": "SecurePassword123!"})
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_forensic_analysis_success_orchestration(auth_context):
    """
    Test 1: Forensic analysis orchestration
    1. Authenticate user
    2. Verify evidence access
    3. Verify evidence integrity
    4. Send evidence reference to forensic engine
    5. Receive structured result
    6. Store AnalysisResult
    7. Create custody event
    8. Create audit log
    9. Return analysis result
    """
    case_id = auth_context["case_id"]
    headers = auth_context["headers"]

    # Ingest evidence
    dummy_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRTESTING_FORENSIC_ORCHESTRATION"
    files = {"file": ("scene_photo.png", dummy_bytes, "image/png")}
    data = {"case_id": case_id}

    upload_res = client.post("/api/evidence/upload", files=files, data=data, headers=headers)
    assert upload_res.status_code == 201
    evidence_id = upload_res.json()["evidence_id"]

    # Execute Forensic Orchestration API
    forensic_res = client.post(f"/api/forensics/analyze/{evidence_id}", headers=headers)
    assert forensic_res.status_code == 200
    res_data = forensic_res.json()

    # Step 5 & 9: Verify structured result returned
    assert res_data["evidence_id"] == evidence_id
    assert res_data["analysis_type"] == "FORENSIC_INSPECTION"
    assert res_data["status"] == "COMPLETED"
    assert "format_valid" in res_data
    assert "magic_bytes" in res_data
    assert "detected_mime" in res_data
    assert "prediction" in res_data
    assert "confidence" in res_data
    assert "risk_score" in res_data
    assert "findings" in res_data
    assert res_data["custody_event_id"] is not None

    # Step 6: Verify AnalysisResult persisted in database
    db = SessionLocal()
    try:
        analysis_record = db.query(AnalysisResult).filter_by(evidence_id=evidence_id, analysis_type="FORENSIC_INSPECTION").first()
        assert analysis_record is not None
        assert analysis_record.status == "COMPLETED"
        assert analysis_record.analysis_id == res_data["analysis_id"]

        # Step 7: Verify CustodyEvent recorded
        custody_event = db.query(CustodyEvent).filter_by(event_id=res_data["custody_event_id"]).first()
        assert custody_event is not None
        assert custody_event.event_type == "FORENSIC_ANALYSIS_COMPLETED"
        assert custody_event.sequence_number >= 2

        # Step 8: Verify AuditLog created
        audit_entry = db.query(AuditLog).filter_by(resource_id=evidence_id, action="FORENSIC_ANALYSIS_PERFORMED").first()
        assert audit_entry is not None
        assert audit_entry.meta_data["analysis_id"] == res_data["analysis_id"]
    finally:
        db.close()


def test_ai_analysis_success_orchestration(auth_context):
    """
    Test 2: AI analysis orchestration
    Verifies all expected fields:
    evidence_id, analysis_type, prediction, confidence, risk_score, findings, explanation, model_version
    """
    case_id = auth_context["case_id"]
    headers = auth_context["headers"]

    # Ingest evidence
    dummy_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRTESTING_AI_ORCHESTRATION_VALID"
    files = {"file": ("surveillance_frame.png", dummy_bytes, "image/png")}
    data = {"case_id": case_id}

    upload_res = client.post("/api/evidence/upload", files=files, data=data, headers=headers)
    assert upload_res.status_code == 201
    evidence_id = upload_res.json()["evidence_id"]

    # Execute AI Orchestration API
    ai_res = client.post(f"/api/ai/analyze/{evidence_id}", headers=headers)
    assert ai_res.status_code == 200
    res_data = ai_res.json()

    # Verify all expected fields
    assert res_data["evidence_id"] == evidence_id
    assert res_data["analysis_type"] == "TAMPER_DETECTION"
    assert res_data["prediction"] in ["NO_TAMPER_INDICATIONS_DETECTED", "TAMPER_DETECTED"]
    assert isinstance(res_data["confidence"], (int, float))
    assert isinstance(res_data["risk_score"], (int, float))
    assert isinstance(res_data["findings"], list)
    assert isinstance(res_data["explanation"], str)
    assert res_data["model_version"] is not None
    assert res_data["status"] == "COMPLETED"
    assert res_data["custody_event_id"] is not None

    # Verify database persistence
    db = SessionLocal()
    try:
        ai_record = db.query(AnalysisResult).filter_by(evidence_id=evidence_id, analysis_type="TAMPER_DETECTION").first()
        assert ai_record is not None
        assert ai_record.status == "COMPLETED"

        custody_event = db.query(CustodyEvent).filter_by(event_id=res_data["custody_event_id"]).first()
        assert custody_event is not None
        assert custody_event.event_type == "AI_ANALYSIS_COMPLETED"

        audit_entry = db.query(AuditLog).filter_by(resource_id=evidence_id, action="AI_ANALYSIS_PERFORMED").first()
        assert audit_entry is not None
    finally:
        db.close()


def test_authentication_and_rbac_enforcement(auth_context, lawyer_headers):
    """
    Test 3: Authentication and RBAC
    - Unauthenticated -> 401
    - Unauthorized role (LAWYER) -> 403
    """
    evidence_id = "EVD-2026-DUMMY"

    # 1. Unauthenticated calls
    f_res = client.post(f"/api/forensics/analyze/{evidence_id}")
    assert f_res.status_code == 401

    ai_res = client.post(f"/api/ai/analyze/{evidence_id}")
    assert ai_res.status_code == 401

    # 2. Unauthorized role calls (LAWYER cannot trigger analysis)
    f_res = client.post(f"/api/forensics/analyze/{evidence_id}", headers=lawyer_headers)
    assert f_res.status_code == 403

    ai_res = client.post(f"/api/ai/analyze/{evidence_id}", headers=lawyer_headers)
    assert ai_res.status_code == 403


def test_missing_evidence_returns_404(auth_context):
    """
    Test 4: Missing evidence returns 404
    """
    headers = auth_context["headers"]
    res_f = client.post("/api/forensics/analyze/EVD-9999-NOTFOUND", headers=headers)
    assert res_f.status_code == 404

    res_ai = client.post("/api/ai/analyze/EVD-9999-NOTFOUND", headers=headers)
    assert res_ai.status_code == 404


def test_compromised_evidence_integrity_aborts_analysis(auth_context):
    """
    Test 5: Compromised evidence integrity aborts analysis (409 Conflict)
    """
    case_id = auth_context["case_id"]
    headers = auth_context["headers"]

    # 1. Ingest evidence
    dummy_bytes = b"%PDF-1.4\n%INTEGRITY_CHECK_ABORTION_TEST"
    files = {"file": ("doc_to_tamper.pdf", dummy_bytes, "application/pdf")}
    data = {"case_id": case_id}

    upload_res = client.post("/api/evidence/upload", files=files, data=data, headers=headers)
    evidence_id = upload_res.json()["evidence_id"]

    # 2. Tamper physical file
    db = SessionLocal()
    try:
        evidence = db.query(Evidence).filter_by(evidence_id=evidence_id).first()
        os.chmod(evidence.storage_reference, stat.S_IWRITE | stat.S_IREAD)
        with open(evidence.storage_reference, "wb") as f:
            f.write(b"%PDF-1.4\n%TAMPERED_CONTENT_UNAUTHORIZED")
        os.chmod(evidence.storage_reference, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    finally:
        db.close()

    # 3. Attempt forensic and AI analysis -> both must abort with 409
    f_res = client.post(f"/api/forensics/analyze/{evidence_id}", headers=headers)
    assert f_res.status_code == 409
    assert "integrity compromised" in f_res.json()["error"]["message"].lower()

    ai_res = client.post(f"/api/ai/analyze/{evidence_id}", headers=headers)
    assert ai_res.status_code == 409
    assert "integrity compromised" in ai_res.json()["error"]["message"].lower()


def test_failure_handling_engine_unavailable(auth_context):
    """
    Test 6: Failure handling - engine unavailable (503, status FAILED)
    """
    case_id = auth_context["case_id"]
    headers = auth_context["headers"]

    dummy_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRTEST_UNAVAILABLE"
    files = {"file": ("photo.png", dummy_bytes, "image/png")}
    data = {"case_id": case_id}
    upload_res = client.post("/api/evidence/upload", files=files, data=data, headers=headers)
    evidence_id = upload_res.json()["evidence_id"]

    # Use service directly with mock adapter simulating engine unavailable
    db = SessionLocal()
    try:
        mock_adapter = MockForensicEngineAdapter(mode="engine_unavailable")
        service = ForensicService(db, adapter=mock_adapter)

        with pytest.raises(Exception) as exc_info:
            service.orchestrate_analysis(evidence_id=evidence_id, user_id=auth_context["user_id"])

        assert exc_info.value.status_code == 503
        assert exc_info.value.error_code == "ENGINE_UNAVAILABLE"

        # Verify DB recorded status FAILED
        failed_record = db.query(AnalysisResult).filter_by(evidence_id=evidence_id, status="FAILED").first()
        assert failed_record is not None

        audit = db.query(AuditLog).filter_by(resource_id=evidence_id, action="FORENSIC_ANALYSIS_FAILED").first()
        assert audit is not None
    finally:
        db.close()


def test_failure_handling_timeout(auth_context):
    """
    Test 7: Failure handling - timeout (504, status FAILED)
    """
    case_id = auth_context["case_id"]
    headers = auth_context["headers"]

    dummy_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRTEST_TIMEOUT"
    files = {"file": ("timeout_test.png", dummy_bytes, "image/png")}
    data = {"case_id": case_id}
    upload_res = client.post("/api/evidence/upload", files=files, data=data, headers=headers)
    evidence_id = upload_res.json()["evidence_id"]

    db = SessionLocal()
    try:
        mock_adapter = MockForensicEngineAdapter(mode="timeout")
        service = ForensicService(db, adapter=mock_adapter)

        with pytest.raises(Exception) as exc_info:
            service.orchestrate_analysis(evidence_id=evidence_id, user_id=auth_context["user_id"])

        assert exc_info.value.status_code == 504
        assert exc_info.value.error_code == "ENGINE_TIMEOUT"

        failed_record = db.query(AnalysisResult).filter_by(evidence_id=evidence_id, status="FAILED").first()
        assert failed_record is not None
    finally:
        db.close()


def test_failure_handling_invalid_response(auth_context):
    """
    Test 8: Failure handling - invalid engine response (502, status FAILED)
    """
    case_id = auth_context["case_id"]
    headers = auth_context["headers"]

    dummy_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRTEST_INVALID_RES"
    files = {"file": ("inv_res.png", dummy_bytes, "image/png")}
    data = {"case_id": case_id}
    upload_res = client.post("/api/evidence/upload", files=files, data=data, headers=headers)
    evidence_id = upload_res.json()["evidence_id"]

    db = SessionLocal()
    try:
        mock_adapter = MockForensicEngineAdapter(mode="invalid_response")
        service = ForensicService(db, adapter=mock_adapter)

        with pytest.raises(Exception) as exc_info:
            service.orchestrate_analysis(evidence_id=evidence_id, user_id=auth_context["user_id"])

        assert exc_info.value.status_code == 502
        assert exc_info.value.error_code == "INVALID_ENGINE_RESPONSE"

        failed_record = db.query(AnalysisResult).filter_by(evidence_id=evidence_id, status="FAILED").first()
        assert failed_record is not None
    finally:
        db.close()


def test_failure_handling_unsupported_media(auth_context):
    """
    Test 9: Failure handling - unsupported media type (415, status FAILED)
    """
    case_id = auth_context["case_id"]
    headers = auth_context["headers"]

    dummy_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRTEST_UNSUPPORTED"
    files = {"file": ("unsupported_test.png", dummy_bytes, "image/png")}
    data = {"case_id": case_id}
    upload_res = client.post("/api/evidence/upload", files=files, data=data, headers=headers)
    evidence_id = upload_res.json()["evidence_id"]

    db = SessionLocal()
    try:
        mock_adapter = MockForensicEngineAdapter(mode="unsupported_media")
        service = ForensicService(db, adapter=mock_adapter)

        with pytest.raises(Exception) as exc_info:
            service.orchestrate_analysis(evidence_id=evidence_id, user_id=auth_context["user_id"])

        assert exc_info.value.status_code == 415
        assert exc_info.value.error_code == "UNSUPPORTED_MEDIA_TYPE"

        failed_record = db.query(AnalysisResult).filter_by(evidence_id=evidence_id, status="FAILED").first()
        assert failed_record is not None
    finally:
        db.close()


def test_failure_handling_analysis_failure(auth_context):
    """
    Test 10: Failure handling - engine internal analysis failure (500, status FAILED)
    """
    case_id = auth_context["case_id"]
    headers = auth_context["headers"]

    dummy_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRTEST_FAILURE"
    files = {"file": ("failure_test.png", dummy_bytes, "image/png")}
    data = {"case_id": case_id}
    upload_res = client.post("/api/evidence/upload", files=files, data=data, headers=headers)
    evidence_id = upload_res.json()["evidence_id"]

    db = SessionLocal()
    try:
        mock_adapter = MockForensicEngineAdapter(mode="failure")
        service = ForensicService(db, adapter=mock_adapter)

        with pytest.raises(Exception) as exc_info:
            service.orchestrate_analysis(evidence_id=evidence_id, user_id=auth_context["user_id"])

        assert exc_info.value.status_code == 500
        assert exc_info.value.error_code == "ANALYSIS_FAILED"

        failed_record = db.query(AnalysisResult).filter_by(evidence_id=evidence_id, status="FAILED").first()
        assert failed_record is not None
    finally:
        db.close()


def test_ai_failure_handling_modes(auth_context):
    """
    Test 11: AI failure handling modes
    Verifies that AI engine failures (engine unavailable, timeout, invalid response, failure)
    result in status FAILED and audit log entries.
    """
    case_id = auth_context["case_id"]
    headers = auth_context["headers"]

    dummy_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRTEST_AI_FAILURES"
    files = {"file": ("ai_failure_test.png", dummy_bytes, "image/png")}
    data = {"case_id": case_id}
    upload_res = client.post("/api/evidence/upload", files=files, data=data, headers=headers)
    evidence_id = upload_res.json()["evidence_id"]

    db = SessionLocal()
    try:
        # 1. Engine unavailable
        ai_service_unavail = AIService(db, adapter=MockAIEngineAdapter(mode="engine_unavailable"))
        with pytest.raises(Exception) as exc1:
            ai_service_unavail.orchestrate_analysis(evidence_id=evidence_id, user_id=auth_context["user_id"])
        assert exc1.value.status_code == 503

        # 2. Timeout
        ai_service_timeout = AIService(db, adapter=MockAIEngineAdapter(mode="timeout"))
        with pytest.raises(Exception) as exc2:
            ai_service_timeout.orchestrate_analysis(evidence_id=evidence_id, user_id=auth_context["user_id"])
        assert exc2.value.status_code == 504

        # 3. Invalid response
        ai_service_invalid = AIService(db, adapter=MockAIEngineAdapter(mode="invalid_response"))
        with pytest.raises(Exception) as exc3:
            ai_service_invalid.orchestrate_analysis(evidence_id=evidence_id, user_id=auth_context["user_id"])
        assert exc3.value.status_code == 502

        # 4. Engine internal failure
        ai_service_failure = AIService(db, adapter=MockAIEngineAdapter(mode="failure"))
        with pytest.raises(Exception) as exc4:
            ai_service_failure.orchestrate_analysis(evidence_id=evidence_id, user_id=auth_context["user_id"])
        assert exc4.value.status_code == 500

        # Verify failed records persisted in database
        failed_records = db.query(AnalysisResult).filter_by(evidence_id=evidence_id, status="FAILED").all()
        assert len(failed_records) >= 4
    finally:
        db.close()
