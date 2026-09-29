"""
NYAYAI - Test Suite: Phase 14 Investigator Operational Case View
Module: tests.test_investigation_operational_view
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Comprehensive focused test suite verifying:
1. Populated case returns operational view.
2. No attention required when case has no unresolved issues (clean case).
3. Compromised evidence creates critical alert.
4. Storage error creates critical alert.
5. Broken custody creates critical alert.
6. Unanalyzed evidence creates pending actions.
7. Missing court report creates pending action when applicable.
8. Correlation red flag creates alert and pending action.
9. Tampered report verification creates alert.
10. attention_required becomes true when needed.
11. attention_required remains false when clean.
12. Unknown case returns 404.
13. RBAC is enforced for authorized roles and unauthenticated requests.
14. GET is read-only and does not mutate persisted data.
15. Alias /overview returns equivalent operational data.
"""

import os
import sys
import uuid
import json
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
    Report,
    VerificationRecord,
    AuditLog
)
from backend.app.core.security import create_access_token
from custody import CryptographicCustodyLedger, GENESIS_HASH

Base.metadata.create_all(bind=engine)
client = TestClient(app)


@pytest.fixture(scope="module")
def rbac_headers():
    """Generates valid JWT bearer headers for platform roles."""
    db = SessionLocal()
    try:
        def get_or_create(role_name: str) -> User:
            u = db.query(User).filter_by(role=role_name).first()
            if not u:
                u = User(
                    id=str(uuid.uuid4()),
                    username=f"test_p14_{role_name.lower()}_{uuid.uuid4().hex[:6]}",
                    email=f"{role_name.lower()}_{uuid.uuid4().hex[:6]}@nyayai.gov.in",
                    hashed_password="hashed_placeholder_p14",
                    role=role_name,
                    is_active=True
                )
                db.add(u)
                db.commit()
                db.refresh(u)
            return u

        inv = get_or_create("INVESTIGATOR")
        admin = get_or_create("ADMIN")
        lawyer = get_or_create("LAWYER")
        judge = get_or_create("JUDGE")
        auditor = get_or_create("AUDITOR")

        return {
            "INVESTIGATOR": {"Authorization": f"Bearer {create_access_token({'sub': inv.id, 'username': inv.username, 'role': 'INVESTIGATOR'})}"},
            "ADMIN": {"Authorization": f"Bearer {create_access_token({'sub': admin.id, 'username': admin.username, 'role': 'ADMIN'})}"},
            "LAWYER": {"Authorization": f"Bearer {create_access_token({'sub': lawyer.id, 'username': lawyer.username, 'role': 'LAWYER'})}"},
            "JUDGE": {"Authorization": f"Bearer {create_access_token({'sub': judge.id, 'username': judge.username, 'role': 'JUDGE'})}"},
            "AUDITOR": {"Authorization": f"Bearer {create_access_token({'sub': auditor.id, 'username': auditor.username, 'role': 'AUDITOR'})}"},
            "user_id": inv.id
        }
    finally:
        db.close()


@pytest.fixture(scope="module")
def clean_case_docket(rbac_headers):
    """
    Creates a completely resolved, clean case:
    - 1 evidence item
    - Valid forensic inspection (no anomalies)
    - Valid AI tamper screening (tamper_detected == False, risk_score == 0.05)
    - Valid intact custody chain
    - Court report generated
    - 0 red flags, 0 tampered verifications
    Should yield: attention_required == False, critical_alerts == [], pending_actions == []
    """
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    uid = rbac_headers["user_id"]
    suffix = uuid.uuid4().hex[:6].upper()

    case_id = f"CASE-P14-CLEAN-{suffix}"
    ev_id = f"EVD-P14-CLEAN-{suffix}"
    rep_id = f"REP-P14-CLEAN-{suffix}"

    try:
        case = Case(
            case_id=case_id,
            case_number=f"CR-2026-CLEAN-{suffix}",
            title="Clean Resolved Digital Evidence Case",
            description="Fully processed and verified case with all artifacts in order.",
            status="COMPLETED",
            jurisdiction="High Court of Delhi",
            created_by=uid,
            created_at=now,
            updated_at=now
        )
        db.add(case)

        evidence = Evidence(
            evidence_id=ev_id,
            case_id=case_id,
            original_filename="verified_cctv.png",
            stored_filename=f"{ev_id}_cctv.png",
            media_type="IMAGE",
            file_size=102400,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            storage_reference=f"./vault/{case_id}/{ev_id}.png",
            status="VERIFIED",
            uploaded_by=uid,
            source_description="CCTV Camera 1",
            created_at=now
        )
        db.add(evidence)

        meta = EvidenceMetadata(
            metadata_id=f"META-P14-CLEAN-{suffix}",
            evidence_id=ev_id,
            format_valid=True,
            magic_bytes="89504e470d0a1a0a",
            exif_data={},
            timestamps_metadata={"created": now.isoformat()},
            anomalies=[],
            created_at=now
        )
        db.add(meta)

        ai_res = AnalysisResult(
            analysis_id=f"AIR-P14-CLEAN-{suffix}",
            evidence_id=ev_id,
            analysis_type="TAMPER_DETECTION",
            status="COMPLETED",
            prediction="NO_TAMPER_INDICATIONS_DETECTED",
            confidence=0.95,
            risk_score=0.05,
            findings=["Baseline structural screening passed"],
            explanation="No pixel anomalies.",
            model_name="TamperScreener",
            model_version="0.1.0",
            created_at=now
        )
        db.add(ai_res)

        ledger = CryptographicCustodyLedger()
        b1 = ledger.create_event(
            evidence_id=ev_id,
            sequence_number=1,
            action="EVIDENCE_UPLOADED",
            actor_id=uid,
            details={"action": "EVIDENCE_UPLOADED"},
            previous_event_hash=GENESIS_HASH
        )
        c_evt = CustodyEvent(
            event_id=b1["event_id"],
            evidence_id=ev_id,
            sequence_number=1,
            event_type=b1["action"],
            user_id=uid,
            timestamp=b1["timestamp"],
            description="Vaulted",
            previous_hash=b1["previous_event_hash"],
            event_hash=b1["event_hash"],
            payload_json=json.dumps(b1["payload_json"])
        )
        db.add(c_evt)

        report = Report(
            report_id=rep_id,
            case_id=case_id,
            report_type="PDF",
            status="GENERATED",
            storage_reference=f"./reports/{rep_id}.pdf",
            verification_code=f"VERIFY-CLEAN-{suffix}",
            report_sha256=f"sha256_rep_clean_{suffix}",
            qr_code_data=f"http://localhost:8000/api/reports/verify/{rep_id}",
            created_by=uid,
            created_at=now
        )
        db.add(report)

        db.commit()
        return case_id
    finally:
        db.close()


@pytest.fixture(scope="module")
def multi_issue_case_docket(rbac_headers):
    """
    Creates a case with multiple operational issues:
    - 1 compromised evidence item (INTEGRITY_COMPROMISED)
    - 1 storage error evidence item (STORAGE_ERROR)
    - 1 unanalyzed evidence item (missing forensic & AI analysis)
    - 1 AI tamper detected item
    - 1 forensic anomaly item
    - 1 broken custody chain
    - 1 tampered report verification record
    """
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    uid = rbac_headers["user_id"]
    suffix = uuid.uuid4().hex[:6].upper()

    case_id = f"CASE-P14-MULTI-{suffix}"
    ev_comp = f"EVD-P14-COMP-{suffix}"
    ev_stor = f"EVD-P14-STOR-{suffix}"
    ev_unan = f"EVD-P14-UNAN-{suffix}"
    ev_anom = f"EVD-P14-ANOM-{suffix}"
    rep_id = f"REP-P14-MULTI-{suffix}"

    try:
        case = Case(
            case_id=case_id,
            case_number=f"CR-2026-MULTI-{suffix}",
            title="Multi-Alert Investigative Docket",
            description="Investigative case with various flagged operational issues.",
            status="UNDER_ANALYSIS",
            jurisdiction="High Court of Delhi",
            created_by=uid,
            created_at=now,
            updated_at=now
        )
        db.add(case)

        # 1. Compromised Evidence
        e1 = Evidence(
            evidence_id=ev_comp,
            case_id=case_id,
            original_filename="tampered_screenshot.png",
            stored_filename=f"{ev_comp}.png",
            media_type="IMAGE",
            file_size=50000,
            sha256_hash="comp_hash_1111",
            storage_reference=f"./vault/{case_id}/{ev_comp}.png",
            status="INTEGRITY_COMPROMISED",
            uploaded_by=uid,
            created_at=now
        )
        db.add(e1)

        # 2. Storage Error Evidence
        e2 = Evidence(
            evidence_id=ev_stor,
            case_id=case_id,
            original_filename="missing_audio.wav",
            stored_filename=f"{ev_stor}.wav",
            media_type="AUDIO",
            file_size=75000,
            sha256_hash="stor_hash_2222",
            storage_reference=f"./vault/{case_id}/{ev_stor}.wav",
            status="STORAGE_ERROR",
            uploaded_by=uid,
            created_at=now
        )
        db.add(e2)

        # 3. Unanalyzed Evidence (no forensic metadata, no AI result)
        e3 = Evidence(
            evidence_id=ev_unan,
            case_id=case_id,
            original_filename="fresh_doc.pdf",
            stored_filename=f"{ev_unan}.pdf",
            media_type="DOCUMENT",
            file_size=120000,
            sha256_hash="unan_hash_3333",
            storage_reference=f"./vault/{case_id}/{ev_unan}.pdf",
            status="SECURED",
            uploaded_by=uid,
            created_at=now
        )
        db.add(e3)

        # 4. Evidence with Forensic Anomaly & AI Tamper Detection
        e4 = Evidence(
            evidence_id=ev_anom,
            case_id=case_id,
            original_filename="anomalous_frame.jpg",
            stored_filename=f"{ev_anom}.jpg",
            media_type="IMAGE",
            file_size=80000,
            sha256_hash="anom_hash_4444",
            storage_reference=f"./vault/{case_id}/{ev_anom}.jpg",
            status="VERIFIED",
            uploaded_by=uid,
            created_at=now
        )
        db.add(e4)

        # Forensic anomaly record
        meta_anom = EvidenceMetadata(
            metadata_id=f"META-ANOM-{suffix}",
            evidence_id=ev_anom,
            format_valid=False,
            magic_bytes="000000",
            anomalies=["Invalid JPEG header marker", "Corrupted SOF0 chunk"],
            created_at=now
        )
        db.add(meta_anom)

        # AI tamper detected record
        ai_tamper = AnalysisResult(
            analysis_id=f"AIR-TAMPER-{suffix}",
            evidence_id=ev_anom,
            analysis_type="TAMPER_DETECTION",
            status="COMPLETED",
            prediction="TAMPER_DETECTED",
            confidence=0.88,
            risk_score=0.85,
            findings=["Copy-move splicing detected in quadrant 2"],
            model_name="TamperScreener",
            model_version="0.1.0",
            created_at=now
        )
        db.add(ai_tamper)

        # Broken custody chain on e1
        c_broken = CustodyEvent(
            event_id=f"EVT-BROKEN-{suffix}",
            evidence_id=ev_comp,
            sequence_number=1,
            event_type="EVIDENCE_UPLOADED",
            user_id=uid,
            timestamp=now.isoformat(),
            description="Invalid hash event",
            previous_hash="0" * 64,
            event_hash=f"corrupted_hash_{suffix}",
            payload_json=json.dumps({"action": "EVIDENCE_UPLOADED"})
        )
        db.add(c_broken)

        # Report with tampered verification
        rep = Report(
            report_id=rep_id,
            case_id=case_id,
            report_type="PDF",
            status="GENERATED",
            storage_reference=f"./reports/{rep_id}.pdf",
            verification_code=f"VERIFY-MULTI-{suffix}",
            report_sha256=f"sha256_rep_multi_{suffix}",
            created_by=uid,
            created_at=now
        )
        db.add(rep)

        ver_tampered = VerificationRecord(
            verification_id=f"VER-TAMP-{suffix}",
            report_id=rep_id,
            verification_method="QR_CODE",
            verifier_identifier="PUBLIC_GATEWAY",
            status="TAMPER_DETECTED",
            ip_address="127.0.0.1",
            timestamp=now
        )
        db.add(ver_tampered)

        db.commit()
        return case_id
    finally:
        db.close()


# =============================================================================
# TESTS
# =============================================================================

def test_populated_case_returns_operational_view(multi_issue_case_docket, rbac_headers):
    """1. Populated case returns 200 OK and validates full OperationalCaseViewResponse schema."""
    case_id = multi_issue_case_docket
    headers = rbac_headers["INVESTIGATOR"]

    res = client.get(f"/api/cases/{case_id}/operational-view", headers=headers)
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["success"] is True
    assert data["case_id"] == case_id
    assert "critical_alerts" in data
    assert "pending_actions" in data
    assert "findings_summary" in data
    assert "summary_metrics" in data
    assert "intelligence_summary" in data


def test_no_attention_when_case_clean(clean_case_docket, rbac_headers):
    """2 & 11. Clean resolved case returns attention_required == False and empty alert/action queues."""
    case_id = clean_case_docket
    headers = rbac_headers["INVESTIGATOR"]

    res = client.get(f"/api/cases/{case_id}/operational-view", headers=headers)
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["attention_required"] is False
    assert len(data["critical_alerts"]) == 0
    assert len(data["pending_actions"]) == 0


def test_compromised_evidence_creates_alert(multi_issue_case_docket, rbac_headers):
    """3. Compromised evidence produces an alert with type INTEGRITY_COMPROMISED and severity HIGH."""
    case_id = multi_issue_case_docket
    headers = rbac_headers["INVESTIGATOR"]

    res = client.get(f"/api/cases/{case_id}/operational-view", headers=headers)
    assert res.status_code == 200
    data = res.json()

    comp_alerts = [a for a in data["critical_alerts"] if a["alert_type"] == "INTEGRITY_COMPROMISED"]
    assert len(comp_alerts) >= 1
    assert comp_alerts[0]["severity"] == "HIGH"


def test_storage_error_creates_alert(multi_issue_case_docket, rbac_headers):
    """4. Evidence storage error produces an alert with type STORAGE_ERROR and severity MEDIUM."""
    case_id = multi_issue_case_docket
    headers = rbac_headers["INVESTIGATOR"]

    res = client.get(f"/api/cases/{case_id}/operational-view", headers=headers)
    assert res.status_code == 200
    data = res.json()

    stor_alerts = [a for a in data["critical_alerts"] if a["alert_type"] == "STORAGE_ERROR"]
    assert len(stor_alerts) >= 1
    assert stor_alerts[0]["severity"] == "MEDIUM"


def test_broken_custody_creates_alert(multi_issue_case_docket, rbac_headers):
    """5. Broken custody chain produces an alert with type BROKEN_CUSTODY_CHAIN and severity HIGH."""
    case_id = multi_issue_case_docket
    headers = rbac_headers["INVESTIGATOR"]

    res = client.get(f"/api/cases/{case_id}/operational-view", headers=headers)
    assert res.status_code == 200
    data = res.json()

    cust_alerts = [a for a in data["critical_alerts"] if a["alert_type"] == "BROKEN_CUSTODY_CHAIN"]
    assert len(cust_alerts) >= 1
    assert cust_alerts[0]["severity"] == "HIGH"


def test_unanalyzed_evidence_creates_pending_action(multi_issue_case_docket, rbac_headers):
    """6. Unanalyzed evidence produces PENDING_FORENSIC_ANALYSIS and PENDING_AI_ANALYSIS actions."""
    case_id = multi_issue_case_docket
    headers = rbac_headers["INVESTIGATOR"]

    res = client.get(f"/api/cases/{case_id}/operational-view", headers=headers)
    assert res.status_code == 200
    data = res.json()

    pending_types = [a["action_type"] for a in data["pending_actions"]]
    assert "PENDING_FORENSIC_ANALYSIS" in pending_types
    assert "PENDING_AI_ANALYSIS" in pending_types


def test_missing_court_report_creates_pending_action(rbac_headers):
    """7. Case with intact evidence but 0 generated reports creates GENERATE_COURT_REPORT action."""
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    uid = rbac_headers["user_id"]
    suffix = uuid.uuid4().hex[:6].upper()
    case_id = f"CASE-P14-NOREP-{suffix}"
    ev_id = f"EVD-P14-NOREP-{suffix}"

    try:
        case = Case(
            case_id=case_id,
            case_number=f"CR-2026-NOREP-{suffix}",
            title="Case Pending Report Issuance",
            description="All evidence is intact, awaiting BSA 2023 certificate generation.",
            status="UNDER_ANALYSIS",
            jurisdiction="High Court of Delhi",
            created_by=uid,
            created_at=now,
            updated_at=now
        )
        db.add(case)

        evidence = Evidence(
            evidence_id=ev_id,
            case_id=case_id,
            original_filename="intact_document.pdf",
            stored_filename=f"{ev_id}.pdf",
            media_type="DOCUMENT",
            file_size=60000,
            sha256_hash="intact_doc_hash_5555",
            storage_reference=f"./vault/{case_id}/{ev_id}.pdf",
            status="VERIFIED",
            uploaded_by=uid,
            created_at=now
        )
        db.add(evidence)

        ledger = CryptographicCustodyLedger()
        b1 = ledger.create_event(
            evidence_id=ev_id,
            sequence_number=1,
            action="EVIDENCE_UPLOADED",
            actor_id=uid,
            details={"action": "EVIDENCE_UPLOADED"},
            previous_event_hash=GENESIS_HASH
        )
        c_evt = CustodyEvent(
            event_id=b1["event_id"],
            evidence_id=ev_id,
            sequence_number=1,
            event_type=b1["action"],
            user_id=uid,
            timestamp=b1["timestamp"],
            description="Vaulted",
            previous_hash=b1["previous_event_hash"],
            event_hash=b1["event_hash"],
            payload_json=json.dumps(b1["payload_json"])
        )
        db.add(c_evt)
        db.commit()
    finally:
        db.close()

    headers = rbac_headers["INVESTIGATOR"]
    res = client.get(f"/api/cases/{case_id}/operational-view", headers=headers)
    assert res.status_code == 200
    data = res.json()

    action_types = [a["action_type"] for a in data["pending_actions"]]
    assert "GENERATE_COURT_REPORT" in action_types


def test_correlation_red_flag_creates_alert_and_action(multi_issue_case_docket, rbac_headers):
    """8. Correlation red flags produce CORRELATION_RED_FLAG alert and REVIEW_CORRELATION_RED_FLAGS action."""
    case_id = multi_issue_case_docket
    headers = rbac_headers["INVESTIGATOR"]

    res = client.get(f"/api/cases/{case_id}/operational-view", headers=headers)
    assert res.status_code == 200
    data = res.json()

    alert_types = [a["alert_type"] for a in data["critical_alerts"]]
    action_types = [a["action_type"] for a in data["pending_actions"]]

    assert "CORRELATION_RED_FLAG" in alert_types
    assert "REVIEW_CORRELATION_RED_FLAGS" in action_types


def test_tampered_report_verification_alert(multi_issue_case_docket, rbac_headers):
    """9. Tampered report verification history produces TAMPERED_REPORT_VERIFICATION alert."""
    case_id = multi_issue_case_docket
    headers = rbac_headers["INVESTIGATOR"]

    res = client.get(f"/api/cases/{case_id}/operational-view", headers=headers)
    assert res.status_code == 200
    data = res.json()

    tamp_alerts = [a for a in data["critical_alerts"] if a["alert_type"] == "TAMPERED_REPORT_VERIFICATION"]
    assert len(tamp_alerts) >= 1
    assert tamp_alerts[0]["severity"] == "HIGH"


def test_attention_required_becomes_true_when_needed(multi_issue_case_docket, rbac_headers):
    """10. attention_required is True when critical alerts or pending actions exist."""
    case_id = multi_issue_case_docket
    headers = rbac_headers["INVESTIGATOR"]

    res = client.get(f"/api/cases/{case_id}/operational-view", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["attention_required"] is True
    assert len(data["critical_alerts"]) > 0 or len(data["pending_actions"]) > 0


def test_attention_required_remains_false_when_clean(clean_case_docket, rbac_headers):
    """11. attention_required remains False when case is completely clean."""
    case_id = clean_case_docket
    headers = rbac_headers["INVESTIGATOR"]

    res = client.get(f"/api/cases/{case_id}/operational-view", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["attention_required"] is False
    assert len(data["critical_alerts"]) == 0
    assert len(data["pending_actions"]) == 0


def test_unknown_case_returns_404(rbac_headers):
    """12. Unknown case_id returns 404 Not Found."""
    headers = rbac_headers["INVESTIGATOR"]
    res = client.get("/api/cases/NON_EXISTENT_CASE_9999/operational-view", headers=headers)
    assert res.status_code == 404


def test_rbac_is_enforced(multi_issue_case_docket, rbac_headers):
    """13. Authorized roles can access operational view; unauthenticated request receives 401/403."""
    case_id = multi_issue_case_docket

    for role in ["INVESTIGATOR", "ADMIN", "LAWYER", "JUDGE", "AUDITOR"]:
        resp = client.get(f"/api/cases/{case_id}/operational-view", headers=rbac_headers[role])
        assert resp.status_code == 200, f"Role {role} failed with {resp.status_code}"

    # Unauthenticated request
    resp_no_auth = client.get(f"/api/cases/{case_id}/operational-view")
    assert resp_no_auth.status_code in (401, 403)



def test_operational_view_is_read_only(multi_issue_case_docket, rbac_headers):
    """14. GET request is strictly read-only and causes zero database mutations."""
    case_id = multi_issue_case_docket
    headers = rbac_headers["INVESTIGATOR"]

    db = SessionLocal()
    try:
        cases_before = db.query(Case).count()
        ev_before = db.query(Evidence).count()
        cust_before = db.query(CustodyEvent).count()
        rep_before = db.query(Report).count()
        ver_before = db.query(VerificationRecord).count()
        aud_before = db.query(AuditLog).count()
    finally:
        db.close()

    # Query 3 times
    for _ in range(3):
        res = client.get(f"/api/cases/{case_id}/operational-view", headers=headers)
        assert res.status_code == 200

    db = SessionLocal()
    try:
        cases_after = db.query(Case).count()
        ev_after = db.query(Evidence).count()
        cust_after = db.query(CustodyEvent).count()
        rep_after = db.query(Report).count()
        ver_after = db.query(VerificationRecord).count()
        aud_after = db.query(AuditLog).count()
    finally:
        db.close()

    assert cases_before == cases_after
    assert ev_before == ev_after
    assert cust_before == cust_after
    assert rep_before == rep_after
    assert ver_before == ver_after
    assert aud_before == aud_after


def test_operational_view_alias_endpoint(multi_issue_case_docket, rbac_headers):
    """15. Alias endpoint /api/cases/{case_id}/overview returns equivalent operational data."""
    case_id = multi_issue_case_docket
    headers = rbac_headers["INVESTIGATOR"]

    res_canonical = client.get(f"/api/cases/{case_id}/operational-view", headers=headers)
    res_alias = client.get(f"/api/cases/{case_id}/overview", headers=headers)

    assert res_canonical.status_code == 200
    assert res_alias.status_code == 200

    data_canon = res_canonical.json()
    data_alias = res_alias.json()

    assert data_canon["case_id"] == data_alias["case_id"]
    assert data_canon["case_number"] == data_alias["case_number"]
    assert data_canon["overall_status"] == data_alias["overall_status"]
    assert data_canon["attention_required"] == data_alias["attention_required"]
    assert data_canon["findings_summary"] == data_alias["findings_summary"]
    assert data_canon["summary_metrics"] == data_alias["summary_metrics"]
    assert len(data_canon["critical_alerts"]) == len(data_alias["critical_alerts"])
    assert len(data_canon["pending_actions"]) == len(data_alias["pending_actions"])
    assert [a["alert_type"] for a in data_canon["critical_alerts"]] == [a["alert_type"] for a in data_alias["critical_alerts"]]
    assert [p["action_type"] for p in data_canon["pending_actions"]] == [p["action_type"] for p in data_alias["pending_actions"]]
    assert data_canon["intelligence_summary"]["case"] == data_alias["intelligence_summary"]["case"]

