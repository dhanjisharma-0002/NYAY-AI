"""
NYAYAI - Test Suite: Phase 13 Case & Evidence Intelligence Summary
Module: tests.test_case_intelligence_summary
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Comprehensive focused test suite verifying:
1. Populated case returns 200 OK and all 12 intelligence summary sections.
2. Empty case returns 200 OK, zeroed metrics, and deterministic 'NO_EVIDENCE' status.
3. Compromised case returns 'INTEGRITY_COMPROMISED' status.
4. Non-existent case returns 404 (CASE_NOT_FOUND).
5. RBAC enforcement (INVESTIGATOR, ADMIN, LAWYER, JUDGE, AUDITOR allowed; unauthenticated 401).
6. Read-only guarantee: summary retrieval never mutates database state.
7. Alias route /api/cases/{case_id}/summary returns identical data.
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
                    username=f"test_p13_{role_name.lower()}_{uuid.uuid4().hex[:6]}",
                    email=f"{role_name.lower()}_{uuid.uuid4().hex[:6]}@nyayai.gov.in",
                    hashed_password="hashed_placeholder_p13",
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
def populated_case_docket(rbac_headers):
    """Creates a fully populated case with evidence, metadata, analysis, custody, report, verification, and audit records."""
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    uid = rbac_headers["user_id"]
    suffix = uuid.uuid4().hex[:6].upper()

    case_id = f"CASE-P13-POP-{suffix}"
    ev_id = f"EVD-P13-POP-{suffix}"
    rep_id = f"REP-P13-POP-{suffix}"
    ver_id = f"VER-P13-POP-{suffix}"
    aud_id = f"AUD-P13-POP-{suffix}"

    try:
        # 1. Case
        case = Case(
            case_id=case_id,
            case_number=f"CR-2026-P13-{suffix}",
            title="State vs. Digital Extortion Syndicate",
            description="High-profile electronic evidence admissibility docket.",
            status="UNDER_ANALYSIS",
            jurisdiction="High Court of Delhi",
            created_by=uid,
            created_at=now,
            updated_at=now
        )
        db.add(case)

        # 2. Evidence
        evidence = Evidence(
            evidence_id=ev_id,
            case_id=case_id,
            original_filename="cctv_extortion_frame.png",
            stored_filename=f"{ev_id}_cctv.png",
            media_type="IMAGE",
            file_size=102400,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            storage_reference=f"./vault/{case_id}/{ev_id}.png",
            status="VERIFIED",
            uploaded_by=uid,
            source_description="Server CCTV DVR #4",
            created_at=now
        )
        db.add(evidence)

        # 3. Evidence Metadata
        metadata = EvidenceMetadata(
            metadata_id=f"META-P13-{suffix}",
            evidence_id=ev_id,
            format_valid=True,
            magic_bytes="89504e470d0a1a0a",
            exif_data={"Make": "Hikvision", "Model": "DS-2CD2042WD-I"},
            timestamps_metadata={"created": now.isoformat()},
            anomalies=[],
            created_at=now
        )
        db.add(metadata)

        # 4. Analysis Results (Forensic & AI)
        forensic_res = AnalysisResult(
            analysis_id=f"ANL-P13-{suffix}",
            evidence_id=ev_id,
            analysis_type="FORENSIC_INSPECTION",
            status="COMPLETED",
            prediction="STRUCTURALLY_CONSISTENT",
            confidence=0.98,
            risk_score=0.05,
            findings=["Valid PNG magic bytes", "No metadata tampering detected"],
            explanation="Header bytes and chunk structure validated.",
            model_name="ForensicEngine",
            model_version="0.1.0",
            created_at=now
        )
        ai_res = AnalysisResult(
            analysis_id=f"AIR-P13-{suffix}",
            evidence_id=ev_id,
            analysis_type="TAMPER_DETECTION",
            status="COMPLETED",
            prediction="NO_TAMPER_INDICATIONS_DETECTED",
            confidence=0.92,
            risk_score=0.08,
            findings=["Statistical pixel histogram consistent"],
            explanation="AI screening verified baseline structural integrity.",
            model_name="TamperScreener-Baseline",
            model_version="0.1.0",
            created_at=now
        )
        db.add(forensic_res)
        db.add(ai_res)

        # 5. Explainability Record
        exp = ExplainabilityRecord(
            record_id=f"EXP-P13-{suffix}",
            evidence_id=ev_id,
            reasoning_summary="No localized pixel anomalies detected across frequency domain.",
            confidence_category="HIGH",
            feature_attributions="Frequency domain discrete cosine transform analysis",
            limitations_disclaimer="Trained on standard CCTV sensor noise profiles.",
            created_at=now
        )
        db.add(exp)

        # 6. Custody Events (Genesis & Verified)
        ledger = CryptographicCustodyLedger()
        b1 = ledger.create_event(
            evidence_id=ev_id,
            sequence_number=1,
            action="EVIDENCE_UPLOADED",
            actor_id=uid,
            details={"action": "EVIDENCE_UPLOADED", "filename": "cctv_extortion_frame.png"},
            previous_event_hash=GENESIS_HASH
        )
        c_evt1 = CustodyEvent(
            event_id=b1["event_id"],
            evidence_id=ev_id,
            sequence_number=1,
            event_type=b1["action"],
            user_id=uid,
            timestamp=b1["timestamp"],
            description="Evidence vaulted",
            previous_hash=b1["previous_event_hash"],
            event_hash=b1["event_hash"],
            payload_json=json.dumps(b1["payload_json"])
        )
        b2 = ledger.create_event(
            evidence_id=ev_id,
            sequence_number=2,
            action="INTEGRITY_VERIFIED",
            actor_id=uid,
            details={"action": "INTEGRITY_VERIFIED", "status": "VERIFIED"},
            previous_event_hash=b1["event_hash"]
        )
        c_evt2 = CustodyEvent(
            event_id=b2["event_id"],
            evidence_id=ev_id,
            sequence_number=2,
            event_type=b2["action"],
            user_id=uid,
            timestamp=b2["timestamp"],
            description="Evidence integrity verified",
            previous_hash=b2["previous_event_hash"],
            event_hash=b2["event_hash"],
            payload_json=json.dumps(b2["payload_json"])
        )
        db.add(c_evt1)
        db.add(c_evt2)

        # 7. Report
        report = Report(
            report_id=rep_id,
            case_id=case_id,
            report_type="PDF",
            status="GENERATED",
            storage_reference=f"./reports/{rep_id}.pdf",
            verification_code=f"VERIFY-{suffix}",
            report_sha256=f"sha256_rep_{suffix}",
            qr_code_data=f"http://localhost:8000/api/reports/verify/{rep_id}",
            created_by=uid,
            created_at=now
        )
        db.add(report)

        # 8. Verification Record
        ver = VerificationRecord(
            verification_id=ver_id,
            report_id=rep_id,
            verification_method="QR_CODE",
            verifier_identifier="PUBLIC_JUDGE_PORTAL",
            status="VALID",
            ip_address="127.0.0.1",
            timestamp=now,
            meta_data={"user_agent": "Mozilla/5.0"}
        )
        db.add(ver)

        # 9. Audit Log
        audit = AuditLog(
            audit_id=aud_id,
            user_id=uid,
            action="EVIDENCE_UPLOADED",
            resource_type="EVIDENCE",
            resource_id=ev_id,
            timestamp=now,
            meta_data={"case_id": case_id, "filename": "cctv_extortion_frame.png"}
        )
        db.add(audit)

        db.commit()
        return case_id
    finally:
        db.close()


@pytest.fixture(scope="module")
def empty_case_docket(rbac_headers):
    """Creates an empty case with no evidence records."""
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    uid = rbac_headers["user_id"]
    suffix = uuid.uuid4().hex[:6].upper()
    case_id = f"CASE-P13-EMPTY-{suffix}"

    try:
        case = Case(
            case_id=case_id,
            case_number=f"CR-2026-EMPTY-{suffix}",
            title="Empty Registered Case Docket",
            description="Case opened with no evidence artifacts ingested yet.",
            status="OPEN",
            jurisdiction="High Court of Delhi",
            created_by=uid,
            created_at=now,
            updated_at=now
        )
        db.add(case)
        db.commit()
        return case_id
    finally:
        db.close()


@pytest.fixture(scope="module")
def compromised_case_docket(rbac_headers):
    """Creates a case with a compromised evidence item."""
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    uid = rbac_headers["user_id"]
    suffix = uuid.uuid4().hex[:6].upper()
    case_id = f"CASE-P13-COMP-{suffix}"
    ev_id = f"EVD-P13-COMP-{suffix}"

    try:
        case = Case(
            case_id=case_id,
            case_number=f"CR-2026-COMP-{suffix}",
            title="Case With Tampered Evidence Artifact",
            description="Compromised hash detected on digital evidence item.",
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
            original_filename="tampered_audio_intercept.mp3",
            stored_filename=f"{ev_id}_audio.mp3",
            media_type="AUDIO",
            file_size=204800,
            sha256_hash="111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000",
            storage_reference=f"./vault/{case_id}/{ev_id}.mp3",
            status="INTEGRITY_COMPROMISED",
            uploaded_by=uid,
            source_description="Audio recorder tap",
            created_at=now
        )
        db.add(evidence)
        db.commit()
        return case_id
    finally:
        db.close()


# =============================================================================
# 1. Populated Case Summary Test
# =============================================================================

def test_populated_case_intelligence_summary(populated_case_docket, rbac_headers):
    """Verifies that a populated case returns 200 OK and complete data across all 12 domains."""
    case_id = populated_case_docket
    headers = rbac_headers["INVESTIGATOR"]

    response = client.get(f"/api/cases/{case_id}/intelligence-summary", headers=headers)
    assert response.status_code == 200, response.text
    data = response.json()

    assert data["success"] is True

    # 1. Case
    case_sec = data["case"]
    assert case_sec["case_id"] == case_id
    assert case_sec["title"] == "State vs. Digital Extortion Syndicate"
    assert case_sec["status"] == "UNDER_ANALYSIS"
    assert case_sec["jurisdiction"] == "High Court of Delhi"

    # 2. Evidence
    ev_sec = data["evidence"]
    assert ev_sec["total_count"] >= 1
    assert "IMAGE" in ev_sec["by_media_type"]
    assert ev_sec["total_size_bytes"] >= 102400
    assert len(ev_sec["items"]) >= 1
    assert ev_sec["items"][0]["original_filename"] == "cctv_extortion_frame.png"

    # 3. Integrity
    int_sec = data["integrity"]
    assert int_sec["total_checked"] >= 1
    assert int_sec["intact_count"] >= 1
    assert int_sec["compromised_count"] == 0
    assert int_sec["storage_error_count"] == 0
    assert int_sec["integrity_status"] == "INTACT"

    # 4. Forensic
    for_sec = data["forensic"]
    assert for_sec["inspected_count"] >= 1
    assert for_sec["format_valid_count"] >= 1
    assert len(for_sec["items"]) >= 1

    # 5. AI Analysis
    ai_sec = data["ai_analysis"]
    assert ai_sec["analyzed_count"] >= 1
    assert len(ai_sec["items"]) >= 1

    # 6. Explainability
    exp_sec = data["explainability"]
    assert exp_sec["records_count"] >= 1
    assert exp_sec["available"] is True
    assert "HIGH" in exp_sec["categories"]

    # 7. Correlation
    corr_sec = data["correlation"]
    assert "timeline_events_count" in corr_sec
    assert "relationships_count" in corr_sec
    assert "red_flags" in corr_sec

    # 8. Timeline
    time_sec = data["timeline"]
    assert time_sec["total_events"] >= 1
    assert time_sec["has_timeline"] is True

    # 9. Custody
    cust_sec = data["custody"]
    assert cust_sec["total_events"] >= 1
    assert len(cust_sec["evidence_chains"]) >= 1

    # 10. Reports
    rep_sec = data["reports"]
    assert rep_sec["total_reports"] >= 1
    assert len(rep_sec["reports_list"]) >= 1

    # 11. Verification
    ver_sec = data["verification"]
    assert ver_sec["total_verifications"] >= 1
    assert ver_sec["valid_verifications"] >= 1

    # 12. Audit
    aud_sec = data["audit"]
    assert aud_sec["total_audit_events"] >= 1

    # Overall Status
    assert data["overall_status"] in ("READY_FOR_COURT", "UNDER_ANALYSIS")


# =============================================================================
# 2. Empty Case Summary Test
# =============================================================================

def test_empty_case_intelligence_summary(empty_case_docket, rbac_headers):
    """Verifies that an empty case returns 200 OK, zeroed stats, and 'NO_EVIDENCE' status."""
    case_id = empty_case_docket
    headers = rbac_headers["INVESTIGATOR"]

    response = client.get(f"/api/cases/{case_id}/intelligence-summary", headers=headers)
    assert response.status_code == 200, response.text
    data = response.json()

    assert data["success"] is True
    assert data["case"]["case_id"] == case_id
    assert data["evidence"]["total_count"] == 0
    assert data["evidence"]["items"] == []
    assert data["integrity"]["integrity_status"] == "NO_EVIDENCE"
    assert data["integrity"]["compromised_count"] == 0
    assert data["forensic"]["inspected_count"] == 0
    assert data["ai_analysis"]["analyzed_count"] == 0
    assert data["explainability"]["available"] is False
    assert data["correlation"]["red_flags_count"] == 0
    assert data["timeline"]["has_timeline"] is False
    assert data["custody"]["total_events"] == 0
    assert data["reports"]["total_reports"] == 0
    assert data["verification"]["total_verifications"] == 0
    assert data["overall_status"] == "NO_EVIDENCE"


# =============================================================================
# 3. Compromised Evidence Case Summary Test
# =============================================================================

def test_compromised_case_intelligence_summary(compromised_case_docket, rbac_headers):
    """Verifies that a case with compromised evidence returns 'INTEGRITY_COMPROMISED' status."""
    case_id = compromised_case_docket
    headers = rbac_headers["INVESTIGATOR"]

    response = client.get(f"/api/cases/{case_id}/intelligence-summary", headers=headers)
    assert response.status_code == 200, response.text
    data = response.json()

    assert data["success"] is True
    assert data["integrity"]["compromised_count"] >= 1
    assert data["integrity"]["integrity_status"] == "INTEGRITY_COMPROMISED"
    assert data["overall_status"] == "INTEGRITY_COMPROMISED"


# =============================================================================
# 4. Missing Case 404 Test
# =============================================================================

def test_missing_case_returns_404(rbac_headers):
    """Verifies that a non-existent case returns 404 (CASE_NOT_FOUND)."""
    headers = rbac_headers["INVESTIGATOR"]
    response = client.get("/api/cases/NON_EXISTENT_CASE_9999/intelligence-summary", headers=headers)
    assert response.status_code == 404


# =============================================================================
# 5. RBAC Permissions Test
# =============================================================================

def test_rbac_case_intelligence_summary(populated_case_docket, rbac_headers):
    """Verifies RBAC rules: authorized roles succeed, unauthenticated gets 401."""
    case_id = populated_case_docket

    # Authorized roles
    for role in ["INVESTIGATOR", "ADMIN", "LAWYER", "JUDGE", "AUDITOR"]:
        resp = client.get(f"/api/cases/{case_id}/intelligence-summary", headers=rbac_headers[role])
        assert resp.status_code == 200, f"Role {role} failed with status {resp.status_code}"

    # Unauthenticated request (no header)
    resp_no_auth = client.get(f"/api/cases/{case_id}/intelligence-summary")
    assert resp_no_auth.status_code in (401, 403)


# =============================================================================
# 6. Read-Only Invariant Test
# =============================================================================

def test_read_only_guarantee(populated_case_docket, rbac_headers):
    """Verifies that querying the summary multiple times causes ZERO database mutations."""
    case_id = populated_case_docket
    headers = rbac_headers["INVESTIGATOR"]

    db = SessionLocal()
    try:
        cases_count_before = db.query(Case).count()
        ev_count_before = db.query(Evidence).count()
        cust_count_before = db.query(CustodyEvent).count()
        rep_count_before = db.query(Report).count()
        ver_count_before = db.query(VerificationRecord).count()
        aud_count_before = db.query(AuditLog).count()
    finally:
        db.close()

    # Query 3 times
    for _ in range(3):
        res = client.get(f"/api/cases/{case_id}/intelligence-summary", headers=headers)
        assert res.status_code == 200

    db = SessionLocal()
    try:
        cases_count_after = db.query(Case).count()
        ev_count_after = db.query(Evidence).count()
        cust_count_after = db.query(CustodyEvent).count()
        rep_count_after = db.query(Report).count()
        ver_count_after = db.query(VerificationRecord).count()
        aud_count_after = db.query(AuditLog).count()
    finally:
        db.close()

    assert cases_count_before == cases_count_after
    assert ev_count_before == ev_count_after
    assert cust_count_before == cust_count_after
    assert rep_count_before == rep_count_after
    assert ver_count_before == ver_count_after
    assert aud_count_before == aud_count_after


# =============================================================================
# 7. Alias Route Test
# =============================================================================

def test_summary_alias_route(populated_case_docket, rbac_headers):
    """Verifies that /api/cases/{case_id}/summary returns identical data to intelligence-summary."""
    case_id = populated_case_docket
    headers = rbac_headers["INVESTIGATOR"]

    res_canonical = client.get(f"/api/cases/{case_id}/intelligence-summary", headers=headers)
    res_alias = client.get(f"/api/cases/{case_id}/summary", headers=headers)

    assert res_canonical.status_code == 200
    assert res_alias.status_code == 200
    assert res_canonical.json() == res_alias.json()
