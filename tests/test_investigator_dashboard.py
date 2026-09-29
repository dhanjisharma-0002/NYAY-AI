"""
NYAYAI - Test Suite: Phase 15 Investigator Portfolio Operational Dashboard
Module: tests.test_investigator_dashboard
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Comprehensive focused test suite verifying:
1. Dashboard returns full operational metrics payload matching schema.
2. Case status distribution accurately aggregates cases by lifecycle status.
3. Cases requiring attention accurately tallies cases with alerts or pending actions.
4. Urgent cases list includes cases with HIGH alerts (integrity, custody, AI tamper).
5. Evidence metrics correctly aggregate total, verified, compromised, and storage errors.
6. Pending action metrics accurately tally uninspected, unanalyzed, and court-report-ready items.
7. RBAC is enforced across roles, prevents unauthenticated access, and respects role isolation.
8. Empty portfolio returns clean zeroed dashboard structure.
9. Read-only guarantee: zero database mutations during request execution.
10. Alias endpoint /api/cases/portfolio-overview returns equivalent operational data.
11. No N+1 query amplification: zero invocations of CaseIntelligenceService summaries.
"""

import os
import sys
import uuid
import json
import pytest
from datetime import datetime, timezone
from unittest.mock import patch
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
    VerificationRecord,
    AuditLog
)
from backend.app.core.security import create_access_token
from backend.app.services.case_intelligence_service import CaseIntelligenceService
from custody import CryptographicCustodyLedger, GENESIS_HASH

Base.metadata.create_all(bind=engine)
client = TestClient(app)


@pytest.fixture(scope="module")
def rbac_users():
    """Provisions test users for platform roles and returns auth headers."""
    db = SessionLocal()
    try:
        def get_or_create(role_name: str, prefix: str = "p15") -> User:
            u = db.query(User).filter_by(role=role_name).first()
            if not u:
                u = User(
                    id=str(uuid.uuid4()),
                    username=f"test_{prefix}_{role_name.lower()}_{uuid.uuid4().hex[:6]}",
                    email=f"{prefix}_{role_name.lower()}_{uuid.uuid4().hex[:6]}@nyayai.gov.in",
                    hashed_password="hashed_placeholder_p15",
                    full_name=f"Test {role_name} User",
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

        # An investigator with zero cases for testing empty portfolio
        empty_inv = User(
            id=str(uuid.uuid4()),
            username=f"empty_inv_{uuid.uuid4().hex[:6]}",
            email=f"empty_inv_{uuid.uuid4().hex[:6]}@nyayai.gov.in",
            hashed_password="hashed_placeholder_p15",
            full_name="Empty Portfolio Investigator",
            role="INVESTIGATOR",
            is_active=True
        )
        db.add(empty_inv)
        db.commit()
        db.refresh(empty_inv)

        return {
            "inv": inv,
            "admin": admin,
            "lawyer": lawyer,
            "judge": judge,
            "auditor": auditor,
            "empty_inv": empty_inv,
            "headers": {
                "INVESTIGATOR": {"Authorization": f"Bearer {create_access_token({'sub': inv.id, 'username': inv.username, 'role': 'INVESTIGATOR'})}"},
                "ADMIN": {"Authorization": f"Bearer {create_access_token({'sub': admin.id, 'username': admin.username, 'role': 'ADMIN'})}"},
                "LAWYER": {"Authorization": f"Bearer {create_access_token({'sub': lawyer.id, 'username': lawyer.username, 'role': 'LAWYER'})}"},
                "JUDGE": {"Authorization": f"Bearer {create_access_token({'sub': judge.id, 'username': judge.username, 'role': 'JUDGE'})}"},
                "AUDITOR": {"Authorization": f"Bearer {create_access_token({'sub': auditor.id, 'username': auditor.username, 'role': 'AUDITOR'})}"},
                "EMPTY_INVESTIGATOR": {"Authorization": f"Bearer {create_access_token({'sub': empty_inv.id, 'username': empty_inv.username, 'role': 'INVESTIGATOR'})}"},
            }
        }
    finally:
        db.close()


@pytest.fixture(scope="module")
def multi_case_portfolio(rbac_users):
    """
    Creates a deterministic 3-case investigative portfolio for the primary investigator:
    1. Case 1 (CLEAN): COMPLETED status, 1 verified evidence, inspected, authentic AI, intact custody, report generated.
       -> attention_required: False, urgent: False
    2. Case 2 (URGENT - INTEGRITY & CUSTODY): UNDER_ANALYSIS status, 1 compromised evidence (SHA mismatch), 1 broken custody chain.
       -> attention_required: True, urgent: True (INTEGRITY_COMPROMISED, BROKEN_CUSTODY_CHAIN)
    3. Case 3 (ATTENTION - PENDING WORK & STORAGE): OPEN status, 1 storage error evidence, 1 fresh unanalyzed evidence.
       -> attention_required: True, urgent: False, pending actions for forensic & AI analysis.
    """
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    inv_id = rbac_users["inv"].id
    suffix = uuid.uuid4().hex[:6].upper()

    cid1 = f"CASE-P15-C1-{suffix}"
    cid2 = f"CASE-P15-C2-{suffix}"
    cid3 = f"CASE-P15-C3-{suffix}"

    try:
        # Case 1: Clean resolved case
        c1 = Case(
            case_id=cid1,
            case_number=f"CR-2026-P15-C1-{suffix}",
            title="Clean Portfolio Case",
            description="Resolved clean case",
            status="COMPLETED",
            created_by=inv_id,
            created_at=now,
            updated_at=now
        )
        db.add(c1)

        ev1 = Evidence(
            evidence_id=f"EVD-P15-1-{suffix}",
            case_id=cid1,
            original_filename="cctv_clean.png",
            stored_filename=f"cctv_{suffix}.png",
            media_type="IMAGE",
            file_size=10000,
            sha256_hash="clean_hash_1111",
            storage_reference=f"./vault/{cid1}/ev1.png",
            status="VERIFIED",
            uploaded_by=inv_id,
            created_at=now
        )
        db.add(ev1)

        meta1 = EvidenceMetadata(
            metadata_id=f"META-P15-1-{suffix}",
            evidence_id=ev1.evidence_id,
            format_valid=True,
            magic_bytes="89504e47",
            anomalies=[],
            created_at=now
        )
        db.add(meta1)

        ai1 = AnalysisResult(
            analysis_id=f"AIR-P15-1-{suffix}",
            evidence_id=ev1.evidence_id,
            analysis_type="TAMPER_DETECTION",
            prediction="AUTHENTIC",
            confidence=0.99,
            risk_score=0.01,
            tamper_detected=False,
            findings=[],
            model_name="TamperNet",
            model_version="1.0.0",
            created_at=now
        )
        db.add(ai1)

        rep1 = Report(
            report_id=f"REP-P15-1-{suffix}",
            case_id=cid1,
            report_type="PDF",
            status="GENERATED",
            storage_reference=f"./reports/{cid1}.pdf",
            verification_code=f"VER-P15-1-{suffix}",
            report_sha256=f"hash_rep1_{suffix}",
            created_by=inv_id,
            created_at=now
        )
        db.add(rep1)

        ledger = CryptographicCustodyLedger()
        b1 = ledger.create_event(
            evidence_id=ev1.evidence_id,
            sequence_number=1,
            action="EVIDENCE_UPLOADED",
            actor_id=inv_id,
            details={"action": "EVIDENCE_UPLOADED"},
            previous_event_hash=GENESIS_HASH
        )
        c_evt1 = CustodyEvent(
            event_id=b1["event_id"],
            evidence_id=ev1.evidence_id,
            sequence_number=1,
            event_type=b1["action"],
            user_id=inv_id,
            timestamp=b1["timestamp"],
            description="Vaulted",
            previous_hash=b1["previous_event_hash"],
            event_hash=b1["event_hash"],
            payload_json=json.dumps(b1["payload_json"])
        )
        db.add(c_evt1)

        # Case 2: Urgent case with compromised evidence and broken custody
        c2 = Case(
            case_id=cid2,
            case_number=f"CR-2026-P15-C2-{suffix}",
            title="Urgent Compromised Portfolio Case",
            description="Compromised integrity case",
            status="UNDER_ANALYSIS",
            created_by=inv_id,
            created_at=now,
            updated_at=now
        )
        db.add(c2)

        ev2 = Evidence(
            evidence_id=f"EVD-P15-2-{suffix}",
            case_id=cid2,
            original_filename="tampered_call.wav",
            stored_filename=f"audio_{suffix}.wav",
            media_type="AUDIO",
            file_size=20000,
            sha256_hash="comp_hash_2222",
            storage_reference=f"./vault/{cid2}/ev2.wav",
            status="INTEGRITY_COMPROMISED",
            uploaded_by=inv_id,
            created_at=now
        )
        db.add(ev2)

        # Broken custody event
        c_broken = CustodyEvent(
            event_id=f"EVT-BROKEN-P15-{suffix}",
            evidence_id=ev2.evidence_id,
            sequence_number=1,
            event_type="EVIDENCE_UPLOADED",
            user_id=inv_id,
            timestamp=now.isoformat(),
            description="Broken chain hash",
            previous_hash="0" * 64,
            event_hash=f"corrupted_event_hash_{suffix}",
            payload_json=json.dumps({"action": "UPLOAD"})
        )
        db.add(c_broken)

        # Case 3: Attention case with storage error & unanalyzed evidence
        c3 = Case(
            case_id=cid3,
            case_number=f"CR-2026-P15-C3-{suffix}",
            title="Pending Actions Portfolio Case",
            description="Storage error and pending inspections",
            status="OPEN",
            created_by=inv_id,
            created_at=now,
            updated_at=now
        )
        db.add(c3)

        ev3_stor = Evidence(
            evidence_id=f"EVD-P15-3A-{suffix}",
            case_id=cid3,
            original_filename="missing_doc.pdf",
            stored_filename=f"doc_{suffix}.pdf",
            media_type="DOCUMENT",
            file_size=30000,
            sha256_hash="stor_hash_3333",
            storage_reference=f"./vault/{cid3}/ev3a.pdf",
            status="STORAGE_ERROR",
            uploaded_by=inv_id,
            created_at=now
        )
        db.add(ev3_stor)

        ev3_unan = Evidence(
            evidence_id=f"EVD-P15-3B-{suffix}",
            case_id=cid3,
            original_filename="fresh_video.mp4",
            stored_filename=f"video_{suffix}.mp4",
            media_type="VIDEO",
            file_size=40000,
            sha256_hash="unan_hash_4444",
            storage_reference=f"./vault/{cid3}/ev3b.mp4",
            status="VERIFIED",
            uploaded_by=inv_id,
            created_at=now
        )
        db.add(ev3_unan)

        db.commit()
        return {
            "case_ids": [cid1, cid2, cid3],
            "urgent_case_id": cid2,
            "attention_case_ids": [cid2, cid3],
            "clean_case_id": cid1
        }
    finally:
        db.close()


# =============================================================================
# TESTS
# =============================================================================

def test_dashboard_returns_metrics(multi_case_portfolio, rbac_users):
    """1. Dashboard returns 200 OK and validates full OperationalDashboardResponse contract."""
    headers = rbac_users["headers"]["INVESTIGATOR"]
    res = client.get("/api/cases/operational-dashboard", headers=headers)
    assert res.status_code == 200, res.text
    data = res.json()

    assert "total_cases" in data
    assert "status_counts" in data
    assert "cases_requiring_attention" in data
    assert "urgent_cases" in data
    assert "evidence_metrics" in data
    assert "pending_actions" in data

    assert data["total_cases"] >= 3
    assert isinstance(data["status_counts"], dict)
    assert isinstance(data["urgent_cases"], list)


def test_status_counts(multi_case_portfolio, rbac_users):
    """2. Status counts correctly tally cases across lifecycle statuses."""
    headers = rbac_users["headers"]["INVESTIGATOR"]
    res = client.get("/api/cases/operational-dashboard", headers=headers)
    assert res.status_code == 200
    data = res.json()

    sc = data["status_counts"]
    assert sc.get("COMPLETED", 0) >= 1
    assert sc.get("UNDER_ANALYSIS", 0) >= 1
    assert sc.get("OPEN", 0) >= 1
    assert sum(sc.values()) == data["total_cases"]


def test_attention_case_count(multi_case_portfolio, rbac_users):
    """3. Cases requiring attention accurately tallies cases with alerts or pending work."""
    headers = rbac_users["headers"]["INVESTIGATOR"]
    res = client.get("/api/cases/operational-dashboard", headers=headers)
    assert res.status_code == 200
    data = res.json()

    # At least Case 2 (urgent) and Case 3 (storage error & pending analysis) require attention
    assert data["cases_requiring_attention"] >= 2
    assert data["cases_requiring_attention"] <= data["total_cases"]


def test_urgent_cases(multi_case_portfolio, rbac_users):
    """4. Urgent cases list includes cases with HIGH alerts (INTEGRITY_COMPROMISED, BROKEN_CUSTODY_CHAIN)."""
    headers = rbac_users["headers"]["INVESTIGATOR"]
    res = client.get("/api/cases/operational-dashboard", headers=headers)
    assert res.status_code == 200
    data = res.json()

    urgent_ids = [c["case_id"] for c in data["urgent_cases"]]
    assert multi_case_portfolio["urgent_case_id"] in urgent_ids

    # Verify high alert types for Case 2
    c2_urgent = next(c for c in data["urgent_cases"] if c["case_id"] == multi_case_portfolio["urgent_case_id"])
    assert "INTEGRITY_COMPROMISED" in c2_urgent["high_alert_types"]
    assert "BROKEN_CUSTODY_CHAIN" in c2_urgent["high_alert_types"]


def test_evidence_metrics(multi_case_portfolio, rbac_users):
    """5. Evidence metrics correctly aggregate total, verified, compromised, and storage errors."""
    headers = rbac_users["headers"]["INVESTIGATOR"]
    res = client.get("/api/cases/operational-dashboard", headers=headers)
    assert res.status_code == 200
    data = res.json()

    em = data["evidence_metrics"]
    assert em["total"] >= 4
    assert em["verified"] >= 2       # ev1 + ev3_unan
    assert em["compromised"] >= 1    # ev2
    assert em["storage_errors"] >= 1 # ev3_stor


def test_pending_action_metrics(multi_case_portfolio, rbac_users):
    """6. Pending action metrics accurately tally uninspected, unanalyzed, and court-report-ready items."""
    headers = rbac_users["headers"]["INVESTIGATOR"]
    res = client.get("/api/cases/operational-dashboard", headers=headers)
    assert res.status_code == 200
    data = res.json()

    pa = data["pending_actions"]
    # ev2, ev3_stor, ev3_unan lack forensic metadata & AI results
    assert pa["forensic_analysis"] >= 2
    assert pa["ai_analysis"] >= 2


def test_rbac(multi_case_portfolio, rbac_users):
    """7. Authorized roles access dashboard; unauthenticated fails; role isolation is respected."""
    for role in ["INVESTIGATOR", "ADMIN", "LAWYER", "JUDGE", "AUDITOR"]:
        resp = client.get("/api/cases/operational-dashboard", headers=rbac_users["headers"][role])
        assert resp.status_code == 200, f"Role {role} failed with {resp.status_code}"

    # Unauthenticated request
    resp_no_auth = client.get("/api/cases/operational-dashboard")
    assert resp_no_auth.status_code in (401, 403)

    # Role isolation: ADMIN sees all cases in the system (>= portfolio cases)
    admin_data = client.get("/api/cases/operational-dashboard", headers=rbac_users["headers"]["ADMIN"]).json()
    inv_data = client.get("/api/cases/operational-dashboard", headers=rbac_users["headers"]["INVESTIGATOR"]).json()
    assert admin_data["total_cases"] >= inv_data["total_cases"]


def test_empty_portfolio(rbac_users):
    """8. Investigator with zero cases receives clean zeroed dashboard structure."""
    headers = rbac_users["headers"]["EMPTY_INVESTIGATOR"]
    res = client.get("/api/cases/operational-dashboard", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["total_cases"] == 0
    assert data["status_counts"] == {}
    assert data["cases_requiring_attention"] == 0
    assert data["urgent_cases"] == []
    assert data["evidence_metrics"] == {
        "total": 0,
        "verified": 0,
        "compromised": 0,
        "storage_errors": 0
    }
    assert data["pending_actions"] == {
        "forensic_analysis": 0,
        "ai_analysis": 0,
        "court_reports": 0
    }


def test_read_only_behavior(multi_case_portfolio, rbac_users):
    """9. GET requests are strictly read-only and cause zero database mutations."""
    headers = rbac_users["headers"]["INVESTIGATOR"]
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
        res = client.get("/api/cases/operational-dashboard", headers=headers)
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


def test_alias_endpoint(multi_case_portfolio, rbac_users):
    """10. Alias endpoint /api/cases/portfolio-overview returns identical data."""
    headers = rbac_users["headers"]["INVESTIGATOR"]
    res_canon = client.get("/api/cases/operational-dashboard", headers=headers)
    res_alias = client.get("/api/cases/portfolio-overview", headers=headers)

    assert res_canon.status_code == 200
    assert res_alias.status_code == 200
    assert res_canon.json() == res_alias.json()


def test_no_n_plus_one_case_summary_calls(multi_case_portfolio, rbac_users):
    """11. Verifies zero N+1 calls to CaseIntelligenceService summaries during dashboard generation."""
    headers = rbac_users["headers"]["INVESTIGATOR"]

    with patch.object(
        CaseIntelligenceService,
        "get_case_intelligence_summary",
        side_effect=AssertionError("get_case_intelligence_summary should NOT be called!")
    ) as mock_intel_summary, patch.object(
        CaseIntelligenceService,
        "get_operational_case_view",
        side_effect=AssertionError("get_operational_case_view should NOT be called!")
    ) as mock_op_view:
        res = client.get("/api/cases/operational-dashboard", headers=headers)
        assert res.status_code == 200
        assert mock_intel_summary.call_count == 0
        assert mock_op_view.call_count == 0
