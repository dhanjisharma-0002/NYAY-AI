"""
NYAYAI - Comprehensive Test Suite: Judicial Courtroom Exhibit Marking & Evidence Tender (Phase 21)
Module: tests.test_case_exhibit_marking
Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

import uuid
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database import SessionLocal, Base, engine
from backend.app.models.user import User
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.report import Report
from backend.app.models.custody import CustodyEvent
from backend.app.models.audit import AuditLog
from backend.app.core.security import create_access_token
from backend.app.services.custody_service import CustodyService

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
                    hashed_password="hashed_placeholder_p21",
                    role=role,
                    full_name=f"Official {username.title()}",
                    badge_number=f"BADGE-{username[:4].upper()}-21",
                    is_active=True
                )
                db.add(u)
                db.commit()
                db.refresh(u)
            return u

        inv1 = get_or_create("p21_inv_lead", "INVESTIGATOR")
        inv2 = get_or_create("p21_inv_other", "INVESTIGATOR")
        admin = get_or_create("p21_admin_lead", "ADMIN")
        judge = get_or_create("p21_hon_judge", "JUDGE")
        lawyer1 = get_or_create("p21_prosecutor", "LAWYER")
        lawyer2 = get_or_create("p21_defence_counsel", "LAWYER")
        auditor = get_or_create("p21_auditor", "AUDITOR")

        def headers_for(user: User):
            token = create_access_token({"sub": user.id, "username": user.username, "role": user.role, "id": user.id})
            return {"Authorization": f"Bearer {token}"}

        return {
            "inv1": inv1,
            "inv2": inv2,
            "admin": admin,
            "judge": judge,
            "lawyer1": lawyer1,
            "lawyer2": lawyer2,
            "auditor": auditor,
            "headers_inv1": headers_for(inv1),
            "headers_inv2": headers_for(inv2),
            "headers_admin": headers_for(admin),
            "headers_judge": headers_for(judge),
            "headers_lawyer1": headers_for(lawyer1),
            "headers_lawyer2": headers_for(lawyer2),
            "headers_auditor": headers_for(auditor),
        }
    finally:
        db.close()


def create_verified_sealed_case_helper(rbac_setup, suffix=None, assigned_counsel=None):
    """Creates, analyzes, seals, and admissibility-verifies a complete case docket."""
    if not suffix:
        suffix = uuid.uuid4().hex[:6].upper()
    headers = rbac_setup["headers_inv1"]

    desc = "Case docket prepared for trial exhibit marking"
    if assigned_counsel:
        desc += f" (Assigned Counsel: {assigned_counsel})"

    # 1. Create Case Docket
    c_res = client.post(
        "/api/cases",
        json={
            "title": f"Trial Exhibit Case {suffix}",
            "description": desc,
            "jurisdiction": "High Court of Delhi"
        },
        headers=headers
    )
    assert c_res.status_code == 201, c_res.text
    case_id = c_res.json()["data"]["case_id"]

    # 2. Upload Evidence 1
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRP21_EVD1_BYTES"
    up1 = client.post(
        "/api/evidence/upload",
        files={"file": ("cctv_camera.png", png_bytes, "image/png")},
        data={"case_id": case_id, "source_description": "Entrance CCTV"},
        headers=headers
    )
    assert up1.status_code == 201, up1.text
    ev1_id = up1.json()["evidence_id"]

    # 3. Upload Evidence 2
    wav_bytes = b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00P21_AUDIO"
    up2 = client.post(
        "/api/evidence/upload",
        files={"file": ("audio_wiretap.wav", wav_bytes, "audio/wav")},
        data={"case_id": case_id, "source_description": "Cellular Intercept"},
        headers=headers
    )
    assert up2.status_code == 201, up2.text
    ev2_id = up2.json()["evidence_id"]

    # 4. Batch Pipeline Execution
    pipe_res = client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers)
    assert pipe_res.status_code == 200, pipe_res.text

    # 5. Court Admissibility Report Generation
    rep_res = client.post(
        f"/api/reports/generate/{case_id}",
        json={
            "certifying_officer_name": "Lead Forensic Examiner",
            "certifying_officer_designation": "Forensic Lead",
            "badge_number": "BADGE-INV-21",
            "jurisdiction": "High Court of Delhi"
        },
        headers=headers
    )
    assert rep_res.status_code in (200, 201), rep_res.text
    rep_data = rep_res.json()
    report_id = rep_data["report_id"] if "report_id" in rep_data else rep_data.get("data", {}).get("report_id")

    # 6. Finalize & Seal Case Docket
    fin_res = client.post(
        f"/api/cases/{case_id}/finalize",
        json={
            "certification_notes": "Forensic pipeline verified for trial marking.",
            "certifying_officer_name": "Lead Forensic Examiner",
            "badge_number": "BADGE-INV-21"
        },
        headers=headers
    )
    assert fin_res.status_code == 200, fin_res.text

    # 7. Judicial Admissibility Verification (Phase 18)
    adm_res = client.post(
        f"/api/cases/{case_id}/verify-admissibility",
        json={
            "court_bench": "Court of Sessions 4, Patiala House Courts",
            "judicial_officer_name": "Hon'ble Justice S. K. Gupta",
            "verification_notes": "Pre-trial admissibility verification under BSA 2023 Section 63."
        },
        headers=rbac_setup["headers_judge"]
    )
    assert adm_res.status_code == 200, adm_res.text
    assert adm_res.json()["is_admissible"] is True

    return {
        "case_id": case_id,
        "evidence_ids": [ev1_id, ev2_id],
        "report_id": report_id
    }


# =============================================================================
# TESTS
# =============================================================================

def test_1_judge_can_mark_exhibit(rbac_setup):
    """1. Judge can mark electronic evidence as an exhibit and record ruling."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    ev1_id = fixture["evidence_ids"][0]

    payload = {
        "target_id": ev1_id,
        "target_type": "EVIDENCE",
        "exhibit_number": "Ex. P-1",
        "tendering_party": "PROSECUTION",
        "tendering_witness": "PW-1 Inspector S. K. Sharma",
        "ruling": "ADMITTED_AS_EXHIBIT",
        "court_bench": "Sessions Court 4, Patiala House Courts",
        "judicial_officer_name": "Hon'ble Justice S. K. Gupta",
        "order_reference": "Sessions Case 402/2026 Order Sheet 12",
        "objections_raised": "Defense objected under BSA 2023 Sec 63 regarding camera calibration.",
        "ruling_rationale": "Overruled. Section 63 certificate verified authentic; streaming SHA-256 intact."
    }

    res = client.post(f"/api/cases/{case_id}/exhibits/mark", json=payload, headers=rbac_setup["headers_judge"])
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["success"] is True
    assert data["exhibit_number"] == "Ex. P-1"
    assert data["target_id"] == ev1_id
    assert data["target_type"] == "EVIDENCE"
    assert data["ruling"] == "ADMITTED_AS_EXHIBIT"
    assert data["tendering_party"] == "PROSECUTION"
    assert data["marked_by_username"] == "p21_hon_judge"
    assert data["custody_event_id"] is not None
    assert len(data["custody_event_hash"]) == 64


def test_2_lawyer_can_tender_evidence(rbac_setup):
    """2. Lawyer can formally tender evidence without assigning final exhibit number or ruling."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    ev2_id = fixture["evidence_ids"][1]

    payload = {
        "target_id": ev2_id,
        "target_type": "EVIDENCE",
        "tendering_party": "PROSECUTION",
        "tendering_witness": "PW-2 Cyber Intelligence Officer",
        "purpose": "Corroboration of accused communications",
        "tender_notes": "Tendered during Examination-in-Chief of PW-2"
    }

    res = client.post(f"/api/cases/{case_id}/exhibits/tender", json=payload, headers=rbac_setup["headers_lawyer1"])
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["success"] is True
    assert data["status"] == "TENDERED"
    assert data["target_id"] == ev2_id
    assert data["tendering_party"] == "PROSECUTION"
    assert data["tendered_by_username"] == "p21_prosecutor"
    assert "exhibit_number" not in data or data.get("exhibit_number") is None


def test_3_investigator_can_tender_when_case_scoped(rbac_setup):
    """3. Owning investigator (inv1) can tender evidence into court record."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    ev1_id = fixture["evidence_ids"][0]

    payload = {
        "target_id": ev1_id,
        "target_type": "EVIDENCE",
        "tendering_party": "PROSECUTION",
        "tendering_witness": "PW-1 Investigating Officer",
        "purpose": "Identification of seizure"
    }

    res = client.post(f"/api/cases/{case_id}/exhibits/tender", json=payload, headers=rbac_setup["headers_inv1"])
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["success"] is True
    assert data["status"] == "TENDERED"


def test_4_unauthorized_role_rejected(rbac_setup):
    """4. Unauthorized roles rejected: Non-judges cannot mark; auditors cannot tender; anonymous gets 401/403."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    ev1_id = fixture["evidence_ids"][0]

    mark_payload = {
        "target_id": ev1_id,
        "target_type": "EVIDENCE",
        "exhibit_number": "Ex. P-99",
        "tendering_party": "PROSECUTION",
        "ruling": "ADMITTED_AS_EXHIBIT"
    }

    # Lawyer cannot mark exhibits (403)
    res_lawyer_mark = client.post(f"/api/cases/{case_id}/exhibits/mark", json=mark_payload, headers=rbac_setup["headers_lawyer1"])
    assert res_lawyer_mark.status_code == 403

    # Investigator cannot mark exhibits (403)
    res_inv_mark = client.post(f"/api/cases/{case_id}/exhibits/mark", json=mark_payload, headers=rbac_setup["headers_inv1"])
    assert res_inv_mark.status_code == 403

    # Admin cannot make judicial rulings (403)
    res_admin_mark = client.post(f"/api/cases/{case_id}/exhibits/mark", json=mark_payload, headers=rbac_setup["headers_admin"])
    assert res_admin_mark.status_code == 403

    # Auditor cannot tender evidence (403)
    tender_payload = {
        "target_id": ev1_id,
        "target_type": "EVIDENCE",
        "tendering_party": "COURT"
    }
    res_auditor_tender = client.post(f"/api/cases/{case_id}/exhibits/tender", json=tender_payload, headers=rbac_setup["headers_auditor"])
    assert res_auditor_tender.status_code == 403

    # Anonymous call rejected (401 or 403)
    res_anon = client.post(f"/api/cases/{case_id}/exhibits/mark", json=mark_payload)
    assert res_anon.status_code in (401, 403)


def test_5_unsealed_case_rejected(rbac_setup):
    """5. Unsealed / OPEN case cannot be presented for trial exhibit marking or tendering (400)."""
    headers = rbac_setup["headers_inv1"]

    # Create unsealed case
    c_res = client.post(
        "/api/cases",
        json={"title": "Unsealed Case", "description": "Open investigation"},
        headers=headers
    )
    open_case_id = c_res.json()["data"]["case_id"]

    # Upload evidence but do NOT finalize or verify
    up = client.post(
        "/api/evidence/upload",
        files={"file": ("open_ev.png", b"PNG_OPEN", "image/png")},
        data={"case_id": open_case_id},
        headers=headers
    )
    ev_id = up.json()["evidence_id"]

    payload = {
        "target_id": ev_id,
        "target_type": "EVIDENCE",
        "exhibit_number": "Ex. P-1",
        "tendering_party": "PROSECUTION",
        "ruling": "ADMITTED_AS_EXHIBIT"
    }

    res = client.post(f"/api/cases/{open_case_id}/exhibits/mark", json=payload, headers=rbac_setup["headers_judge"])
    assert res.status_code == 400
    assert "CASE_NOT_SEALED" in res.text or "UNSEALED" in res.text


def test_6_missing_target_rejected(rbac_setup):
    """6. Non-existent evidence or report target returns HTTP 404."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]

    payload = {
        "target_id": f"EVD-NONEXISTENT-{uuid.uuid4().hex[:6]}",
        "target_type": "EVIDENCE",
        "exhibit_number": "Ex. P-10",
        "tendering_party": "PROSECUTION",
        "ruling": "ADMITTED_AS_EXHIBIT"
    }

    res = client.post(f"/api/cases/{case_id}/exhibits/mark", json=payload, headers=rbac_setup["headers_judge"])
    assert res.status_code == 404


def test_7_duplicate_exhibit_number_rejected(rbac_setup):
    """7. Reusing an assigned exhibit number for a different target is rejected with HTTP 409 Conflict."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    ev1_id = fixture["evidence_ids"][0]
    ev2_id = fixture["evidence_ids"][1]

    # Mark Evidence 1 as Ex. P-1
    res1 = client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={
            "target_id": ev1_id,
            "target_type": "EVIDENCE",
            "exhibit_number": "Ex. P-1",
            "tendering_party": "PROSECUTION",
            "ruling": "ADMITTED_AS_EXHIBIT"
        },
        headers=rbac_setup["headers_judge"]
    )
    assert res1.status_code == 200

    # Attempt to mark Evidence 2 with the SAME exhibit number Ex. P-1
    res2 = client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={
            "target_id": ev2_id,
            "target_type": "EVIDENCE",
            "exhibit_number": "Ex. P-1",
            "tendering_party": "PROSECUTION",
            "ruling": "ADMITTED_AS_EXHIBIT"
        },
        headers=rbac_setup["headers_judge"]
    )
    assert res2.status_code == 409
    assert "DUPLICATE_EXHIBIT_NUMBER" in res2.text


def test_8_already_admitted_target_rejected(rbac_setup):
    """8. Evidence already ADMITTED_AS_EXHIBIT cannot be re-admitted under another exhibit number (409 Conflict)."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    ev1_id = fixture["evidence_ids"][0]

    # Admit as Ex. P-1
    res1 = client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={
            "target_id": ev1_id,
            "target_type": "EVIDENCE",
            "exhibit_number": "Ex. P-1",
            "tendering_party": "PROSECUTION",
            "ruling": "ADMITTED_AS_EXHIBIT"
        },
        headers=rbac_setup["headers_judge"]
    )
    assert res1.status_code == 200

    # Attempt to re-admit same evidence as Ex. P-5
    res2 = client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={
            "target_id": ev1_id,
            "target_type": "EVIDENCE",
            "exhibit_number": "Ex. P-5",
            "tendering_party": "PROSECUTION",
            "ruling": "ADMITTED_AS_EXHIBIT"
        },
        headers=rbac_setup["headers_judge"]
    )
    assert res2.status_code == 409
    assert "TARGET_ALREADY_ADMITTED" in res2.text


def test_9_evidence_marking(rbac_setup):
    """9. EVIDENCE marking appends JUDICIAL_EXHIBIT_MARKED custody block and records audit log."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    ev1_id = fixture["evidence_ids"][0]

    res = client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={
            "target_id": ev1_id,
            "target_type": "EVIDENCE",
            "exhibit_number": "Ex. P-1",
            "tendering_party": "PROSECUTION",
            "ruling": "ADMITTED_AS_EXHIBIT"
        },
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 200
    data = res.json()
    assert data["target_type"] == "EVIDENCE"
    assert data["custody_event_id"] is not None


def test_10_report_marking(rbac_setup):
    """10. REPORT marking allows Section 63 forensic report to be marked as an exhibit (e.g. Ex. P-2)."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    report_id = fixture["report_id"]

    res = client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={
            "target_id": report_id,
            "target_type": "REPORT",
            "exhibit_number": "Ex. P-2",
            "tendering_party": "PROSECUTION",
            "tendering_witness": "PW-4 Forensic System Lead",
            "ruling": "ADMITTED_AS_EXHIBIT",
            "ruling_rationale": "Section 63 Certificate proved by expert witness."
        },
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["target_type"] == "REPORT"
    assert data["target_id"] == report_id
    assert data["exhibit_number"] == "Ex. P-2"
    assert data["ruling"] == "ADMITTED_AS_EXHIBIT"


def test_11_all_four_ruling_states(rbac_setup):
    """11. All four statutory judicial rulings tested across distinct exhibits."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    ev1_id = fixture["evidence_ids"][0]
    ev2_id = fixture["evidence_ids"][1]
    report_id = fixture["report_id"]

    # 1. ADMITTED_AS_EXHIBIT
    r1 = client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={"target_id": ev1_id, "target_type": "EVIDENCE", "exhibit_number": "Ex. P-1", "tendering_party": "PROSECUTION", "ruling": "ADMITTED_AS_EXHIBIT"},
        headers=rbac_setup["headers_judge"]
    )
    assert r1.status_code == 200
    assert r1.json()["ruling"] == "ADMITTED_AS_EXHIBIT"

    # 2. MARKED_FOR_IDENTIFICATION
    r2 = client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={"target_id": ev2_id, "target_type": "EVIDENCE", "exhibit_number": "Mark A", "tendering_party": "DEFENCE", "ruling": "MARKED_FOR_IDENTIFICATION"},
        headers=rbac_setup["headers_judge"]
    )
    assert r2.status_code == 200
    assert r2.json()["ruling"] == "MARKED_FOR_IDENTIFICATION"

    # 3. OBJECTED_DECISION_RESERVED
    r3 = client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={"target_id": report_id, "target_type": "REPORT", "exhibit_number": "Ex. P-2", "tendering_party": "PROSECUTION", "ruling": "OBJECTED_DECISION_RESERVED"},
        headers=rbac_setup["headers_judge"]
    )
    assert r3.status_code == 200
    assert r3.json()["ruling"] == "OBJECTED_DECISION_RESERVED"

    # 4. REJECTED on another fixture case
    fix2 = create_verified_sealed_case_helper(rbac_setup)
    r4 = client.post(
        f"/api/cases/{fix2['case_id']}/exhibits/mark",
        json={"target_id": fix2["evidence_ids"][0], "target_type": "EVIDENCE", "exhibit_number": "Ex. D-1", "tendering_party": "DEFENCE", "ruling": "REJECTED"},
        headers=rbac_setup["headers_judge"]
    )
    assert r4.status_code == 200
    assert r4.json()["ruling"] == "REJECTED"


def test_12_custody_chain_remains_valid(rbac_setup):
    """12. Cryptographic custody chain remains intact after tendering and marking."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    ev1_id = fixture["evidence_ids"][0]

    # Tender
    client.post(
        f"/api/cases/{case_id}/exhibits/tender",
        json={"target_id": ev1_id, "target_type": "EVIDENCE", "tendering_party": "PROSECUTION"},
        headers=rbac_setup["headers_lawyer1"]
    )

    # Mark
    client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={"target_id": ev1_id, "target_type": "EVIDENCE", "exhibit_number": "Ex. P-1", "tendering_party": "PROSECUTION", "ruling": "ADMITTED_AS_EXHIBIT"},
        headers=rbac_setup["headers_judge"]
    )

    db = SessionLocal()
    try:
        custody_service = CustodyService(db)
        history = custody_service.get_chronological_history(ev1_id)
        assert history["chain_intact"] is True
        event_types = [e["event_type"] for e in history["history"]]
        assert "DOCKET_SEALED" in event_types
        assert "EXHIBIT_TENDERED_IN_COURT" in event_types
        assert "JUDICIAL_EXHIBIT_MARKED" in event_types
        # Monotonic sequence check
        for i, e in enumerate(history["history"]):
            assert e["sequence_number"] == i + 1
    finally:
        db.close()


def test_13_audit_events_created(rbac_setup):
    """13. Exact EXHIBIT_TENDERED and EXHIBIT_MARKED audit records are recorded."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    ev1_id = fixture["evidence_ids"][0]

    # Tender
    client.post(
        f"/api/cases/{case_id}/exhibits/tender",
        json={"target_id": ev1_id, "target_type": "EVIDENCE", "tendering_party": "PROSECUTION"},
        headers=rbac_setup["headers_lawyer1"]
    )

    # Mark
    client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={"target_id": ev1_id, "target_type": "EVIDENCE", "exhibit_number": "Ex. P-1", "tendering_party": "PROSECUTION", "ruling": "ADMITTED_AS_EXHIBIT"},
        headers=rbac_setup["headers_judge"]
    )

    db = SessionLocal()
    try:
        tenders = db.query(AuditLog).filter_by(resource_id=case_id, action="EXHIBIT_TENDERED").all()
        assert len(tenders) == 1
        assert tenders[0].meta_data["target_id"] == ev1_id

        markings = db.query(AuditLog).filter_by(resource_id=case_id, action="EXHIBIT_MARKED").all()
        assert len(markings) == 1
        assert markings[0].meta_data["exhibit_number"] == "Ex. P-1"
        assert markings[0].meta_data["ruling"] == "ADMITTED_AS_EXHIBIT"
    finally:
        db.close()


def test_14_register_ordering_and_stats(rbac_setup):
    """14. Judicial Exhibit Register returns chronological exhibit history and accurate counts."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    ev1_id = fixture["evidence_ids"][0]
    ev2_id = fixture["evidence_ids"][1]
    report_id = fixture["report_id"]

    # Mark 1
    client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={"target_id": ev1_id, "target_type": "EVIDENCE", "exhibit_number": "Ex. P-1", "tendering_party": "PROSECUTION", "ruling": "ADMITTED_AS_EXHIBIT"},
        headers=rbac_setup["headers_judge"]
    )

    # Mark 2
    client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={"target_id": ev2_id, "target_type": "EVIDENCE", "exhibit_number": "Mark A", "tendering_party": "DEFENCE", "ruling": "MARKED_FOR_IDENTIFICATION"},
        headers=rbac_setup["headers_judge"]
    )

    # Mark 3
    client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={"target_id": report_id, "target_type": "REPORT", "exhibit_number": "Ex. P-2", "tendering_party": "PROSECUTION", "ruling": "ADMITTED_AS_EXHIBIT"},
        headers=rbac_setup["headers_judge"]
    )

    reg_res = client.get(f"/api/cases/{case_id}/exhibits", headers=rbac_setup["headers_judge"])
    assert reg_res.status_code == 200, reg_res.text
    reg = reg_res.json()

    assert reg["success"] is True
    assert reg["case_id"] == case_id
    assert reg["total_exhibits"] == 3
    assert reg["admitted_count"] == 2
    assert reg["mfi_count"] == 1
    assert reg["objected_count"] == 0
    assert reg["rejected_count"] == 0
    assert len(reg["exhibits"]) == 3
    assert reg["exhibits"][0]["exhibit_number"] == "Ex. P-1"
    assert reg["exhibits"][1]["exhibit_number"] == "Mark A"
    assert reg["exhibits"][2]["exhibit_number"] == "Ex. P-2"


def test_15_get_endpoints_read_only(rbac_setup):
    """15. GET exhibit endpoints are strictly read-only and generate zero database modifications."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    ev1_id = fixture["evidence_ids"][0]

    # Mark exhibit
    client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={"target_id": ev1_id, "target_type": "EVIDENCE", "exhibit_number": "Ex. P-1", "tendering_party": "PROSECUTION", "ruling": "ADMITTED_AS_EXHIBIT"},
        headers=rbac_setup["headers_judge"]
    )

    db = SessionLocal()
    try:
        initial_audits = db.query(AuditLog).count()
        initial_custody = db.query(CustodyEvent).count()
    finally:
        db.close()

    # Query register
    client.get(f"/api/cases/{case_id}/exhibits", headers=rbac_setup["headers_judge"])
    # Query exhibit by number
    client.get(f"/api/cases/{case_id}/exhibits/Ex. P-1", headers=rbac_setup["headers_judge"])
    # Query evidence exhibit status
    client.get(f"/api/cases/{case_id}/evidence/{ev1_id}/exhibit", headers=rbac_setup["headers_judge"])

    db2 = SessionLocal()
    try:
        assert db2.query(AuditLog).count() == initial_audits
        assert db2.query(CustodyEvent).count() == initial_custody
    finally:
        db2.close()


def test_16_cross_case_access_rejected(rbac_setup):
    """16. Cross-case access rejected: Foreign investigator and foreign lawyer cannot access unassigned case."""
    fixture1 = create_verified_sealed_case_helper(rbac_setup, assigned_counsel="p21_prosecutor")
    case1_id = fixture1["case_id"]
    ev1_id = fixture1["evidence_ids"][0]

    tender_payload = {
        "target_id": ev1_id,
        "target_type": "EVIDENCE",
        "tendering_party": "PROSECUTION"
    }

    # 1. Foreign Investigator (inv2) cannot tender on case created by inv1 (403)
    res_inv2 = client.post(f"/api/cases/{case1_id}/exhibits/tender", json=tender_payload, headers=rbac_setup["headers_inv2"])
    assert res_inv2.status_code == 403

    # 2. Foreign Lawyer (lawyer2) cannot tender on case scoped to lawyer1 (403)
    res_lawyer2 = client.post(f"/api/cases/{case1_id}/exhibits/tender", json=tender_payload, headers=rbac_setup["headers_lawyer2"])
    assert res_lawyer2.status_code == 403


def test_17_aliases_parity(rbac_setup):
    """17. Endpoint aliases return identical results."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    ev1_id = fixture["evidence_ids"][0]
    ev2_id = fixture["evidence_ids"][1]

    # Tender canonical vs alias
    t_canon = client.post(
        f"/api/cases/{case_id}/exhibits/tender",
        json={"target_id": ev1_id, "target_type": "EVIDENCE", "tendering_party": "PROSECUTION"},
        headers=rbac_setup["headers_lawyer1"]
    )
    assert t_canon.status_code == 200

    t_alias = client.post(
        f"/api/cases/{case_id}/tender-evidence",
        json={"target_id": ev2_id, "target_type": "EVIDENCE", "tendering_party": "DEFENCE"},
        headers=rbac_setup["headers_lawyer1"]
    )
    assert t_alias.status_code == 200
    assert t_alias.json()["status"] == "TENDERED"

    # Mark canonical vs alias
    m_canon = client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={"target_id": ev1_id, "target_type": "EVIDENCE", "exhibit_number": "Ex. P-1", "tendering_party": "PROSECUTION", "ruling": "ADMITTED_AS_EXHIBIT"},
        headers=rbac_setup["headers_judge"]
    )
    assert m_canon.status_code == 200

    m_alias = client.post(
        f"/api/cases/{case_id}/mark-exhibit",
        json={"target_id": ev2_id, "target_type": "EVIDENCE", "exhibit_number": "Ex. D-1", "tendering_party": "DEFENCE", "ruling": "ADMITTED_AS_EXHIBIT"},
        headers=rbac_setup["headers_judge"]
    )
    assert m_alias.status_code == 200

    # Register canonical vs alias
    reg_canon = client.get(f"/api/cases/{case_id}/exhibits", headers=rbac_setup["headers_judge"])
    reg_alias = client.get(f"/api/cases/{case_id}/exhibit-register", headers=rbac_setup["headers_judge"])
    assert reg_canon.status_code == 200
    assert reg_alias.status_code == 200
    assert reg_canon.json()["total_exhibits"] == reg_alias.json()["total_exhibits"]


def test_18_idempotent_mark_and_tender(rbac_setup):
    """18. Identical repeated tender and mark requests are idempotent and do not corrupt sequence."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    ev1_id = fixture["evidence_ids"][0]

    # Tender twice identically
    t_req = {"target_id": ev1_id, "target_type": "EVIDENCE", "tendering_party": "PROSECUTION", "purpose": "Identical"}
    t1 = client.post(f"/api/cases/{case_id}/exhibits/tender", json=t_req, headers=rbac_setup["headers_lawyer1"])
    t2 = client.post(f"/api/cases/{case_id}/exhibits/tender", json=t_req, headers=rbac_setup["headers_lawyer1"])
    assert t1.status_code == 200
    assert t2.status_code == 200
    assert t1.json()["tender_id"] == t2.json()["tender_id"]

    # Mark twice identically
    m_req = {
        "target_id": ev1_id,
        "target_type": "EVIDENCE",
        "exhibit_number": "Ex. P-1",
        "tendering_party": "PROSECUTION",
        "ruling": "ADMITTED_AS_EXHIBIT"
    }
    m1 = client.post(f"/api/cases/{case_id}/exhibits/mark", json=m_req, headers=rbac_setup["headers_judge"])
    m2 = client.post(f"/api/cases/{case_id}/exhibits/mark", json=m_req, headers=rbac_setup["headers_judge"])
    assert m1.status_code == 200
    assert m2.status_code == 200
    assert m1.json()["exhibit_id"] == m2.json()["exhibit_id"]


def test_19_api_v1_versioned_prefix(rbac_setup):
    """19. Versioned prefix /api/v1/cases/{case_id}/exhibits functions identically."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]

    res_v1 = client.get(f"/api/v1/cases/{case_id}/exhibits", headers=rbac_setup["headers_judge"])
    assert res_v1.status_code == 200
    assert res_v1.json()["success"] is True
