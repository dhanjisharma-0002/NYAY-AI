"""
NYAYAI - Comprehensive Test Suite: Judicial Trial Disposition, Objection Resolution & Exhibit Disposal (Phase 22)
Module: tests.test_case_trial_disposition
Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

import os
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
    """Provisions investigator, admin, judge, lawyer, and auditor users with auth headers."""
    db = SessionLocal()
    try:
        def get_or_create(username: str, role: str) -> User:
            u = db.query(User).filter_by(username=username).first()
            if not u:
                u = User(
                    id=str(uuid.uuid4()),
                    username=username,
                    email=f"{username}@nyayai.gov.in",
                    hashed_password="hashed_placeholder_p22",
                    role=role,
                    full_name=f"Official {username.title()}",
                    badge_number=f"BADGE-{username[:4].upper()}-22",
                    is_active=True
                )
                db.add(u)
                db.commit()
                db.refresh(u)
            return u

        inv1 = get_or_create("p22_inv_lead", "INVESTIGATOR")
        inv2 = get_or_create("p22_inv_other", "INVESTIGATOR")
        admin = get_or_create("p22_admin_lead", "ADMIN")
        judge = get_or_create("p22_hon_judge", "JUDGE")
        lawyer1 = get_or_create("p22_prosecutor", "LAWYER")
        lawyer2 = get_or_create("p22_defence_counsel", "LAWYER")
        auditor = get_or_create("p22_auditor", "AUDITOR")

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


def create_verified_sealed_exhibit_case_helper(rbac_setup, suffix=None, assigned_counsel=None):
    """Creates, seals, verifies, tenders, and marks exhibits on a case docket."""
    if not suffix:
        suffix = uuid.uuid4().hex[:6].upper()
    headers_inv = rbac_setup["headers_inv1"]
    headers_judge = rbac_setup["headers_judge"]

    desc = f"Trial case ready for disposition {suffix}"
    if assigned_counsel:
        desc += f" (Assigned Counsel: {assigned_counsel})"

    # 1. Create Case Docket
    c_res = client.post(
        "/api/cases",
        json={
            "title": f"Trial Disposition Case {suffix}",
            "description": desc,
            "jurisdiction": "High Court of Delhi"
        },
        headers=headers_inv
    )
    assert c_res.status_code == 201, c_res.text
    case_id = c_res.json()["data"]["case_id"]

    # 2. Upload Evidence 1
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRP22_EVD1_BYTES"
    up1 = client.post(
        "/api/evidence/upload",
        files={"file": (f"disk_clone_{suffix}.png", png_bytes, "image/png")},
        data={"case_id": case_id, "source_description": "Entrance CCTV"},
        headers=headers_inv
    )
    assert up1.status_code == 201, up1.text
    e1_id = up1.json()["evidence_id"]

    # 3. Upload Evidence 2
    wav_bytes = b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00P22_AUDIO"
    up2 = client.post(
        "/api/evidence/upload",
        files={"file": (f"cctv_footage_{suffix}.wav", wav_bytes, "audio/wav")},
        data={"case_id": case_id, "source_description": "Cellular Intercept"},
        headers=headers_inv
    )
    assert up2.status_code == 201, up2.text
    e2_id = up2.json()["evidence_id"]

    # 4. Batch Pipeline Execution
    pipe_res = client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers_inv)
    assert pipe_res.status_code == 200, pipe_res.text

    # 5. Court Admissibility Report Generation
    rep_res = client.post(
        f"/api/reports/generate/{case_id}",
        json={
            "certifying_officer_name": "Lead Forensic Examiner",
            "certifying_officer_designation": "Forensic Lead",
            "badge_number": "BADGE-INV-22",
            "jurisdiction": "High Court of Delhi"
        },
        headers=headers_inv
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
            "badge_number": "BADGE-INV-22"
        },
        headers=headers_inv
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
        headers=headers_judge
    )
    assert adm_res.status_code == 200, adm_res.text

    # 8. Tender Evidence 1 (Prosecution)
    t1_res = client.post(
        f"/api/cases/{case_id}/exhibits/tender",
        json={
            "target_id": e1_id,
            "target_type": "EVIDENCE",
            "tendering_party": "PROSECUTION",
            "tendering_witness": "PW-1 Insp. Sharma",
            "purpose": "Corroboration of hard drive recovery"
        },
        headers=headers_inv
    )
    assert t1_res.status_code in (200, 201), t1_res.text

    # 9. Mark Evidence 1 as Ex. P-1 with OBJECTED_DECISION_RESERVED
    m1_res = client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={
            "target_id": e1_id,
            "target_type": "EVIDENCE",
            "exhibit_number": f"Ex. P-1-{suffix}",
            "tendering_party": "PROSECUTION",
            "ruling": "OBJECTED_DECISION_RESERVED",
            "tendering_witness": "PW-1 Insp. Sharma",
            "court_bench": "Court of Sessions, Patiala House Courts",
            "judicial_officer_name": "Hon'ble Justice S. K. Gupta",
            "objections_raised": "Defense counsel objects to secondary electronic storage certificate",
            "ruling_rationale": "Decision reserved till final arguments under Bipin Shantilal Panchal doctrine"
        },
        headers=headers_judge
    )
    assert m1_res.status_code in (200, 201), m1_res.text

    # 10. Tender and Mark Evidence 2 as Mark A with MARKED_FOR_IDENTIFICATION (MFI)
    client.post(
        f"/api/cases/{case_id}/exhibits/tender",
        json={
            "target_id": e2_id,
            "target_type": "EVIDENCE",
            "tendering_party": "PROSECUTION",
            "tendering_witness": "PW-2 Sub-Insp. Verma"
        },
        headers=headers_inv
    )
    m2_res = client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={
            "target_id": e2_id,
            "target_type": "EVIDENCE",
            "exhibit_number": f"Mark A-{suffix}",
            "tendering_party": "PROSECUTION",
            "ruling": "MARKED_FOR_IDENTIFICATION",
            "tendering_witness": "PW-2 Sub-Insp. Verma",
            "court_bench": "Court of Sessions, Patiala House Courts",
            "judicial_officer_name": "Hon'ble Justice S. K. Gupta"
        },
        headers=headers_judge
    )
    assert m2_res.status_code in (200, 201), m2_res.text

    # 11. Mark Report as Ex. P-3 with ADMITTED_AS_EXHIBIT
    m3_res = client.post(
        f"/api/cases/{case_id}/exhibits/mark",
        json={
            "target_id": report_id,
            "target_type": "REPORT",
            "exhibit_number": f"Ex. P-3-{suffix}",
            "tendering_party": "COURT",
            "ruling": "ADMITTED_AS_EXHIBIT",
            "court_bench": "Court of Sessions, Patiala House Courts",
            "judicial_officer_name": "Hon'ble Justice S. K. Gupta"
        },
        headers=headers_judge
    )
    assert m3_res.status_code in (200, 201), m3_res.text

    return {
        "case_id": case_id,
        "e1_id": e1_id,
        "e2_id": e2_id,
        "report_id": report_id,
        "ex1_num": f"Ex. P-1-{suffix}",
        "ex2_num": f"Mark A-{suffix}",
        "ex3_num": f"Ex. P-3-{suffix}",
        "suffix": suffix
    }


def test_1_judge_can_pronounce_verdict(rbac_setup):
    """Test Judge successfully pronounces trial verdict and sets appellate legal hold."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup)
    case_id = case_data["case_id"]

    res = client.post(
        f"/api/cases/{case_id}/disposition/verdict",
        json={
            "verdict": "CONVICTED",
            "order_reference": "Judgment in Sessions Case No. 42/2026",
            "court_bench": "Court of Sessions, Patiala House Courts",
            "judicial_officer_name": "Hon'ble Justice S. K. Gupta",
            "disposition_summary": "Accused convicted under Section 318(4) BNSS and Section 66 IT Act.",
            "statutory_provisions": ["BNSS_2023_SECTION_250", "BSA_2023_SECTION_63"],
            "appeal_limitation_days": 60
        },
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 201, res.text
    data = res.json()
    assert data["success"] is True
    assert data["verdict"] == "CONVICTED"
    assert data["appeal_limitation_days"] == 60
    assert data["appellate_hold_expires_at"] is not None
    assert "DISP-" in data["disposition_id"]
    assert "AUD-" in data["audit_id"]


def test_2_non_judge_cannot_pronounce_verdict(rbac_setup):
    """Test non-Judge roles (Lawyer, Investigator, Admin, Auditor) receive 403 Forbidden."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup)
    case_id = case_data["case_id"]

    for role_key in ["headers_lawyer1", "headers_inv1", "headers_admin", "headers_auditor"]:
        res = client.post(
            f"/api/cases/{case_id}/disposition/verdict",
            json={"verdict": "CONVICTED"},
            headers=rbac_setup[role_key]
        )
        assert res.status_code == 403, f"Role {role_key} should be forbidden"


def test_3_all_five_verdict_types(rbac_setup):
    """Test all five statutory verdict classifications and validation."""
    valid_verdicts = ["CONVICTED", "ACQUITTED", "DISCHARGED", "DISMISSED", "PARTIALLY_CONVICTED"]

    for v in valid_verdicts:
        cdata = create_verified_sealed_exhibit_case_helper(rbac_setup)
        res = client.post(
            f"/api/cases/{cdata['case_id']}/disposition/verdict",
            json={"verdict": v, "order_reference": f"Order for {v}"},
            headers=rbac_setup["headers_judge"]
        )
        assert res.status_code == 201, res.text
        assert res.json()["verdict"] == v

    # Invalid verdict
    cdata = create_verified_sealed_exhibit_case_helper(rbac_setup)
    bad_res = client.post(
        f"/api/cases/{cdata['case_id']}/disposition/verdict",
        json={"verdict": "INVALID_VERDICT_XYZ"},
        headers=rbac_setup["headers_judge"]
    )
    assert bad_res.status_code == 422


def test_4_unsealed_case_verdict_rejected(rbac_setup):
    """Test verdict pronouncement rejected on unsealed case docket with HTTP 400."""
    res = client.post(
        "/api/cases",
        json={"title": "Unsealed Case Docket"},
        headers=rbac_setup["headers_inv1"]
    )
    raw_case_id = res.json()["data"]["case_id"]

    v_res = client.post(
        f"/api/cases/{raw_case_id}/disposition/verdict",
        json={"verdict": "ACQUITTED"},
        headers=rbac_setup["headers_judge"]
    )
    assert v_res.status_code == 400
    assert v_res.json()["error_code"] == "CASE_NOT_SEALED"


def test_5_conflicting_verdict_rejected_and_idempotency(rbac_setup):
    """Test conflicting verdict returns 409 Conflict, while identical payload returns 200 idempotently."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup)
    case_id = case_data["case_id"]

    # First pronouncement
    res1 = client.post(
        f"/api/cases/{case_id}/disposition/verdict",
        json={"verdict": "CONVICTED", "order_reference": "Order 1"},
        headers=rbac_setup["headers_judge"]
    )
    assert res1.status_code == 201

    # Idempotent second pronouncement
    res2 = client.post(
        f"/api/cases/{case_id}/disposition/verdict",
        json={"verdict": "CONVICTED", "order_reference": "Order 1"},
        headers=rbac_setup["headers_judge"]
    )
    assert res2.status_code == 201
    assert res2.json()["disposition_id"] == res1.json()["disposition_id"]

    # Conflicting pronouncement
    res3 = client.post(
        f"/api/cases/{case_id}/disposition/verdict",
        json={"verdict": "ACQUITTED", "order_reference": "Order 2"},
        headers=rbac_setup["headers_judge"]
    )
    assert res3.status_code == 409
    assert res3.json()["error_code"] == "TRIAL_ALREADY_ADJUDICATED"


def test_6_judge_can_resolve_reserved_objection(rbac_setup):
    """Test resolving OBJECTED_DECISION_RESERVED to ADMITTED_AS_EXHIBIT with custody extension."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup)
    case_id = case_data["case_id"]
    ex1_num = case_data["ex1_num"]

    res = client.post(
        f"/api/cases/{case_id}/exhibits/{ex1_num}/resolve-objection",
        json={
            "final_ruling": "ADMITTED_AS_EXHIBIT",
            "ruling_rationale": "Section 63 certificate verified; objection overruled upon final arguments.",
            "order_reference": "Judgment Section IV, para 18"
        },
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["success"] is True
    assert data["prior_ruling"] == "OBJECTED_DECISION_RESERVED"
    assert data["final_ruling"] == "ADMITTED_AS_EXHIBIT"
    assert data["custody_event_id"] is not None

    # Verify custody continuity
    hist_res = client.get(f"/api/custody/evidence/{case_data['e1_id']}", headers=rbac_setup["headers_judge"])
    assert hist_res.status_code == 200
    events = hist_res.json()["history"]
    assert any(e["event_type"] == "EXHIBIT_OBJECTION_RESOLVED" for e in events)


def test_7_judge_can_resolve_mfi_exhibit(rbac_setup):
    """Test resolving MARKED_FOR_IDENTIFICATION exhibit to REJECTED."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup)
    case_id = case_data["case_id"]
    ex2_num = case_data["ex2_num"]

    res = client.post(
        f"/api/cases/{case_id}/exhibits/{ex2_num}/resolve-objection",
        json={
            "final_ruling": "REJECTED",
            "ruling_rationale": "Secondary video footage could not be proven by competent witness."
        },
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["prior_ruling"] == "MARKED_FOR_IDENTIFICATION"
    assert data["final_ruling"] == "REJECTED"


def test_8_resolving_already_admitted_exhibit_rejected(rbac_setup):
    """Test attempting to resolve an exhibit already in ADMITTED_AS_EXHIBIT returns 409 Conflict."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup)
    case_id = case_data["case_id"]
    ex3_num = case_data["ex3_num"]  # Marked as ADMITTED_AS_EXHIBIT

    res = client.post(
        f"/api/cases/{case_id}/exhibits/{ex3_num}/resolve-objection",
        json={"final_ruling": "REJECTED"},
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 409
    assert res.json()["error_code"] == "EXHIBIT_NOT_RESERVED"


def test_9_non_judge_cannot_resolve_objection(rbac_setup):
    """Test non-Judge cannot resolve objections (HTTP 403 Forbidden)."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup)
    case_id = case_data["case_id"]
    ex1_num = case_data["ex1_num"]

    for role_key in ["headers_lawyer1", "headers_inv1", "headers_admin", "headers_auditor"]:
        res = client.post(
            f"/api/cases/{case_id}/exhibits/{ex1_num}/resolve-objection",
            json={"final_ruling": "ADMITTED_AS_EXHIBIT"},
            headers=rbac_setup[role_key]
        )
        assert res.status_code == 403


def test_10_judge_can_order_statutory_disposal(rbac_setup):
    """Test Judge issues statutory exhibit disposal order under BNSS Section 503."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup)
    case_id = case_data["case_id"]
    ex1_num = case_data["ex1_num"]

    res = client.post(
        f"/api/cases/{case_id}/exhibits/{ex1_num}/disposal-order",
        json={
            "disposal_type": "RETAINED_FOR_APPEAL",
            "statutory_authority": "BNSS_2023_SECTION_503",
            "disposal_instructions": "Retain in Malkhana digital custody pending appeal limitation period.",
            "appellate_hold": True,
            "order_reference": "Order on Disposal of Case Property, Para 5"
        },
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 201, res.text
    data = res.json()
    assert data["success"] is True
    assert data["disposal_type"] == "RETAINED_FOR_APPEAL"
    assert data["appellate_hold"] is True
    assert data["custody_event_id"] is not None


def test_11_destroyed_disposal_preserves_worm_vault_file(rbac_setup):
    """CRITICAL TEST: Verify DESTROYED disposal order NEVER deletes physical WORM vault file."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup)
    case_id = case_data["case_id"]
    ex2_num = case_data["ex2_num"]
    e2_id = case_data["e2_id"]

    db = SessionLocal()
    ev_record = db.query(Evidence).filter_by(evidence_id=e2_id).first()
    storage_path = ev_record.storage_reference
    original_hash = ev_record.sha256_hash
    db.close()

    assert os.path.exists(storage_path), "Physical vault file must exist prior to disposal order"

    # Issue judicial destruction order
    res = client.post(
        f"/api/cases/{case_id}/exhibits/{ex2_num}/disposal-order",
        json={
            "disposal_type": "DESTROYED",
            "disposal_instructions": "Judicial destruction ordered for contraband digital payload.",
            "order_reference": "Destruction Order No. 9"
        },
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 201, res.text
    assert res.json()["disposal_type"] == "DESTROYED"

    # CRITICAL VERIFICATION: Physical WORM file must STILL exist and remain untouched
    assert os.path.exists(storage_path), "CRITICAL FAILURE: Physical WORM file was deleted!"
    with open(storage_path, "rb") as f:
        file_bytes = f.read()
    import hashlib
    assert hashlib.sha256(file_bytes).hexdigest() == original_hash, "WORM file bytes were mutated!"


def test_12_conflicting_disposal_order_rejected(rbac_setup):
    """Test conflicting disposal order returns 409 Conflict, while identical order is idempotent."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup)
    case_id = case_data["case_id"]
    ex3_num = case_data["ex3_num"]

    # First order
    res1 = client.post(
        f"/api/cases/{case_id}/exhibits/{ex3_num}/disposal-order",
        json={"disposal_type": "RETURNED_TO_OWNER", "recipient_details": "Complainant Shri R. K. Sharma"},
        headers=rbac_setup["headers_judge"]
    )
    assert res1.status_code == 201

    # Idempotent second order
    res2 = client.post(
        f"/api/cases/{case_id}/exhibits/{ex3_num}/disposal-order",
        json={"disposal_type": "RETURNED_TO_OWNER"},
        headers=rbac_setup["headers_judge"]
    )
    assert res2.status_code == 201
    assert res2.json()["disposal_order_id"] == res1.json()["disposal_order_id"]

    # Conflicting order
    res3 = client.post(
        f"/api/cases/{case_id}/exhibits/{ex3_num}/disposal-order",
        json={"disposal_type": "CONFISCATED"},
        headers=rbac_setup["headers_judge"]
    )
    assert res3.status_code == 409
    assert res3.json()["error_code"] == "DISPOSAL_ALREADY_ORDERED"


def test_13_non_judge_cannot_order_disposal(rbac_setup):
    """Test non-Judge cannot issue disposal orders (HTTP 403 Forbidden)."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup)
    case_id = case_data["case_id"]
    ex1_num = case_data["ex1_num"]

    for role_key in ["headers_lawyer1", "headers_inv1", "headers_admin", "headers_auditor"]:
        res = client.post(
            f"/api/cases/{case_id}/exhibits/{ex1_num}/disposal-order",
            json={"disposal_type": "RETURNED_TO_OWNER"},
            headers=rbac_setup[role_key]
        )
        assert res.status_code == 403


def test_14_archive_blocked_without_verdict(rbac_setup):
    """Test archiving blocked if trial verdict has not been pronounced (HTTP 400 VERDICT_REQUIRED)."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup)
    case_id = case_data["case_id"]

    res = client.post(
        f"/api/cases/{case_id}/archive",
        json={"reason": "Attempting premature archival"},
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 400
    assert res.json()["error_code"] == "VERDICT_REQUIRED"


def test_15_archive_blocked_with_unresolved_objections(rbac_setup):
    """Test archiving blocked if any exhibit remains in OBJECTED_DECISION_RESERVED or MFI (HTTP 400 UNRESOLVED_EXHIBITS)."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup)
    case_id = case_data["case_id"]

    # Pronounce verdict
    client.post(
        f"/api/cases/{case_id}/disposition/verdict",
        json={"verdict": "CONVICTED"},
        headers=rbac_setup["headers_judge"]
    )

    # Attempt archival without resolving Ex. P-1 or Mark A
    res = client.post(
        f"/api/cases/{case_id}/archive",
        json={"reason": "Premature archival with unresolved exhibits"},
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 400
    assert res.json()["error_code"] == "UNRESOLVED_EXHIBITS"


def test_16_archive_blocked_with_undisposed_exhibits(rbac_setup):
    """Test archiving blocked if any exhibit lacks a statutory disposal order (HTTP 400 UNDISPOSED_EXHIBITS)."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup)
    case_id = case_data["case_id"]

    # Pronounce verdict
    client.post(
        f"/api/cases/{case_id}/disposition/verdict",
        json={"verdict": "CONVICTED"},
        headers=rbac_setup["headers_judge"]
    )

    # Resolve both exhibits
    client.post(
        f"/api/cases/{case_id}/exhibits/{case_data['ex1_num']}/resolve-objection",
        json={"final_ruling": "ADMITTED_AS_EXHIBIT"},
        headers=rbac_setup["headers_judge"]
    )
    client.post(
        f"/api/cases/{case_id}/exhibits/{case_data['ex2_num']}/resolve-objection",
        json={"final_ruling": "REJECTED"},
        headers=rbac_setup["headers_judge"]
    )

    # Dispose only Ex. P-1, leaving Mark A and Ex. P-3 undisposed
    client.post(
        f"/api/cases/{case_id}/exhibits/{case_data['ex1_num']}/disposal-order",
        json={"disposal_type": "RETAINED_FOR_APPEAL"},
        headers=rbac_setup["headers_judge"]
    )

    res = client.post(
        f"/api/cases/{case_id}/archive",
        json={"reason": "Attempting archival with missing disposal orders"},
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 400
    assert res.json()["error_code"] == "UNDISPOSED_EXHIBITS"


def test_17_successful_judicial_archival(rbac_setup):
    """Test end-to-end judicial docket archival upon verdict, objection resolution, and disposal."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup)
    case_id = case_data["case_id"]

    # 1. Pronounce Verdict
    v_res = client.post(
        f"/api/cases/{case_id}/disposition/verdict",
        json={"verdict": "CONVICTED", "order_reference": "Judgment in Case 104"},
        headers=rbac_setup["headers_judge"]
    )
    assert v_res.status_code == 201

    # 2. Resolve Objections
    client.post(
        f"/api/cases/{case_id}/exhibits/{case_data['ex1_num']}/resolve-objection",
        json={"final_ruling": "ADMITTED_AS_EXHIBIT", "ruling_rationale": "Admitted on merit"},
        headers=rbac_setup["headers_judge"]
    )
    client.post(
        f"/api/cases/{case_id}/exhibits/{case_data['ex2_num']}/resolve-objection",
        json={"final_ruling": "REJECTED", "ruling_rationale": "Excluded from evidence"},
        headers=rbac_setup["headers_judge"]
    )

    # 3. Order Disposal for All Exhibits
    client.post(
        f"/api/cases/{case_id}/exhibits/{case_data['ex1_num']}/disposal-order",
        json={"disposal_type": "RETAINED_FOR_APPEAL", "appellate_hold": True},
        headers=rbac_setup["headers_judge"]
    )
    client.post(
        f"/api/cases/{case_id}/exhibits/{case_data['ex2_num']}/disposal-order",
        json={"disposal_type": "DESTROYED", "disposal_instructions": "Judicial destruction ordered"},
        headers=rbac_setup["headers_judge"]
    )
    client.post(
        f"/api/cases/{case_id}/exhibits/{case_data['ex3_num']}/disposal-order",
        json={"disposal_type": "CONFISCATED", "disposal_instructions": "Preserve in judicial archive"},
        headers=rbac_setup["headers_judge"]
    )

    # 4. Check Trial Disposition Register
    disp_res = client.get(f"/api/cases/{case_id}/disposition", headers=rbac_setup["headers_judge"])
    assert disp_res.status_code == 200
    disp_data = disp_res.json()
    assert disp_data["has_verdict"] is True
    assert disp_data["unresolved_exhibits_count"] == 0
    assert disp_data["pending_disposal_count"] == 0
    assert disp_data["is_ready_for_archival"] is True

    # 5. Archive Case Docket
    arch_res = client.post(
        f"/api/cases/{case_id}/archive",
        json={
            "reason": "Trial concluded, judgment delivered, all exhibits disposed under BNSS Section 503.",
            "order_reference": "Record Room Consignment Order No. 42"
        },
        headers=rbac_setup["headers_judge"]
    )
    assert arch_res.status_code == 200, arch_res.text
    arch_data = arch_res.json()
    assert arch_data["success"] is True
    assert arch_data["previous_status"] == "COMPLETED"
    assert arch_data["current_status"] == "ARCHIVED"
    assert arch_data["verdict"] == "CONVICTED"
    assert arch_data["total_exhibits_disposed"] == 3
    assert arch_data["appellate_holds_active"] == 1

    # Verify Case DB status is ARCHIVED
    db = SessionLocal()
    case_in_db = db.query(Case).filter_by(case_id=case_id).first()
    assert case_in_db.status == "ARCHIVED"
    db.close()


def test_18_generic_patch_cannot_bypass_archival(rbac_setup):
    """Test generic PATCH cannot transition a sealed/completed case to ARCHIVED (HTTP 400 ARCHIVAL_GOVERNANCE_BYPASS)."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup)
    case_id = case_data["case_id"]

    # Attempting to patch status to ARCHIVED directly
    patch_res = client.patch(
        f"/api/cases/{case_id}",
        json={"status": "ARCHIVED"},
        headers=rbac_setup["headers_inv1"]
    )
    assert patch_res.status_code == 400
    assert patch_res.json()["error_code"] == "ARCHIVAL_GOVERNANCE_BYPASS"


def test_19_cross_case_access_rejected(rbac_setup):
    """Test unauthorized cross-case access is forbidden with HTTP 403."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup, assigned_counsel="p22_prosecutor")
    case_id = case_data["case_id"]

    # Non-creator investigator gets 403
    inv2_res = client.get(f"/api/cases/{case_id}/disposition", headers=rbac_setup["headers_inv2"])
    assert inv2_res.status_code == 403

    # Unassigned lawyer gets 403
    law2_res = client.get(f"/api/cases/{case_id}/disposition", headers=rbac_setup["headers_lawyer2"])
    assert law2_res.status_code == 403


def test_20_disposition_register_and_lookup(rbac_setup):
    """Test retrieving consolidated disposition register and single exhibit disposal lookup."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup)
    case_id = case_data["case_id"]
    ex1_num = case_data["ex1_num"]

    # Issue disposal
    client.post(
        f"/api/cases/{case_id}/exhibits/{ex1_num}/disposal-order",
        json={"disposal_type": "RETURNED_TO_OWNER", "recipient_details": "Victim A"},
        headers=rbac_setup["headers_judge"]
    )

    # Lookup by exhibit number
    lookup_res = client.get(
        f"/api/cases/{case_id}/exhibits/{ex1_num}/disposal",
        headers=rbac_setup["headers_judge"]
    )
    assert lookup_res.status_code == 200
    assert lookup_res.json()["disposal_type"] == "RETURNED_TO_OWNER"
    assert lookup_res.json()["recipient_details"] == "Victim A"


def test_21_versioned_v1_parity(rbac_setup):
    """Test /api/v1 versioned prefix operates with 100% parity."""
    case_data = create_verified_sealed_exhibit_case_helper(rbac_setup)
    case_id = case_data["case_id"]

    v1_res = client.get(f"/api/v1/cases/{case_id}/disposition", headers=rbac_setup["headers_judge"])
    assert v1_res.status_code == 200
    assert v1_res.json()["case_id"] == case_id
