"""
NYAYAI - Test Suite: Phase 20 Judicial Discovery Bundle Cryptographic Verification & Tamper Audit Gateway
Module: tests.test_case_bundle_verification
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Comprehensive focused test suite verifying:
1. Valid Phase 19 bundle verification (BUNDLE_VERIFIED_AUTHENTIC).
2. Modified evidence byte detection (BUNDLE_TAMPERED).
3. Modified manifest detection (BUNDLE_TAMPERED).
4. Root checksum mismatch detection (ROOT_CHECKSUM_MISMATCH).
5. Missing manifest detection (BUNDLE_TAMPERED).
6. Missing Section 63 certificate detection (BUNDLE_TAMPERED).
7. Malformed / corrupted ZIP archive handling (CORRUPTED_ARCHIVE).
8. Zip-slip / path traversal rejection (CORRUPTED_ARCHIVE).
9. Oversized archive / entry rejection (CORRUPTED_ARCHIVE).
10. Unregistered / forged sealing hash rejection (UNREGISTERED_SEALING_HASH).
11. Phase 18 certificate mismatch detection (BUNDLE_TAMPERED).
12. Role-Based Access Control (RBAC): Judge, Admin, Lawyer, Owning Investigator permitted;
    Foreign Investigator blocked (403), Anonymous blocked (401/403).
13. Non-existent case docket handling (HTTP 404).
14. Exactly one CASE_BUNDLE_VERIFIED audit event per run.
15. Alias endpoint POST /api/cases/{case_id}/verify-disclosure-package parity.
16. Strictly read-only database behavior (no mutations to evidence, case, reports, custody).
17. Air-gap manifest verification endpoint POST /api/verification/bundle-manifest.
"""

import os
import io
import sys
import uuid
import json
import zipfile
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
    CustodyEvent,
    Report,
    AuditLog
)
from backend.app.core.security import create_access_token

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
                    hashed_password="hashed_placeholder_p20",
                    role=role,
                    full_name=f"Official {username.title()}",
                    badge_number=f"BADGE-{username[:4].upper()}-20",
                    is_active=True
                )
                db.add(u)
                db.commit()
                db.refresh(u)
            return u

        inv1 = get_or_create("p20_inv_lead", "INVESTIGATOR")
        inv2 = get_or_create("p20_inv_other", "INVESTIGATOR")
        admin = get_or_create("p20_admin_lead", "ADMIN")
        judge = get_or_create("p20_hon_judge", "JUDGE")
        lawyer = get_or_create("p20_advocate", "LAWYER")

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


def create_exported_bundle_fixture(rbac_setup, suffix=None):
    """
    Creates, analyzes, reports, seals, admissibility-verifies, and exports a Phase 19 bundle.
    Returns case metadata and valid ZIP bytes.
    """
    if not suffix:
        suffix = uuid.uuid4().hex[:6].upper()
    headers = rbac_setup["headers_inv1"]

    # 1. Create Case Docket
    c_res = client.post(
        "/api/cases",
        json={
            "title": f"Bundle Verification Case {suffix}",
            "description": "Evidence docket for judicial bundle cryptographic verification audit",
            "jurisdiction": "High Court of Judicature at Delhi"
        },
        headers=headers
    )
    assert c_res.status_code == 201, c_res.text
    case_id = c_res.json()["data"]["case_id"]

    # 2. Upload Evidence
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRP20_VERIFY_IMG_BYTES"
    up1 = client.post(
        "/api/evidence/upload",
        files={"file": ("evidence_doc.png", png_bytes, "image/png")},
        data={"case_id": case_id, "source_description": "CCTV Evidence Feed"},
        headers=headers
    )
    assert up1.status_code == 201, up1.text
    ev1_id = up1.json()["evidence_id"]

    # 3. Pipeline Analysis
    pipe_res = client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers)
    assert pipe_res.status_code == 200, pipe_res.text

    # 4. Court Admissibility Report Generation
    rep_res = client.post(
        f"/api/reports/generate/{case_id}",
        json={
            "certifying_officer_name": "Lead Forensic Examiner",
            "certifying_officer_designation": "Forensic Investigator",
            "badge_number": "BADGE-VERIFY-20",
            "jurisdiction": "High Court of Judicature at Delhi"
        },
        headers=headers
    )
    assert rep_res.status_code in (200, 201), rep_res.text

    # 5. Case Finalization & Sealing (Phase 17)
    fin_res = client.post(
        f"/api/cases/{case_id}/finalize",
        json={
            "certification_notes": "Forensic sealing complete.",
            "certifying_officer_name": "Lead Forensic Examiner",
            "badge_number": "BADGE-VERIFY-20"
        },
        headers=headers
    )
    assert fin_res.status_code == 200, fin_res.text
    sealing_data = fin_res.json()
    sealing_hash = sealing_data["docket_sealing_hash"]

    # 6. Judicial Admissibility Verification (Phase 18)
    ver_res = client.post(
        f"/api/cases/{case_id}/verify-admissibility",
        json={"court_bench": "Courtroom 4", "judicial_officer_name": "Justice M. Rao"},
        headers=rbac_setup["headers_judge"]
    )
    assert ver_res.status_code == 200, ver_res.text
    assert ver_res.json()["is_admissible"] is True

    # 7. Export Discovery Bundle (Phase 19)
    exp_res = client.post(
        f"/api/cases/{case_id}/export-bundle",
        json={"purpose": "Judicial verification test run"},
        headers=rbac_setup["headers_judge"]
    )
    assert exp_res.status_code == 200, exp_res.text
    exp_data = exp_res.json()

    # 8. Download Binary ZIP
    dl_res = client.get(f"/api/cases/{case_id}/download-bundle", headers=rbac_setup["headers_judge"])
    assert dl_res.status_code == 200, dl_res.text
    zip_bytes = dl_res.content

    return {
        "case_id": case_id,
        "evidence_id": ev1_id,
        "sealing_hash": sealing_hash,
        "root_checksum": exp_data["root_checksum"],
        "zip_bytes": zip_bytes,
        "headers": headers
    }


def repack_zip_modifying(zip_bytes: bytes, modify_fn) -> bytes:
    """
    Helper to unpack, modify in-memory, and repackage a ZIP archive.
    modify_fn receives a dict {arc_path: bytes} and modifies it in-place or returns a new dict.
    """
    entries = {}
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        for name in zf.namelist():
            entries[name] = zf.read(name)

    result_entries = modify_fn(entries) or entries

    out_bio = io.BytesIO()
    with zipfile.ZipFile(out_bio, "w", compression=zipfile.ZIP_DEFLATED) as new_zf:
        for name, data in sorted(result_entries.items()):
            new_zf.writestr(name, data)

    return out_bio.getvalue()


# =============================================================================
# TESTS
# =============================================================================

def test_valid_phase19_bundle_verification(rbac_setup):
    """1. Valid Phase 19 bundle verification returns BUNDLE_VERIFIED_AUTHENTIC."""
    fixture = create_exported_bundle_fixture(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    res = client.post(
        f"/api/cases/{case_id}/verify-bundle",
        files={"file": ("bundle.zip", fixture["zip_bytes"], "application/zip")},
        data={"notes": "Judicial magistrate preliminary discovery inspection"},
        headers=headers
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["case_id"] == case_id
    assert data["verification_status"] == "BUNDLE_VERIFIED_AUTHENTIC"
    assert data["is_authentic"] is True
    assert data["checks"]["archive_structure_valid"] is True
    assert data["checks"]["manifest_present"] is True
    assert data["checks"]["all_artifacts_intact"] is True
    assert data["checks"]["root_checksum_verified"] is True
    assert data["checks"]["sealing_hash_registered"] is True
    assert data["checks"]["admissibility_certified"] is True
    assert data["checks"]["tampered_artifacts_count"] == 0
    assert len(data["checks"]["tampered_artifact_paths"]) == 0
    assert data["expected_sealing_hash"] == fixture["sealing_hash"]
    assert data["bundle_sealing_hash"] == fixture["sealing_hash"]
    assert data["computed_root_checksum"] == fixture["root_checksum"]


def test_modified_evidence_byte_detection(rbac_setup):
    """2. Tampering a single byte inside an evidence file triggers BUNDLE_TAMPERED."""
    fixture = create_exported_bundle_fixture(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    def tamper_evidence(entries):
        ev_keys = [k for k in entries.keys() if k.startswith("evidence/")]
        assert len(ev_keys) > 0
        target = ev_keys[0]
        # Modify bytes in evidence file
        entries[target] = entries[target] + b"_TAMPERED_BYTE_EXACT"

    tampered_zip = repack_zip_modifying(fixture["zip_bytes"], tamper_evidence)

    res = client.post(
        f"/api/cases/{case_id}/verify-bundle",
        files={"file": ("tampered_bundle.zip", tampered_zip, "application/zip")},
        headers=headers
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["verification_status"] == "BUNDLE_TAMPERED"
    assert data["is_authentic"] is False
    assert data["checks"]["all_artifacts_intact"] is False
    assert data["checks"]["tampered_artifacts_count"] >= 1
    assert any("evidence/" in p for p in data["checks"]["tampered_artifact_paths"])


def test_modified_manifest_detection(rbac_setup):
    """3. Tampering manifest.json content triggers BUNDLE_TAMPERED."""
    fixture = create_exported_bundle_fixture(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    def tamper_manifest(entries):
        assert "manifest.json" in entries
        mf = json.loads(entries["manifest.json"].decode("utf-8"))
        mf["title"] = "FORGED_CASE_TITLE_MALICIOUS"
        entries["manifest.json"] = json.dumps(mf, indent=2).encode("utf-8")

    tampered_zip = repack_zip_modifying(fixture["zip_bytes"], tamper_manifest)

    res = client.post(
        f"/api/cases/{case_id}/verify-bundle",
        files={"file": ("tampered_manifest.zip", tampered_zip, "application/zip")},
        headers=headers
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["verification_status"] == "BUNDLE_TAMPERED"
    assert data["is_authentic"] is False
    assert "manifest.json" in data["checks"]["tampered_artifact_paths"]


def test_root_checksum_mismatch_detection(rbac_setup):
    """4. Tampering DISCOVERY_BUNDLE_CHECKSUM.sha256 triggers ROOT_CHECKSUM_MISMATCH."""
    fixture = create_exported_bundle_fixture(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    def tamper_checksum_file(entries):
        assert "DISCOVERY_BUNDLE_CHECKSUM.sha256" in entries
        # Replace first hash with a dummy hash
        orig = entries["DISCOVERY_BUNDLE_CHECKSUM.sha256"].decode("utf-8")
        lines = orig.splitlines()
        new_lines = []
        for l in lines:
            if "  " in l:
                parts = l.split("  ", 1)
                new_lines.append(f"0000000000000000000000000000000000000000000000000000000000000000  {parts[1]}")
            else:
                new_lines.append(l)
        entries["DISCOVERY_BUNDLE_CHECKSUM.sha256"] = "\n".join(new_lines).encode("utf-8")

    tampered_zip = repack_zip_modifying(fixture["zip_bytes"], tamper_checksum_file)

    res = client.post(
        f"/api/cases/{case_id}/verify-bundle",
        files={"file": ("tampered_cs.zip", tampered_zip, "application/zip")},
        headers=headers
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["verification_status"] in ("ROOT_CHECKSUM_MISMATCH", "BUNDLE_TAMPERED")
    assert data["is_authentic"] is False
    assert data["checks"]["root_checksum_verified"] is False


def test_missing_manifest_detection(rbac_setup):
    """5. Omission of manifest.json triggers BUNDLE_TAMPERED."""
    fixture = create_exported_bundle_fixture(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    def remove_manifest(entries):
        entries.pop("manifest.json", None)

    tampered_zip = repack_zip_modifying(fixture["zip_bytes"], remove_manifest)

    res = client.post(
        f"/api/cases/{case_id}/verify-bundle",
        files={"file": ("no_manifest.zip", tampered_zip, "application/zip")},
        headers=headers
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["verification_status"] == "BUNDLE_TAMPERED"
    assert data["is_authentic"] is False
    assert "manifest.json" in data["checks"]["tampered_artifact_paths"]


def test_missing_certificate_detection(rbac_setup):
    """6. Omission of admissibility_certificate.json triggers BUNDLE_TAMPERED."""
    fixture = create_exported_bundle_fixture(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    def remove_cert(entries):
        entries.pop("admissibility_certificate.json", None)

    tampered_zip = repack_zip_modifying(fixture["zip_bytes"], remove_cert)

    res = client.post(
        f"/api/cases/{case_id}/verify-bundle",
        files={"file": ("no_cert.zip", tampered_zip, "application/zip")},
        headers=headers
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["verification_status"] == "BUNDLE_TAMPERED"
    assert data["is_authentic"] is False
    assert "admissibility_certificate.json" in data["checks"]["tampered_artifact_paths"]


def test_corrupted_archive_detection(rbac_setup):
    """7. Malformed / corrupted ZIP archive triggers CORRUPTED_ARCHIVE."""
    fixture = create_exported_bundle_fixture(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    corrupt_bytes = b"PK\x03\x04CORRUPTED_ZIP_STREAM_NOT_A_VALID_ARCHIVE"

    res = client.post(
        f"/api/cases/{case_id}/verify-bundle",
        files={"file": ("corrupt.zip", corrupt_bytes, "application/zip")},
        headers=headers
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["verification_status"] == "CORRUPTED_ARCHIVE"
    assert data["is_authentic"] is False
    assert data["checks"]["archive_structure_valid"] is False


def test_zip_slip_path_traversal_rejection(rbac_setup):
    """8. Zip-slip and path traversal attempts are safely rejected with CORRUPTED_ARCHIVE."""
    fixture = create_exported_bundle_fixture(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    # Craft ZIP with directory traversal entries
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("../etc/passwd", b"root:x:0:0:root:/root:/bin/bash")
        zf.writestr("manifest.json", b"{}")
        zf.writestr("DISCOVERY_BUNDLE_CHECKSUM.sha256", b"")
        zf.writestr("admissibility_certificate.json", b"{}")

    res = client.post(
        f"/api/cases/{case_id}/verify-bundle",
        files={"file": ("zip_slip.zip", bio.getvalue(), "application/zip")},
        headers=headers
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["verification_status"] == "CORRUPTED_ARCHIVE"
    assert data["is_authentic"] is False
    assert "Zip-slip" in data["verification_summary"] or "traversal" in data["verification_summary"]


def test_oversized_archive_rejection(rbac_setup):
    """9. Oversized archive / entry is safely rejected with CORRUPTED_ARCHIVE (Zip-Bomb protection)."""
    fixture = create_exported_bundle_fixture(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    from backend.app.services.bundle_verification_service import BundleVerificationService
    orig_max = BundleVerificationService.MAX_ENTRY_UNCOMPRESSED_SIZE
    try:
        BundleVerificationService.MAX_ENTRY_UNCOMPRESSED_SIZE = 50  # 50 bytes limit
        res = client.post(
            f"/api/cases/{case_id}/verify-bundle",
            files={"file": ("oversized.zip", fixture["zip_bytes"], "application/zip")},
            headers=headers
        )
        assert res.status_code == 200, res.text
        data = res.json()

        assert data["verification_status"] == "CORRUPTED_ARCHIVE"
        assert data["is_authentic"] is False
        assert "exceeds maximum allowed uncompressed size" in data["verification_summary"]
    finally:
        BundleVerificationService.MAX_ENTRY_UNCOMPRESSED_SIZE = orig_max


def test_unregistered_sealing_hash_rejection(rbac_setup):
    """10. Unregistered / forged sealing hash triggers UNREGISTERED_SEALING_HASH."""
    fixture = create_exported_bundle_fixture(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    def forge_sealing_hash(entries):
        assert "manifest.json" in entries
        mf = json.loads(entries["manifest.json"].decode("utf-8"))
        mf["docket_sealing_hash"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        entries["manifest.json"] = json.dumps(mf, indent=2).encode("utf-8")

    tampered_zip = repack_zip_modifying(fixture["zip_bytes"], forge_sealing_hash)

    res = client.post(
        f"/api/cases/{case_id}/verify-bundle",
        files={"file": ("unregistered_seal.zip", tampered_zip, "application/zip")},
        headers=headers
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["verification_status"] == "UNREGISTERED_SEALING_HASH"
    assert data["is_authentic"] is False
    assert data["checks"]["sealing_hash_registered"] is False


def test_phase18_certificate_mismatch_detection(rbac_setup):
    """11. Phase 18 certificate mismatch (wrong case ID or status) triggers BUNDLE_TAMPERED."""
    fixture = create_exported_bundle_fixture(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    def tamper_cert(entries):
        assert "admissibility_certificate.json" in entries
        cert = json.loads(entries["admissibility_certificate.json"].decode("utf-8"))
        cert["case_id"] = "CASE-FOREIGN-FORGED-001"
        cert["is_admissible"] = False
        entries["admissibility_certificate.json"] = json.dumps(cert, indent=2).encode("utf-8")

    tampered_zip = repack_zip_modifying(fixture["zip_bytes"], tamper_cert)

    res = client.post(
        f"/api/cases/{case_id}/verify-bundle",
        files={"file": ("bad_cert.zip", tampered_zip, "application/zip")},
        headers=headers
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["verification_status"] == "BUNDLE_TAMPERED"
    assert data["is_authentic"] is False
    assert data["checks"]["admissibility_certified"] is False


def test_rbac_authorization(rbac_setup):
    """12. RBAC: Judge, Admin, Lawyer, Owning Investigator allowed; Foreign Investigator blocked (403), Anon blocked (401/403)."""
    fixture = create_exported_bundle_fixture(rbac_setup)
    case_id = fixture["case_id"]
    zip_payload = {"file": ("bundle.zip", fixture["zip_bytes"], "application/zip")}

    # 1. Owning Investigator -> 200
    res_inv1 = client.post(
        f"/api/cases/{case_id}/verify-bundle",
        files={"file": ("bundle.zip", fixture["zip_bytes"], "application/zip")},
        headers=rbac_setup["headers_inv1"]
    )
    assert res_inv1.status_code == 200, res_inv1.text

    # 2. Judge -> 200
    res_judge = client.post(
        f"/api/cases/{case_id}/verify-bundle",
        files={"file": ("bundle.zip", fixture["zip_bytes"], "application/zip")},
        headers=rbac_setup["headers_judge"]
    )
    assert res_judge.status_code == 200, res_judge.text

    # 3. Admin -> 200
    res_admin = client.post(
        f"/api/cases/{case_id}/verify-bundle",
        files={"file": ("bundle.zip", fixture["zip_bytes"], "application/zip")},
        headers=rbac_setup["headers_admin"]
    )
    assert res_admin.status_code == 200, res_admin.text

    # 4. Lawyer -> 200
    res_lawyer = client.post(
        f"/api/cases/{case_id}/verify-bundle",
        files={"file": ("bundle.zip", fixture["zip_bytes"], "application/zip")},
        headers=rbac_setup["headers_lawyer"]
    )
    assert res_lawyer.status_code == 200, res_lawyer.text

    # 5. Foreign Investigator -> 403 Forbidden
    res_inv2 = client.post(
        f"/api/cases/{case_id}/verify-bundle",
        files={"file": ("bundle.zip", fixture["zip_bytes"], "application/zip")},
        headers=rbac_setup["headers_inv2"]
    )
    assert res_inv2.status_code == 403, res_inv2.text

    # 6. Anonymous -> 401/403
    res_anon = client.post(
        f"/api/cases/{case_id}/verify-bundle",
        files={"file": ("bundle.zip", fixture["zip_bytes"], "application/zip")}
    )
    assert res_anon.status_code in (401, 403), res_anon.text


def test_nonexistent_case_404(rbac_setup):
    """13. Non-existent case returns HTTP 404."""
    non_case_id = f"CASE-NONEXISTENT-{uuid.uuid4().hex[:6]}"
    res = client.post(
        f"/api/cases/{non_case_id}/verify-bundle",
        files={"file": ("bundle.zip", b"PK\x05\x06" + b"\x00"*18, "application/zip")},
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 404, res.text


def test_single_audit_event_emission(rbac_setup):
    """14. Exactly one CASE_BUNDLE_VERIFIED audit event is emitted per verification run."""
    fixture = create_exported_bundle_fixture(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    db = SessionLocal()
    try:
        before_count = db.query(AuditLog).filter_by(
            resource_id=case_id,
            action="CASE_BUNDLE_VERIFIED"
        ).count()
    finally:
        db.close()

    res = client.post(
        f"/api/cases/{case_id}/verify-bundle",
        files={"file": ("bundle.zip", fixture["zip_bytes"], "application/zip")},
        headers=headers
    )
    assert res.status_code == 200, res.text

    db = SessionLocal()
    try:
        after_count = db.query(AuditLog).filter_by(
            resource_id=case_id,
            action="CASE_BUNDLE_VERIFIED"
        ).count()
        latest = db.query(AuditLog).filter_by(
            resource_id=case_id,
            action="CASE_BUNDLE_VERIFIED"
        ).order_by(AuditLog.timestamp.desc()).first()
    finally:
        db.close()

    assert after_count == before_count + 1
    assert latest is not None
    assert latest.meta_data.get("verification_status") == "BUNDLE_VERIFIED_AUTHENTIC"
    assert latest.meta_data.get("is_authentic") is True


def test_alias_endpoint_parity(rbac_setup):
    """15. Alias endpoint POST /api/cases/{case_id}/verify-disclosure-package matches canonical."""
    fixture = create_exported_bundle_fixture(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    res = client.post(
        f"/api/cases/{case_id}/verify-disclosure-package",
        files={"file": ("bundle.zip", fixture["zip_bytes"], "application/zip")},
        data={"notes": "Discovery disclosure verification alias"},
        headers=headers
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["case_id"] == case_id
    assert data["verification_status"] == "BUNDLE_VERIFIED_AUTHENTIC"
    assert data["is_authentic"] is True
    assert data["checks"]["all_artifacts_intact"] is True


def test_read_only_database_behavior(rbac_setup):
    """16. Verification is strictly read-only: case status, evidence, and reports are unchanged."""
    fixture = create_exported_bundle_fixture(rbac_setup)
    case_id = fixture["case_id"]
    evidence_id = fixture["evidence_id"]
    headers = rbac_setup["headers_judge"]

    db = SessionLocal()
    try:
        c_before = db.query(Case).filter_by(case_id=case_id).first()
        ev_before = db.query(Evidence).filter_by(case_id=case_id).all()
        rep_before = db.query(Report).filter_by(case_id=case_id).all()
        cust_before = db.query(CustodyEvent).filter_by(evidence_id=evidence_id).count()

        status_before = c_before.status
        ev_hashes_before = {e.evidence_id: e.sha256_hash for e in ev_before}
        rep_hashes_before = {r.report_id: r.report_sha256 for r in rep_before}
    finally:
        db.close()

    # Perform verification
    res = client.post(
        f"/api/cases/{case_id}/verify-bundle",
        files={"file": ("bundle.zip", fixture["zip_bytes"], "application/zip")},
        headers=headers
    )
    assert res.status_code == 200, res.text

    # Re-verify DB state
    db = SessionLocal()
    try:
        c_after = db.query(Case).filter_by(case_id=case_id).first()
        ev_after = db.query(Evidence).filter_by(case_id=case_id).all()
        rep_after = db.query(Report).filter_by(case_id=case_id).all()
        cust_after = db.query(CustodyEvent).filter_by(evidence_id=evidence_id).count()

        assert c_after.status == status_before
        assert {e.evidence_id: e.sha256_hash for e in ev_after} == ev_hashes_before
        assert {r.report_id: r.report_sha256 for r in rep_after} == rep_hashes_before
        assert cust_after == cust_before
    finally:
        db.close()


def test_bundle_manifest_airgap_verification_endpoint(rbac_setup):
    """17. Air-gap manifest verification endpoint POST /api/verification/bundle-manifest."""
    fixture = create_exported_bundle_fixture(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    # 1. Valid Manifest Verification
    valid_payload = {
        "case_id": case_id,
        "root_checksum": fixture["root_checksum"],
        "docket_sealing_hash": fixture["sealing_hash"],
        "notes": "Air-gap verification at courtroom registry"
    }
    res = client.post("/api/verification/bundle-manifest", json=valid_payload, headers=headers)
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["case_id"] == case_id
    assert data["verification_status"] == "BUNDLE_VERIFIED_AUTHENTIC"
    assert data["is_authentic"] is True
    assert data["docket_sealing_hash_matches"] is True
    assert data["root_checksum_matches"] is True

    # 2. Forged Sealing Hash Mismatch
    bad_seal_payload = {
        "case_id": case_id,
        "root_checksum": fixture["root_checksum"],
        "docket_sealing_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "notes": "Forged sealing hash attempt"
    }
    bad_res = client.post("/api/verification/bundle-manifest", json=bad_seal_payload, headers=headers)
    assert bad_res.status_code == 200, bad_res.text
    bad_data = bad_res.json()
    assert bad_data["verification_status"] == "UNREGISTERED_SEALING_HASH"
    assert bad_data["is_authentic"] is False
    assert bad_data["docket_sealing_hash_matches"] is False
