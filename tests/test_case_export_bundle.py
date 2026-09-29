"""
NYAYAI - Test Suite: Phase 19 Case Docket Judicial Discovery & Cryptographic Export Bundle Gateway
Module: tests.test_case_export_bundle
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Comprehensive focused test suite verifying:
1. Successful judicial discovery export bundle creation (.zip on disk).
2. Archive directory structure and internal artifact hash integrity.
3. Deterministic root checksum calculation independent of ZIP metadata.
4. Validation gate: unsealed case docket rejection (HTTP 400).
5. Validation gate: empty case docket rejection (HTTP 400).
6. Validation gate: vaulted evidence file tampering rejection (HTTP 400).
7. Role-based access control (RBAC): Judge, Admin, Lawyer, Owning Investigator permitted; Foreign Investigator blocked (403), Anonymous (401/403).
8. Non-existent case docket handling (HTTP 404).
9. Exactly one CASE_BUNDLE_EXPORTED audit event per new export.
10. Cached bundle reuse on repeated requests without redundant re-zipping or audit logging.
11. Binary bundle streaming download endpoint (GET /download-bundle) with application/zip.
12. Alias endpoint POST /api/cases/{case_id}/create-disclosure-package parity.
13. Bundle manifest inspection endpoint (GET /export-bundle/manifest).
"""

import os
import io
import sys
import uuid
import json
import stat
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
                    hashed_password="hashed_placeholder_p19",
                    role=role,
                    full_name=f"Official {username.title()}",
                    badge_number=f"BADGE-{username[:4].upper()}-99",
                    is_active=True
                )
                db.add(u)
                db.commit()
                db.refresh(u)
            return u

        inv1 = get_or_create("p19_inv_lead", "INVESTIGATOR")
        inv2 = get_or_create("p19_inv_other", "INVESTIGATOR")
        admin = get_or_create("p19_admin_lead", "ADMIN")
        judge = get_or_create("p19_hon_judge", "JUDGE")
        lawyer = get_or_create("p19_advocate", "LAWYER")

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


def create_verified_sealed_case_helper(rbac_setup, suffix=None):
    """
    Creates, analyzes, reports, seals, and admissibility-verifies a case docket.
    Returns case metadata ready for judicial export bundle packaging.
    """
    if not suffix:
        suffix = uuid.uuid4().hex[:6].upper()
    headers = rbac_setup["headers_inv1"]

    # 1. Create Case Docket
    c_res = client.post(
        "/api/cases",
        json={
            "title": f"Discovery Export Case {suffix}",
            "description": "Evidence docket for complete trial disclosure packaging",
            "jurisdiction": "High Court of Delhi"
        },
        headers=headers
    )
    assert c_res.status_code == 201, c_res.text
    case_id = c_res.json()["data"]["case_id"]

    # 2. Upload Evidence 1 (PNG image)
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRP19_IMG_BYTES"
    up1 = client.post(
        "/api/evidence/upload",
        files={"file": ("evidence1.png", png_bytes, "image/png")},
        data={"case_id": case_id, "source_description": "Traffic Cam 1"},
        headers=headers
    )
    assert up1.status_code == 201, up1.text
    ev1_id = up1.json()["evidence_id"]

    # 3. Upload Evidence 2 (WAV audio)
    wav_bytes = b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00P19_AUDIO"
    up2 = client.post(
        "/api/evidence/upload",
        files={"file": ("evidence2.wav", wav_bytes, "audio/wav")},
        data={"case_id": case_id, "source_description": "Wiretap Intercept"},
        headers=headers
    )
    assert up2.status_code == 201, up2.text
    ev2_id = up2.json()["evidence_id"]

    # 4. Batch Pipeline Analysis
    pipe_res = client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers)
    assert pipe_res.status_code == 200, pipe_res.text

    # 5. Court Admissibility Report Generation
    rep_res = client.post(
        f"/api/reports/generate/{case_id}",
        json={
            "certifying_officer_name": "Official Lead Investigator",
            "certifying_officer_designation": "Forensic Investigator",
            "badge_number": "BADGE-INV-99",
            "jurisdiction": "High Court of Delhi"
        },
        headers=headers
    )
    assert rep_res.status_code in (200, 201), rep_res.text

    # 6. Case Finalization & Sealing (Phase 17)
    fin_res = client.post(
        f"/api/cases/{case_id}/finalize",
        json={
            "certification_notes": "Forensic and custody validation complete.",
            "certifying_officer_name": "Official Lead Investigator",
            "badge_number": "BADGE-INV-99"
        },
        headers=headers
    )
    assert fin_res.status_code == 200, fin_res.text
    sealing_data = fin_res.json()

    # 7. Judicial Admissibility Verification (Phase 18)
    ver_res = client.post(
        f"/api/cases/{case_id}/verify-admissibility",
        json={"court_bench": "Division Bench I", "judicial_officer_name": "Justice Verma"},
        headers=rbac_setup["headers_judge"]
    )
    assert ver_res.status_code == 200, ver_res.text
    assert ver_res.json()["is_admissible"] is True

    return {
        "case_id": case_id,
        "evidence_ids": [ev1_id, ev2_id],
        "sealing_hash": sealing_data["docket_sealing_hash"],
        "headers": headers
    }


# =============================================================================
# TESTS
# =============================================================================

def test_successful_export_bundle_generation(rbac_setup):
    """1. Generates complete, valid ZIP discovery bundle on disk with expected artifacts."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    payload = {
        "purpose": "Trial Evidence Tender under BSA Section 63",
        "recipient_court_or_agency": "Sessions Court, New Delhi",
        "authorized_officer_name": "Public Prosecutor S. Sharma"
    }

    res = client.post(f"/api/cases/{case_id}/export-bundle", json=payload, headers=headers)
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["case_id"] == case_id
    assert data["cached"] is False
    assert data["admissibility_status"] == "ADMISSIBLE"
    assert data["docket_sealing_hash"] == fixture["sealing_hash"]
    assert len(data["root_checksum"]) == 64
    assert data["total_artifacts"] >= 8
    assert data["bundle_filename"].endswith(".zip")
    assert data["bundle_file_size"] > 0
    assert data["download_url"] == f"/api/cases/{case_id}/download-bundle"

    # Verify all mandatory artifact paths are recorded
    paths = [a["path"] for a in data["artifacts"]]
    assert "manifest.json" in paths
    assert "admissibility_certificate.json" in paths
    assert "custody/custody_ledger.json" in paths
    assert "custody/events_timeline.json" in paths
    assert "reports/reports_index.json" in paths
    assert "audit/case_audit_trail.json" in paths
    assert "DISCOVERY_BUNDLE_CHECKSUM.sha256" in paths
    assert any(p.startswith("evidence/") for p in paths)
    assert any(p.startswith("reports/") and p.endswith(".pdf") for p in paths)


def test_bundle_structure_and_artifact_hashes(rbac_setup):
    """2. ZIP archive matches on-disk file contents and constituent SHA-256 hashes."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    res = client.post(f"/api/cases/{case_id}/export-bundle", headers=headers)
    assert res.status_code == 200
    manifest_data = res.json()

    # Download binary zip to inspect internal structure
    dl_res = client.get(f"/api/cases/{case_id}/download-bundle", headers=headers)
    assert dl_res.status_code == 200

    zip_bytes = io.BytesIO(dl_res.content)
    assert zipfile.is_zipfile(zip_bytes)

    with zipfile.ZipFile(zip_bytes, "r") as zf:
        namelist = zf.namelist()
        assert "manifest.json" in namelist
        assert "DISCOVERY_BUNDLE_CHECKSUM.sha256" in namelist
        assert "admissibility_certificate.json" in namelist

        # Verify each artifact inside the zip against the hash recorded in manifest
        artifact_map = {a["path"]: a["sha256"] for a in manifest_data["artifacts"]}
        for name in namelist:
            if name in artifact_map:
                file_content = zf.read(name)
                calc_hash = hashlib.sha256(file_content).hexdigest().lower()
                assert calc_hash == artifact_map[name], f"Hash mismatch for enclosed file: {name}"


def test_deterministic_root_checksum(rbac_setup):
    """3. Root checksum matches deterministic SHA-256 over alphabetically sorted artifact paths & hashes."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    res = client.post(f"/api/cases/{case_id}/export-bundle", headers=headers)
    assert res.status_code == 200
    data = res.json()

    # Download bundle and extract DISCOVERY_BUNDLE_CHECKSUM.sha256
    dl_res = client.get(f"/api/cases/{case_id}/download-bundle", headers=headers)
    assert dl_res.status_code == 200

    with zipfile.ZipFile(io.BytesIO(dl_res.content), "r") as zf:
        checksum_content = zf.read("DISCOVERY_BUNDLE_CHECKSUM.sha256").decode("utf-8")

    # Filter out comments and blank lines
    entry_lines = [line.strip() for line in checksum_content.splitlines() if line.strip() and not line.startswith("#")]
    assert len(entry_lines) >= 7

    # Ensure entries are sorted alphabetically by path
    paths_in_checksum = [line.split("  ")[1] for line in entry_lines]
    assert paths_in_checksum == sorted(paths_in_checksum)

    # Re-compute root checksum from canonical body
    recomputed_root = hashlib.sha256("\n".join(entry_lines).encode("utf-8")).hexdigest().lower()
    assert recomputed_root == data["root_checksum"]


def test_unsealed_case_rejection(rbac_setup):
    """4. Unsealed / open case docket cannot be exported (HTTP 400)."""
    headers = rbac_setup["headers_inv1"]
    c_res = client.post(
        "/api/cases",
        json={"title": "Unsealed Export Test", "jurisdiction": "Delhi"},
        headers=headers
    )
    assert c_res.status_code == 201
    case_id = c_res.json()["data"]["case_id"]

    res = client.post(f"/api/cases/{case_id}/export-bundle", headers=headers)
    assert res.status_code == 400
    assert "UNSEALED" in res.text or "sealed" in res.text.lower()


def test_empty_case_rejection(rbac_setup):
    """5. Empty case docket cannot be exported (HTTP 400)."""
    headers = rbac_setup["headers_inv1"]
    c_res = client.post(
        "/api/cases",
        json={"title": "Empty Case Export Test", "jurisdiction": "Delhi"},
        headers=headers
    )
    assert c_res.status_code == 201
    case_id = c_res.json()["data"]["case_id"]

    # Mark as completed in DB to isolate empty check
    db = SessionLocal()
    try:
        case = db.query(Case).filter_by(case_id=case_id).first()
        case.status = "COMPLETED"
        db.commit()
    finally:
        db.close()

    res = client.post(f"/api/cases/{case_id}/export-bundle", headers=headers)
    assert res.status_code == 400
    assert "EMPTY_CASE" in res.text or "zero" in res.text.lower()


def test_vault_tamper_rejection(rbac_setup):
    """6. Corrupted evidence vault file triggers pre-export integrity rejection (HTTP 400)."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    ev1_id = fixture["evidence_ids"][0]

    # Tamper with evidence 1 file in storage
    db = SessionLocal()
    try:
        ev1 = db.query(Evidence).filter_by(evidence_id=ev1_id).first()
        assert ev1 is not None
        assert os.path.exists(ev1.storage_reference)
        os.chmod(ev1.storage_reference, stat.S_IWRITE)
        with open(ev1.storage_reference, "wb") as f:
            f.write(b"TAMPERED_PHYSICAL_BYTES_FOR_BUNDLE_EXPORT")
    finally:
        db.close()

    res = client.post(
        f"/api/cases/{case_id}/export-bundle",
        json={"force_repackage": True},
        headers=rbac_setup["headers_judge"]
    )
    assert res.status_code == 400
    assert "EVIDENCE_TAMPERED" in res.text or "tamper" in res.text.lower()


def test_role_based_access_control(rbac_setup):
    """7. Strict RBAC: Judge, Admin, Lawyer, Owning Investigator permitted; Foreign Investigator forbidden."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]

    # 1. JUDGE - Permitted (200)
    res_judge = client.post(f"/api/cases/{case_id}/export-bundle", headers=rbac_setup["headers_judge"])
    assert res_judge.status_code == 200

    # 2. ADMIN - Permitted (200)
    res_admin = client.post(f"/api/cases/{case_id}/export-bundle", headers=rbac_setup["headers_admin"])
    assert res_admin.status_code == 200

    # 3. LAWYER - Permitted for legal discovery (200)
    res_lawyer = client.post(f"/api/cases/{case_id}/export-bundle", headers=rbac_setup["headers_lawyer"])
    assert res_lawyer.status_code == 200

    # 4. Owning INVESTIGATOR (inv1) - Permitted (200)
    res_inv1 = client.post(f"/api/cases/{case_id}/export-bundle", headers=rbac_setup["headers_inv1"])
    assert res_inv1.status_code == 200

    # 5. Non-owning INVESTIGATOR (inv2) - Forbidden (403)
    res_inv2 = client.post(f"/api/cases/{case_id}/export-bundle", headers=rbac_setup["headers_inv2"])
    assert res_inv2.status_code == 403

    # 6. Anonymous (No token) - Unauthorized (401 or 403)
    res_anon = client.post(f"/api/cases/{case_id}/export-bundle")
    assert res_anon.status_code in (401, 403)


def test_case_not_found_404(rbac_setup):
    """8. Non-existent case returns HTTP 404."""
    non_existent = f"CASE-DOESNOTEXIST-{uuid.uuid4().hex[:6]}"
    res = client.post(f"/api/cases/{non_existent}/export-bundle", headers=rbac_setup["headers_judge"])
    assert res.status_code == 404


def test_single_export_audit_log(rbac_setup):
    """9. Exactly one CASE_BUNDLE_EXPORTED audit log is recorded per fresh bundle creation."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]

    db = SessionLocal()
    try:
        initial_count = (
            db.query(AuditLog)
            .filter_by(resource_id=case_id, action="CASE_BUNDLE_EXPORTED")
            .count()
        )
    finally:
        db.close()
    assert initial_count == 0

    res = client.post(f"/api/cases/{case_id}/export-bundle", headers=rbac_setup["headers_judge"])
    assert res.status_code == 200
    data = res.json()

    db2 = SessionLocal()
    try:
        audits = (
            db2.query(AuditLog)
            .filter_by(resource_id=case_id, action="CASE_BUNDLE_EXPORTED")
            .all()
        )
        assert len(audits) == 1
        log = audits[0]
        assert log.meta_data["root_checksum"] == data["root_checksum"]
        assert log.meta_data["docket_sealing_hash"] == data["docket_sealing_hash"]
        assert log.meta_data["bundle_filename"] == data["bundle_filename"]
    finally:
        db2.close()


def test_cached_bundle_reuse(rbac_setup):
    """10. Repeated requests serve cached bundle without re-compression or duplicate audit logs."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    # First call: Generates bundle (cached = False)
    res1 = client.post(f"/api/cases/{case_id}/export-bundle", headers=headers)
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["cached"] is False

    # Second call: Serves cached bundle (cached = True)
    res2 = client.post(f"/api/cases/{case_id}/export-bundle", headers=headers)
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["cached"] is True
    assert data2["root_checksum"] == data1["root_checksum"]
    assert data2["bundle_filename"] == data1["bundle_filename"]

    # Verify no second audit log was emitted for cached retrieval
    db = SessionLocal()
    try:
        count = (
            db.query(AuditLog)
            .filter_by(resource_id=case_id, action="CASE_BUNDLE_EXPORTED")
            .count()
        )
        assert count == 1
    finally:
        db.close()

    # Force repackage call: Generates fresh bundle (cached = False)
    res3 = client.post(
        f"/api/cases/{case_id}/export-bundle",
        json={"force_repackage": True},
        headers=headers
    )
    assert res3.status_code == 200
    data3 = res3.json()
    assert data3["cached"] is False


def test_download_bundle_endpoint(rbac_setup):
    """11. GET /api/cases/{case_id}/download-bundle streams valid application/zip."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    # Ensure bundle exists
    client.post(f"/api/cases/{case_id}/export-bundle", headers=headers)

    res = client.get(f"/api/cases/{case_id}/download-bundle", headers=headers)
    assert res.status_code == 200
    assert "application/zip" in res.headers["content-type"]
    assert "attachment" in res.headers.get("content-disposition", "")
    assert len(res.content) > 0

    with zipfile.ZipFile(io.BytesIO(res.content), "r") as zf:
        assert "manifest.json" in zf.namelist()


def test_create_disclosure_package_alias_parity(rbac_setup):
    """12. Alias POST /create-disclosure-package returns identical payload to /export-bundle."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    res_alias = client.post(f"/api/cases/{case_id}/create-disclosure-package", headers=headers)
    assert res_alias.status_code == 200
    data_alias = res_alias.json()

    assert data_alias["case_id"] == case_id
    assert data_alias["admissibility_status"] == "ADMISSIBLE"
    assert len(data_alias["root_checksum"]) == 64


def test_bundle_manifest_endpoint(rbac_setup):
    """13. GET /api/cases/{case_id}/export-bundle/manifest inspects manifest and root checksum."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    # 1. Export bundle first
    res_exp = client.post(f"/api/cases/{case_id}/export-bundle", headers=headers)
    assert res_exp.status_code == 200
    exp_data = res_exp.json()

    # 2. Inspect manifest via GET
    res_man = client.get(f"/api/cases/{case_id}/export-bundle/manifest", headers=headers)
    assert res_man.status_code == 200
    man_data = res_man.json()

    assert man_data["case_id"] == case_id
    assert man_data["root_checksum"] == exp_data["root_checksum"]
    assert man_data["total_artifacts"] == exp_data["total_artifacts"]
    assert man_data["docket_sealing_hash"] == exp_data["docket_sealing_hash"]


# =============================================================================
# PHASE 19 SECURITY REVIEW TESTS
# =============================================================================

def test_zip_path_safety_traversal_prevention(rbac_setup):
    """14. Security: Evidence original filenames cannot create ../, absolute paths, or escape evidence/."""
    headers = rbac_setup["headers_inv1"]
    suffix = uuid.uuid4().hex[:6].upper()

    # 1. Create Case Docket
    c_res = client.post(
        "/api/cases",
        json={"title": f"Traversal Security Case {suffix}", "jurisdiction": "Delhi"},
        headers=headers
    )
    assert c_res.status_code == 201
    case_id = c_res.json()["data"]["case_id"]

    # 2. Upload Evidence with malicious path traversal in filename
    malicious_filename = "../../../etc/cron.d/malicious_payload.png"
    up = client.post(
        "/api/evidence/upload",
        files={"file": (malicious_filename, b"\x89PNG\r\n\x1a\nTRAVERSAL_TEST", "image/png")},
        data={"case_id": case_id},
        headers=headers
    )
    assert up.status_code == 201

    # Pipeline, report, finalize, verify
    client.post(f"/api/cases/{case_id}/process-pipeline", headers=headers)
    client.post(f"/api/reports/generate/{case_id}", headers=headers)
    client.post(
        f"/api/cases/{case_id}/finalize",
        json={"certifying_officer_name": "Official Lead Investigator"},
        headers=headers
    )
    client.post(f"/api/cases/{case_id}/verify-admissibility", headers=rbac_setup["headers_judge"])

    # 3. Export bundle
    res = client.post(f"/api/cases/{case_id}/export-bundle", headers=rbac_setup["headers_judge"])
    assert res.status_code == 200
    data = res.json()

    # 4. Download and inspect all ZIP entry paths
    dl_res = client.get(f"/api/cases/{case_id}/download-bundle", headers=rbac_setup["headers_judge"])
    assert dl_res.status_code == 200

    with zipfile.ZipFile(io.BytesIO(dl_res.content), "r") as zf:
        for name in zf.namelist():
            assert not name.startswith("/"), f"Absolute path detected in zip: {name}"
            assert ".." not in name, f"Path traversal sequence detected in zip: {name}"
            if name.endswith(".png"):
                assert name.startswith("evidence/"), f"Evidence file not strictly contained under evidence/: {name}"


def test_corrupted_cached_zip_auto_recovery(rbac_setup):
    """15. Security: Corrupted or truncated cached ZIP is not blindly trusted; auto-recovers fresh."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]
    headers = rbac_setup["headers_judge"]

    # Export bundle once to populate cache
    res1 = client.post(f"/api/cases/{case_id}/export-bundle", headers=headers)
    assert res1.status_code == 200

    # Locate and corrupt cached ZIP on disk (truncate to 0 bytes)
    bundle_filename = res1.json()["bundle_filename"]
    from backend.app.config import settings
    bundle_path = os.path.join(settings.EVIDENCE_VAULT_PATH, case_id, "bundles", bundle_filename)
    assert os.path.exists(bundle_path)

    with open(bundle_path, "wb") as f:
        f.write(b"CORRUPTED_NON_ZIP_BYTES")

    # Download request should detect invalid ZIP, auto-recover fresh, and serve a valid archive
    dl_res = client.get(f"/api/cases/{case_id}/download-bundle", headers=headers)
    assert dl_res.status_code == 200
    assert zipfile.is_zipfile(io.BytesIO(dl_res.content)), "Did not recover valid zip on corrupted cache"


def test_force_repackage_rbac_security(rbac_setup):
    """16. Security: force_repackage cannot bypass RBAC, and normal cache hits emit 0 duplicate audits."""
    fixture = create_verified_sealed_case_helper(rbac_setup)
    case_id = fixture["case_id"]

    # 1. Foreign investigator cannot bypass RBAC with force_repackage=True
    res_bad = client.post(
        f"/api/cases/{case_id}/export-bundle",
        json={"force_repackage": True},
        headers=rbac_setup["headers_inv2"]
    )
    assert res_bad.status_code == 403

    # 2. Legitimate export
    res_good = client.post(f"/api/cases/{case_id}/export-bundle", headers=rbac_setup["headers_judge"])
    assert res_good.status_code == 200

    # Check audit count
    db = SessionLocal()
    try:
        count1 = db.query(AuditLog).filter_by(resource_id=case_id, action="CASE_BUNDLE_EXPORTED").count()
    finally:
        db.close()
    assert count1 == 1

    # Repeated calls on cached bundle
    client.post(f"/api/cases/{case_id}/export-bundle", headers=rbac_setup["headers_judge"])
    client.get(f"/api/cases/{case_id}/export-bundle/manifest", headers=rbac_setup["headers_judge"])

    # Audit count must still be exactly 1
    db2 = SessionLocal()
    try:
        count2 = db2.query(AuditLog).filter_by(resource_id=case_id, action="CASE_BUNDLE_EXPORTED").count()
    finally:
        db2.close()
    assert count2 == 1

