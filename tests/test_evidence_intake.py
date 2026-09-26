"""
NYAYAI - Test Suite: Evidence Intake Backend (Phase 5)
Tests:
1. Image upload (PNG, JPEG, WEBP)
2. PDF document upload
3. Invalid / executable extension rejection (e.g. .exe, .bat, .xyz)
4. Oversized file handling (HTTP 413)
5. Missing case handling (HTTP 404)
6. Unauthorized access (Missing token -> 401; Unauthorized role -> 403)
7. Cryptographic hash generation verification (SHA-256 matches exact bytes)
8. Duplicate upload behavior (rejection with 409 Conflict, preserving original evidence)
"""

import os
import sys
import uuid
import hashlib
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
from backend.app.config import settings
from backend.app.database import SessionLocal
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.evidence_metadata import EvidenceMetadata
from backend.app.models.custody import CustodyEvent
from backend.app.models.audit import AuditLog
from database.init_db import init_database

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_environment():
    init_database()


@pytest.fixture
def investigator_client():
    """Returns authenticated investigator credentials and auth headers."""
    suffix = uuid.uuid4().hex[:8]
    username = f"inv_intake_{suffix}"
    reg_payload = {
        "username": username,
        "email": f"{username}@nyayai.gov.in",
        "password": "Password123!",
        "full_name": "Evidence Officer",
        "role": "INVESTIGATOR",
        "badge_number": f"INV-EVD-{suffix}"
    }
    client.post("/api/auth/register", json=reg_payload)
    login_res = client.post("/api/auth/login", json={"username": username, "password": "Password123!"})
    token = login_res.json()["access_token"]
    user_id = login_res.json()["user"]["user_id"]
    return {
        "headers": {"Authorization": f"Bearer {token}"},
        "user_id": user_id,
        "username": username
    }


@pytest.fixture
def lawyer_client():
    """Returns authenticated lawyer credentials and auth headers."""
    suffix = uuid.uuid4().hex[:8]
    username = f"lawyer_intake_{suffix}"
    reg_payload = {
        "username": username,
        "email": f"{username}@nyayai.gov.in",
        "password": "Password123!",
        "full_name": "Counsel Representative",
        "role": "LAWYER"
    }
    client.post("/api/auth/register", json=reg_payload)
    login_res = client.post("/api/auth/login", json={"username": username, "password": "Password123!"})
    token = login_res.json()["access_token"]
    return {"headers": {"Authorization": f"Bearer {token}"}}


@pytest.fixture
def test_case(investigator_client):
    """Creates a fresh test case docket and returns its case_id."""
    res = client.post(
        "/api/cases",
        json={"title": "Intake Test Case Docket", "description": "Testing evidence intake"},
        headers=investigator_client["headers"]
    )
    assert res.status_code == 201
    return res.json()["data"]["case_id"]


# ==============================================================================
# 1. Image Upload Tests
# ==============================================================================

def test_image_upload_png(investigator_client, test_case):
    """
    Test POST /api/evidence/upload with PNG image.
    Verifies response structure, DB records (Evidence, EvidenceMetadata, CustodyEvent, AuditLog).
    """
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR_FORENSIC_INTAKE_TEST_PIXELS"
    expected_hash = hashlib.sha256(png_bytes).hexdigest()

    files = {"file": ("cctv_frame_01.png", png_bytes, "image/png")}
    data = {"case_id": test_case, "source_description": "Traffic junction camera #14"}

    res = client.post("/api/evidence/upload", files=files, data=data, headers=investigator_client["headers"])
    assert res.status_code == 201
    body = res.json()

    # Response verification
    assert body["case_id"] == test_case
    assert body["filename"] == "cctv_frame_01.png"
    assert body["media_type"] == "image/png"
    assert body["file_size"] == len(png_bytes)
    assert body["sha256_hash"] == expected_hash
    assert body["status"] == "SECURED"
    assert "evidence_id" in body
    assert "created_at" in body

    evidence_id = body["evidence_id"]

    # Verify database persistence across all tables
    db = SessionLocal()
    try:
        ev = db.query(Evidence).filter_by(evidence_id=evidence_id).first()
        assert ev is not None
        assert ev.sha256_hash == expected_hash
        assert ev.uploaded_by == investigator_client["user_id"]
        assert os.path.exists(ev.storage_reference)

        # EvidenceMetadata
        meta = db.query(EvidenceMetadata).filter_by(evidence_id=evidence_id).first()
        assert meta is not None
        assert meta.format_valid is True
        assert meta.magic_bytes.startswith("89504e47") # 89 P N G in hex

        # Genesis CustodyEvent
        custody = db.query(CustodyEvent).filter_by(evidence_id=evidence_id).first()
        assert custody is not None
        assert custody.sequence_number == 1
        assert custody.previous_hash == "0" * 64
        assert len(custody.event_hash) == 64

        # AuditLog
        audit = db.query(AuditLog).filter_by(resource_id=evidence_id).first()
        assert audit is not None
        assert audit.action == "EVIDENCE_UPLOADED"
        assert audit.user_id == investigator_client["user_id"]
    finally:
        db.close()


def test_image_upload_jpeg(investigator_client, test_case):
    """Test POST /api/evidence/upload with JPEG image."""
    jpg_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00_EXIF_IMAGE_TEST"
    expected_hash = hashlib.sha256(jpg_bytes).hexdigest()

    files = {"file": ("crime_scene_photo.jpg", jpg_bytes, "image/jpeg")}
    data = {"case_id": test_case}

    res = client.post("/api/evidence/upload", files=files, data=data, headers=investigator_client["headers"])
    assert res.status_code == 201
    body = res.json()
    assert body["media_type"] == "image/jpeg"
    assert body["sha256_hash"] == expected_hash


# ==============================================================================
# 2. PDF Document Upload Tests
# ==============================================================================

def test_pdf_document_upload(investigator_client, test_case):
    """Test POST /api/evidence/upload with PDF document."""
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Title (Confidential Memo) >>\nendobj\n%%EOF"
    expected_hash = hashlib.sha256(pdf_bytes).hexdigest()

    files = {"file": ("forensic_subpoena.pdf", pdf_bytes, "application/pdf")}
    data = {"case_id": test_case, "source_description": "Court warrant seizure"}

    res = client.post("/api/evidence/upload", files=files, data=data, headers=investigator_client["headers"])
    assert res.status_code == 201
    body = res.json()
    assert body["media_type"] == "application/pdf"
    assert body["filename"] == "forensic_subpoena.pdf"
    assert body["sha256_hash"] == expected_hash


# ==============================================================================
# 3. Invalid Extension & Executable Blocking Tests
# ==============================================================================

def test_invalid_extension_rejected(investigator_client, test_case):
    """Test upload with unapproved extension (e.g. .xyz) rejected with HTTP 422."""
    files = {"file": ("payload.xyz", b"arbitrary unknown format", "application/octet-stream")}
    data = {"case_id": test_case}

    res = client.post("/api/evidence/upload", files=files, data=data, headers=investigator_client["headers"])
    assert res.status_code == 422
    assert "Unsupported file type" in res.json()["message"]


def test_executable_extension_rejected(investigator_client, test_case):
    """Test upload with executable extension (.exe, .bat) rejected with HTTP 422."""
    files = {"file": ("trojan_installer.exe", b"MZ_WINDOWS_PE_EXECUTABLE", "application/x-msdownload")}
    data = {"case_id": test_case}

    res = client.post("/api/evidence/upload", files=files, data=data, headers=investigator_client["headers"])
    assert res.status_code == 422
    assert "prohibited" in res.json()["message"].lower()


def test_executable_magic_byte_masquerade_rejected(investigator_client, test_case):
    """Test file with approved extension (.png) but executable magic bytes (MZ header) is rejected."""
    fake_png_with_exe_header = b"MZ\x90\x00\x03\x00\x00\x00THIS_IS_A_WINDOWS_EXE"
    files = {"file": ("fake_image.png", fake_png_with_exe_header, "image/png")}
    data = {"case_id": test_case}

    res = client.post("/api/evidence/upload", files=files, data=data, headers=investigator_client["headers"])
    assert res.status_code == 422
    assert "executable" in res.json()["message"].lower()


# ==============================================================================
# 4. Oversized File Handling Tests
# ==============================================================================

def test_oversized_file_rejected(investigator_client, test_case, monkeypatch):
    """Test file exceeding MAX_EVIDENCE_FILE_SIZE_MB is rejected with HTTP 413."""
    # Temporarily set max upload size to 0.001 MB (~1KB)
    from backend.app.config import settings
    monkeypatch.setattr(settings, "MAX_EVIDENCE_FILE_SIZE_MB", 0.001)

    oversized_bytes = b"A" * 5000 # 5KB, exceeds 1KB
    files = {"file": ("large_clip.mp4", oversized_bytes, "video/mp4")}
    data = {"case_id": test_case}

    res = client.post("/api/evidence/upload", files=files, data=data, headers=investigator_client["headers"])
    assert res.status_code == 413
    assert res.json()["error_code"] == "FILE_OVERSIZED"


# ==============================================================================
# 5. Missing Case Tests
# ==============================================================================

def test_upload_to_missing_case_rejected(investigator_client):
    """Test upload to non-existent case_id returns HTTP 404."""
    non_existent_case = "CASE-9999-DOES-NOT-EXIST"
    files = {"file": ("sample.png", b"\x89PNG\r\n\x1a\n_VALID_BYTES", "image/png")}
    data = {"case_id": non_existent_case}

    res = client.post("/api/evidence/upload", files=files, data=data, headers=investigator_client["headers"])
    assert res.status_code == 404
    assert res.json()["error_code"] == "CASE_NOT_FOUND"


# ==============================================================================
# 6. Unauthorized Access Tests
# ==============================================================================

def test_unauthenticated_upload_rejected():
    """Test upload without Authorization header returns HTTP 401 Unauthorized."""
    files = {"file": ("unauth.png", b"\x89PNG\r\n\x1a\nBYTES", "image/png")}
    data = {"case_id": "CASE-ANY"}

    res = client.post("/api/evidence/upload", files=files, data=data)
    assert res.status_code == 401


def test_unauthorized_role_upload_rejected(lawyer_client, test_case):
    """Test upload by non-investigator role (e.g. LAWYER) returns HTTP 403 Forbidden."""
    files = {"file": ("lawyer_brief.pdf", b"%PDF-1.4_SAMPLE", "application/pdf")}
    data = {"case_id": test_case}

    res = client.post("/api/evidence/upload", files=files, data=data, headers=lawyer_client["headers"])
    assert res.status_code == 403
    assert "Access forbidden" in res.json()["message"]


# ==============================================================================
# 7. Cryptographic Hash Generation Verification
# ==============================================================================

def test_hash_generation_integrity(investigator_client, test_case):
    """Verify cryptographic SHA-256 generation matches exact byte stream."""
    test_content = b"CRITICAL_FORENSIC_STREAM_FOR_SHA256_INTEGRITY_CHECK_2026"
    exact_hash = hashlib.sha256(test_content).hexdigest()

    files = {"file": ("audit_log.txt", test_content, "text/plain")}
    data = {"case_id": test_case}

    res = client.post("/api/evidence/upload", files=files, data=data, headers=investigator_client["headers"])
    assert res.status_code == 201
    assert res.json()["sha256_hash"] == exact_hash


# ==============================================================================
# 8. Duplicate Upload Behavior
# ==============================================================================

def test_duplicate_upload_behavior(investigator_client, test_case):
    """
    Test duplicate upload behavior:
    1. First upload of file succeeds (201 Created).
    2. Second upload of identical file to the same case is detected and rejected with HTTP 409 Conflict.
    3. Verifies original file remains intact and is never replaced or overwritten.
    """
    unique_content = f"UNIQUE_CONTENT_FOR_DUPLICATE_CHECK_{uuid.uuid4().hex}".encode("utf-8")
    files1 = {"file": ("unique_evidence.txt", unique_content, "text/plain")}
    data1 = {"case_id": test_case}

    # 1. First upload: succeeds
    res1 = client.post("/api/evidence/upload", files=files1, data=data1, headers=investigator_client["headers"])
    assert res1.status_code == 201
    first_evidence_id = res1.json()["evidence_id"]
    first_hash = res1.json()["sha256_hash"]

    # 2. Second upload with identical bytes: rejected with 409 Conflict
    files2 = {"file": ("unique_evidence_reupload.txt", unique_content, "text/plain")}
    data2 = {"case_id": test_case}

    res2 = client.post("/api/evidence/upload", files=files2, data=data2, headers=investigator_client["headers"])
    assert res2.status_code == 409
    body2 = res2.json()
    assert body2["error_code"] == "DUPLICATE_EVIDENCE"
    assert "Duplicate evidence detected" in body2["message"]

    # 3. Confirm original evidence is untouched in DB
    db = SessionLocal()
    try:
        ev = db.query(Evidence).filter_by(evidence_id=first_evidence_id).first()
        assert ev is not None
        assert ev.sha256_hash == first_hash
    finally:
        db.close()
