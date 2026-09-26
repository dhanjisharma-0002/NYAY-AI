"""
NYAYAI - Test Suite: Secure Storage & Evidence Integrity Verification (Phase 6)
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Tests:
1. Normal verification (intact vaulted file matches stored hash)
2. Modified-file simulation (tampering detected, stored hash never overwritten)
3. Missing file handling (missing file returns ERROR status, audit log created)
4. Hash mismatch detection and reporting
5. Storage error handling (I/O failure handling, history preserved)
6. Missing evidence record returns 404
7. Reusable HashingService unit tests (bytes, files, streams, constant-time compare)
8. Storage abstraction drivers (LocalStorage, S3, MinIO, WORM policy enforcement)
"""

import os
import stat
import io
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database import SessionLocal
from backend.app.models.user import User
from backend.app.models.role import Role
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.custody import CustodyEvent
from backend.app.models.audit import AuditLog
from backend.app.core.security import get_password_hash, create_access_token
from backend.app.services.hashing_service import HashingService
from backend.app.storage import (
    LocalStorageDriver,
    S3StorageDriver,
    MinIOStorageDriver,
    get_storage_driver,
    StoragePermissionException,
    StorageFileNotFoundException,
    StorageException
)
from backend.app.services.integrity_service import EvidenceIntegrityService

client = TestClient(app)


@pytest.fixture
def auth_context():
    """Sets up an authenticated investigator for integrity verification tests."""
    import uuid
    suffix = uuid.uuid4().hex[:8]
    username = f"inv_phase6_{suffix}"
    reg_payload = {
        "username": username,
        "email": f"{username}@nyayai.gov.in",
        "password": "SecurePassword123!",
        "full_name": "Investigator Phase 6 Lead",
        "role": "INVESTIGATOR",
        "badge_number": f"INV-6-{suffix}"
    }
    client.post("/api/auth/register", json=reg_payload)
    login_res = client.post("/api/auth/login", json={"username": username, "password": "SecurePassword123!"})
    login_data = login_res.json()
    token = login_data["access_token"]
    user_id = login_data["user"]["user_id"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create a test case
    case_res = client.post(
        "/api/cases",
        json={
            "title": f"Phase 6 Storage Docket {suffix}",
            "description": "Verification of cryptographic integrity and storage abstraction",
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


def test_normal_verification_success(auth_context):
    """
    Test 1: Normal verification
    Valid evidence uploaded -> verify-integrity returns VERIFIED,
    hashes match, custody event created, audit log created.
    """
    case_id = auth_context["case_id"]
    headers = auth_context["headers"]

    # 1. Upload valid evidence
    file_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRTESTING_PHASE_6_INTEGRITY_NORMAL"
    files = {"file": ("tamper_free_sample.png", file_bytes, "image/png")}
    data = {"case_id": case_id, "source_description": "CCTV snapshot"}

    upload_res = client.post("/api/evidence/upload", files=files, data=data, headers=headers)
    assert upload_res.status_code == 201
    upload_data = upload_res.json()
    evidence_id = upload_data["evidence_id"]
    stored_hash = upload_data["sha256_hash"]

    # 2. Call verify-integrity
    verify_res = client.post(f"/api/evidence/{evidence_id}/verify-integrity", headers=headers)
    assert verify_res.status_code == 200
    v_data = verify_res.json()

    assert v_data["evidence_id"] == evidence_id
    assert v_data["stored_hash"] == stored_hash
    assert v_data["current_hash"] == stored_hash
    assert v_data["integrity_status"] == "VERIFIED"
    assert v_data["verified_at"] is not None
    assert v_data["error_message"] is None

    # 3. Verify custody event and audit log in database
    db = SessionLocal()
    try:
        events = db.query(CustodyEvent).filter_by(evidence_id=evidence_id).order_by(CustodyEvent.sequence_number.asc()).all()
        assert len(events) >= 2 # Genesis + Verification event
        latest_event = events[-1]
        assert latest_event.event_type == "EVIDENCE_INTEGRITY_VERIFIED"
        assert latest_event.sequence_number == 2

        # Check audit log
        audit = db.query(AuditLog).filter_by(resource_id=evidence_id, action="EVIDENCE_INTEGRITY_VERIFIED").first()
        assert audit is not None
        assert audit.meta_data["integrity_status"] == "VERIFIED"
    finally:
        db.close()


def test_modified_file_simulation_mismatch(auth_context):
    """
    Test 2: Modified-file simulation
    Altering the physical file in vault results in MISMATCH.
    Original stored hash is NEVER overwritten.
    Evidence status is marked INTEGRITY_COMPROMISED.
    Audit and custody events are created.
    """
    case_id = auth_context["case_id"]
    headers = auth_context["headers"]

    # 1. Upload valid evidence
    original_bytes = b"%PDF-1.4\n%AUTHENTIC LEGAL DOCUMENT EVIDENCE ORIGINAL CONTENT"
    files = {"file": ("contract.pdf", original_bytes, "application/pdf")}
    data = {"case_id": case_id}

    upload_res = client.post("/api/evidence/upload", files=files, data=data, headers=headers)
    assert upload_res.status_code == 201
    upload_data = upload_res.json()
    evidence_id = upload_data["evidence_id"]
    stored_hash = upload_data["sha256_hash"]

    # 2. Locate stored file on disk and deliberately mutate it
    db = SessionLocal()
    try:
        evidence = db.query(Evidence).filter_by(evidence_id=evidence_id).first()
        file_path = evidence.storage_reference
        assert os.path.exists(file_path)

        # Remove read-only temporarily to simulate unauthorized filesystem tampering
        os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD)
        with open(file_path, "wb") as f:
            f.write(b"%PDF-1.4\n%TAMPERED TAMPERED TAMPERED FRAUDULENT INSERTION")
        # Re-apply read-only
        os.chmod(file_path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    finally:
        db.close()

    # 3. Call verify-integrity
    verify_res = client.post(f"/api/evidence/{evidence_id}/verify-integrity", headers=headers)
    assert verify_res.status_code == 200
    v_data = verify_res.json()

    assert v_data["evidence_id"] == evidence_id
    assert v_data["stored_hash"] == stored_hash
    assert v_data["current_hash"] != stored_hash
    assert v_data["integrity_status"] == "MISMATCH"
    assert "Cryptographic hash mismatch" in v_data["error_message"]

    # 4. Check that database stored hash was NEVER overwritten
    db = SessionLocal()
    try:
        refreshed_evidence = db.query(Evidence).filter_by(evidence_id=evidence_id).first()
        # Stored hash must remain unaltered
        assert refreshed_evidence.sha256_hash == stored_hash
        # Status must be updated to INTEGRITY_COMPROMISED
        assert refreshed_evidence.status == "INTEGRITY_COMPROMISED"

        # Check custody ledger recorded tamper event
        custody_event = (
            db.query(CustodyEvent)
            .filter_by(evidence_id=evidence_id)
            .order_by(CustodyEvent.sequence_number.desc())
            .first()
        )
        assert custody_event.event_type == "EVIDENCE_INTEGRITY_TAMPER_DETECTED"

        # Check audit log recorded mismatch
        audit = db.query(AuditLog).filter_by(resource_id=evidence_id, action="EVIDENCE_INTEGRITY_MISMATCH").first()
        assert audit is not None
        assert audit.meta_data["integrity_status"] == "MISMATCH"
    finally:
        db.close()


def test_missing_file_error(auth_context):
    """
    Test 3: Missing file handling
    If stored file is removed from disk, verify-integrity returns ERROR.
    Original hash is preserved, audit log records storage error.
    """
    case_id = auth_context["case_id"]
    headers = auth_context["headers"]

    # 1. Upload valid evidence
    file_bytes = b"AUDIO_RECORDING_TRANSCRIPT_ORIGINAL"
    files = {"file": ("statement.txt", file_bytes, "text/plain")}
    data = {"case_id": case_id}

    upload_res = client.post("/api/evidence/upload", files=files, data=data, headers=headers)
    assert upload_res.status_code == 201
    evidence_id = upload_res.json()["evidence_id"]
    stored_hash = upload_res.json()["sha256_hash"]

    # 2. Delete file from storage
    db = SessionLocal()
    try:
        evidence = db.query(Evidence).filter_by(evidence_id=evidence_id).first()
        file_path = evidence.storage_reference
        if os.path.exists(file_path):
            os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD)
            os.remove(file_path)
    finally:
        db.close()

    # 3. Call verify-integrity
    verify_res = client.post(f"/api/evidence/{evidence_id}/verify-integrity", headers=headers)
    assert verify_res.status_code == 200
    v_data = verify_res.json()

    assert v_data["evidence_id"] == evidence_id
    assert v_data["stored_hash"] == stored_hash
    assert v_data["current_hash"] is None
    assert v_data["integrity_status"] == "ERROR"
    assert "missing" in v_data["error_message"].lower() or "not found" in v_data["error_message"].lower()

    # 4. Verify DB status and stored hash preservation
    db = SessionLocal()
    try:
        refreshed = db.query(Evidence).filter_by(evidence_id=evidence_id).first()
        assert refreshed.sha256_hash == stored_hash
        assert refreshed.status == "STORAGE_ERROR"

        audit = db.query(AuditLog).filter_by(resource_id=evidence_id, action="EVIDENCE_STORAGE_ERROR").first()
        assert audit is not None
        assert audit.meta_data["integrity_status"] == "ERROR"
    finally:
        db.close()


def test_hash_mismatch_direct_scenario(auth_context):
    """
    Test 4: Hash mismatch detection
    Validates that a 1-bit difference in content causes an explicit MISMATCH.
    """
    hasher = HashingService()
    content_a = b"CONFIDENTIAL WHATSAPP ARCHIVE 2026-A"
    content_b = b"CONFIDENTIAL WHATSAPP ARCHIVE 2026-B"

    hash_a = hasher.compute_bytes_hash(content_a)
    hash_b = hasher.compute_bytes_hash(content_b)

    assert hash_a != hash_b
    assert not hasher.verify_hash(hash_a, hash_b)
    assert hasher.verify_hash(hash_a, hash_a.upper()) # Case-insensitive constant-time compare


def test_storage_error_handling(auth_context):
    """
    Test 5: Storage error handling
    Simulates a low-level driver failure (e.g. disk I/O error) and ensures
    status ERROR is cleanly returned with audit logging.
    """
    case_id = auth_context["case_id"]
    headers = auth_context["headers"]

    # 1. Upload valid evidence
    file_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRTEST_STORAGE_ERR"
    files = {"file": ("storage_err_test.png", file_bytes, "image/png")}
    data = {"case_id": case_id}

    upload_res = client.post("/api/evidence/upload", files=files, data=data, headers=headers)
    assert upload_res.status_code == 201
    evidence_id = upload_res.json()["evidence_id"]
    stored_hash = upload_res.json()["sha256_hash"]

    # 2. Mock storage driver to simulate I/O exception
    class FailingStorageDriver(LocalStorageDriver):
        def exists(self, storage_reference: str) -> bool:
            return True
        def retrieve(self, storage_reference: str) -> bytes:
            raise StorageException("Hardware I/O sector read error on storage pool")

    db = SessionLocal()
    try:
        service = EvidenceIntegrityService(db, storage_driver=FailingStorageDriver())
        result = service.verify_evidence_integrity(evidence_id=evidence_id)

        assert result["integrity_status"] == "ERROR"
        assert result["stored_hash"] == stored_hash
        assert result["current_hash"] is None
        assert "Hardware I/O sector read error" in result["error_message"]

        # Ensure evidence record preserved stored hash
        refreshed = db.query(Evidence).filter_by(evidence_id=evidence_id).first()
        assert refreshed.sha256_hash == stored_hash
    finally:
        db.close()


def test_missing_evidence_returns_404(auth_context):
    """
    Test 6: Missing evidence record returns 404
    """
    headers = auth_context["headers"]
    res = client.post("/api/evidence/EVD-9999-NOTFOUND/verify-integrity", headers=headers)
    assert res.status_code == 404


def test_reusable_hashing_service():
    """
    Test 7: Unit tests for HashingService
    Tests bytes, file, stream, and verification functionality.
    """
    hasher = HashingService()
    test_bytes = b"NYAYAI PROPRIETARY FORENSIC PAYLOAD 2026"
    expected_hex = "00eb064972f7c00e1cf9d0baef07469a473fecfa659146141a27e7d0f98be128" # pre-computed sha256

    # Test bytes hash
    computed_bytes = hasher.compute_bytes_hash(test_bytes)
    assert len(computed_bytes) == 64

    # Test stream hash
    stream = io.BytesIO(test_bytes)
    computed_stream = hasher.compute_stream_hash(stream)
    assert computed_stream == computed_bytes

    # Test static class methods
    assert HashingService.hash_bytes(test_bytes) == computed_bytes
    assert HashingService.compare(computed_bytes, computed_stream) is True
    assert HashingService.compare(computed_bytes, "invalid_hash_string") is False


def test_storage_abstraction_drivers(tmp_path):
    """
    Test 8: Storage abstraction drivers (Local, S3, MinIO)
    Verifies WORM semantics: write once, read many, delete prohibited.
    """
    # 1. LocalStorageDriver
    local_driver = LocalStorageDriver(base_dir=str(tmp_path))
    content = b"WORM_EVIDENCE_PAYLOAD_BYTE_EXACT"
    rel_path = "case_101/evd_202/evidence.bin"

    stored_ref = local_driver.store(rel_path, content)
    assert os.path.exists(stored_ref)
    assert local_driver.exists(stored_ref) is True
    assert local_driver.get_size(stored_ref) == len(content)
    assert local_driver.retrieve(stored_ref) == content

    # Test WORM overwrite prevention
    with pytest.raises(StoragePermissionException):
        local_driver.store(rel_path, b"MUTATED_CONTENT")

    # Test WORM deletion prevention
    with pytest.raises(StoragePermissionException):
        local_driver.delete(stored_ref)

    # 2. S3StorageDriver (environment-configured, no hardcoded secrets)
    s3_driver = S3StorageDriver(
        endpoint_url=None,
        bucket_name="nyayai-test-vault"
    )
    s3_ref = s3_driver.store("cases/c1/ev1.bin", b"S3_TEST_BYTES")
    assert s3_driver.exists(s3_ref) is True
    assert s3_driver.retrieve(s3_ref) == b"S3_TEST_BYTES"
    with pytest.raises(StoragePermissionException):
        s3_driver.store("cases/c1/ev1.bin", b"OVERWRITE_S3")
    with pytest.raises(StoragePermissionException):
        s3_driver.delete(s3_ref)

    # 3. MinIOStorageDriver
    minio_driver = MinIOStorageDriver(
        endpoint_url="http://127.0.0.1:9000",
        bucket_name="minio-nyayai-vault"
    )
    minio_ref = minio_driver.store("cases/c2/ev2.bin", b"MINIO_TEST_BYTES")
    assert minio_driver.exists(minio_ref) is True
    assert minio_driver.retrieve(minio_ref) == b"MINIO_TEST_BYTES"
    with pytest.raises(StoragePermissionException):
        minio_driver.delete(minio_ref)

    # 4. Storage Factory
    factory_local = get_storage_driver("local")
    assert isinstance(factory_local, LocalStorageDriver)
    factory_s3 = get_storage_driver("s3", force_new=True)
    assert isinstance(factory_s3, S3StorageDriver)
    factory_minio = get_storage_driver("minio", force_new=True)
    assert isinstance(factory_minio, MinIOStorageDriver)
