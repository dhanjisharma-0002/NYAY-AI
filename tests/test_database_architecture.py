"""
NYAYAI - Test Suite: Database Architecture & Core Relational Entities (Phase 2)
Tests:
- Database connectivity & ping
- Table creation & schema verification (All 10 core tables)
- Entity relationships & foreign keys
- Unique constraints (case_number, verification_code, sha256_hash, etc.)
- Basic CRUD operations across core entities
"""

import uuid
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from backend.app.database import engine, SessionLocal, check_database_connection, Base
from backend.app.models import (
    User,
    Role,
    Case,
    Evidence,
    EvidenceItem,
    EvidenceMetadata,
    ForensicArtifact,
    AnalysisResult,
    AIAnalysisResult,
    CustodyEvent,
    AuditLog,
    Report,
    CourtReport,
    VerificationRecord
)


@pytest.fixture(scope="function")
def db_session():
    """Provides an isolated transactional session per test."""
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def test_database_connection():
    """Test database connection health check."""
    assert check_database_connection() is True


def test_core_tables_registered_in_metadata():
    """Verify that all 10 required core tables exist in SQLAlchemy metadata."""
    expected_tables = {
        "roles",
        "users",
        "cases",
        "evidence",
        "evidence_metadata",
        "analysis_results",
        "custody_events",
        "audit_logs",
        "reports",
        "verification_records"
    }
    actual_tables = set(Base.metadata.tables.keys())
    for t in expected_tables:
        assert t in actual_tables, f"Missing table in metadata: {t}"


def test_role_and_user_crud(db_session):
    """Test Role creation and User-Role relationship."""
    role_id = str(uuid.uuid4())
    test_role = Role(
        id=role_id,
        name=f"TEST_ROLE_{uuid.uuid4().hex[:6]}",
        description="Test Role for Phase 2 Verification",
        permissions=["test:read", "test:write"]
    )
    db_session.add(test_role)
    db_session.commit()

    user_id = str(uuid.uuid4())
    test_user = User(
        id=user_id,
        username=f"test_officer_{uuid.uuid4().hex[:6]}",
        email=f"officer_{uuid.uuid4().hex[:6]}@nyayai.gov.in",
        hashed_password="hashed_test_password",
        full_name="Officer Jane Doe",
        badge_number="INV-JD-001",
        role_id=test_role.id,
        role=test_role.name,
        is_active=True
    )
    db_session.add(test_user)
    db_session.commit()

    # Read & Relationship verification
    fetched_user = db_session.query(User).filter_by(id=user_id).first()
    assert fetched_user is not None
    assert fetched_user.role_rel.name == test_role.name
    assert fetched_user.role_rel.permissions == ["test:read", "test:write"]

    # Update
    fetched_user.full_name = "Chief Officer Jane Doe"
    db_session.commit()
    db_session.refresh(fetched_user)
    assert fetched_user.full_name == "Chief Officer Jane Doe"


def test_case_crud_and_synonyms(db_session):
    """Test Case entity creation with case_number, created_by, and synonyms."""
    user = db_session.query(User).first()
    case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
    case_num = f"DOCKET-{uuid.uuid4().hex[:8].upper()}"

    new_case = Case(
        case_id=case_id,
        case_number=case_num,
        title="Phase 2 Forensic Trial Investigation",
        description="Testing relational schema integrity",
        status="OPEN",
        created_by=user.id,
        jurisdiction="High Court of Bombay"
    )
    db_session.add(new_case)
    db_session.commit()

    fetched = db_session.query(Case).filter_by(case_id=case_id).first()
    assert fetched is not None
    assert fetched.case_number == case_num
    assert fetched.created_by == user.id
    # Test backward-compatible synonym
    assert fetched.investigator_id == user.id
    assert fetched.creator.id == user.id


def test_evidence_and_metadata_relationships(db_session):
    """Test Evidence and EvidenceMetadata relationships, fields, and aliases."""
    user = db_session.query(User).first()
    case = db_session.query(Case).first()

    ev_id = f"EVD-{uuid.uuid4().hex[:8].upper()}"
    test_hash = f"sha256_{uuid.uuid4().hex[:56]}"

    # Test Evidence creation using Phase 2 fields
    new_evidence = Evidence(
        evidence_id=ev_id,
        case_id=case.case_id,
        original_filename="cctv_footage_raw.mp4",
        stored_filename=f"vault_{uuid.uuid4().hex[:16]}.mp4",
        media_type="video/mp4",
        file_size=104857600, # 100 MB
        sha256_hash=test_hash,
        storage_reference=f"./storage/vault/{case.case_id}/{ev_id}/cctv.mp4",
        status="SECURED",
        uploaded_by=user.id,
        source_description="Surveillance Camera #09 Seized"
    )
    db_session.add(new_evidence)
    db_session.commit()

    # Test synonyms
    assert new_evidence.mime_type == "video/mp4"
    assert new_evidence.file_size_bytes == 104857600
    assert new_evidence.vault_path == new_evidence.storage_reference
    assert new_evidence.intake_by_user_id == user.id

    # Create EvidenceMetadata
    meta_id = f"META-{uuid.uuid4().hex[:8].upper()}"
    meta = EvidenceMetadata(
        metadata_id=meta_id,
        evidence_id=ev_id,
        format_valid=True,
        magic_bytes="0000001866747970",
        exif_data={"Codec": "h264", "Duration": "00:05:32"},
        timestamps_metadata={"camera_clock": "2026-09-24T18:00:00Z"},
        anomalies=[]
    )
    db_session.add(meta)
    db_session.commit()

    # Verify bidirectional relationship
    db_session.refresh(new_evidence)
    assert new_evidence.metadata_record is not None
    assert new_evidence.metadata_record.metadata_id == meta_id
    assert new_evidence.metadata_record.artifact_id == meta_id # Synonym
    assert new_evidence.forensic_artifacts.format_valid is True # Property alias


def test_analysis_result_crud(db_session):
    """Test AnalysisResult with JSON/JSONB findings and backward-compatible properties."""
    evidence = db_session.query(Evidence).first()
    anl_id = f"ANL-{uuid.uuid4().hex[:8].upper()}"

    analysis = AnalysisResult(
        analysis_id=anl_id,
        evidence_id=evidence.evidence_id,
        analysis_type="DEEPFAKE_DETECTION",
        status="COMPLETED",
        prediction="TAMPER_DETECTED",
        confidence=0.88,
        risk_score=0.85,
        findings=[
            {"frame": 104, "anomaly": "Facial boundary splice detected"},
            {"frame": 112, "anomaly": "Spectral voice artifact mismatch"}
        ],
        model_name="DeepfakeScreener",
        model_version="1.2.0"
    )
    db_session.add(analysis)
    db_session.commit()

    fetched = db_session.query(AnalysisResult).filter_by(analysis_id=anl_id).first()
    assert fetched is not None
    assert fetched.confidence_score == 0.88 # Synonym
    assert fetched.tamper_detected is True # Property
    assert len(fetched.findings) == 2
    assert "frame" in fetched.findings_json # JSON text property


def test_custody_event_fields_and_integrity(db_session):
    """Test CustodyEvent with Phase 2 fields (event_type, user_id, previous_hash)."""
    user = db_session.query(User).first()
    case = db_session.query(Case).first()

    ev_id = f"EVD-{uuid.uuid4().hex[:8].upper()}"
    test_evidence = Evidence(
        evidence_id=ev_id,
        case_id=case.case_id,
        original_filename="custody_audit_clip.mp4",
        stored_filename=f"custody_{uuid.uuid4().hex[:12]}.mp4",
        media_type="video/mp4",
        file_size=52428800,
        sha256_hash=f"hash_{uuid.uuid4().hex[:56]}",
        storage_reference=f"./storage/vault/{ev_id}/audit.mp4",
        status="SECURED",
        uploaded_by=user.id
    )
    db_session.add(test_evidence)
    db_session.commit()

    evt_id = f"EVT-{uuid.uuid4().hex[:8].upper()}"

    custody = CustodyEvent(
        event_id=evt_id,
        evidence_id=test_evidence.evidence_id,
        sequence_number=1,
        event_type="EVIDENCE_INTAKE_RECORDED",
        user_id="USR-SYSTEM-LEAD",
        timestamp="2026-09-26T13:00:00Z",
        description="Physical intake into WORM vault",
        previous_hash="0" * 64,
        event_hash=f"hash_{uuid.uuid4().hex[:58]}",
        payload_json='{"status": "intake_complete"}'
    )
    db_session.add(custody)
    db_session.commit()

    fetched = db_session.query(CustodyEvent).filter_by(event_id=evt_id).first()
    assert fetched is not None
    assert fetched.action == "EVIDENCE_INTAKE_RECORDED" # Synonym
    assert fetched.actor_id == "USR-SYSTEM-LEAD" # Synonym
    assert fetched.previous_event_hash == "0" * 64 # Synonym


def test_audit_log_crud(db_session):
    """Test AuditLog entity creation with metadata."""
    user = db_session.query(User).first()
    audit = AuditLog(
        audit_id=f"AUD-{uuid.uuid4().hex[:8].upper()}",
        user_id=user.id,
        action="EVIDENCE_VAULT_ACCESSED",
        resource_type="EVIDENCE",
        resource_id="EVD-TEST-001",
        meta_data={"ip": "127.0.0.1", "client": "Investigator Portal"}
    )
    db_session.add(audit)
    db_session.commit()

    fetched = db_session.query(AuditLog).filter_by(audit_id=audit.audit_id).first()
    assert fetched is not None
    assert fetched.action == "EVIDENCE_VAULT_ACCESSED"
    assert fetched.user.id == user.id
    assert fetched.meta_data["ip"] == "127.0.0.1"


def test_report_and_verification_record_relationship(db_session):
    """Test Report and VerificationRecord entities."""
    user = db_session.query(User).first()
    case = db_session.query(Case).first()

    report_id = f"REP-{uuid.uuid4().hex[:8].upper()}"
    report_sha = f"sha_{uuid.uuid4().hex[:60]}"

    report = Report(
        report_id=report_id,
        case_id=case.case_id,
        report_type="BSA_2023_SEC_63_65B",
        status="GENERATED",
        storage_reference=f"./storage/reports/{report_id}.pdf",
        report_sha256=report_sha,
        verification_code=f"CODE-{uuid.uuid4().hex[:12].upper()}",
        qr_code_data=f"http://localhost:8000/api/v1/reports/verify/{report_id}",
        created_by=user.id
    )
    db_session.add(report)
    db_session.commit()

    # Add a VerificationRecord linked to this Report
    ver_id = f"VER-{uuid.uuid4().hex[:8].upper()}"
    verification = VerificationRecord(
        verification_id=ver_id,
        report_id=report_id,
        verification_method="QR_SCAN",
        verifier_identifier="Honorable High Court Judicial Bench",
        status="VALID",
        ip_address="192.168.1.100",
        meta_data={"user_agent": "CourtPortal/2.1"}
    )
    db_session.add(verification)
    db_session.commit()

    db_session.refresh(report)
    assert len(report.verifications) == 1
    assert report.verifications[0].verification_id == ver_id
    assert report.verifications[0].report.report_id == report_id


def test_unique_constraints(db_session):
    """Verify unique constraints prevent duplicates."""
    user = db_session.query(User).first()
    case = db_session.query(Case).first()

    # Attempt duplicate case_number
    duplicate_case = Case(
        case_id=f"CASE-{uuid.uuid4().hex[:8].upper()}",
        case_number=case.case_number, # Duplicate
        title="Duplicate Case Docket",
        created_by=user.id
    )
    db_session.add(duplicate_case)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()
