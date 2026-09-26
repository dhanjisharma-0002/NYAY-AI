"""
NYAYAI - Test Suite: Evidence Correlation Integration (Phase 9)
Lead: Ridhi Mashi (Evidence Intelligence & Chain-of-Custody Engineer)
Integration Lead: Dhananjay Sharma (Backend & System Integration Lead)

Comprehensive Test Suite Verifying:
1. case with multiple evidence items: Cross-evidence timeline, relationships, matches, and red flags.
2. empty case: Graceful handling of dockets with 0 evidence artifacts.
3. timestamp ordering: Strictly chronological timeline; no invented/synthetic timestamps (null/unknown preserved).
4. relationship retrieval: Evidence A -> related_to -> Evidence B with stored reason.
5. red flag retrieval: Objective, evidence-based red flags (timestamp inconsistency, hash mismatch, duplicate evidence, analysis anomaly) with zero criminality claims.
6. security & boundaries: 401 for unauthenticated calls, 404 for nonexistent cases.
"""

import os
import sys
import uuid
import hashlib
import json
from datetime import datetime, timezone, timedelta
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
from backend.app.database import SessionLocal
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.evidence_metadata import EvidenceMetadata
from backend.app.models.analysis_result import AnalysisResult
from backend.app.models.custody import CustodyEvent
from database.init_db import init_database

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_environment():
    """Initializes the database schema before test execution."""
    init_database()


@pytest.fixture
def auth_context():
    """Creates authenticated investigator and lawyer credentials."""
    suffix = uuid.uuid4().hex[:8]

    # Investigator
    inv_user = f"inv_corr_{suffix}"
    client.post("/api/auth/register", json={
        "username": inv_user,
        "email": f"{inv_user}@nyayai.gov.in",
        "password": "Password123!",
        "full_name": "Detective Sharma",
        "role": "INVESTIGATOR",
        "badge_number": f"INV-CORR-{suffix}"
    })
    inv_login = client.post("/api/auth/login", json={"username": inv_user, "password": "Password123!"})
    inv_token = inv_login.json()["access_token"]
    inv_id = inv_login.json()["user"]["user_id"]

    # Lawyer
    lawyer_user = f"lawyer_corr_{suffix}"
    client.post("/api/auth/register", json={
        "username": lawyer_user,
        "email": f"{lawyer_user}@nyayai.gov.in",
        "password": "Password123!",
        "full_name": "Advocate Verma",
        "role": "LAWYER"
    })
    lawyer_login = client.post("/api/auth/login", json={"username": lawyer_user, "password": "Password123!"})
    lawyer_token = lawyer_login.json()["access_token"]

    return {
        "inv_headers": {"Authorization": f"Bearer {inv_token}"},
        "inv_id": inv_id,
        "lawyer_headers": {"Authorization": f"Bearer {lawyer_token}"}
    }


@pytest.fixture
def fresh_case(auth_context):
    """Creates a new case docket."""
    res = client.post(
        "/api/cases",
        json={"title": "Operation Midnight Nexus", "description": "Correlation and intelligence verification docket"},
        headers=auth_context["inv_headers"]
    )
    assert res.status_code == 201
    return res.json()["data"]["case_id"]


# ==============================================================================
# 1. Empty Case Test
# ==============================================================================

def test_empty_case_correlation(auth_context, fresh_case):
    """
    Test 1: Empty Case Handling
    - Querying a case with 0 evidence items must succeed with 200 OK
    - Returns empty lists for timeline, relationships, cross_evidence_matches, and red_flags
    - total_evidence_count == 0, total_red_flags == 0
    """
    res = client.get(f"/api/correlation/case/{fresh_case}", headers=auth_context["inv_headers"])
    assert res.status_code == 200
    data = res.json()

    assert data["success"] is True
    assert data["case_id"] == fresh_case
    assert data["total_evidence_count"] == 0
    assert data["total_red_flags"] == 0
    assert isinstance(data["timeline"], list)
    assert len(data["timeline"]) == 0
    assert isinstance(data["relationships"], list)
    assert len(data["relationships"]) == 0
    assert isinstance(data["cross_evidence_matches"], list)
    assert len(data["cross_evidence_matches"]) == 0
    assert isinstance(data["red_flags"], list)
    assert len(data["red_flags"]) == 0


# ==============================================================================
# 2. Case with Multiple Evidence Items Test
# ==============================================================================

def test_case_with_multiple_evidence_items(auth_context, fresh_case):
    """
    Test 2: Case with Multiple Evidence Items
    - Ingests multiple evidence artifacts into the same case
    - Verifies populated timeline, relationships, matches, and red flags
    """
    headers = auth_context["inv_headers"]

    # Evidence 1: Image from Camera 14
    img_bytes1 = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR_FRAME_ALPHA_01"
    res1 = client.post(
        "/api/evidence/upload",
        files={"file": ("cctv_frame_alpha.png", img_bytes1, "image/png")},
        data={"case_id": fresh_case, "source_description": "Traffic junction camera #14"},
        headers=headers
    )
    assert res1.status_code == 201
    ev1_id = res1.json()["evidence_id"]

    # Evidence 2: PDF Document from Investigation Bureau
    pdf_bytes = b"%PDF-1.4\n%Digital Forensic Report Seizure Log Document"
    res2 = client.post(
        "/api/evidence/upload",
        files={"file": ("seizure_memo.pdf", pdf_bytes, "application/pdf")},
        data={"case_id": fresh_case, "source_description": "Field Officer Memo"},
        headers=headers
    )
    assert res2.status_code == 201
    ev2_id = res2.json()["evidence_id"]

    # Evidence 3: Image from Camera 14 (same source device)
    img_bytes2 = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR_FRAME_BETA_02"
    res3 = client.post(
        "/api/evidence/upload",
        files={"file": ("cctv_frame_beta.png", img_bytes2, "image/png")},
        data={"case_id": fresh_case, "source_description": "Traffic junction camera #14"},
        headers=headers
    )
    assert res3.status_code == 201
    ev3_id = res3.json()["evidence_id"]

    # Query Case Correlation API
    res = client.get(f"/api/correlation/case/{fresh_case}", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["case_id"] == fresh_case
    assert data["total_evidence_count"] >= 3

    # 1. Timeline verification
    timeline = data["timeline"]
    assert len(timeline) >= 3
    timeline_ev_ids = [t["evidence_id"] for t in timeline]
    assert ev1_id in timeline_ev_ids
    assert ev2_id in timeline_ev_ids
    assert ev3_id in timeline_ev_ids

    # 2. Relationships verification
    relationships = data["relationships"]
    assert len(relationships) >= 1

    # Verify that Evidence 1 and Evidence 3 are linked via SAME_SOURCE_DEVICE
    source_links = [
        r for r in relationships
        if r["relationship_type"] == "SAME_SOURCE_DEVICE"
        and {r["source_evidence_id"], r["target_evidence_id"]} == {ev1_id, ev3_id}
    ]
    assert len(source_links) >= 1
    rel = source_links[0]
    assert rel["related_to"] == rel["target_evidence_id"]
    assert "Traffic junction camera #14" in rel["reason"]

    # 3. Cross-evidence matches verification
    matches = data["cross_evidence_matches"]
    assert len(matches) >= 1
    assert any(m["matched_attribute"] == "source_description" for m in matches)


# ==============================================================================
# 3. Timestamp Ordering and No-Invention Tests
# ==============================================================================

def test_timestamp_ordering_and_no_invention(auth_context, fresh_case):
    """
    Test 3: Timestamp Ordering and No-Invention Guarantee
    - Verifies timeline entries with valid timestamps are strictly in ascending chronological order
    - Verifies missing timestamps are preserved as None/null without inventing synthetic values
    """
    headers = auth_context["inv_headers"]

    # Ingest evidence
    res1 = client.post(
        "/api/evidence/upload",
        files={"file": ("log_order_check.txt", b"Incident Log Sequence Check Content", "text/plain")},
        data={"case_id": fresh_case},
        headers=headers
    )
    assert res1.status_code == 201

    res = client.get(f"/api/correlation/case/{fresh_case}", headers=headers)
    assert res.status_code == 200
    timeline = res.json()["timeline"]

    # Verify chronological ordering
    parsed_timestamps = []
    for item in timeline:
        ts = item.get("timestamp")
        if ts is not None:
            clean_ts = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_ts)
            if not dt.tzinfo:
                dt = dt.replace(tzinfo=timezone.utc)
            parsed_timestamps.append(dt)

    # All parsed timestamps must be monotonically non-decreasing
    for i in range(1, len(parsed_timestamps)):
        assert parsed_timestamps[i] >= parsed_timestamps[i - 1], (
            f"Timestamp order inversion: {parsed_timestamps[i]} < {parsed_timestamps[i - 1]}"
        )

    # Test no invention: direct engine check with missing timestamp
    from correlation import BaselineCorrelationEngine
    engine = BaselineCorrelationEngine()
    test_items = [
        {"evidence_id": "EVD-KNOWN", "created_at": "2026-09-26T12:00:00Z"},
        {"evidence_id": "EVD-UNKNOWN", "created_at": None}  # Timestamp missing
    ]
    res_engine = engine.correlate_case_evidence("CASE-TEST", test_items)
    timeline_engine = res_engine["timeline"]
    unknown_item = next(t for t in timeline_engine if t["evidence_id"] == "EVD-UNKNOWN")

    # MUST be None / null, NOT invented!
    assert unknown_item["timestamp"] is None, "Engine invented a timestamp for missing date!"


# ==============================================================================
# 4. Relationship Retrieval Tests
# ==============================================================================

def test_relationship_retrieval(auth_context, fresh_case):
    """
    Test 4: Relationship Representation
    - Evidence A -> related_to -> Evidence B
    - Stores the relationship reason
    - Checks shared source device and media format relationships
    """
    headers = auth_context["inv_headers"]

    # Upload A: Frame 1 from Traffic Cam 99
    content_a = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR_CAM_99_FRAME_A"
    res_a = client.post(
        "/api/evidence/upload",
        files={"file": ("cam99_01.png", content_a, "image/png")},
        data={"case_id": fresh_case, "source_description": "Traffic junction camera #99"},
        headers=headers
    )
    assert res_a.status_code == 201
    id_a = res_a.json()["evidence_id"]

    # Upload B: Frame 2 from Traffic Cam 99
    content_b = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR_CAM_99_FRAME_B"
    res_b = client.post(
        "/api/evidence/upload",
        files={"file": ("cam99_02.png", content_b, "image/png")},
        data={"case_id": fresh_case, "source_description": "Traffic junction camera #99"},
        headers=headers
    )
    assert res_b.status_code == 201
    id_b = res_b.json()["evidence_id"]

    # Query Correlation
    res = client.get(f"/api/correlation/case/{fresh_case}", headers=headers)
    assert res.status_code == 200
    relationships = res.json()["relationships"]

    # Verify source device relationship
    source_rel = next(
        (r for r in relationships if r["relationship_type"] == "SAME_SOURCE_DEVICE" and {r["source_evidence_id"], r["target_evidence_id"]} == {id_a, id_b}),
        None
    )
    assert source_rel is not None, "Failed to retrieve SAME_SOURCE_DEVICE relationship"

    # Verify required relationship representation
    assert source_rel["source_evidence_id"] in (id_a, id_b)
    assert source_rel["target_evidence_id"] in (id_a, id_b)
    assert source_rel["related_to"] == source_rel["target_evidence_id"]
    assert len(source_rel["reason"]) > 10, "Relationship reason is missing or too short"
    assert "Traffic junction camera #99" in source_rel["reason"]
    assert source_rel["confidence"] > 0.0

    # Also test IDENTICAL_FILE_HASH relationship via engine directly
    from correlation import BaselineCorrelationEngine
    engine = BaselineCorrelationEngine()
    test_evidence = [
        {"evidence_id": "EVD-ALPHA", "sha256_hash": "a" * 64, "filename": "clone1.png"},
        {"evidence_id": "EVD-BETA", "sha256_hash": "a" * 64, "filename": "clone2.png"}
    ]
    engine_res = engine.correlate_case_evidence("CASE-TEST", test_evidence)
    hash_rel = engine_res["relationships"][0]
    assert hash_rel["relationship_type"] == "IDENTICAL_FILE_HASH"
    assert hash_rel["related_to"] == "EVD-BETA"
    assert "identical" in hash_rel["reason"].lower()


# ==============================================================================
# 5. Red Flag Retrieval Tests (Strict: No criminality claims)
# ==============================================================================

def test_red_flag_retrieval_and_no_criminality_claims(auth_context, fresh_case):
    """
    Test 5: Red Flag Retrieval
    - Verifies evidence-based red flags:
      1. Duplicate evidence
      2. Hash mismatch (integrity compromise)
      3. Timestamp inconsistency
      4. Metadata inconsistency
      5. Analysis anomaly
    - Verifies strict compliance: 'Do not claim criminality'
    """
    headers = auth_context["inv_headers"]

    # Upload evidence item
    sample_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR_FLAG_TEST_PIXELS"
    expected_hash = hashlib.sha256(sample_bytes).hexdigest()

    res = client.post(
        "/api/evidence/upload",
        files={"file": ("red_flag_primary.png", sample_bytes, "image/png")},
        data={"case_id": fresh_case, "source_description": "Suspect Device Extraction"},
        headers=headers
    )
    assert res.status_code == 201
    primary_ev_id = res.json()["evidence_id"]

    # Simulate realistic case anomalies directly in DB
    db = SessionLocal()
    try:
        # 1. Duplicate evidence simulation: insert a duplicate item with identical hash
        dup_ev_id = f"EVD-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:8].upper()}"
        dup_record = Evidence(
            evidence_id=dup_ev_id,
            case_id=fresh_case,
            original_filename="red_flag_duplicate.png",
            stored_filename="red_flag_duplicate.png",
            media_type="image/png",
            file_size=len(sample_bytes),
            sha256_hash=expected_hash,
            storage_reference="vault/duplicate",
            status="SECURED",
            uploaded_by=auth_context["inv_id"],
            source_description="Secondary clone seizure",
            created_at=datetime.now(timezone.utc)
        )
        db.add(dup_record)

        # 2. Hash Mismatch trigger: mark primary evidence status as INTEGRITY_COMPROMISED
        ev_record = db.query(Evidence).filter_by(evidence_id=primary_ev_id).first()
        assert ev_record is not None
        ev_record.status = "INTEGRITY_COMPROMISED"

        # 3. Post-dated capture timestamp (capture timestamp occurs after intake)
        meta_record = db.query(EvidenceMetadata).filter_by(evidence_id=primary_ev_id).first()
        if meta_record:
            future_ts = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
            meta_record.timestamps_metadata = {"capture_time": future_ts}
            meta_record.format_valid = False
            meta_record.anomalies = ["Magic byte masquerade detected", "Truncated chunk length"]

        # 4. Analysis Anomaly trigger
        analysis = AnalysisResult(
            analysis_id=f"AN-{uuid.uuid4().hex[:8].upper()}",
            evidence_id=primary_ev_id,
            analysis_type="TAMPER_DETECTION",
            status="COMPLETED",
            prediction="TAMPER_DETECTED",
            confidence=0.88,
            risk_score=0.92,
            findings=["Inconsistent noise distribution", "Compression grid disparity"],
            explanation="Elevated anomaly detected during automated pixel analysis",
            created_at=datetime.now(timezone.utc)
        )
        db.add(analysis)
        db.commit()
    finally:
        db.close()

    # Query Case Correlation API
    corr_res = client.get(f"/api/correlation/case/{fresh_case}", headers=headers)
    assert corr_res.status_code == 200
    data = corr_res.json()

    red_flags = data["red_flags"]
    assert len(red_flags) >= 4

    flag_types = [f["flag_type"] for f in red_flags]

    # Verify presence of evidence-based categories
    assert "DUPLICATE_EVIDENCE" in flag_types
    assert "HASH_MISMATCH" in flag_types
    assert "TIMESTAMP_INCONSISTENCY" in flag_types
    assert "METADATA_INCONSISTENCY" in flag_types
    assert "ANALYSIS_ANOMALY" in flag_types

    # Strict Check: "Do not claim criminality"
    prohibited_criminal_words = ["criminal", "fraudulent", "guilty", "illegal", "forgery", "crime", "felony"]
    for flag in red_flags:
        desc_lower = flag["description"].lower()
        for word in prohibited_criminal_words:
            assert word not in desc_lower, (
                f"Red flag description violated 'Do not claim criminality' rule with word '{word}': {flag['description']}"
            )
        assert flag["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        assert "evidence_reference" in flag


# ==============================================================================
# 6. Security & Boundaries Tests
# ==============================================================================

def test_correlation_security_and_nonexistent_case(auth_context, fresh_case):
    """
    Test 6: Security and Error Handling
    - Unauthenticated request -> 401 Unauthorized
    - Nonexistent case_id -> 404 Not Found
    - Authorized Lawyer -> 200 OK (Court docket inspection permitted)
    """
    # 1. Unauthenticated -> 401
    unauth_res = client.get(f"/api/correlation/case/{fresh_case}")
    assert unauth_res.status_code == 401

    # 2. Nonexistent case -> 404
    missing_res = client.get("/api/correlation/case/CASE-NONEXISTENT-999", headers=auth_context["inv_headers"])
    assert missing_res.status_code == 404

    # 3. Authorized Lawyer -> 200 OK
    lawyer_res = client.get(f"/api/correlation/case/{fresh_case}", headers=auth_context["lawyer_headers"])
    assert lawyer_res.status_code == 200
    assert lawyer_res.json()["success"] is True
