"""
NYAYAI - Test Suite: Backend API Endpoints & Integrated Pipeline
Tests full workflow: Auth -> Case Creation -> Evidence Intake -> Pipeline Execution -> Custody Verification -> Report Generation -> QR Verification
"""

import os
import sys
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
from database.connection import Base, engine

# Initialize tables
Base.metadata.create_all(bind=engine)
client = TestClient(app)


def test_health_endpoint():
    """Verify system health check reports active engines and compliance."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert len(data["engines_active"]) == 6


def test_end_to_end_api_workflow():
    """
    Executes full pipeline via HTTP API:
    1. Create Case
    2. Ingest Evidence
    3. Run Forensic & AI Analysis
    4. Verify Chain of Custody
    5. Issue BSA Court Report
    6. Verify via Public QR Endpoint
    """
    # 0. Authenticate
    from backend.app.core.security import create_access_token
    token = create_access_token({"sub": "USR-SYSTEM-LEAD", "username": "investigator_dhananjay", "role": "INVESTIGATOR"})
    auth_headers = {"Authorization": f"Bearer {token}"}

    # 1. Create Case
    case_res = client.post(
        "/api/v1/cases",
        json={
            "title": "Integrated Test Docket 2026",
            "description": "Integration test for digital evidence pipeline",
            "jurisdiction": "High Court of Delhi"
        },
        headers=auth_headers
    )
    assert case_res.status_code == 201
    case_id = case_res.json()["data"]["case_id"]
    assert case_id.startswith("CASE-")

    # 2. Intake Evidence
    dummy_file_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRTESTING_NYAYAI_EVIDENCE"
    files = {"file": ("screenshot.png", dummy_file_bytes, "image/png")}
    data = {"source_description": "Seized during lawful search warrant #44"}

    evidence_res = client.post(f"/api/v1/cases/{case_id}/evidence", files=files, data=data)
    assert evidence_res.status_code == 201
    ev_data = evidence_res.json()["data"]
    evidence_id = ev_data["evidence_id"]
    sha256 = ev_data["sha256_hash"]

    assert evidence_id.startswith("EVD-")
    assert len(sha256) == 64
    assert ev_data["vault_status"] == "SECURED_READONLY"
    assert "genesis_event_hash" in ev_data

    # 3. Trigger Analysis Pipeline
    pipeline_res = client.post(f"/api/v1/evidence/{evidence_id}/analyze")
    assert pipeline_res.status_code == 200
    p_data = pipeline_res.json()["data"]

    assert p_data["status"] == "ANALYZED"
    assert "forensic_report" in p_data
    assert "ai_analysis" in p_data
    assert "explainability" in p_data
    assert "custody_event_hash" in p_data

    # 4. Check Custody Ledger & Verify Cryptographic Integrity
    custody_res = client.get(f"/api/v1/evidence/{evidence_id}/custody")
    assert custody_res.status_code == 200
    c_data = custody_res.json()
    assert c_data["chain_intact"] is True
    assert c_data["total_events"] == 2 # Intake + Pipeline Run

    verify_res = client.post(f"/api/v1/evidence/{evidence_id}/custody/verify")
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["is_valid"] is True
    assert v_data["verified_blocks"] == 2

    # 5. Generate Court Admissibility Report
    report_res = client.post(
        f"/api/v1/cases/{case_id}/report",
        json={
            "certifying_officer_name": "Dhananjay Sharma",
            "certifying_officer_designation": "Forensic Systems Lead",
            "badge_number": "INV-DL-9841",
            "jurisdiction": "High Court of Delhi"
        }
    )
    assert report_res.status_code == 201
    rep_data = report_res.json()["data"]
    report_id = rep_data["report_id"]
    assert len(rep_data["report_sha256"]) == 64

    # 6. Verify via Public QR Verification Endpoint
    qr_verify_res = client.get(f"/api/v1/reports/verify/{report_id}")
    assert qr_verify_res.status_code == 200
    qr_data = qr_verify_res.json()
    assert qr_data["verified"] is True
    assert qr_data["integrity_status"] == "AUTHENTIC_AND_UNCOMPROMISED"
    assert qr_data["official_report_sha256"] == rep_data["report_sha256"]
