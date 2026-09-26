"""
NYAYAI - Backend Foundation Health & Structure Test Suite (Phase 1)
Tests:
- GET /api/health returns required structure: {"status": "ok", "service": "NYAYAI Backend"}
- Prepared endpoints availability (/api/cases, /api/auth, /api/forensics, etc.)
- Error handling consistency (status, message, error_code, no stack trace)
- Structured logging redaction (passwords, tokens, API keys, credentials)
"""

import logging
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.database import Base, engine
from backend.app.utils.logger import redact_sensitive_data, SensitiveDataFilter, get_logger

# Ensure database tables are created
Base.metadata.create_all(bind=engine)
client = TestClient(app)


def test_api_health_endpoint():
    """Verify GET /api/health returns the exact required structure."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data == {
        "status": "ok",
        "service": "NYAYAI Backend"
    }


def test_api_v1_health_endpoint():
    """Verify GET /api/v1/health returns the required structure."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "NYAYAI Backend"


def test_root_health_endpoint():
    """Verify root GET /health returns detailed status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert "NYAYAI" in data["service"]


def test_prepared_api_routes_exist():
    """Verify prepared API routers are mounted under /api."""
    # Auth (using valid JWT token to probe protected /me endpoint)
    from backend.app.core.security import create_access_token
    token = create_access_token({"sub": "USR-SYSTEM-LEAD", "username": "investigator_dhananjay", "role": "INVESTIGATOR"})
    auth_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert auth_res.status_code == 200
    assert "user_id" in auth_res.json()

    # Cases
    cases_res = client.get("/api/cases", headers={"Authorization": f"Bearer {token}"})
    assert cases_res.status_code == 200
    assert cases_res.json()["success"] is True

    # Evidence
    evidence_res = client.get("/api/evidence")
    assert evidence_res.status_code == 200
    assert evidence_res.json()["success"] is True


def test_consistent_error_handling_format():
    """Verify error responses contain status, message, error_code and zero stack traces."""
    # 404 Case Not Found
    from backend.app.core.security import create_access_token
    token = create_access_token({"sub": "USR-SYSTEM-LEAD", "username": "investigator_dhananjay", "role": "INVESTIGATOR"})
    response = client.get("/api/cases/CASE-NON-EXISTENT-99999", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 404
    data = response.json()

    assert "status" in data
    assert data["status"] == 404
    assert "message" in data
    assert "error_code" in data
    assert data["error_code"] == "CASE_NOT_FOUND"

    # Verify no stack trace leaks
    assert "traceback" not in str(data).lower()
    assert "file \"" not in str(data).lower()


def test_logging_sensitive_data_redaction():
    """Verify sensitive keys (passwords, tokens, API keys, credentials) are redacted."""
    sensitive_payload = {
        "username": "investigator",
        "password": "SuperSecretPassword123!",
        "access_token": "eyJhbGciOiJIUzI1NiIsIn...",
        "api_key": "live_sec_9999999",
        "private_key": "-----BEGIN PRIVATE KEY-----...",
        "raw_evidence": b"\x89PNG\r\n\x1a\nBINARYPAYLOAD",
        "case_title": "Normal Case Title"
    }

    cleaned = redact_sensitive_data(sensitive_payload)

    assert cleaned["password"] == "[REDACTED]"
    assert cleaned["access_token"] == "[REDACTED]"
    assert cleaned["api_key"] == "[REDACTED]"
    assert cleaned["private_key"] == "[REDACTED]"
    assert "[BINARY_DATA:" in cleaned["raw_evidence"]
    assert cleaned["case_title"] == "Normal Case Title"
    assert cleaned["username"] == "investigator"
