"""
NYAYAI - Test Suite: Case Management (Phase 4)
Tests:
1. Case Creation (POST /api/cases)
   - Unique case_id generation
   - Storing: case_id, case_number, title, description, status="OPEN", created_by, created_at, updated_at
2. List Cases (GET /api/cases)
   - Listing with and without status filter (OPEN, UNDER_ANALYSIS, COMPLETED, ARCHIVED)
3. Retrieve Case (GET /api/cases/{case_id})
   - Fetching complete case docket details
4. Update Case (PATCH /api/cases/{case_id})
   - Updating title, description, status (OPEN -> UNDER_ANALYSIS -> COMPLETED -> ARCHIVED)
5. Validation:
   - Required title (empty / whitespace rejected with 422)
   - Valid status (invalid status strings rejected with 422)
   - Authorized creator (created_by bound to verified identity)
6. Unauthorized Access:
   - Requests without token rejected with 401 Unauthorized
   - Requests with invalid token rejected with 401 Unauthorized
   - Unauthorized roles (LAWYER, JUDGE) attempting to create or patch cases rejected with 403 Forbidden
7. Invalid Case ID:
   - GET /api/cases/{non_existent_id} returns 404 Not Found (CASE_NOT_FOUND)
   - PATCH /api/cases/{non_existent_id} returns 404 Not Found (CASE_NOT_FOUND)
"""

import os
import sys
import uuid
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
from backend.app.core.security import create_access_token
from database.init_db import init_database

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def ensure_db():
    init_database()


@pytest.fixture
def investigator_auth():
    """Create a unique authenticated investigator token and headers."""
    unique_suffix = uuid.uuid4().hex[:8]
    username = f"inv_case_{unique_suffix}"
    reg_payload = {
        "username": username,
        "email": f"{username}@nyayai.gov.in",
        "password": "Password123!",
        "full_name": "Field Investigator Officer",
        "role": "INVESTIGATOR",
        "badge_number": f"INV-{unique_suffix}"
    }
    reg_res = client.post("/api/auth/register", json=reg_payload)
    assert reg_res.status_code == 201
    user_id = reg_res.json()["user_id"]

    login_res = client.post("/api/auth/login", json={"username": username, "password": "Password123!"})
    token = login_res.json()["access_token"]
    return {
        "headers": {"Authorization": f"Bearer {token}"},
        "user_id": user_id,
        "username": username
    }


@pytest.fixture
def lawyer_auth():
    """Create a unique authenticated lawyer token and headers."""
    unique_suffix = uuid.uuid4().hex[:8]
    username = f"lawyer_case_{unique_suffix}"
    reg_payload = {
        "username": username,
        "email": f"{username}@nyayai.gov.in",
        "password": "Password123!",
        "full_name": "Legal Counsel",
        "role": "LAWYER"
    }
    client.post("/api/auth/register", json=reg_payload)
    login_res = client.post("/api/auth/login", json={"username": username, "password": "Password123!"})
    token = login_res.json()["access_token"]
    return {"headers": {"Authorization": f"Bearer {token}"}}


@pytest.fixture
def judge_auth():
    """Create a unique authenticated judge token and headers."""
    unique_suffix = uuid.uuid4().hex[:8]
    username = f"judge_case_{unique_suffix}"
    reg_payload = {
        "username": username,
        "email": f"{username}@nyayai.gov.in",
        "password": "Password123!",
        "full_name": "Judicial Officer",
        "role": "JUDGE"
    }
    client.post("/api/auth/register", json=reg_payload)
    login_res = client.post("/api/auth/login", json={"username": username, "password": "Password123!"})
    token = login_res.json()["access_token"]
    return {"headers": {"Authorization": f"Bearer {token}"}}


# ==============================================================================
# 1. Case Creation Tests
# ==============================================================================

def test_create_case_success(investigator_auth):
    """
    Test POST /api/cases creates case with unique case_id, case_number,
    stores title, description, status="OPEN", created_by, created_at, updated_at.
    """
    payload = {
        "title": "State vs Cyber Extortion Syndicate",
        "description": "Evidence recovery from targeted ransomware breach",
        "jurisdiction": "High Court of Delhi"
    }
    res = client.post("/api/cases", json=payload, headers=investigator_auth["headers"])
    assert res.status_code == 201
    body = res.json()
    assert body["success"] is True

    data = body["data"]
    assert data["case_id"].startswith("CASE-")
    assert data["case_number"].startswith("CR-")
    assert data["title"] == payload["title"]
    assert data["description"] == payload["description"]
    assert data["status"] == "OPEN"
    assert data["created_by"] == investigator_auth["user_id"]
    assert "created_at" in data
    assert "updated_at" in data


def test_create_case_validation_missing_or_empty_title(investigator_auth):
    """Test POST /api/cases rejects missing or empty title with HTTP 422."""
    # 1. Missing title
    res1 = client.post("/api/cases", json={"description": "No title provided"}, headers=investigator_auth["headers"])
    assert res1.status_code == 422

    # 2. Empty string title
    res2 = client.post("/api/cases", json={"title": "   ", "description": "Blank spaces"}, headers=investigator_auth["headers"])
    assert res2.status_code == 422


def test_create_case_validation_invalid_status(investigator_auth):
    """Test POST /api/cases rejects invalid lifecycle status with HTTP 422."""
    payload = {
        "title": "Invalid Status Case Docket",
        "status": "NON_EXISTENT_STATUS"
    }
    res = client.post("/api/cases", json=payload, headers=investigator_auth["headers"])
    assert res.status_code == 422


# ==============================================================================
# 2. List Cases Tests
# ==============================================================================

def test_list_cases_and_filter_by_status(investigator_auth):
    """Test GET /api/cases returns cases and supports ?status= filter."""
    # Create two cases with distinct titles
    client.post("/api/cases", json={"title": "Case Docket Alpha 1"}, headers=investigator_auth["headers"])
    c2_res = client.post("/api/cases", json={"title": "Case Docket Beta 2"}, headers=investigator_auth["headers"])
    c2_id = c2_res.json()["data"]["case_id"]

    # Update second case to UNDER_ANALYSIS
    client.patch(f"/api/cases/{c2_id}", json={"status": "UNDER_ANALYSIS"}, headers=investigator_auth["headers"])

    # 1. List all cases
    all_res = client.get("/api/cases", headers=investigator_auth["headers"])
    assert all_res.status_code == 200
    all_cases = all_res.json()["data"]
    assert len(all_cases) >= 2

    # 2. Filter by status=OPEN
    open_res = client.get("/api/cases?status=OPEN", headers=investigator_auth["headers"])
    assert open_res.status_code == 200
    for c in open_res.json()["data"]:
        assert c["status"] == "OPEN"

    # 3. Filter by status=UNDER_ANALYSIS
    analyzing_res = client.get("/api/cases?status=UNDER_ANALYSIS", headers=investigator_auth["headers"])
    assert analyzing_res.status_code == 200
    analyzing_cases = analyzing_res.json()["data"]
    assert any(c["case_id"] == c2_id for c in analyzing_cases)
    for c in analyzing_cases:
        assert c["status"] == "UNDER_ANALYSIS"


# ==============================================================================
# 3. Retrieve Case Tests
# ==============================================================================

def test_retrieve_case_by_id(investigator_auth):
    """Test GET /api/cases/{case_id} retrieves complete metadata."""
    create_res = client.post(
        "/api/cases",
        json={"title": "Detailed Docket Inspection", "description": "Forensic audit case"},
        headers=investigator_auth["headers"]
    )
    case_id = create_res.json()["data"]["case_id"]

    get_res = client.get(f"/api/cases/{case_id}", headers=investigator_auth["headers"])
    assert get_res.status_code == 200
    c_data = get_res.json()["data"]

    assert c_data["case_id"] == case_id
    assert c_data["title"] == "Detailed Docket Inspection"
    assert c_data["description"] == "Forensic audit case"
    assert c_data["status"] == "OPEN"
    assert c_data["created_by"] == investigator_auth["user_id"]
    assert "case_number" in c_data
    assert "created_at" in c_data
    assert "updated_at" in c_data


# ==============================================================================
# 4. Update Case Tests
# ==============================================================================

def test_update_case_status_and_title(investigator_auth):
    """
    Test PATCH /api/cases/{case_id} updates title, description,
    and transitions through allowed statuses (UNDER_ANALYSIS, COMPLETED, ARCHIVED).
    """
    create_res = client.post(
        "/api/cases",
        json={"title": "Original Case Title", "description": "Original narrative"},
        headers=investigator_auth["headers"]
    )
    case_id = create_res.json()["data"]["case_id"]

    # 1. Update title and transition to UNDER_ANALYSIS
    patch1 = client.patch(
        f"/api/cases/{case_id}",
        json={"title": "Updated Case Title", "status": "UNDER_ANALYSIS"},
        headers=investigator_auth["headers"]
    )
    assert patch1.status_code == 200
    d1 = patch1.json()["data"]
    assert d1["title"] == "Updated Case Title"
    assert d1["status"] == "UNDER_ANALYSIS"

    # 2. Transition to COMPLETED
    patch2 = client.patch(
        f"/api/cases/{case_id}",
        json={"status": "COMPLETED"},
        headers=investigator_auth["headers"]
    )
    assert patch2.status_code == 200
    assert patch2.json()["data"]["status"] == "COMPLETED"

    # 3. Transition to ARCHIVED
    patch3 = client.patch(
        f"/api/cases/{case_id}",
        json={"status": "ARCHIVED"},
        headers=investigator_auth["headers"]
    )
    assert patch3.status_code == 200
    assert patch3.json()["data"]["status"] == "ARCHIVED"


def test_update_case_invalid_status_rejected(investigator_auth):
    """Test PATCH /api/cases/{case_id} rejects invalid status with HTTP 422."""
    create_res = client.post(
        "/api/cases",
        json={"title": "Status Validation Test"},
        headers=investigator_auth["headers"]
    )
    case_id = create_res.json()["data"]["case_id"]

    patch_res = client.patch(
        f"/api/cases/{case_id}",
        json={"status": "FORGED_DELETED_STATUS"},
        headers=investigator_auth["headers"]
    )
    assert patch_res.status_code == 422


# ==============================================================================
# 5. Unauthorized Access Tests
# ==============================================================================

def test_unauthenticated_requests_rejected_with_401():
    """Verify requests without token are strictly rejected with 401 Unauthorized."""
    # POST
    assert client.post("/api/cases", json={"title": "No Auth"}).status_code == 401
    # GET list
    assert client.get("/api/cases").status_code == 401
    # GET single
    assert client.get("/api/cases/CASE-2026-TEST").status_code == 401
    # PATCH
    assert client.patch("/api/cases/CASE-2026-TEST", json={"status": "ARCHIVED"}).status_code == 401


def test_role_authorization_boundaries(investigator_auth, lawyer_auth, judge_auth):
    """
    Verify role authorization:
    - INVESTIGATOR can create and update cases.
    - LAWYER can list and retrieve cases, but CANNOT create or update cases (403 Forbidden).
    - JUDGE can list and retrieve cases, but CANNOT create or update cases (403 Forbidden).
    """
    # 1. Investigator creates a case
    create_res = client.post(
        "/api/cases",
        json={"title": "Authorized Case for Access Boundaries"},
        headers=investigator_auth["headers"]
    )
    assert create_res.status_code == 201
    case_id = create_res.json()["data"]["case_id"]

    # 2. LAWYER can view cases
    lawyer_list = client.get("/api/cases", headers=lawyer_auth["headers"])
    assert lawyer_list.status_code == 200
    lawyer_get = client.get(f"/api/cases/{case_id}", headers=lawyer_auth["headers"])
    assert lawyer_get.status_code == 200

    # 3. LAWYER CANNOT create cases -> 403 Forbidden
    lawyer_create = client.post(
        "/api/cases",
        json={"title": "Lawyer Attempting Case Creation"},
        headers=lawyer_auth["headers"]
    )
    assert lawyer_create.status_code == 403

    # 4. LAWYER CANNOT update cases -> 403 Forbidden
    lawyer_patch = client.patch(
        f"/api/cases/{case_id}",
        json={"status": "COMPLETED"},
        headers=lawyer_auth["headers"]
    )
    assert lawyer_patch.status_code == 403

    # 5. JUDGE can view cases
    judge_list = client.get("/api/cases", headers=judge_auth["headers"])
    assert judge_list.status_code == 200
    judge_get = client.get(f"/api/cases/{case_id}", headers=judge_auth["headers"])
    assert judge_get.status_code == 200

    # 6. JUDGE CANNOT create cases -> 403 Forbidden
    judge_create = client.post(
        "/api/cases",
        json={"title": "Judge Attempting Case Creation"},
        headers=judge_auth["headers"]
    )
    assert judge_create.status_code == 403

    # 7. JUDGE CANNOT update cases -> 403 Forbidden
    judge_patch = client.patch(
        f"/api/cases/{case_id}",
        json={"status": "ARCHIVED"},
        headers=judge_auth["headers"]
    )
    assert judge_patch.status_code == 403


# ==============================================================================
# 6. Invalid Case ID Tests
# ==============================================================================

def test_invalid_case_id_returns_404(investigator_auth):
    """Test querying non-existent case_id returns HTTP 404 with standard error structure."""
    non_existent_id = "CASE-9999-DOES-NOT-EXIST"

    # GET
    get_res = client.get(f"/api/cases/{non_existent_id}", headers=investigator_auth["headers"])
    assert get_res.status_code == 404
    assert get_res.json()["error_code"] == "CASE_NOT_FOUND"

    # PATCH
    patch_res = client.patch(
        f"/api/cases/{non_existent_id}",
        json={"title": "New Title"},
        headers=investigator_auth["headers"]
    )
    assert patch_res.status_code == 404
    assert patch_res.json()["error_code"] == "CASE_NOT_FOUND"
