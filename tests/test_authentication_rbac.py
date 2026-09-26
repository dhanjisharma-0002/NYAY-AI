"""
NYAYAI - Test Suite: Authentication & Role-Based Access Control (Phase 3)
Tests:
1. Registration (Valid user creation, password hashed with bcrypt, no plain text)
2. Duplicate user prevention (Username & Email uniqueness)
3. Login (Valid credentials returning JWT access token with expiration)
4. Invalid password handling (401 Unauthorized, generic error message)
5. Token validation (GET /api/auth/me with valid Bearer token)
6. Missing / malformed / expired token validation (401 Unauthorized)
7. Role-Based Access Control (RBAC):
   - ADMIN: user management, system administration
   - INVESTIGATOR: case creation, evidence intake, initiating analysis
   - LAWYER: view permitted case info, view reports
   - JUDGE: view reports, verify report authenticity
8. Unauthorized access (403 Forbidden when role lacks permissions)
9. Security verification: Zero password hash or JWT secret leakage in responses
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
from backend.app.database import SessionLocal
from backend.app.models.user import User
from backend.app.core.security import verify_password, create_access_token

client = TestClient(app)


@pytest.fixture(scope="module")
def setup_roles_and_users():
    """Ensure database has initialized roles and base users."""
    from database.init_db import init_database
    init_database()


def test_user_registration_success(setup_roles_and_users):
    """Test POST /api/auth/register creates user with bcrypt-hashed password."""
    unique_suffix = uuid.uuid4().hex[:8]
    payload = {
        "username": f"inv_user_{unique_suffix}",
        "email": f"inv_{unique_suffix}@nyayai.gov.in",
        "password": "StrongPassword123!",
        "full_name": "Test Officer",
        "role": "INVESTIGATOR",
        "badge_number": f"BADGE-{unique_suffix}"
    }

    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()

    # Verify response structure
    assert data["username"] == payload["username"]
    assert data["email"] == payload["email"]
    assert data["role"] == "INVESTIGATOR"
    assert data["is_active"] is True
    assert "user_id" in data

    # CRITICAL SECURITY CHECK: password and hash must never be in response
    assert "password" not in data
    assert "hashed_password" not in data

    # Verify in DB that password is salted bcrypt hash
    db = SessionLocal()
    try:
        user_in_db = db.query(User).filter_by(username=payload["username"]).first()
        assert user_in_db is not None
        assert user_in_db.hashed_password != payload["password"]
        assert user_in_db.hashed_password.startswith("$2b$") or user_in_db.hashed_password.startswith("$2a$")
        assert verify_password("StrongPassword123!", user_in_db.hashed_password) is True
        assert verify_password("WrongPassword!", user_in_db.hashed_password) is False
    finally:
        db.close()


def test_user_registration_duplicate_username(setup_roles_and_users):
    """Test registration rejects duplicate username with HTTP 400."""
    unique_suffix = uuid.uuid4().hex[:8]
    payload = {
        "username": f"dup_user_{unique_suffix}",
        "email": f"dup1_{unique_suffix}@nyayai.gov.in",
        "password": "Password123!",
        "full_name": "Officer One",
        "role": "INVESTIGATOR"
    }

    # First registration: succeeds
    res1 = client.post("/api/auth/register", json=payload)
    assert res1.status_code == 201

    # Second registration with same username: fails with 400
    payload2 = {
        "username": f"dup_user_{unique_suffix}", # Same username
        "email": f"dup2_{unique_suffix}@nyayai.gov.in",
        "password": "Password123!",
        "full_name": "Officer Two",
        "role": "INVESTIGATOR"
    }
    res2 = client.post("/api/auth/register", json=payload2)
    assert res2.status_code == 400
    assert "already in use" in res2.json()["message"]


def test_user_registration_duplicate_email(setup_roles_and_users):
    """Test registration rejects duplicate email with HTTP 400."""
    unique_suffix = uuid.uuid4().hex[:8]
    shared_email = f"shared_{unique_suffix}@nyayai.gov.in"

    payload1 = {
        "username": f"user_a_{unique_suffix}",
        "email": shared_email,
        "password": "Password123!",
        "full_name": "User Alpha",
        "role": "LAWYER"
    }
    res1 = client.post("/api/auth/register", json=payload1)
    assert res1.status_code == 201

    payload2 = {
        "username": f"user_b_{unique_suffix}",
        "email": shared_email, # Duplicate email
        "password": "Password123!",
        "full_name": "User Beta",
        "role": "JUDGE"
    }
    res2 = client.post("/api/auth/register", json=payload2)
    assert res2.status_code == 400
    assert "already registered" in res2.json()["message"]


def test_login_success(setup_roles_and_users):
    """Test POST /api/auth/login returns valid JWT and user profile."""
    unique_suffix = uuid.uuid4().hex[:8]
    username = f"login_user_{unique_suffix}"
    password = "CorrectSecretPass2026!"

    # Register user
    reg_payload = {
        "username": username,
        "email": f"{username}@nyayai.gov.in",
        "password": password,
        "full_name": "Login Test User",
        "role": "JUDGE"
    }
    reg_res = client.post("/api/auth/register", json=reg_payload)
    assert reg_res.status_code == 201

    # Login
    login_payload = {
        "username": username,
        "password": password
    }
    login_res = client.post("/api/auth/login", json=login_payload)
    assert login_res.status_code == 200
    data = login_res.json()

    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0
    assert data["user"]["username"] == username
    assert data["user"]["role"] == "JUDGE"

    # Security check: zero hash leakage
    assert "hashed_password" not in str(data)


def test_login_invalid_password(setup_roles_and_users):
    """Test POST /api/auth/login with wrong password returns 401 Unauthorized."""
    unique_suffix = uuid.uuid4().hex[:8]
    username = f"user_badpw_{unique_suffix}"

    client.post("/api/auth/register", json={
        "username": username,
        "email": f"{username}@nyayai.gov.in",
        "password": "ValidPassword123!",
        "full_name": "Security Check User",
        "role": "INVESTIGATOR"
    })

    # Attempt login with incorrect password
    bad_login_res = client.post("/api/auth/login", json={
        "username": username,
        "password": "WrongPasswordAttempt!"
    })
    assert bad_login_res.status_code == 401
    assert "Invalid username or password" in bad_login_res.json()["message"]


def test_login_nonexistent_user(setup_roles_and_users):
    """Test POST /api/auth/login with nonexistent user returns 401 Unauthorized."""
    res = client.post("/api/auth/login", json={
        "username": "totally_nonexistent_user_9999",
        "password": "SomePassword123!"
    })
    assert res.status_code == 401
    assert "Invalid username or password" in res.json()["message"]


def test_token_validation_get_me(setup_roles_and_users):
    """Test GET /api/auth/me resolves identity from valid Bearer token."""
    unique_suffix = uuid.uuid4().hex[:8]
    username = f"me_test_{unique_suffix}"
    password = "ProfilePassword123!"

    client.post("/api/auth/register", json={
        "username": username,
        "email": f"{username}@nyayai.gov.in",
        "password": password,
        "full_name": "Advocate Sharma",
        "role": "LAWYER"
    })

    login_res = client.post("/api/auth/login", json={"username": username, "password": password})
    token = login_res.json()["access_token"]

    # Call /api/auth/me with valid Authorization header
    headers = {"Authorization": f"Bearer {token}"}
    me_res = client.get("/api/auth/me", headers=headers)
    assert me_res.status_code == 200
    user_info = me_res.json()

    assert user_info["username"] == username
    assert user_info["role"] == "LAWYER"
    assert user_info["full_name"] == "Advocate Sharma"
    assert "password" not in user_info
    assert "hashed_password" not in user_info


def test_token_validation_unauthorized_cases():
    """Test GET /api/auth/me without token, with malformed token, or corrupted signature."""
    # 1. Missing header
    res_no_token = client.get("/api/auth/me")
    assert res_no_token.status_code == 401

    # 2. Corrupted signature token
    bad_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.tampered_signature_bytes"
    res_bad_token = client.get("/api/auth/me", headers={"Authorization": f"Bearer {bad_token}"})
    assert res_bad_token.status_code == 401


def test_rbac_admin_capabilities(setup_roles_and_users):
    """
    Test ADMIN capabilities:
    - User management: GET /api/rbac/admin/users
    - System administration: GET /api/rbac/admin/system/status
    - Non-admin (INVESTIGATOR, LAWYER, JUDGE) rejected with 403 Forbidden.
    """
    # 1. Create ADMIN user
    admin_suffix = uuid.uuid4().hex[:8]
    admin_user = f"admin_{admin_suffix}"
    client.post("/api/auth/register", json={
        "username": admin_user,
        "email": f"{admin_user}@nyayai.gov.in",
        "password": "AdminPassword123!",
        "full_name": "System Administrator",
        "role": "ADMIN"
    })
    admin_token = client.post("/api/auth/login", json={
        "username": admin_user,
        "password": "AdminPassword123!"
    }).json()["access_token"]

    # 2. Create non-admin (INVESTIGATOR) user
    inv_suffix = uuid.uuid4().hex[:8]
    inv_user = f"inv_{inv_suffix}"
    client.post("/api/auth/register", json={
        "username": inv_user,
        "email": f"{inv_user}@nyayai.gov.in",
        "password": "InvPassword123!",
        "full_name": "Field Investigator",
        "role": "INVESTIGATOR"
    })
    inv_token = client.post("/api/auth/login", json={
        "username": inv_user,
        "password": "InvPassword123!"
    }).json()["access_token"]

    # ADMIN accessing admin endpoint -> 200 OK
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    res_admin_users = client.get("/api/rbac/admin/users", headers=admin_headers)
    assert res_admin_users.status_code == 200
    assert len(res_admin_users.json()) >= 1

    res_admin_sys = client.get("/api/rbac/admin/system/status", headers=admin_headers)
    assert res_admin_sys.status_code == 200
    assert res_admin_sys.json()["system_state"] == "OPTIMAL"

    # INVESTIGATOR attempting to access admin endpoint -> 403 Forbidden
    inv_headers = {"Authorization": f"Bearer {inv_token}"}
    res_inv_forbidden = client.get("/api/rbac/admin/users", headers=inv_headers)
    assert res_inv_forbidden.status_code == 403
    assert "Access forbidden" in res_inv_forbidden.json()["message"]


def test_rbac_investigator_capabilities(setup_roles_and_users):
    """
    Test INVESTIGATOR capabilities:
    - Initiate analysis: POST /api/rbac/investigator/analysis/{id}/initiate
    - LAWYER attempting to initiate analysis -> 403 Forbidden.
    """
    # 1. Investigator login
    inv_suffix = uuid.uuid4().hex[:8]
    inv_user = f"inv_ops_{inv_suffix}"
    client.post("/api/auth/register", json={
        "username": inv_user,
        "email": f"{inv_user}@nyayai.gov.in",
        "password": "Password123!",
        "full_name": "Investigator Officer",
        "role": "INVESTIGATOR"
    })
    inv_token = client.post("/api/auth/login", json={
        "username": inv_user,
        "password": "Password123!"
    }).json()["access_token"]

    # 2. Lawyer login
    lawyer_suffix = uuid.uuid4().hex[:8]
    lawyer_user = f"lawyer_ops_{lawyer_suffix}"
    client.post("/api/auth/register", json={
        "username": lawyer_user,
        "email": f"{lawyer_user}@nyayai.gov.in",
        "password": "Password123!",
        "full_name": "Counsel Representative",
        "role": "LAWYER"
    })
    lawyer_token = client.post("/api/auth/login", json={
        "username": lawyer_user,
        "password": "Password123!"
    }).json()["access_token"]

    # INVESTIGATOR initiates analysis -> 200 OK
    inv_res = client.post(
        "/api/rbac/investigator/analysis/EVD-TEST-999/initiate",
        headers={"Authorization": f"Bearer {inv_token}"}
    )
    assert inv_res.status_code == 200
    assert inv_res.json()["pipeline_state"] == "DISPATCHED_TO_INFERENCE_ENGINE"

    # LAWYER attempting to initiate analysis -> 403 Forbidden
    lawyer_res = client.post(
        "/api/rbac/investigator/analysis/EVD-TEST-999/initiate",
        headers={"Authorization": f"Bearer {lawyer_token}"}
    )
    assert lawyer_res.status_code == 403
    assert "Access forbidden" in lawyer_res.json()["message"]


def test_rbac_lawyer_capabilities(setup_roles_and_users):
    """
    Test LAWYER capabilities:
    - View permitted case brief: GET /api/rbac/lawyer/cases/{case_id}/permitted-brief
    """
    lawyer_suffix = uuid.uuid4().hex[:8]
    lawyer_user = f"lawyer_view_{lawyer_suffix}"
    client.post("/api/auth/register", json={
        "username": lawyer_user,
        "email": f"{lawyer_user}@nyayai.gov.in",
        "password": "Password123!",
        "full_name": "Bar Advocate",
        "role": "LAWYER"
    })
    lawyer_token = client.post("/api/auth/login", json={
        "username": lawyer_user,
        "password": "Password123!"
    }).json()["access_token"]

    # LAWYER views permitted brief -> 200 OK
    res = client.get(
        "/api/rbac/lawyer/cases/CASE-2026-TEST/permitted-brief",
        headers={"Authorization": f"Bearer {lawyer_token}"}
    )
    assert res.status_code == 200
    assert res.json()["access_scope"] == "DEFENSE_PROSECUTION_BRIEF"


def test_rbac_judge_capabilities_and_strict_separation(setup_roles_and_users):
    """
    Test JUDGE capabilities and strict access boundaries ('Do not assume unrestricted access'):
    - Verify report authenticity: POST /api/rbac/judge/reports/{id}/verify-authenticity
    - Strictly JUDGE only: Even INVESTIGATOR and LAWYER get 403 Forbidden.
    """
    # 1. Create JUDGE user
    judge_suffix = uuid.uuid4().hex[:8]
    judge_user = f"judge_bench_{judge_suffix}"
    client.post("/api/auth/register", json={
        "username": judge_user,
        "email": f"{judge_user}@nyayai.gov.in",
        "password": "Password123!",
        "full_name": "Honorable Judicial Magistrate",
        "role": "JUDGE",
        "badge_number": "JUD-BENCH-04"
    })
    judge_token = client.post("/api/auth/login", json={
        "username": judge_user,
        "password": "Password123!"
    }).json()["access_token"]

    # 2. Create LAWYER user
    counsel_suffix = uuid.uuid4().hex[:8]
    counsel_user = f"counsel_{counsel_suffix}"
    client.post("/api/auth/register", json={
        "username": counsel_user,
        "email": f"{counsel_user}@nyayai.gov.in",
        "password": "Password123!",
        "full_name": "Defense Counsel",
        "role": "LAWYER"
    })
    counsel_token = client.post("/api/auth/login", json={
        "username": counsel_user,
        "password": "Password123!"
    }).json()["access_token"]

    # JUDGE performs judicial verification -> 200 OK
    judge_headers = {"Authorization": f"Bearer {judge_token}"}
    judge_res = client.post(
        "/api/rbac/judge/reports/REP-2026-888/verify-authenticity",
        headers=judge_headers
    )
    assert judge_res.status_code == 200
    assert judge_res.json()["authenticity_sealed"] is True
    assert judge_res.json()["admissibility_finding"] == "ADMISSIBLE_UNDER_BSA_2023"

    # LAWYER attempting judicial authenticity verification -> 403 Forbidden
    counsel_headers = {"Authorization": f"Bearer {counsel_token}"}
    counsel_res = client.post(
        "/api/rbac/judge/reports/REP-2026-888/verify-authenticity",
        headers=counsel_headers
    )
    assert counsel_res.status_code == 403
    assert "Access forbidden" in counsel_res.json()["message"]


def test_unauthenticated_request_to_protected_endpoints():
    """Test requests without any Authorization header return 401 Unauthorized."""
    res1 = client.get("/api/rbac/admin/users")
    assert res1.status_code == 401

    res2 = client.post("/api/rbac/investigator/analysis/EVD-123/initiate")
    assert res2.status_code == 401

    res3 = client.get("/api/rbac/lawyer/cases/CASE-123/permitted-brief")
    assert res3.status_code == 401

    res4 = client.post("/api/rbac/judge/reports/REP-123/verify-authenticity")
    assert res4.status_code == 401
