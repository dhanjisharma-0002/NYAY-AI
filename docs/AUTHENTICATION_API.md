# NYAYAI – Authentication and Role-Based Access Control (RBAC) Specification
**Phase 3: Authentication and Role-Based Access Control**  
**Lead Engineer**: Dhananjay Sharma (Backend & System Integration Lead)  
**Security Standard**: ISO/IEC 27001, OWASP ASVS v4.0, BSA 2023 Digital Evidence Admissibility  
**Token Standard**: RFC 7519 JSON Web Token (JWT) with HS256 HMAC-SHA256 signature  
**Password Hashing**: Adaptive Salting via bcrypt (12 rounds)  

---

## 1. Architectural Security Principles

1. **Zero Plaintext Password Storage**:
   - Plaintext passwords are never stored in databases, caches, or logs.
   - All passwords are encrypted using adaptive `bcrypt` hashing with individual per-user salts.
   - Password hashes and JWT secrets are strictly filtered out of all API serializations and error logs.

2. **Stateless JWT Authorization**:
   - Authentication yields cryptographically signed JWT access tokens containing subject (`sub`), role, issued-at (`iat`), expiration (`exp`), and token ID (`jti`).
   - Token validity and signature verification are handled via `PyJWT` with secrets configured via environment variables (`SECRET_KEY`).
   - Tokens expire automatically after `ACCESS_TOKEN_EXPIRE_MINUTES` (default 60 minutes).

3. **Strict Role-Based Access Boundaries ("Do not assume unrestricted access")**:
   - Access to API operations is segregated by strict role requirements.
   - Operations designated for specific judicial or legal oversight (e.g. judicial report authenticity sealing) cannot be bypassed by unauthorized actors.

---

## 2. Supported Roles & Capability Matrix

| Role | Primary Scope | Permitted Operations | Restricted / Prohibited Operations |
| :--- | :--- | :--- | :--- |
| **`ADMIN`** | System Administration & User Management | - User account creation & review<br>- Platform configuration<br>- System health & diagnostic logs | - Cannot falsify forensic chain of custody<br>- Cannot forge judicial sign-offs |
| **`INVESTIGATOR`** | Law Enforcement Case & Evidence Handling | - Create cases & investigative dockets<br>- Ingest and vault evidence artifacts<br>- Dispatch evidence for AI & forensic analysis | - Cannot access administrative user registries<br>- Cannot seal judicial review verdicts |
| **`LAWYER`** | Legal Defense / Prosecution Counsel | - Inspect permitted case briefs<br>- View finalized forensic & AI reports | - Cannot modify evidence or cases<br>- Cannot initiate AI analysis pipelines<br>- Cannot access admin tooling |
| **`JUDGE`** | Bench Adjudication & Court Authentication | - Review complete admissibility reports<br>- Validate Section 63/65B BSA compliance<br>- Seal evidentiary certificate authenticity | - Cannot tamper with intake hashes<br>- Cannot modify raw evidence or case files |

*Legacy Compatibility*: `SYSTEM_LEAD`, `FORENSIC_EXPERT`, and `AUDITOR` are mapped to their respective administrative, forensic, and audit capabilities.

---

## 3. Authentication API Contracts

### 3.1 Register User
Registers a new platform user with salted bcrypt password hashing.

- **HTTP Method**: `POST`
- **Path**: `/api/auth/register` (also mounted at `/api/v1/auth/register`)
- **Headers**: `Content-Type: application/json`

#### Request Body
```json
{
  "username": "advocate_mehta",
  "email": "mehta@delhicourt.gov.in",
  "password": "StrongPassword123!",
  "full_name": "Senior Advocate Rajesh Mehta",
  "role": "LAWYER",
  "badge_number": "D-10492-2015"
}
```

#### Responses
- **`201 Created`**: User successfully registered.
  ```json
  {
    "user_id": "8d3e9112-6f23-455a-b678-75e33a1e9481",
    "username": "advocate_mehta",
    "email": "mehta@delhicourt.gov.in",
    "full_name": "Senior Advocate Rajesh Mehta",
    "badge_number": "D-10492-2015",
    "role": "LAWYER",
    "is_active": true,
    "created_at": "2026-09-26T13:45:00.000000Z"
  }
  ```
- **`400 Bad Request`**: Duplicate username or email.
  ```json
  {
    "status": 400,
    "message": "Username 'advocate_mehta' is already in use.",
    "error_code": "DUPLICATE_USERNAME",
    "success": false
  }
  ```
- **`422 Unprocessable Entity`**: Validation failure (password too short, invalid role, invalid email).

---

### 3.2 Authenticate / Login
Validates credentials against stored bcrypt hash and issues a signed JWT access token.

- **HTTP Method**: `POST`
- **Path**: `/api/auth/login` (also mounted at `/api/v1/auth/login`)
- **Headers**: `Content-Type: application/json`

#### Request Body
```json
{
  "username": "investigator_dhananjay",
  "password": "SecureNyayPassword2026!"
}
```

#### Responses
- **`200 OK`**: Authentication successful.
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMmY0NzM4Zi0zOGQ1LTQ3ZGMtOGY2Zi0wOGMyNGQ1ZjYxZjUiLCJ1c2VybmFtZSI6ImludmVzdGlnYXRvcl9kaGFuYW5qYXkiLCJyb2xlIjoiSU5WRVNUSUdBVE9SIiwiZXhwIjoxNzk0MzI2MDAwLCJpYXQiOjE3OTQzMjI0MDAsImp0aSI6ImMyYTYyOGU0LTc0MTYtNGVjMi1iZjI3LWNjMzFjOWJkYzc3MCJ9.signature_digest",
    "token_type": "bearer",
    "expires_in": 3600,
    "user": {
      "user_id": "12f4738f-38d5-47dc-8f6f-08c24d5f61f5",
      "username": "investigator_dhananjay",
      "email": "dhananjay@nyayai.gov.in",
      "full_name": "Dhananjay Sharma",
      "badge_number": "INV-DL-9841",
      "role": "INVESTIGATOR",
      "is_active": true,
      "created_at": "2026-09-26T07:57:41.945121Z"
    }
  }
  ```
- **`401 Unauthorized`**: Invalid username or password.
  ```json
  {
    "status": 401,
    "message": "Invalid username or password.",
    "error_code": "AUTHENTICATION_FAILED",
    "success": false
  }
  ```

---

### 3.3 Get Current User Profile
Retrieves the identity and role profile of the authenticated JWT bearer.

- **HTTP Method**: `GET`
- **Path**: `/api/auth/me` (also mounted at `/api/v1/auth/me`)
- **Headers**: `Authorization: Bearer <access_token>`

#### Responses
- **`200 OK`**: Identity verified.
  ```json
  {
    "user_id": "12f4738f-38d5-47dc-8f6f-08c24d5f61f5",
    "username": "investigator_dhananjay",
    "email": "dhananjay@nyayai.gov.in",
    "full_name": "Dhananjay Sharma",
    "badge_number": "INV-DL-9841",
    "role": "INVESTIGATOR",
    "is_active": true,
    "created_at": "2026-09-26T07:57:41.945121Z"
  }
  ```
- **`401 Unauthorized`**: Token missing, expired, or invalid signature.
  ```json
  {
    "status": 401,
    "message": "Authentication token has expired. Please log in again.",
    "error_code": "AUTHENTICATION_FAILED",
    "success": false
  }
  ```

---

## 4. Protected RBAC Operations

All protected endpoints enforce authorization checks via FastAPI dependency injection:
- `require_roles(*roles)`: Verifies role possession.
- Missing Token $\rightarrow$ **`401 Unauthorized`**.
- Role Lacks Permission $\rightarrow$ **`403 Forbidden`**.

### 4.1 Admin Operations (`ADMIN` only)
- **`GET /api/rbac/admin/users`**: List all registered users across the platform.
- **`GET /api/rbac/admin/system/status`**: Diagnostic and operational system inspection.

### 4.2 Investigator Operations (`INVESTIGATOR`, `ADMIN`)
- **`POST /api/rbac/investigator/analysis/{evidence_id}/initiate`**: Triggers forensic intake and AI deepfake detection pipeline.

### 4.3 Lawyer Operations (`LAWYER`, `ADMIN`)
- **`GET /api/rbac/lawyer/cases/{case_id}/permitted-brief`**: Retrieves defense or prosecution permitted docket summary.

### 4.4 Judge Operations (`JUDGE` strictly)
- **`GET /api/rbac/judge/reports/{report_id}`**: Retrieves court admissibility certificate for judicial bench review.
- **`POST /api/rbac/judge/reports/{report_id}/verify-authenticity`**: Authenticity certificate sealing under BSA 2023 Section 63/65B.
  - *Strict Separation*: Even `INVESTIGATOR` and `LAWYER` receive `403 Forbidden` on this endpoint.

---

## 5. Security Configuration Reference

The following environment variables control authentication and token parameters:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `SECRET_KEY` | HMAC secret for signing JWT tokens | Configured in `.env` |
| `ALGORITHM` | JWT signing algorithm | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token lifetime before expiration | `60` |

---

## 6. Test Suite Reference

The complete authentication and authorization lifecycle is validated in:
- [tests/test_authentication_rbac.py](file:///c:/Users/DELL/OneDrive/Desktop/NYAY%20AI/tests/test_authentication_rbac.py) (13 tests covering registration, duplicate rejection, login, invalid password, token validation, role boundaries, and unauthorized 401/403 handling).
