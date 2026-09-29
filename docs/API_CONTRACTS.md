# NYAYAI – REST API Specifications & Service Contracts

**Base URL**: `http://localhost:8000/api/v1`  
**API Version**: `v1`  
**Content-Type**: `application/json` (unless `multipart/form-data` for file uploads)  
**Authentication**: Bearer JWT (`Authorization: Bearer <token>`)

---

## 1. Standard Envelope & Error Format

All API errors adhere to RFC 7807 problem details:

```json
{
  "success": false,
  "error": {
    "code": "EVIDENCE_NOT_FOUND",
    "message": "The requested evidence with id 'EVD-2026-0001' was not found in vault.",
    "timestamp": "2026-09-26T12:00:00Z",
    "details": {}
  }
}
```

---

## 2. Authentication & User Endpoints

### 2.1 Register User
- **POST** `/auth/register`
- **Request Body**:
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
- **Response** `201 Created`:
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

### 2.2 Authenticate User
- **POST** `/auth/login`
- **Request Body**:
  ```json
  {
    "username": "investigator_dhananjay",
    "password": "SecureNyayPassword2026!"
  }
  ```
- **Response** `200 OK`:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
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

### 2.3 Current User Profile
- **GET** `/auth/me`
- **Headers**: `Authorization: Bearer <token>`
- **Response** `200 OK`:
  ```json
  {
    "user_id": "12f4738f-38d5-47dc-8f6f-08c24d5f61f5",
    "username": "investigator_dhananjay",
    "email": "dhananjay@nyayai.gov.in",
    "full_name": "Dhananjay Sharma",
    "badge_number": "INV-DL-9841",
    "role": "INVESTIGATOR",
    "is_active": true
  }
  ```

### 2.4 Role-Based Access Control (RBAC Endpoints)
- **GET** `/rbac/admin/users`: ADMIN only.
- **GET** `/rbac/admin/system/status`: ADMIN only.
- **POST** `/rbac/investigator/analysis/{evidence_id}/initiate`: INVESTIGATOR and ADMIN.
- **GET** `/rbac/lawyer/cases/{case_id}/permitted-brief`: LAWYER and ADMIN.
- **GET** `/rbac/judge/reports/{report_id}`: JUDGE and ADMIN.
- **POST** `/rbac/judge/reports/{report_id}/verify-authenticity`: JUDGE only (strict separation).

---

## 3. Case Management Endpoints

### 3.1 Create New Case
- **POST** `/cases` (also `/api/cases` and `/api/v1/cases`)
- **Authorization**: Bearer JWT (`INVESTIGATOR`, `ADMIN`)
- **Request Body**:
  ```json
  {
    "title": "State vs. Anonymous Cyber Extortion",
    "description": "Investigation into digital blackmail artifacts recovered from victim cloud storage.",
    "case_number": "CR-2026-DL-8821",
    "jurisdiction": "High Court of Delhi"
  }
  ```
- **Response** `201 Created`:
  ```json
  {
    "success": true,
    "data": {
      "case_id": "CASE-2026-9FA1C2D8",
      "case_number": "CR-2026-DL-8821",
      "title": "State vs. Anonymous Cyber Extortion",
      "description": "Investigation into digital blackmail artifacts recovered from victim cloud storage.",
      "status": "OPEN",
      "created_by": "12f4738f-38d5-47dc-8f6f-08c24d5f61f5",
      "created_at": "2026-09-26T14:00:00.000000Z",
      "updated_at": "2026-09-26T14:00:00.000000Z",
      "jurisdiction": "High Court of Delhi",
      "evidence_count": 0
    }
  }
  ```
- **Validation**:
  - `title` is mandatory (non-empty, non-whitespace; 422 if missing).
  - `status` defaults to `OPEN`.
  - Unauthenticated requests receive `401 Unauthorized`.
  - Unauthorized roles (`LAWYER`, `JUDGE`) receive `403 Forbidden`.

### 3.2 List All Cases
- **GET** `/cases` (also `/api/cases` and `/api/v1/cases`)
- **Authorization**: Bearer JWT (`INVESTIGATOR`, `ADMIN`, `LAWYER`, `JUDGE`)
- **Query Parameters**:
  - `status`: Optional filter (`OPEN`, `UNDER_ANALYSIS`, `COMPLETED`, `ARCHIVED`)
- **Response** `200 OK`:
  ```json
  {
    "success": true,
    "total": 1,
    "data": [
      {
        "case_id": "CASE-2026-9FA1C2D8",
        "case_number": "CR-2026-DL-8821",
        "title": "State vs. Anonymous Cyber Extortion",
        "description": "Investigation into digital blackmail artifacts...",
        "status": "OPEN",
        "created_by": "12f4738f-38d5-47dc-8f6f-08c24d5f61f5",
        "created_at": "2026-09-26T14:00:00.000000Z",
        "updated_at": "2026-09-26T14:00:00.000000Z",
        "jurisdiction": "High Court of Delhi",
        "evidence_count": 0
      }
    ]
  }
  ```

### 3.3 Get Case Details
- **GET** `/cases/{case_id}` (also `/api/cases/{case_id}` and `/api/v1/cases/{case_id}`)
- **Authorization**: Bearer JWT (`INVESTIGATOR`, `ADMIN`, `LAWYER`, `JUDGE`)
- **Response** `200 OK`:
  ```json
  {
    "success": true,
    "data": {
      "case_id": "CASE-2026-9FA1C2D8",
      "case_number": "CR-2026-DL-8821",
      "title": "State vs. Anonymous Cyber Extortion",
      "description": "Investigation into digital blackmail artifacts...",
      "status": "OPEN",
      "created_by": "12f4738f-38d5-47dc-8f6f-08c24d5f61f5",
      "created_at": "2026-09-26T14:00:00.000000Z",
      "updated_at": "2026-09-26T14:00:00.000000Z",
      "jurisdiction": "High Court of Delhi",
      "evidence_items": []
    }
  }
  ```
- **Error** `404 Not Found`: If `case_id` does not exist (`CASE_NOT_FOUND`).

### 3.4 Partially Update Case Docket
- **PATCH** `/cases/{case_id}` (also `/api/cases/{case_id}` and `/api/v1/cases/{case_id}`)
- **Authorization**: Bearer JWT (`INVESTIGATOR`, `ADMIN`)
- **Request Body**:
  ```json
  {
    "title": "State vs. Cyber Extortion Syndicate (Amended)",
    "description": "Primary suspect cloud server identified.",
    "status": "UNDER_ANALYSIS"
  }
  ```
- **Response** `200 OK`:
  ```json
  {
    "success": true,
    "message": "Case docket updated successfully.",
    "data": {
      "case_id": "CASE-2026-9FA1C2D8",
      "case_number": "CR-2026-DL-8821",
      "title": "State vs. Cyber Extortion Syndicate (Amended)",
      "description": "Primary suspect cloud server identified.",
      "status": "UNDER_ANALYSIS",
      "created_by": "12f4738f-38d5-47dc-8f6f-08c24d5f61f5",
      "created_at": "2026-09-26T14:00:00.000000Z",
      "updated_at": "2026-09-26T14:15:22.000000Z",
      "jurisdiction": "High Court of Delhi",
      "evidence_count": 0
    }
  }
  ```
- **Validation**:
  - Allowed statuses: `OPEN`, `UNDER_ANALYSIS`, `COMPLETED`, `ARCHIVED` (422 if invalid).
  - Unauthenticated requests receive `401 Unauthorized`.
  - Non-manager roles (`LAWYER`, `JUDGE`) receive `403 Forbidden`.

---

## 4. Evidence Intake & Vault Endpoints

### 4.1 Secure Evidence Intake Upload
- **POST** `/api/evidence/upload` (and `/api/v1/evidence/upload`)
- **Authorization**: Bearer JWT (`INVESTIGATOR`, `ADMIN`, `SYSTEM_LEAD`)
- **Content-Type**: `multipart/form-data`
- **Form Parameters**:
  - `case_id`: `String` (Required, valid existing case docket ID)
  - `file`: `UploadFile` (Required, binary evidence file)
  - `source_description`: `String` (Optional, seizure notes, chain of custody origin)
  - `client_sha256`: `String` (Optional, client-computed SHA-256 for dual-verification)

#### Supported Media Types & Extensions
| Category | Extensions | Allowed MIME Types |
| :--- | :--- | :--- |
| **Image** | `.jpg`, `.jpeg`, `.png`, `.webp` | `image/jpeg`, `image/png`, `image/webp` |
| **Video** | `.mp4`, `.mov`, `.avi` | `video/mp4`, `video/quicktime`, `video/x-msvideo` |
| **Audio** | `.mp3`, `.wav`, `.m4a` | `audio/mpeg`, `audio/wav`, `audio/mp4`, `audio/x-m4a` |
| **Document** | `.pdf`, `.docx`, `.txt` | `application/pdf`, `application/vnd.openxmlformats-officedocument.wordprocessingml.document`, `text/plain` |

> **Security Rule**: Arbitrary executable files (`.exe`, `.dll`, `.bat`, `.cmd`, `.sh`, `.bin`, etc.) and files with executable binary magic bytes (`MZ`, `ELF`, `#!`, Mach-O) are strictly blocked (`400 Bad Request`).
> **Size Limit**: Configurable via `MAX_EVIDENCE_FILE_SIZE_MB` (default: 500MB). Files exceeding this limit return `413 Request Entity Too Large`.

#### 11-Step Cryptographic Intake Process
1. **Authenticate User**: Verify JWT bearer token and enforce `INVESTIGATOR` / `ADMIN` role.
2. **Verify Case Access**: Confirm valid `case_id` exists in database (`404` if missing).
3. **Validate File**: Whitelist file extension, inspect magic bytes against executables, enforce size limit.
4. **Determine Media Type**: Classify into canonical categories (`IMAGE`, `VIDEO`, `AUDIO`, `DOCUMENT`).
5. **Generate Evidence ID**: Unique identifier formatted as `EVD-<YEAR>-<UUID_HEX>`.
6. **Calculate SHA-256**: Stream file content and compute deterministic SHA-256 cryptographic digest.
7. **Store Original File**: Vault byte-exact file copy to unique WORM path (`evidence_vault/<case_id>/<evidence_id>_<safe_filename>`). File is never modified or overwritten.
8. **Store Evidence Metadata**: Record filesystem size, MIME type, SHA-256, extraction timestamp in database.
9. **Create Initial Custody Event**: Mint genesis block (sequence 1, `previous_hash="0"*64`) in continuous SHA-256 custody ledger.
10. **Create Audit Log**: Record `EVIDENCE_UPLOADED` compliance entry with user ID and resource tracking.
11. **Return Evidence Information**: Return verified metadata and genesis proof.

- **Response** `201 Created`:
  ```json
  {
    "evidence_id": "EVD-2026-A1B2C3D4",
    "case_id": "CASE-2026-9FA1C2D8",
    "filename": "surveillance_clip.mp4",
    "media_type": "VIDEO",
    "file_size": 15849200,
    "sha256_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "status": "VAULTED",
    "created_at": "2026-09-26T14:20:00.000000Z",
    "success": true,
    "data": {
      "evidence_id": "EVD-2026-A1B2C3D4",
      "case_id": "CASE-2026-9FA1C2D8",
      "filename": "surveillance_clip.mp4",
      "original_filename": "surveillance_clip.mp4",
      "media_type": "VIDEO",
      "mime_type": "video/mp4",
      "file_size": 15849200,
      "file_size_bytes": 15849200,
      "sha256_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
      "vault_status": "SECURED_READONLY",
      "genesis_event_hash": "a4d3f5...",
      "status": "VAULTED",
      "created_at": "2026-09-26T14:20:00.000000Z"
    }
  }
  ```

#### Duplicate Upload Behavior
If an identical file (matching SHA-256 hash) is uploaded to the same case docket, the upload is rejected with `409 Conflict`:
```json
{
  "success": false,
  "error": {
    "code": "DUPLICATE_EVIDENCE",
    "message": "Identical evidence with SHA-256 2cf24d... is already registered in case CASE-2026-9FA1C2D8 as EVD-2026-A1B2C3D4.",
    "timestamp": "2026-09-26T14:22:00.000000Z",
    "details": {}
  }
}
```

### 4.2 Legacy Case Evidence Intake
- **POST** `/cases/{case_id}/evidence` (and `/api/v1/cases/{case_id}/evidence`)
- Backward-compatible wrapper calling the unified `EvidenceService.intake_evidence()` pipeline.

### 4.3 Get Evidence Details
- **GET** `/evidence/{evidence_id}`
- **Response** `200 OK`:
  ```json
  {
    "success": true,
    "data": {
      "evidence_id": "EVD-2026-0001",
      "case_id": "CASE-2026-0001",
      "original_filename": "extortion_screenshot.png",
      "file_size_bytes": 245100,
      "mime_type": "image/png",
      "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "integrity_verified": true,
      "status": "READY_FOR_ANALYSIS"
    }
  }
  ```

### 4.4 Cryptographic Evidence Integrity Verification (Phase 6)
- **POST** `/api/evidence/{evidence_id}/verify-integrity` (and `/api/v1/evidence/{evidence_id}/verify-integrity`)
- **Authorization**: Bearer JWT (optional for internal probes, recommended for audit logging)
- **Path Parameters**:
  - `evidence_id`: Unique identifier of vaulted evidence artifact.
- **Process**:
  1. Retrieves original stored file from storage abstraction (Local WORM, S3, or MinIO).
  2. Computes current SHA-256 hash using chunked streaming reads via `HashingService`.
  3. Performs timing-safe comparison against registered `evidence.sha256_hash`.
  4. Appends a tamper-evident block to the Chain of Custody ledger.
  5. Records compliance audit trail event.
  6. Returns verification report.

#### Responses

##### 1. Intact Evidence (`VERIFIED`):
- **Status**: `200 OK`
```json
{
  "evidence_id": "EVD-2026-A1B2C3D4",
  "stored_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  "current_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  "integrity_status": "VERIFIED",
  "verified_at": "2026-09-26T14:28:00.000000Z",
  "error_message": null,
  "custody_event_id": "EVT-C1D2E3F4"
}
```

##### 2. Tampered / Modified Evidence (`MISMATCH`):
> **Zero-Overwrite Guarantee**: The original `stored_hash` is **never** overwritten. The evidence status is updated to `INTEGRITY_COMPROMISED`.
- **Status**: `200 OK`
```json
{
  "evidence_id": "EVD-2026-A1B2C3D4",
  "stored_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  "current_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "integrity_status": "MISMATCH",
  "verified_at": "2026-09-26T14:28:00.000000Z",
  "error_message": "Cryptographic hash mismatch! Vaulted file hash does not match registered hash.",
  "custody_event_id": "EVT-TAMPER-001"
}
```

##### 3. Storage Error or Missing File (`ERROR`):
- **Status**: `200 OK`
```json
{
  "evidence_id": "EVD-2026-A1B2C3D4",
  "stored_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  "current_hash": null,
  "integrity_status": "ERROR",
  "verified_at": "2026-09-26T14:28:00.000000Z",
  "error_message": "Evidence file missing from vault storage: ./storage/vault/CASE-01/EVD-01_file.png",
  "custody_event_id": "EVT-ERROR-001"
}
```

---

## 5. Forensic and AI Orchestration Endpoints (Phase 7)

The backend acts strictly as an orchestration layer; forensic analysis and model inference are delegated to pluggable adapters connecting to Anu Sharma's engines.

### 5.1 Orchestrate Forensic Analysis
- **POST** `/api/forensics/analyze/{evidence_id}` (and `/api/v1/forensics/analyze/{evidence_id}`)
- **Authorization**: Bearer JWT (`INVESTIGATOR`, `ADMIN`, `FORENSIC_EXPERT`, `SYSTEM_LEAD`)
- **9-Step Orchestration Process**:
  1. Authenticate user.
  2. Verify evidence access.
  3. Verify evidence integrity against vaulted SHA-256 hash (aborts with `409` if tampered).
  4. Send evidence reference to forensic engine adapter.
  5. Receive structured non-destructive result.
  6. Persist `AnalysisResult` (status: `COMPLETED` or `FAILED`).
  7. Mint next block in `CustodyEvent` ledger.
  8. Log compliance `AuditLog` entry.
  9. Return analysis result.
- **Response** `200 OK`:
  ```json
  {
    "analysis_id": "ANL-2026-F1A2B3C4",
    "evidence_id": "EVD-2026-A1B2C3D4",
    "analysis_type": "FORENSIC_INSPECTION",
    "status": "COMPLETED",
    "format_valid": true,
    "magic_bytes": "89504e470d0a1a0a",
    "detected_mime": "image/png",
    "anomalies": [],
    "metadata": {
      "filesystem": { "size": 158400 },
      "exif": {}
    },
    "prediction": "STRUCTURALLY_CONSISTENT",
    "confidence": 0.95,
    "risk_score": 0.10,
    "findings": ["Binary header and metadata validated against format specification."],
    "explanation": "File header, signature bytes, and structural metadata are consistent with declared format.",
    "custody_event_id": "EVT-C1D2E3F4",
    "created_at": "2026-09-26T14:40:00.000000Z"
  }
  ```

### 5.2 Orchestrate AI Analysis
- **POST** `/api/ai/analyze/{evidence_id}` (and `/api/v1/ai/analyze/{evidence_id}`)
- **Authorization**: Bearer JWT (`INVESTIGATOR`, `ADMIN`, `FORENSIC_EXPERT`, `SYSTEM_LEAD`)
- **Orchestration Pattern**: Identical 9-step pipeline as forensic analysis.
- **Expected Fields**:
  - `evidence_id`: str
  - `analysis_type`: str
  - `prediction`: str
  - `confidence`: float
  - `risk_score`: float
  - `findings`: List[str]
  - `explanation`: str
  - `model_version`: str
- **Response** `200 OK`:
  ```json
  {
    "evidence_id": "EVD-2026-A1B2C3D4",
    "analysis_type": "TAMPER_DETECTION",
    "prediction": "NO_TAMPER_INDICATIONS_DETECTED",
    "confidence": 0.60,
    "risk_score": 0.40,
    "findings": ["Baseline structural screening complete. No blatant file truncations detected."],
    "explanation": "Statistical heuristic screening found no structural manipulation markers with confidence 0.60.",
    "model_version": "0.1.0",
    "model_name": "TamperScreener-Baseline",
    "status": "COMPLETED",
    "analysis_id": "AIR-2026-9B8A7C6D",
    "custody_event_id": "EVT-E5F6G7H8",
    "created_at": "2026-09-26T14:40:00.000000Z"
  }
  ```

### 5.3 Failure Handling & Engine Status Matrix

| Failure Mode | HTTP Status | Error Code | AnalysisResult Status | Audit Action |
| :--- | :--- | :--- | :--- | :--- |
| **Engine Offline / Unreachable** | `503 Service Unavailable` | `ENGINE_UNAVAILABLE` | `FAILED` | `..._ANALYSIS_FAILED` |
| **Worker Processing Timeout** | `504 Gateway Timeout` | `ENGINE_TIMEOUT` | `FAILED` | `..._ANALYSIS_FAILED` |
| **Malformed / Invalid Response** | `502 Bad Gateway` | `INVALID_ENGINE_RESPONSE` | `FAILED` | `..._ANALYSIS_FAILED` |
| **Unsupported Media Format** | `415 Unsupported Media` | `UNSUPPORTED_MEDIA_TYPE` | `FAILED` | `..._ANALYSIS_FAILED` |
| **Engine Internal Crash / Fault** | `500 Internal Error` | `ANALYSIS_FAILED` | `FAILED` | `..._ANALYSIS_FAILED` |
| **Pre-Check Integrity Violation** | `409 Conflict` | `INTEGRITY_COMPROMISED` | (Aborted) | `INTEGRITY_COMPROMISED` |

### 5.4 Legacy Pipeline Endpoints
- **GET** `/evidence/{evidence_id}/analysis`
- **Response** `200 OK`:
  ```json
  {
    "success": true,
    "data": {
      "evidence_id": "EVD-2026-0001",
      "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "forensic_report": {
        "format_valid": true,
        "magic_bytes_match": true,
        "mime_detected": "image/png",
        "exif_metadata": {
          "Software": "Adobe Photoshop 24.1",
          "ModifyDate": "2026-09-24T18:32:00Z"
        },
        "anomalies_detected": ["Software tag indicates photo manipulation suite edit."]
      },
      "ai_analysis": {
        "tamper_detected": true,
        "tamper_probability": 0.88,
        "model_version": "tamper-screener-v1.0",
        "methods_detected": ["Copy-Move splicing near timestamp badge"]
      },
      "explainability": {
        "summary": "High probability of local pixel manipulation detected in top-right quadrant.",
        "confidence_level": "HIGH",
        "confidence_score": 0.88,
        "limitations": "Model trained on common PNG compression profiles. Independent human forensic review advised."
      }
    }
  }
  ```

---

## 6. Chain of Custody Endpoints (Phase 8 Specification)

### 6.1 Get Chronological Evidence Custody History
- **GET** `/api/custody/evidence/{evidence_id}`
- **Security**: Requires Bearer JWT with authorized role (`INVESTIGATOR`, `ADMIN`, `JUDGE`, `AUDITOR`, `SYSTEM_LEAD`, `FORENSIC_EXPERT`).
- **Response** `200 OK`:
  ```json
  {
    "success": true,
    "evidence_id": "EVD-2026-6BAAC7B6",
    "chain_intact": true,
    "total_events": 3,
    "history": [
      {
        "event_id": "EVT-47EAC3058ABC",
        "evidence_id": "EVD-2026-6BAAC7B6",
        "user_id": "fc1f16b2-b306-4b11-b6f5-648c304d3caf",
        "event_type": "EVIDENCE_UPLOADED",
        "timestamp": "2026-09-26T09:21:17.603900+00:00",
        "description": "Evidence 'cctv_frame.png' securely vaulted into WORM vault with SHA-256 e24d...",
        "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "event_hash": "cef7fa2a95dbfb8ff75da4b063237e5307b783bc518f85fef142bd20a01e8f41"
      },
      {
        "event_id": "EVT-89472AF01C92",
        "evidence_id": "EVD-2026-6BAAC7B6",
        "user_id": "fc1f16b2-b306-4b11-b6f5-648c304d3caf",
        "event_type": "FORENSIC_ANALYSIS_COMPLETED",
        "timestamp": "2026-09-26T09:21:20.124500+00:00",
        "description": "Forensic structural inspection completed by fc1f16b2... Risk score: 0.10",
        "previous_hash": "cef7fa2a95dbfb8ff75da4b063237e5307b783bc518f85fef142bd20a01e8f41",
        "event_hash": "d1e2f3a4b5c67890123456789abcdef0123456789abcdef0123456789abcdef0"
      },
      {
        "event_id": "EVT-C34810BA9342",
        "evidence_id": "EVD-2026-6BAAC7B6",
        "user_id": "fc1f16b2-b306-4b11-b6f5-648c304d3caf",
        "event_type": "INTEGRITY_VERIFIED",
        "timestamp": "2026-09-26T09:21:22.845100+00:00",
        "description": "Cryptographic evidence integrity verified for EVD-2026-6BAAC7B6",
        "previous_hash": "d1e2f3a4b5c67890123456789abcdef0123456789abcdef0123456789abcdef0",
        "event_hash": "e2f3a4b5c67890123456789abcdef0123456789abcdef0123456789abcdef01"
      }
    ],
    "events": [...]
  }
  ```

### 6.2 Append Custody Event Block
- **POST** `/api/custody/evidence/{evidence_id}/events`
- **Security**: Requires Bearer JWT (`INVESTIGATOR`, `ADMIN`, `SYSTEM_LEAD`, `FORENSIC_EXPERT`).
- **Request Body**:
  ```json
  {
    "event_type": "EVIDENCE_TRANSFERRED",
    "description": "Evidence transferred to Cyber Crime Forensic Division, New Delhi",
    "details": {
      "transferred_to": "Dr. Anu Sharma",
      "department": "Digital Forensics Lab",
      "dispatch_id": "DSP-DL-2026-99"
    }
  }
  ```
- **Response** `201 Created`:
  ```json
  {
    "success": true,
    "message": "Custody event 'EVIDENCE_TRANSFERRED' recorded successfully.",
    "event": {
      "event_id": "EVT-...",
      "evidence_id": "EVD-2026-6BAAC7B6",
      "user_id": "usr-...",
      "event_type": "EVIDENCE_TRANSFERRED",
      "timestamp": "2026-09-26T09:25:00.000000+00:00",
      "description": "Evidence transferred to Cyber Crime Forensic Division, New Delhi",
      "previous_hash": "...",
      "event_hash": "...",
      "sequence_number": 4
    }
  }
  ```

### 6.3 Verify Cryptographic Chain Integrity
- **POST** `/api/custody/{evidence_id}/verify` (also `/api/evidence/{evidence_id}/custody/verify`)
- **Response** `200 OK`:
  ```json
  {
    "evidence_id": "EVD-2026-6BAAC7B6",
    "is_valid": true,
    "verified_blocks": 3,
    "broken_at_event_id": null,
    "diagnostic_message": "Chain verified."
  }
  ```


---

## 7. Court Admissibility & Report Endpoints

### 7.1 Generate Admissibility Certificate (BSA / 65B)
- **POST** `/cases/{case_id}/report`
- **Request Body**:
  ```json
  {
    "certifying_officer_name": "Dhananjay Sharma",
    "certifying_officer_designation": "Forensic Systems Lead",
    "jurisdiction": "High Court of Delhi",
    "include_evidence_ids": ["EVD-2026-0001"]
  }
  ```
- **Response** `201 Created`:
  ```json
  {
    "success": true,
    "data": {
      "report_id": "REP-2026-001",
      "case_id": "CASE-2026-0001",
      "generated_at": "2026-09-26T12:16:00Z",
      "compliance_standard": "Bharatiya Sakshya Adhiniyam, 2023 - Section 63/65B",
      "report_sha256": "4a7d1ed414474e4033ac29ccb8653d9b...",
      "qr_verification_url": "http://localhost:8000/api/v1/reports/verify/REP-2026-001",
      "download_url": "/api/v1/reports/download/REP-2026-001.pdf"
    }
  }
  ```

### 7.2 Public QR Verification Endpoint
- **GET** `/reports/verify/{report_id}`
- **Response** `200 OK`:
  ```json
  {
    "success": true,
    "verified": true,
    "report_id": "REP-2026-001",
    "case_id": "CASE-2026-0001",
    "certifying_authority": "Dhananjay Sharma (Forensic Systems Lead)",
    "official_report_sha256": "4a7d1ed414474e4033ac29ccb8653d9b...",
    "custody_chain_status": "UNBROKEN_CRYPTOGRAPHIC_VERIFIED",
    "total_evidences_certified": 1,
    "tamper_detected_in_case": true
  }
  ```


---

## 8. Evidence Correlation & Intelligence Endpoints (Phase 9 Specification)

### 8.1 Get Case Evidence Correlation & Intelligence
- **GET** `/api/correlation/case/{case_id}`
- **Security**: Requires Bearer JWT with authorized role (`INVESTIGATOR`, `ADMIN`, `JUDGE`, `LAWYER`, `SYSTEM_LEAD`, `FORENSIC_EXPERT`, `AUDITOR`).
- **Response** `200 OK`:
  ```json
  {
    "success": true,
    "case_id": "CASE-2026-CAD5341C",
    "total_evidence_count": 2,
    "total_red_flags": 1,
    "timeline": [
      {
        "sequence_index": 1,
        "event_id": "INTAKE-EVD-2026-414A7550",
        "evidence_id": "EVD-2026-414A7550",
        "filename": "cctv_frame_alpha.png",
        "event_type": "EVIDENCE_INTAKE",
        "timestamp": "2026-09-26T09:21:17.601947+00:00",
        "description": "Evidence artifact 'cctv_frame_alpha.png' registered in case docket",
        "status": "SECURED",
        "source": "EVIDENCE_INTAKE"
      },
      {
        "sequence_index": 2,
        "event_id": "INTAKE-EVD-2026-AE9D6916",
        "evidence_id": "EVD-2026-AE9D6916",
        "filename": "cctv_frame_beta.png",
        "event_type": "EVIDENCE_INTAKE",
        "timestamp": "2026-09-26T09:21:19.421500+00:00",
        "description": "Evidence artifact 'cctv_frame_beta.png' registered in case docket",
        "status": "SECURED",
        "source": "EVIDENCE_INTAKE"
      }
    ],
    "relationships": [
      {
        "source_evidence_id": "EVD-2026-414A7550",
        "target_evidence_id": "EVD-2026-AE9D6916",
        "related_to": "EVD-2026-AE9D6916",
        "relationship_type": "SAME_SOURCE_DEVICE",
        "reason": "Evidence EVD-2026-414A7550 and Evidence EVD-2026-AE9D6916 were acquired from the identical origin source: 'Traffic junction camera #14'.",
        "confidence": 0.85,
        "notes": "Evidence EVD-2026-414A7550 and Evidence EVD-2026-AE9D6916 were acquired from the identical origin source: 'Traffic junction camera #14'."
      }
    ],
    "cross_evidence_matches": [
      {
        "match_type": "SOURCE_MATCH",
        "evidence_ids": ["EVD-2026-414A7550", "EVD-2026-AE9D6916"],
        "matched_attribute": "source_description",
        "matched_value": "Traffic junction camera #14",
        "confidence": 0.85,
        "description": "Shared seizure source 'Traffic junction camera #14' linked across EVD-2026-414A7550 and EVD-2026-AE9D6916."
      }
    ],
    "red_flags": [
      {
        "flag_id": "FLAG-DUP-14A89C02",
        "flag_type": "DUPLICATE_EVIDENCE",
        "evidence_id": "EVD-2026-414A7550",
        "severity": "MEDIUM",
        "description": "Duplicate evidence detected: Evidence EVD-2026-414A7550 shares identical cryptographic SHA-256 hash with evidence ['EVD-2026-AE9D6916'].",
        "evidence_reference": {
          "evidence_id": "EVD-2026-414A7550",
          "duplicate_evidence_ids": ["EVD-2026-AE9D6916"],
          "sha256_hash": "e3b0c44..."
        }
      }
    ]
  }
  ```

### 8.2 Principles & Compliance Guarantees
1. **Timestamp Authenticity**: Uses solely documented evidence and custody event timestamps. Does NOT invent timestamps; if missing, returns `null` / `"unknown"`.
2. **Relationships**: Stores directed links (`Evidence A related_to Evidence B`) alongside detailed evidence-based `reason`.
3. **Red Flags**: Evidence-based anomalies only (`timestamp inconsistency`, `hash mismatch`, `metadata inconsistency`, `duplicate evidence`, `analysis anomaly`).
4. **Admissibility Safeguard**: Strict prohibition against claiming criminality in red flags; empirical forensic and computational observations only.

---

## 9. Case & Evidence Intelligence Summary (Phase 13 Specification)

### 9.1 Consolidated Case Intelligence Summary
- **GET** `/api/cases/{case_id}/intelligence-summary` (and alias `/api/cases/{case_id}/summary`)
- **Authorization**: Bearer JWT (`INVESTIGATOR`, `ADMIN`, `LAWYER`, `JUDGE`, `AUDITOR`, `SYSTEM_LEAD`, `FORENSIC_EXPERT`)
- **Purpose**: Provides a consolidated, read-only case-level intelligence view aggregating existing project data across 12 distinct domains without database mutation.
- **Response** `200 OK`:
  ```json
  {
    "success": true,
    "case": {
      "case_id": "CASE-2026-9FA1C2D8",
      "case_number": "CR-2026-DL-8821",
      "title": "State vs. Anonymous Cyber Extortion",
      "description": "Investigation into digital blackmail artifacts.",
      "status": "UNDER_ANALYSIS",
      "jurisdiction": "High Court of Delhi",
      "created_by": "12f4738f-38d5-47dc-8f6f-08c24d5f61f5",
      "created_at": "2026-09-26T14:00:00.000000Z",
      "updated_at": "2026-09-26T14:00:00.000000Z"
    },
    "evidence": {
      "total_count": 1,
      "by_media_type": {
        "IMAGE": 1
      },
      "total_size_bytes": 102400,
      "items": [
        {
          "evidence_id": "EVD-2026-A1B2C3D4",
          "original_filename": "extortion_screenshot.png",
          "media_type": "IMAGE",
          "mime_type": "image/png",
          "file_size_bytes": 102400,
          "sha256_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
          "status": "VERIFIED",
          "source_description": "Victim desktop export",
          "created_at": "2026-09-26T14:20:00.000000Z"
        }
      ]
    },
    "integrity": {
      "total_checked": 1,
      "intact_count": 1,
      "compromised_count": 0,
      "storage_error_count": 0,
      "integrity_status": "INTACT"
    },
    "forensic": {
      "inspected_count": 1,
      "anomalies_detected_count": 0,
      "format_valid_count": 1,
      "items": [
        {
          "evidence_id": "EVD-2026-A1B2C3D4",
          "format_valid": true,
          "magic_bytes": "89504e470d0a1a0a",
          "anomalies_count": 0,
          "anomalies": []
        }
      ]
    },
    "ai_analysis": {
      "analyzed_count": 1,
      "tamper_detected_count": 0,
      "average_risk_score": 0.08,
      "items": [
        {
          "analysis_id": "AIR-2026-9B8A7C6D",
          "evidence_id": "EVD-2026-A1B2C3D4",
          "analysis_type": "TAMPER_DETECTION",
          "prediction": "NO_TAMPER_INDICATIONS_DETECTED",
          "confidence": 0.92,
          "risk_score": 0.08,
          "tamper_detected": false,
          "findings": ["Statistical pixel histogram consistent"],
          "model_name": "TamperScreener-Baseline",
          "model_version": "0.1.0"
        }
      ]
    },
    "explainability": {
      "records_count": 1,
      "available": true,
      "categories": {
        "HIGH": 1
      }
    },
    "correlation": {
      "timeline_events_count": 2,
      "relationships_count": 0,
      "cross_matches_count": 0,
      "red_flags_count": 0,
      "red_flags": []
    },
    "timeline": {
      "total_events": 2,
      "has_timeline": true,
      "earliest_timestamp": "2026-09-26T14:20:00.000000Z",
      "latest_timestamp": "2026-09-26T14:28:00.000000Z"
    },
    "custody": {
      "total_events": 2,
      "all_chains_intact": true,
      "broken_chains_count": 0,
      "evidence_chains": [
        {
          "evidence_id": "EVD-2026-A1B2C3D4",
          "chain_intact": true,
          "total_events": 2,
          "broken_at_event_id": null
        }
      ]
    },
    "reports": {
      "total_reports": 1,
      "reports_list": [
        {
          "report_id": "REP-2026-001",
          "report_type": "PDF",
          "status": "GENERATED",
          "report_sha256": "4a7d1ed414474e4033ac29ccb8653d9b...",
          "verification_code": "VERIFY-9FA1C2D8",
          "created_at": "2026-09-26T14:35:00.000000Z"
        }
      ]
    },
    "verification": {
      "total_verifications": 1,
      "valid_verifications": 1,
      "tampered_verifications": 0,
      "recent_verifications": [
        {
          "verification_id": "VER-8D3E9112",
          "report_id": "REP-2026-001",
          "verification_method": "QR_CODE",
          "status": "VALID",
          "timestamp": "2026-09-26T14:40:00.000000Z"
        }
      ]
    },
    "audit": {
      "total_audit_events": 4,
      "recent_events": [
        {
          "audit_id": "AUD-E1F2A3B4",
          "user_id": "12f4738f-38d5-47dc-8f6f-08c24d5f61f5",
          "action": "EVIDENCE_UPLOADED",
          "resource_type": "EVIDENCE",
          "resource_id": "EVD-2026-A1B2C3D4",
          "timestamp": "2026-09-26T14:20:00.000000Z",
          "metadata": {
            "filename": "extortion_screenshot.png"
          }
        }
      ]
    },
    "overall_status": "READY_FOR_COURT"
  }
  ```

### 9.2 Deterministic Overall Status Rules
The `overall_status` field is computed deterministically using the following strict priority rules:
1. `NO_EVIDENCE`: When `evidence.total_count == 0`.
2. `INTEGRITY_COMPROMISED`: If any evidence has `status == "INTEGRITY_COMPROMISED"`, any custody chain is broken (`broken_chains_count > 0`), or any report verification detected tampering (`tampered_verifications > 0`).
3. `STORAGE_ERROR`: If any evidence has `status == "STORAGE_ERROR"`.
4. `ARCHIVED`: If the case lifecycle status is `ARCHIVED`.
5. `READY_FOR_COURT`: If evidence is present (`total_count > 0`), all cryptographic custody chains are unbroken, zero integrity compromises exist, and at least one court admissibility report has been issued (`total_reports > 0`).
6. `UNDER_ANALYSIS`: If evidence is present and intact, but no final court admissibility certificate/report has been generated yet.

### 9.3 404 Not Found Behavior
If `case_id` does not exist in the database, the endpoint returns `404 Not Found` with RFC 7807 problem details:
```json
{
  "success": false,
  "error": {
    "code": "CASE_NOT_FOUND",
    "message": "The requested Case with identifier 'CASE-NONEXISTENT' was not found in vault.",
    "timestamp": "2026-09-26T14:45:00.000000Z",
    "details": {}
  }
}
```

---

## 10. Investigator Operational Case View (Phase 14)

### 10.1 Overview & Endpoint Specification
Provides a deterministic, read-only operational triage layer on top of the Phase 13 Case Intelligence Summary (`CaseIntelligenceService.get_case_intelligence_summary`). It translates aggregated case forensic, AI screening, integrity, custody, and verification records into actionable operational alerts and pending actions.

- **Endpoint (Canonical)**: `GET /cases/{case_id}/operational-view`  
- **Endpoint (Alias)**: `GET /cases/{case_id}/overview`  
- **Router Prefix**: Exposed on both `/api/cases` and `/api/v1/cases`  
- **Method**: `GET` (Strictly read-only; zero database mutations, no audit event generation, no state changes)  
- **Authorization**: Bearer JWT. Reuses existing case viewer RBAC (`auth_case_viewer`).  
  - Allowed Roles: `INVESTIGATOR`, `ADMIN`, `LAWYER`, `JUDGE`, `AUDITOR`, `SYSTEM_LEAD`, `FORENSIC_EXPERT`

### 10.2 Response Schema & Contract
Returns `200 OK` with `OperationalCaseViewResponse`:

```json
{
  "success": true,
  "case_id": "CASE-2026-A1B2C3D4",
  "case_number": "CR-2026-0926-01",
  "title": "State v. Extortion Syndicate",
  "overall_status": "INTEGRITY_COMPROMISED",
  "attention_required": true,
  "critical_alerts": [
    {
      "alert_type": "INTEGRITY_COMPROMISED",
      "severity": "HIGH",
      "resource_id": "EVD-2026-0001",
      "description": "Evidence 'tampered_screenshot.png' cryptographic integrity is compromised (SHA-256 mismatch)."
    },
    {
      "alert_type": "BROKEN_CUSTODY_CHAIN",
      "severity": "HIGH",
      "resource_id": "EVD-2026-0001",
      "description": "Cryptographic chain of custody verification failed for evidence 'EVD-2026-0001'."
    },
    {
      "alert_type": "STORAGE_ERROR",
      "severity": "MEDIUM",
      "resource_id": "EVD-2026-0002",
      "description": "Evidence 'corrupted_audio.wav' encountered a storage access or missing file error."
    }
  ],
  "pending_actions": [
    {
      "action_type": "REVIEW_INTEGRITY_COMPROMISE",
      "resource_id": "EVD-2026-0001",
      "description": "Review cryptographic hash mismatch and chain breach for evidence 'EVD-2026-0001'."
    },
    {
      "action_type": "VERIFY_CUSTODY_CHAIN",
      "resource_id": "EVD-2026-0001",
      "description": "Re-audit broken chain of custody blocks for evidence 'EVD-2026-0001'."
    },
    {
      "action_type": "PENDING_FORENSIC_ANALYSIS",
      "resource_id": "EVD-2026-0003",
      "description": "Evidence 'newly_vaulted_doc.pdf' requires forensic metadata and byte structure inspection."
    }
  ],
  "findings_summary": {
    "validated_findings": 3,
    "anomalous_findings": 2,
    "red_flags": 1
  },
  "summary_metrics": {
    "total_evidence": 3,
    "verified_evidence": 1,
    "compromised_evidence": 1,
    "analyzed_evidence": 2,
    "active_red_flags": 1,
    "reports_generated": 1
  },
  "intelligence_summary": {
    "success": true,
    "case": { "...": "..." },
    "evidence": { "...": "..." },
    "integrity": { "...": "..." },
    "forensic": { "...": "..." },
    "ai_analysis": { "...": "..." },
    "explainability": { "...": "..." },
    "correlation": { "...": "..." },
    "timeline": { "...": "..." },
    "custody": { "...": "..." },
    "reports": { "...": "..." },
    "verification": { "...": "..." },
    "audit": { "...": "..." },
    "overall_status": "INTEGRITY_COMPROMISED"
  }
}
```

### 10.3 Deterministic Critical Alerts
Surfaces alerts **only** from persisted case intelligence. No risk scores or legal conclusions are invented.

| Alert Type | Deterministic Trigger | Severity |
| :--- | :--- | :--- |
| `INTEGRITY_COMPROMISED` | Persisted evidence status is `INTEGRITY_COMPROMISED` (SHA-256 hash mismatch). | `HIGH` |
| `BROKEN_CUSTODY_CHAIN` | Evidence chain of custody verification failed (`chain_intact == false`). | `HIGH` |
| `AI_TAMPER_DETECTED` | DeepFake / tampering screening detected manipulation (`tamper_detected == true`). | `HIGH` |
| `TAMPERED_REPORT_VERIFICATION` | Report verification record records tamper status (`TAMPER_DETECTED`, `INVALID`, `TAMPERED`). | `HIGH` |
| `STORAGE_ERROR` | Persisted evidence status is `STORAGE_ERROR` (file missing or read failure). | `MEDIUM` |
| `FORENSIC_ANOMALY` | Byte header validation failed (`format_valid == false`) or metadata anomalies detected. | `MEDIUM` |
| `CORRELATION_RED_FLAG` | Evidence correlation engine identified cross-evidence discrepancies / red flags. | `MEDIUM` |

### 10.4 Deterministic Pending Actions
Surfaces actionable operational next steps only when genuine investigative work is required:

| Action Type | Condition |
| :--- | :--- |
| `REVIEW_INTEGRITY_COMPROMISE` | Surfaced for any evidence with `status == "INTEGRITY_COMPROMISED"`. |
| `VERIFY_CUSTODY_CHAIN` | Surfaced for any evidence where cryptographic custody verification failed. |
| `PENDING_FORENSIC_ANALYSIS` | Surfaced for evidence lacking structural/metadata inspection records. |
| `PENDING_AI_ANALYSIS` | Surfaced for evidence lacking automated AI screening results. |
| `REVIEW_CORRELATION_RED_FLAGS` | Surfaced when active correlation red flags exist for the case docket. |
| `GENERATE_COURT_REPORT` | Surfaced when evidence exists, is intact (`compromised_count == 0`, custody intact), but 0 reports have been issued. |

### 10.5 Attention Required Flag
Deterministic boolean flag:
- `attention_required = true`: When one or more `critical_alerts` OR `pending_actions` exist.
- `attention_required = false`: When all evidence is verified, all custody chains are intact, forensic & AI screenings are complete, 0 red flags exist, and court admissibility certificates have been generated.

### 10.6 404 Not Found Behavior
If `case_id` is not found, standard `CASE_NOT_FOUND` response with status `404 Not Found` is returned identical to Section 9.3.



