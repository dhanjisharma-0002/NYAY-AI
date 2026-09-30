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

---

## 11. Investigator Portfolio Operational Dashboard (Phase 15)

### 11.1 Overview & Endpoint Specification
Provides a cross-case operational dashboard and portfolio overview. Aggregates portfolio health, evidence metrics, pending actions, and urgent cases across all accessible case dockets deterministically without N+1 query amplification.

- **Endpoint (Canonical)**: `GET /cases/operational-dashboard`  
- **Endpoint (Alias)**: `GET /cases/portfolio-overview`  
- **Router Prefix**: Exposed on both `/api/cases` and `/api/v1/cases`  
- **Method**: `GET` (Strictly read-only; zero database mutations, no audit event generation, no state changes)  
- **Authorization**: Bearer JWT. Reuses existing case viewer RBAC (`auth_case_viewer`).  
  - `INVESTIGATOR`: Only accessible/owned/assigned cases (`created_by == current_user.id`).  
  - `ADMIN`, `JUDGE`, `AUDITOR`, `SYSTEM_LEAD`, `LAWYER`, `FORENSIC_EXPERT`: Broader system-wide case visibility.

### 11.2 Response Schema & Contract
Returns `200 OK` with `OperationalDashboardResponse`:

```json
{
  "total_cases": 12,
  "status_counts": {
    "OPEN": 3,
    "UNDER_ANALYSIS": 5,
    "COMPLETED": 4,
    "ARCHIVED": 0
  },
  "cases_requiring_attention": 4,
  "urgent_cases": [
    {
      "case_id": "CASE-2026-A1B2C3D4",
      "case_number": "CR-2026-0926-01",
      "title": "State v. Extortion Syndicate",
      "status": "UNDER_ANALYSIS",
      "high_alert_types": [
        "INTEGRITY_COMPROMISED",
        "BROKEN_CUSTODY_CHAIN"
      ]
    },
    {
      "case_id": "CASE-2026-E5F6G7H8",
      "case_number": "CR-2026-0926-02",
      "title": "State v. Deepfake Impersonation",
      "status": "UNDER_ANALYSIS",
      "high_alert_types": [
        "AI_TAMPER_DETECTED"
      ]
    }
  ],
  "evidence_metrics": {
    "total": 35,
    "verified": 28,
    "compromised": 4,
    "storage_errors": 3
  },
  "pending_actions": {
    "forensic_analysis": 6,
    "ai_analysis": 8,
    "court_reports": 2
  }
}
```

### 11.3 Urgent Cases Derivation
Cases are included in `urgent_cases` if they possess one or more active `HIGH` alerts as defined in Phase 14:
- `INTEGRITY_COMPROMISED`: Any evidence item with `status == "INTEGRITY_COMPROMISED"` (cryptographic hash mismatch).
- `BROKEN_CUSTODY_CHAIN`: Any evidence item where cryptographic chain of custody verification failed (`chain_intact == false`).
- `AI_TAMPER_DETECTED`: Any evidence item where AI analysis detected media tampering / deepfake artifacts.
- `TAMPERED_REPORT_VERIFICATION`: Any court report verification recording tamper status (`TAMPER_DETECTED`, `INVALID`, `TAMPERED`).

### 11.4 Evidence & Pending Action Metrics
- `evidence_metrics.total`: Total evidence items across accessible cases.
- `evidence_metrics.verified`: Evidence items with status `VERIFIED`.
- `evidence_metrics.compromised`: Evidence items with status `INTEGRITY_COMPROMISED`.
- `evidence_metrics.storage_errors`: Evidence items with status `STORAGE_ERROR`.
- `pending_actions.forensic_analysis`: Evidence items lacking structural/metadata inspection records (`EvidenceMetadata`).
- `pending_actions.ai_analysis`: Evidence items lacking AI screening results (`AnalysisResult`).
- `pending_actions.court_reports`: Cases with intact evidence (`total_evidence > 0`, zero compromised evidence, zero broken custody chains) where no court admissibility certificate has yet been issued (`total_reports == 0`).

### 11.5 Performance & Query Constraints
- **Zero N+1 Queries**: Aggregation is computed via batch queries over `Case`, `Evidence`, `EvidenceMetadata`, `AnalysisResult`, `CustodyEvent`, `Report`, and `VerificationRecord`.
- Zero calls to `get_case_intelligence_summary` or `get_operational_case_view`.

---

## 12. Case Docket Batch Pipeline Orchestrator (Phase 16)

### 12.1 Overview & Endpoint Specification
Executes automated end-to-end evidence processing (forensic metadata extraction, AI tamper screening, legal explainability, and cryptographic chain of custody logging) across all pending evidence items in a case docket. Resolves pending actions surfaced in Phase 14 & 15.

- **Endpoint (Canonical)**: `POST /cases/{case_id}/process-pipeline`  
- **Endpoint (Alias)**: `POST /cases/{case_id}/run-analysis`  
- **Router Prefix**: Exposed on both `/api/cases` and `/api/v1/cases`  
- **Method**: `POST`  
- **Authorization**: Bearer JWT (`INVESTIGATOR`, `ADMIN`, `SYSTEM_LEAD`).  
  - `INVESTIGATOR`: Scoped strictly to assigned/owned cases (`created_by == current_user.id`).  
  - `ADMIN`, `SYSTEM_LEAD`: Broad docket execution authority.

### 12.2 Request & Response Contract
- **Request Body** (Optional):
  ```json
  {
    "force_reanalysis": false
  }
  ```

- **Response** `200 OK` (`CaseBatchPipelineResponse`):
  ```json
  {
    "case_id": "CASE-2026-A1B2C3D4",
    "total_items": 4,
    "processed_count": 3,
    "anomalies_detected": 1,
    "tamper_detected_count": 1,
    "compromised_count": 0,
    "new_case_status": "UNDER_ANALYSIS"
  }
  ```

### 12.3 Execution Guarantees
1. **Idempotency**: By default (`force_reanalysis = false`), skips items that already possess both forensic metadata and AI analysis records. Calling the endpoint repeatedly on an already-processed docket returns `processed_count = 0`.
2. **Pre-Analysis Vault Verification**: Re-verifies file SHA-256 against registered baseline before invoking analysis engines.
3. **Fault-Tolerant Failure Handling**: On hash tampering or storage error, marks individual evidence item (`INTEGRITY_COMPROMISED` or `STORAGE_ERROR`) and records custody exception without aborting the batch.
4. **Cryptographic Custody Continuity**: Accurately chains each evidence event block to the latest existing block for that evidence.
5. **Lifecycle State Transition**: Transitions case status from `OPEN` to `UNDER_ANALYSIS` once at least one item is processed.
6. **Consolidated Audit Trail**: Emits exactly one `CASE_PIPELINE_BATCH_EXECUTED` audit event per batch execution.

---

## 13. Case Docket Finalization & Judicial Sealing (Phase 17)

### 13.1 Overview & Endpoint Specification
Provides formal judicial completion and cryptographic sealing for investigative case dockets under BSA 2023 / ISO 27037 standards. Enforces rigorous pre-closure validation gates, generates a deterministic docket sealing manifest hash, appends terminal `DOCKET_SEALED` chain-of-custody blocks to all evidence artifacts, transitions the case to `COMPLETED`, blocks future evidence intake, and emits a consolidated `CASE_FINALIZED` audit event.

- **Endpoint (Canonical)**: `POST /cases/{case_id}/finalize`
- **Endpoint (Alias)**: `POST /cases/{case_id}/seal`
- **Manifest Inspection**: `GET /cases/{case_id}/sealing-manifest`
- **Router Prefix**: Exposed on both `/api/cases` and `/api/v1/cases`
- **Method**: `POST` (finalization), `GET` (manifest inspection)
- **Authorization**: Bearer JWT (`INVESTIGATOR`, `ADMIN`, `JUDGE`, `SYSTEM_LEAD`).
  - `INVESTIGATOR`: Scoped strictly to owned/assigned cases (`created_by == current_user.id`).
  - `ADMIN`, `JUDGE`, `SYSTEM_LEAD`: Broad docket finalization authority.
  - Read-only manifest inspection allows `auth_case_viewer` (`INVESTIGATOR`, `ADMIN`, `LAWYER`, `JUDGE`, `AUDITOR`, `SYSTEM_LEAD`).

### 13.2 Pre-Finalization Validation Gates
All the following checks are enforced atomically before docket sealing:
1. **Non-Empty Docket**: Rejects empty cases (`total_evidence > 0`). Error: `EMPTY_CASE_DOCKET` (HTTP 400).
2. **Analysis Completeness**: Rejects cases with pending forensic or AI analysis (`PENDING_FORENSIC_ANALYSIS`, `PENDING_AI_ANALYSIS`). Error: `PENDING_ANALYSIS_REMAINS` (HTTP 400).
3. **Integrity Validation**: Rejects cases with any `INTEGRITY_COMPROMISED` or `STORAGE_ERROR` evidence items. Error: `EVIDENCE_INTEGRITY_COMPROMISED` (HTTP 400).
4. **Custody Chain Continuity**: Validates that all cryptographic custody event hash chains are unbroken (`is_valid == true`). Error: `BROKEN_CUSTODY_CHAIN` (HTTP 400).
5. **Court Report Requirement**: Requires at least one official court admissibility report (BSA 2023) generated for the case. Error: `COURT_REPORT_REQUIRED` (HTTP 400).
6. **Idempotency Guard**: Cases already in `COMPLETED` or `ARCHIVED` status cannot be finalized again. Error: `CASE_ALREADY_COMPLETED` (HTTP 409).

### 13.3 Request & Response Contract
- **Request Body** (Optional):
  ```json
  {
    "certification_notes": "All forensic analyses, AI screening, and custody chains verified for court submission.",
    "certifying_officer_name": "Dhananjay Sharma",
    "badge_number": "INV-DL-9841"
  }
  ```

- **Response** `200 OK` (`CaseFinalizationResponse`):
  ```json
  {
    "case_id": "CASE-2026-A1B2C3D4",
    "case_number": "CR-2026-0926-01",
    "previous_status": "UNDER_ANALYSIS",
    "new_status": "COMPLETED",
    "sealed_at": "2026-09-29T16:20:00.000000Z",
    "docket_sealing_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "total_evidence_sealed": 3,
    "court_reports_referenced": 1,
    "custody_events_appended": 3,
    "sealed_by": "USR-INV-001"
  }
  ```

- **Sealing Manifest Response** `GET /cases/{case_id}/sealing-manifest`:
  ```json
  {
    "case_id": "CASE-2026-A1B2C3D4",
    "case_number": "CR-2026-0926-01",
    "status": "COMPLETED",
    "is_sealed": true,
    "docket_sealing_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sealed_at": "2026-09-29T16:20:00.000000Z",
    "sealed_by": "USR-INV-001",
    "certification_notes": "All forensic analyses verified.",
    "evidence_manifest": [
      {
        "evidence_id": "EVD-2026-0001",
        "original_filename": "extortion_screenshot.png",
        "sha256_hash": "a1b2c3d4...",
        "status": "ANALYZED",
        "terminal_custody_hash": "f5e6d7..."
      }
    ],
    "reports_manifest": [
      {
        "report_id": "REP-2026-0001",
        "report_type": "PDF",
        "report_sha256": "c7d8e9...",
        "verification_code": "NYAY-2026-A1B2C3",
        "created_at": "2026-09-29T16:15:00.000000Z"
      }
    ]
  }
  ```

### 13.4 Post-Finalization Immutability Enforcement
Once a case docket reaches `COMPLETED` or `ARCHIVED` status:
- All evidence upload routes (`POST /api/evidence/upload` and `POST /api/cases/{case_id}/evidence`) block new intake with `400 Bad Request` (`error_code: CASE_SEALED`).
- Terminal `DOCKET_SEALED` custody blocks prevent further unauthorized state alterations.

---

## 14. Case Docket Judicial Admissibility & Verification Gateway (Phase 18)

### 14.1 Overview & Endpoint Specification
Provides a strictly read-only, non-mutating judicial verification gateway that evaluates whether a sealed case docket satisfies technical evidentiary admissibility standards under Section 63 of Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023) and ISO/IEC 27037:
1. Re-computes streaming SHA-256 hashes of all physical evidence files in WORM storage against registered baselines.
2. Cryptographically verifies every custody event chain from genesis block through `DOCKET_SEALED`.
3. Deterministically recalculates the Phase 17 docket sealing manifest hash to detect post-sealing alterations.
4. Audits the authenticity and integrity of official court admissibility reports.
5. Emits exactly one `CASE_ADMISSIBILITY_VERIFIED` audit log per verification run.
6. Strictly preserves evidence baseline hashes and case status without mutating the docket.

- **Endpoint (Canonical)**: `POST /cases/{case_id}/verify-admissibility`
- **Endpoint (Alias)**: `POST /cases/{case_id}/judicial-verification`
- **Admissibility Certificate Query**: `GET /cases/{case_id}/admissibility-certificate`
- **Router Prefix**: Exposed on both `/api/cases` and `/api/v1/cases`
- **Method**: `POST` (verification), `GET` (certificate query)
- **Authorization**: Bearer JWT (`JUDGE`, `ADMIN`, `AUDITOR`, `SYSTEM_LEAD`, `LAWYER`, `INVESTIGATOR`).
  - `INVESTIGATOR`: Scoped strictly to owned/assigned cases (`created_by == current_user.id`).
  - `JUDGE`, `ADMIN`, `AUDITOR`, `SYSTEM_LEAD`, `LAWYER`: Authorized docket verification roles.

### 14.2 Technical Admissibility Status Outcomes
Determines technical verification outcomes (distinct from judicial legal determinations):
- `ADMISSIBLE`: All vaulted evidence files match SHA-256 baselines, all custody chains are intact, sealing manifest hash matches live state, and authentic court report exists.
- `INADMISSIBLE_TAMPERED`: Physical evidence vault file content differs from original ingested SHA-256 hash or is missing from storage.
- `CHAIN_OF_CUSTODY_BREACHED`: One or more evidence items possess an altered or broken cryptographic custody chain.
- `SEALING_HASH_MISMATCH`: Docket content altered post-sealing; recalculated manifest hash does not match sealed hash.
- `UNSEALED`: Case docket is in `OPEN`, `UNDER_ANALYSIS`, or other non-finalized state.
- `MISSING_COURT_REPORT`: Case docket lacks an official court-ready admissibility report artifact.
- `EMPTY_CASE`: Case contains zero evidence artifacts.

### 14.3 Request & Response Contract
- **Request Body** (Optional `CaseAdmissibilityRequest`):
  ```json
  {
    "court_bench": "Courtroom 3A, High Court of Judicature at Delhi",
    "judicial_officer_name": "Hon'ble Justice S. K. Gupta",
    "verification_notes": "Tendered as electronic evidence in trial proceedings under BSA Section 63."
  }
  ```

- **Response** `200 OK` (`CaseAdmissibilityResponse`):
  ```json
  {
    "case_id": "CASE-2026-A1B2C3D4",
    "case_number": "CR-2026-0926-01",
    "case_status": "COMPLETED",
    "admissibility_status": "ADMISSIBLE",
    "is_admissible": true,
    "statutory_framework": "BSA_2023_SECTION_63",
    "verified_at": "2026-09-29T16:30:00.000000Z",
    "verifier": {
      "user_id": "usr-judge-01",
      "username": "judge_gupta",
      "role": "JUDGE",
      "judicial_officer_name": "Hon'ble Justice S. K. Gupta",
      "court_bench": "Courtroom 3A, High Court of Judicature at Delhi"
    },
    "checks": {
      "vault_integrity_passed": true,
      "custody_chains_intact": true,
      "sealing_hash_verified": true,
      "court_reports_valid": true,
      "total_evidence_verified": 2,
      "compromised_evidence_count": 0,
      "broken_custody_chains_count": 0,
      "compromised_evidence_ids": [],
      "broken_chain_evidence_ids": []
    },
    "sealing_verification": {
      "is_sealed": true,
      "expected_sealing_hash": "a9f8b7c6...",
      "recalculated_sealing_hash": "a9f8b7c6...",
      "hashes_match": true
    },
    "admissibility_summary": "All 2 evidence artifacts, cryptographic custody chains, and judicial sealing manifest are intact and compliant with Section 63 of Bharatiya Sakshya Adhiniyam, 2023.",
    "evidence_items": [
      {
        "evidence_id": "EVD-2026-0001",
        "original_filename": "extortion_screenshot.png",
        "stored_hash": "e3b0c442...",
        "vault_file_hash": "e3b0c442...",
        "vault_integrity": "VERIFIED",
        "custody_chain_intact": true,
        "total_custody_events": 4
      }
    ],
    "reports": [
      {
        "report_id": "REP-2026-0001",
        "report_type": "PDF",
        "stored_sha256": "f5e4d3...",
        "vault_file_sha256": "f5e4d3...",
        "is_valid": true
      }
    ]
  }
  ```

- **Admissibility Certificate Response** `GET /cases/{case_id}/admissibility-certificate`:
  Returns the official judicial admissibility certificate matching the `AdmissibilityCertificateResponse` schema.

---

## 15. Case Docket Judicial Discovery & Cryptographic Export Bundle Gateway (Phase 19)

### 15.1 Overview & Endpoint Specification
Provides a self-contained, air-gap verifiable Digital Evidence Bag and Judicial Disclosure Package (`.zip`) under Section 63 of Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023) and Section 230 / Section 238 of Bharatiya Nagarik Suraksha Sanhita, 2023 (BNSS 2023 for statutory supply of electronic records to court and defense counsel):
1. Validates finalized/sealed state (`COMPLETED`).
2. Performs full streaming SHA-256 integrity re-verification of all physical vault evidence files against baseline digests.
3. Validates unbroken custody ledger history and official court admissibility report existence.
4. Confirms Phase 18 judicial admissibility verification (`ADMISSIBLE`).
5. Assembles all constituents deterministically on disk (NOT fully in memory).
6. Computes a deterministic root checksum (`DISCOVERY_BUNDLE_CHECKSUM.sha256`) from alphabetically sorted artifact paths and hashes, unaffected by ZIP archive metadata or compression timestamps.
7. Caches packages by `case_id + docket_sealing_hash` to avoid redundant recompression.
8. Emits exactly one `CASE_BUNDLE_EXPORTED` audit log per new export.
9. Strictly read-only: never modifies evidence baseline hashes, case status, custody events, or reports.

- **Endpoint (Canonical)**: `POST /cases/{case_id}/export-bundle`
- **Endpoint (Alias)**: `POST /cases/{case_id}/create-disclosure-package`
- **Bundle Manifest Inspection**: `GET /cases/{case_id}/export-bundle/manifest`
- **Download Stream**: `GET /cases/{case_id}/download-bundle`
- **Router Prefix**: Exposed on both `/api/cases` and `/api/v1/cases`
- **Method**: `POST` (generate package), `GET` (inspect manifest / stream download)
- **Authorization**: Bearer JWT (`JUDGE`, `ADMIN`, `AUDITOR`, `SYSTEM_LEAD`, `LAWYER`, `INVESTIGATOR`).
  - `INVESTIGATOR`: Scoped strictly to owned/assigned cases (`created_by == current_user.id`).
  - `LAWYER`: Permitted to inspect manifest and download legal disclosure copies for assigned cases under statutory discovery (BNSS Sec 230).
  - `JUDGE`, `ADMIN`, `AUDITOR`, `SYSTEM_LEAD`: Broad docket export and download authority.

### 15.2 Discovery Bundle Archive Architecture
```
NYAYAI_DISCOVERY_BUNDLE_<case_number>_<sealing_hash[:16]>.zip
├── manifest.json
├── admissibility_certificate.json
├── evidence/
│   ├── <evidence_id_1>_<original_filename_1>
│   └── <evidence_id_2>_<original_filename_2>
├── custody/
│   ├── custody_ledger.json
│   └── events_timeline.json
├── reports/
│   ├── <report_id>.pdf
│   └── reports_index.json
├── audit/
│   └── case_audit_trail.json
└── DISCOVERY_BUNDLE_CHECKSUM.sha256
```

### 15.3 Request & Response Contract
- **Request Body** (Optional `ExportBundleRequest`):
  ```json
  {
    "purpose": "Trial Evidence Production under BSA Section 63",
    "recipient_court_or_agency": "Court of Sessions, Patiala House Courts, New Delhi",
    "authorized_officer_name": "Special Public Prosecutor R. K. Singh",
    "notes": "Electronic evidence tender along with Section 63 certificate.",
    "force_repackage": false
  }
  ```

- **Response** `200 OK` (`ExportBundleResponse`):
  ```json
  {
    "case_id": "CASE-2026-A1B2C3D4",
    "case_number": "CR-2026-0926-01",
    "bundle_filename": "NYAYAI_DISCOVERY_BUNDLE_CR-2026-0926-01_a6d73c017995c53d.zip",
    "bundle_file_size": 245892,
    "root_checksum": "9b7d8e6f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d",
    "docket_sealing_hash": "a6d73c017995c53d48da431ce7478d7cf03435dee9e08bd9975d508bf89571e1",
    "admissibility_status": "ADMISSIBLE",
    "statutory_framework": "BSA_2023_SEC_63_BNSS_2023_SEC_230",
    "exported_at": "2026-09-29T17:15:00.000000Z",
    "exporter": {
      "user_id": "usr-judge-01",
      "username": "judge_gupta",
      "role": "JUDGE",
      "authorized_officer_name": "Special Public Prosecutor R. K. Singh",
      "purpose": "Trial Evidence Production under BSA Section 63",
      "recipient": "Court of Sessions, Patiala House Courts, New Delhi"
    },
    "total_artifacts": 8,
    "cached": false,
    "download_url": "/api/cases/CASE-2026-A1B2C3D4/download-bundle",
    "artifacts": [
      {
        "path": "DISCOVERY_BUNDLE_CHECKSUM.sha256",
        "artifact_type": "ROOT_CHECKSUM",
        "file_size": 892,
        "sha256": "4b5c6d..."
      },
      {
        "path": "admissibility_certificate.json",
        "artifact_type": "ADMISSIBILITY_CERTIFICATE",
        "file_size": 2048,
        "sha256": "1a2b3c..."
      },
      {
        "path": "audit/case_audit_trail.json",
        "artifact_type": "AUDIT_TRAIL",
        "file_size": 3120,
        "sha256": "8d7e6f..."
      },
      {
        "path": "custody/custody_ledger.json",
        "artifact_type": "CUSTODY_LEDGER",
        "file_size": 4210,
        "sha256": "3c4d5e..."
      },
      {
        "path": "custody/events_timeline.json",
        "artifact_type": "CUSTODY_TIMELINE",
        "file_size": 2180,
        "sha256": "9f8e7d..."
      },
      {
        "path": "evidence/EVD-2026-0001_screenshot.png",
        "artifact_type": "EVIDENCE",
        "file_size": 45120,
        "sha256": "e3b0c4..."
      },
      {
        "path": "manifest.json",
        "artifact_type": "BUNDLE_MANIFEST",
        "file_size": 1540,
        "sha256": "6b7c8d..."
      },
      {
        "path": "reports/REP-2026-0001.pdf",
        "artifact_type": "COURT_REPORT",
        "file_size": 89400,
        "sha256": "7a8b9c..."
      }
    ]
  }
  ```

---

## 16. Judicial Discovery Bundle Cryptographic Verification & Tamper Audit Gateway (Phase 20)

### 16.1 Overview & Endpoint Specification
Provides offline, non-mutating cryptographic authenticity and tamper audit verification for exported Judicial Discovery Bundles (`.zip`) under Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023) Section 63 and Bharatiya Nagarik Suraksha Sanhita, 2023 (BNSS 2023) Section 230 / Section 238:
1. **Safe In-Memory Streaming Inspection**: Never extracts archives blindly to disk. Inspects entries via `ZipFile.open()` with strict 250 MB per-entry and 1 GB total uncompressed size limits (Zip bomb protection).
2. **Zip-Slip & Path Traversal Prevention**: Strictly rejects paths with `..`, absolute paths, leading slashes, drive colons, or traversal sequences (`CORRUPTED_ARCHIVE`).
3. **Artifact Hash Verification**: Verifies SHA-256 for every expected bundle constituent against `manifest.json`.
4. **Deterministic Root Checksum Re-computation**: Reconstructs the canonical sorted `<sha256>  <archive_relative_path>` representation independent of ZIP timestamps and metadata, verifying `DISCOVERY_BUNDLE_CHECKSUM.sha256`.
5. **Required Artifacts Audit**: Asserts presence and integrity of `manifest.json`, `admissibility_certificate.json`, `evidence/*`, `custody/*`, `reports/*`, `audit/*`, and `DISCOVERY_BUNDLE_CHECKSUM.sha256`.
6. **Authoritative Docket Cross-Check**: Validates bundle `docket_sealing_hash` against authoritative Phase 17 registered sealing information (`AuditLog(action="CASE_FINALIZED")`), preventing acceptance of forged or foreign sealed dockets.
7. **Phase 18 Section 63 Cross-Check**: Confirms enclosed admissibility certificate corresponds to the requested case and authoritative docket sealing state.
8. **Technical Verification Determinations**:
   - `BUNDLE_VERIFIED_AUTHENTIC`: All constituent hashes, custody ledgers, court reports, Section 63 admissibility certificate, and root checksum match authoritative sealed records.
   - `BUNDLE_TAMPERED`: Constituent artifact SHA-256 divergence, missing mandatory files, or altered Section 63 admissibility certificate.
   - `ROOT_CHECKSUM_MISMATCH`: Recomputed canonical root checksum does not match `DISCOVERY_BUNDLE_CHECKSUM.sha256` or authoritative export audit.
   - `UNREGISTERED_SEALING_HASH`: Bundle sealing hash does not match registered case docket sealing manifest.
   - `CORRUPTED_ARCHIVE`: Non-ZIP format, corrupt bytes, path traversal attempt, or size limit breach.
9. **Single Audit Event**: Emits exactly one `CASE_BUNDLE_VERIFIED` audit log per verification request.
10. **Strictly Read-Only**: Performs zero database mutations to evidence baselines, case status, custody, or reports.

- **Endpoint (Canonical)**: `POST /cases/{case_id}/verify-bundle`
- **Endpoint (Alias)**: `POST /cases/{case_id}/verify-disclosure-package`
- **Air-Gap / Lightweight Manifest Endpoint**: `POST /verification/bundle-manifest`
- **Router Prefixes**: Mounted at `/api/cases` and `/api/v1/cases`, and `/api/verification` and `/api/v1/verification`
- **Authorization**:
  - Full bundle upload: `JUDGE`, `ADMIN`, `AUDITOR`, `SYSTEM_LEAD`, `LAWYER`, and owning `INVESTIGATOR` (foreign investigator rejected with `403 Forbidden`).
  - Manifest verification: Authenticated users enforce RBAC; unauthenticated verifiers are logged as `PUBLIC_VERIFIER`.

### 16.2 Request & Response Contracts

#### A. Full Archive Upload Verification (`POST /cases/{case_id}/verify-bundle`)
- **Request**: Multipart Form Data
  - `file`: Uploaded discovery `.zip` archive (Binary)
  - `notes`: Optional auditor notes (String)

- **Response** `200 OK` (`BundleVerificationResponse`):
  ```json
  {
    "case_id": "CASE-2026-A1B2C3D4",
    "case_number": "CR-2026-0926-01",
    "verification_status": "BUNDLE_VERIFIED_AUTHENTIC",
    "is_authentic": true,
    "statutory_framework": "BSA_2023_SEC_63_BNSS_2023_SEC_230",
    "verified_at": "2026-09-29T16:45:00.000000Z",
    "verifier": {
      "user_id": "usr-judge-01",
      "username": "judge_gupta",
      "role": "JUDGE",
      "notes": "Verified by Judicial Magistrate prior to trial marking."
    },
    "checks": {
      "archive_structure_valid": true,
      "manifest_present": true,
      "all_artifacts_intact": true,
      "root_checksum_verified": true,
      "sealing_hash_registered": true,
      "admissibility_certified": true,
      "total_artifacts_checked": 7,
      "tampered_artifacts_count": 0,
      "tampered_artifact_paths": []
    },
    "expected_sealing_hash": "a9f8b7c6...",
    "bundle_sealing_hash": "a9f8b7c6...",
    "expected_root_checksum": "5d4e3f2a...",
    "computed_root_checksum": "5d4e3f2a...",
    "verification_summary": "Judicial Discovery Package verified authentic under Section 63 of Bharatiya Sakshya Adhiniyam, 2023. All 7 artifacts, custody ledgers, reports, and root checksum match authoritative sealed records.",
    "artifacts": [
      {
        "path": "evidence/EVD-2026-0001_screenshot.png",
        "artifact_type": "EVIDENCE",
        "expected_sha256": "e3b0c442...",
        "computed_sha256": "e3b0c442...",
        "matches": true,
        "file_size": 45120
      },
      {
        "path": "manifest.json",
        "artifact_type": "BUNDLE_MANIFEST",
        "expected_sha256": "6b7c8d9e...",
        "computed_sha256": "6b7c8d9e...",
        "matches": true,
        "file_size": 1540
      }
    ]
  }
  ```

#### B. Air-Gap / Lightweight Manifest Verification (`POST /verification/bundle-manifest`)
- **Request Body** (`BundleManifestVerificationRequest`):
  ```json
  {
    "case_id": "CASE-2026-A1B2C3D4",
    "root_checksum": "5d4e3f2a1b0c...",
    "docket_sealing_hash": "a9f8b7c6d5e4...",
    "checksum_manifest_text": "# NYAY-AI CASE DOCKET DISCOVERY BUNDLE CHECKSUM MANIFEST\n...",
    "notes": "Verified at court registry"
  }
  ```

- **Response** `200 OK` (`BundleManifestVerificationResponse`):
  ```json
  {
    "case_id": "CASE-2026-A1B2C3D4",
    "case_number": "CR-2026-0926-01",
    "verification_status": "BUNDLE_VERIFIED_AUTHENTIC",
    "is_authentic": true,
    "statutory_framework": "BSA_2023_SEC_63_BNSS_2023_SEC_230",
    "verified_at": "2026-09-29T16:50:00.000000Z",
    "verifier": {
      "user_id": "usr-judge-01",
      "username": "judge_gupta",
      "role": "JUDGE",
      "notes": "Verified at court registry"
    },
    "docket_sealing_hash_matches": true,
    "root_checksum_matches": true,
    "admissibility_status": "ADMISSIBLE",
    "verification_summary": "Discovery bundle manifest and root checksum verified authentic against court docket records."
  }
  ```

---

## 17. Judicial Courtroom Exhibit Marking, Evidence Tender & Admissibility Ruling Gateway (Phase 21)

### 17.1 Overview & Statutory Framework
Provides official courtroom presentation, advocate evidence tendering, and presiding judicial exhibit marking and admissibility rulings under Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023) Section 63 and Bharatiya Nagarik Suraksha Sanhita, 2023 (BNSS 2023):
1. **Evidence Tendering**: Authorized advocates (`LAWYER` for Prosecution or Defence) or investigating officers (`INVESTIGATOR`) submit digital evidence artifacts or official Section 63 reports for court tender. Tendering submits evidence into the trial record without assigning final exhibit numbers or judicial determinations.
2. **Official Judicial Exhibit Marking & Ruling**: Strictly restricted to `JUDGE`. The presiding judge assigns the formal judicial exhibit identifier (e.g. `Ex. P-1`, `Ex. D-1`, `MO-1`, `Mark A`) and records the statutory ruling:
   - `ADMITTED_AS_EXHIBIT`: Formally admitted into trial evidence under BSA 2023 Section 63.
   - `MARKED_FOR_IDENTIFICATION`: Marked for identification (MFI) pending operator/expert testimony.
   - `OBJECTED_DECISION_RESERVED`: Formal counsel objection noted; ruling reserved for final judgment.
   - `REJECTED`: Excluded as inadmissible.
3. **Cryptographic Custody Transition**: Tendering and marking append new cryptographic blocks (`EXHIBIT_TENDERED_IN_COURT`, `JUDICIAL_EXHIBIT_MARKED`) to the evidence custody ledger without breaking the historical hash chain.
4. **Compliance Audit Trail**: Emits exactly one `EXHIBIT_TENDERED` or `EXHIBIT_MARKED` audit event per action.
5. **Case-Scoped Uniqueness**: Strictly enforces case-scoped exhibit identifier uniqueness (`HTTP 409 Conflict` on duplicate exhibit number).
6. **Double-Admission Guard**: Prohibits re-admitting an already admitted evidence artifact (`HTTP 409 Conflict`).
7. **Strictly Read-Only Queries**: Exhibit register and lookup routes never mutate database rows or WORM storage files.

- **Endpoints**:
  - `POST /cases/{case_id}/exhibits/tender` (Alias: `POST /cases/{case_id}/tender-evidence`)
  - `POST /cases/{case_id}/exhibits/mark` (Alias: `POST /cases/{case_id}/mark-exhibit`)
  - `GET /cases/{case_id}/exhibits` (Alias: `GET /cases/{case_id}/exhibit-register`)
  - `GET /cases/{case_id}/exhibits/{exhibit_number}`
  - `GET /cases/{case_id}/evidence/{evidence_id}/exhibit`
- **Router Prefixes**: Mounted at `/api/cases` and `/api/v1/cases`.
- **Authorization**:
  - Marking/Ruling: `JUDGE` only (`ADMIN`, `LAWYER`, `INVESTIGATOR` rejected with `403 Forbidden`).
  - Tendering: `LAWYER`, `INVESTIGATOR`, `JUDGE`, `ADMIN`. Case-scoping enforced.
  - Viewing/Register: Authorized case viewers (`JUDGE`, `LAWYER`, `INVESTIGATOR`, `ADMIN`, `AUDITOR`).

### 17.2 Request & Response Contracts

#### A. Evidence Tendering (`POST /cases/{case_id}/exhibits/tender`)
- **Request Body** (`EvidenceTenderRequest`):
  ```json
  {
    "target_id": "EVD-2026-0001",
    "target_type": "EVIDENCE",
    "tendering_party": "PROSECUTION",
    "tendering_witness": "PW-1 Inspector S. K. Sharma",
    "purpose": "Corroboration of CCTV timestamp and vehicle ingress",
    "tender_notes": "Tendered during Examination-in-Chief of PW-1"
  }
  ```

- **Response** `200 OK` (`EvidenceTenderResponse`):
  ```json
  {
    "success": true,
    "tender_id": "TND-2026-A1B2C3D4",
    "case_id": "CASE-2026-A1B2C3D4",
    "case_number": "CR-2026-0926-01",
    "target_id": "EVD-2026-0001",
    "target_type": "EVIDENCE",
    "target_filename": "cctv_camera_01.mp4",
    "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "tendering_party": "PROSECUTION",
    "tendering_witness": "PW-1 Inspector S. K. Sharma",
    "purpose": "Corroboration of CCTV timestamp and vehicle ingress",
    "tender_notes": "Tendered during Examination-in-Chief of PW-1",
    "tendered_by": "usr-prosecutor-01",
    "tendered_by_username": "prosecutor_singh",
    "tendered_at": "2026-09-30T10:15:00.000000Z",
    "status": "TENDERED",
    "custody_event_id": "EVT-2026-98765432",
    "audit_id": "AUD-2026-11223344"
  }
  ```

#### B. Judicial Exhibit Marking (`POST /cases/{case_id}/exhibits/mark`)
- **Request Body** (`ExhibitMarkingRequest`):
  ```json
  {
    "target_id": "EVD-2026-0001",
    "target_type": "EVIDENCE",
    "exhibit_number": "Ex. P-1",
    "tendering_party": "PROSECUTION",
    "tendering_witness": "PW-1 Inspector S. K. Sharma",
    "ruling": "ADMITTED_AS_EXHIBIT",
    "court_bench": "Court of Sessions No. 4, Patiala House Courts, New Delhi",
    "judicial_officer_name": "Hon'ble Justice S. K. Gupta",
    "order_reference": "Sessions Case 402/2026 Order dated 2026-09-30",
    "objections_raised": "Defense objected under BSA Sec 63 claiming device hash re-computation needed.",
    "ruling_rationale": "Overruled. Admissibility Certificate verified authentic under BSA 2023 Section 63; sealing hash intact."
  }
  ```

- **Response** `200 OK` (`ExhibitRecordResponse`):
  ```json
  {
    "success": true,
    "exhibit_id": "EXH-2026-E1E2E3E4",
    "case_id": "CASE-2026-A1B2C3D4",
    "case_number": "CR-2026-0926-01",
    "exhibit_number": "Ex. P-1",
    "target_id": "EVD-2026-0001",
    "target_type": "EVIDENCE",
    "target_filename": "cctv_camera_01.mp4",
    "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "tendering_party": "PROSECUTION",
    "tendering_witness": "PW-1 Inspector S. K. Sharma",
    "ruling": "ADMITTED_AS_EXHIBIT",
    "court_bench": "Court of Sessions No. 4, Patiala House Courts, New Delhi",
    "judicial_officer_name": "Hon'ble Justice S. K. Gupta",
    "order_reference": "Sessions Case 402/2026 Order dated 2026-09-30",
    "objections_raised": "Defense objected under BSA Sec 63 claiming device hash re-computation needed.",
    "ruling_rationale": "Overruled. Admissibility Certificate verified authentic under BSA 2023 Section 63; sealing hash intact.",
    "marked_by": "usr-judge-01",
    "marked_by_username": "judge_gupta",
    "marked_at": "2026-09-30T10:20:00.000000Z",
    "custody_event_id": "EVT-2026-88776655",
    "custody_event_hash": "4a5b6c7d8e9f...",
    "audit_id": "AUD-2026-55443322"
  }
  ```

#### C. Case Exhibit Register (`GET /cases/{case_id}/exhibits`)
- **Response** `200 OK` (`CaseExhibitRegisterResponse`):
  ```json
  {
    "success": true,
    "case_id": "CASE-2026-A1B2C3D4",
    "case_number": "CR-2026-0926-01",
    "case_status": "COMPLETED",
    "docket_sealing_hash": "a9f8b7c6d5e4...",
    "total_exhibits": 2,
    "admitted_count": 2,
    "mfi_count": 0,
    "objected_count": 0,
    "rejected_count": 0,
    "exhibits": [ ... ],
    "tenders": [ ... ]
  }
  ```









