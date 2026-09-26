# NYAYAI – Team Roles, Ownership & Responsibilities

---

### Team Roster

| Member | Title | Core Module Ownership | Primary Language / Stack |
| :--- | :--- | :--- | :--- |
| **Ayushi Sharma** | Frontend & Evidence Intake Engineer | `frontend/`, UI Components, Dashboard, Intake Portal | HTML5, Vanilla CSS3, JavaScript (ES6+), Web APIs |
| **Anu Sharma** | Forensic & AI Analysis Engineer | `forensic-engine/`, `ai-engine/` | Python 3, OpenCV, Pillow, PyTorch/ONNX, Scikit-learn |
| **Ridhi Mashi** | Evidence Intelligence & Chain-of-Custody Engineer | `correlation/`, `custody/`, `explainability/` | Python 3, Graph Algorithms, Cryptography (SHA-256) |
| **Dhananjay Sharma** | Backend & System Integration Lead | `backend/`, `database/`, `reports/`, `deployment/`, integration | Python 3, FastAPI, SQLAlchemy 2.0, Docker, Nginx |

---

## 1. Ayushi Sharma – Frontend & Evidence Intake Engineer

### Owned Directories & Files
- `frontend/`
- `frontend/index.html`
- `frontend/css/style.css`
- `frontend/js/api.js`
- `frontend/js/app.js`

### Primary Responsibilities
1. **Evidence Intake Portal**:
   - Build a drag-and-drop secure file intake interface supporting single and batch uploads.
   - Implement client-side preliminary hashing (Web Cryptography API SHA-256) so the user can verify the file fingerprint before and after upload.
   - Display file size, MIME type detection, and intake progress indicators.
2. **Investigator Dashboard**:
   - Clean, dark-mode, high-legibility legal tech UI.
   - Case summary overview: active cases, total evidence items, verification statuses, alerts.
3. **Case & Custody Viewer**:
   - Interactive timeline visualization showing chronological evidence history.
   - Chain-of-custody audit log viewer displaying cryptographic block hashes and verification badges.
   - Court report preview modal with embedded QR code.
4. **Integration Boundary**:
   - Communicates strictly with the backend via `backend/app/api/v1/` REST endpoints.
   - No direct database access or direct engine invocation.

---

## 2. Anu Sharma – Forensic & AI Analysis Engineer

### Owned Directories & Files
- `forensic-engine/`
- `ai-engine/`
- `forensic-engine/forensic_engine/`
- `ai-engine/ai_engine/`

### Primary Responsibilities
1. **Forensic Engine**:
   - Extract embedded metadata (EXIF tags, GPS coordinates, device serial numbers, camera models).
   - Verify file format authenticity using magic bytes / file signature detection (preventing file extension spoofing).
   - Provide streaming SHA-256 calculation utilities adhering to strict non-mutation guarantees.
2. **AI Analysis Engine**:
   - Build automated screening pipelines for media tampering (Copy-Move, Splicing, Resampling, Error Level Analysis - ELA).
   - Audio/Video analysis: silence detection, synthetic voice artifact screening, transcription stubs.
   - Ensure every AI model output includes: `model_name`, `model_version`, `raw_score`, `calibrated_confidence`, `findings_summary`.
3. **Forensic Integrity Constraints**:
   - **Rule 2**: Never overwrite original evidence files. Always read stream or copy.
   - **Rule 13**: Do not invent AI accuracy. Output realistic probability distributions and metrics.
   - **Rule 14**: Do not claim forensic certainty without evidence. Distinguish clearly between "mathematical mismatch" and "statistical anomaly".

---

## 3. Ridhi Mashi – Evidence Intelligence & Chain-of-Custody Engineer

### Owned Directories & Files
- `custody/`
- `correlation/`
- `explainability/`

### Primary Responsibilities
1. **Chain of Custody Ledger (`custody/`)**:
   - Maintain an unbroken, tamper-evident cryptographic ledger where each event is chained to the previous event via SHA-256.
   - Implement `verify_chain(evidence_id)` function returning boolean verification, event count, and any point of failure.
   - Guarantee idempotency and non-repudiation for every evidence action.
2. **Evidence Correlation Engine (`correlation/`)**:
   - Ingest multiple evidence items from a single case and construct unified chronological timelines.
   - Identify cross-evidence links: identical timestamps, overlapping geolocation coordinates, matching participants or phone numbers.
   - Output structured graph nodes and edges for visualization by Ayushi's frontend.
3. **Explainability Engine (`explainability/`)**:
   - Translate complex AI outputs and forensic anomalies into plain-language rationales admissible in court.
   - Generate confidence interval representations and list known scientific limitations for each analysis.
   - Adhere strictly to judicial requirements: judges and lawyers must be able to understand *why* an anomaly was flagged.

---

## 4. Dhananjay Sharma – Backend & System Integration Lead

### Owned Directories & Files
- `backend/`
- `database/`
- `reports/`
- `deployment/`
- Top-level `tests/`, `docs/`, `docker-compose.yml`, `.env.example`, `README.md`

### Primary Responsibilities
1. **System Orchestration & API Gateway**:
   - Maintain FastAPI application lifecycle, routing, middleware, CORS, rate limiting, and RBAC authentication.
   - Orchestrate end-to-end analysis pipelines: Evidence Intake → Vault Storage → Hash Verification → Forensic Engine → AI Engine → Explainability → Correlation → Custody Event → Report Generation.
2. **Database Architecture & Persistence**:
   - Design and maintain relational models in `database/models.py` (SQLAlchemy 2.0).
   - Ensure transaction isolation and data integrity across cases, evidence, and custody events.
3. **Court Admissibility Reports (`reports/`)**:
   - Implement court report generator complying with Section 63/65B of the Bharatiya Sakshya Adhiniyam, 2023.
   - Embed cryptographic hash tables, chain-of-custody audit logs, and verifiable QR code URLs.
4. **Infrastructure & Release**:
   - Oversee deployment containerization (Docker, Docker Compose, Nginx).
   - Enforce integration testing, API contract compliance, and code quality standards across all modules.

---

## 5. Cross-Team Communication & Integration Protocol

```
Ayushi (Frontend)
       │ HTTP / JSON
       ▼
Dhananjay (Backend Orchestrator)
       ├──> Anu (Forensic Engine / AI Engine)      [Python Interface]
       ├──> Ridhi (Custody / Correlation / Explain) [Python Interface]
       └──> Dhananjay (DB & Court Reports)         [SQLAlchemy / PDF]
```

- Any change to request or response payloads must be reflected in `docs/API_CONTRACTS.md` prior to code merging (**Rule 10 & 12**).
- Every engine must provide standalone mock implementations satisfying its protocol for seamless offline testing.
