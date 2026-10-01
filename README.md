# NYAYAI – Digital Evidence AI Platform

[![Phase](https://img.shields.io/badge/Phase-0%20Architecture%20%26%20Foundation-gold.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.11%2B%20%7C%203.14-blue.svg)](#)
[![Compliance](https://img.shields.io/badge/Compliance-BSA%202023%20%2F%20Sec%2065B-emerald.svg)](#)
[![Tests](https://img.shields.io/badge/Tests-13%20Passing-brightgreen.svg)](#)

NYAYAI is an enterprise-grade digital evidence platform engineered to maintain cryptographic integrity, perform multi-modal forensic inspection, screen for AI-generated manipulation, link cross-evidence timelines, preserve an unbroken chain of custody, and produce court-admissible electronic record certificates under the **Bharatiya Sakshya Adhiniyam (BSA), 2023** and **ISO/IEC 27037**.

---

| **Lead Engineer**    | **Role**                       | **Module Ownership**                                                | **Core Directories**                                                  |
| -------------------- | ------------------------------ | ------------------------------------------------------------------- | --------------------------------------------------------------------- |
| **Ayushi Sharma**    | Frontend & Intake Engineer     | Evidence Intake Portal, Dashboard UI, Case UI                       | `frontend/`                                                           |
| **Anu Sharma**       | Forensic Engineer              | Metadata Extraction, Magic Bytes, Forensic Analysis                 | `forensic-engine/`                                                    |
| **Ridhi Mashi**      | **Evidence Intelligence Lead** | **AI Engine, Chain of Custody Ledger, Correlation, Explainability** | **`ai-engine/`, `custody/`, `correlation/`, `explainability/`**       |
| **Dhananjay Sharma** | Backend & System Lead          | Orchestrator, REST APIs, Database, Reports, Deploy                  | `backend/`, `database/`, `reports/`, `deployment/`, `docs/`, `tests/` |


---

## 2. Directory Layout

```
NYAYAI/
│
├── backend/                  # Orchestrator & REST APIs (Dhananjay)
│   ├── app/
│   │   ├── api/v1/           # Cases, Evidence, Pipeline, Custody, Reports
│   │   ├── core/             # Settings, Security & Auth
│   │   ├── orchestrator/     # Decoupled Engine Coordinator
│   │   └── main.py           # FastAPI entrypoint & middleware
│   └── requirements.txt
│
├── frontend/                 # Client Portal & Dashboards (Ayushi)
│   ├── index.html            # Single-page interface
│   ├── css/style.css         # Dark-mode legal tech design system
│   ├── js/api.js             # Client REST service
│   ├── js/app.js             # UI state & WebCrypto SHA-256 pre-check
│   └── package.json
│
├── forensic-engine/          # Forensics, Metadata, SHA-256 (Anu)
│   ├── forensic_engine/
│   │   ├── base.py           # BaseForensicAnalyzer contract
│   │   ├── integrity.py      # Streaming SHA-256 chunked hasher
│   │   └── metadata.py       # Magic bytes & EXIF inspector
│   └── requirements.txt
│
├── ai-engine/                # AI Tamper & Synthesis Screening (Anu)
│   ├── ai_engine/
│   │   ├── base.py           # BaseAIAnalyzer contract
│   │   └── tamper_detector.py# Heuristic screening with calibrated confidence
│   └── requirements.txt
│
├── custody/                  # Cryptographic Chain of Custody (Ridhi)
│   ├── custody/
│   │   ├── base.py           # BaseCustodyLedger contract
│   │   └── ledger.py         # Tamper-evident SHA-256 block ledger
│   └── requirements.txt
│
├── explainability/           # Court Admissibility Rationales (Ridhi)
│   ├── explainability/
│   │   ├── base.py           # BaseExplainer contract
│   │   └── explainer.py      # Judicial rationale & limitations generator
│   └── requirements.txt
│
├── correlation/              # Multi-Evidence Cross-Referencing (Ridhi)
│   ├── correlation/
│   │   ├── base.py           # BaseCorrelationEngine contract
│   │   └── engine.py         # Timeline & duplicate file graph builder
│   └── requirements.txt
│
├── reports/                  # Court Admissibility & Legal Certificates (Dhananjay)
│   ├── reports/
│   │   ├── base.py           # BaseReportGenerator contract
│   │   └── generator.py      # BSA 2023 Section 63/65B certificate & QR generator
│   └── requirements.txt
│
├── database/                 # SQLAlchemy Persistence (Dhananjay)
│   ├── connection.py         # DB Engine & SessionLocal
│   ├── models.py             # Declarative models
│   └── init_db.py            # Initialization & seeding script
│
├── tests/                    # Independent Test Suites
│   ├── test_integrity_and_hashing.py
│   ├── test_custody_ledger.py
│   ├── test_module_contracts.py
│   └── test_api_endpoints.py
│
├── docs/                     # Full Documentation
│   ├── PROJECT_OVERVIEW.md   # Mission, Legal Admissibility & Life Cycle
│   ├── ARCHITECTURE.md       # Micro-modular breakdown & storage design
│   ├── TEAM_ROLES.md         # Team responsibilities & contracts
│   ├── API_CONTRACTS.md      # REST specifications & JSON envelopes
│   ├── DATABASE_SCHEMA.md    # Relational ER schema & column constraints
│   ├── DEVELOPMENT_RULES.md  # 15 mandatory engineering rules
│   └── INTEGRATION_GUIDE.md  # Engine integration & protocol guides
│
├── deployment/               # Containerization & Infrastructure (Dhananjay)
│   ├── Dockerfile.backend
│   ├── docker-compose.yml
│   └── nginx.conf
│
├── .env.example              # Environment configuration template
├── .gitignore                # Version control exclusions
├── pytest.ini                # Test runner configuration
└── README.md                 # Project README
```

---

## 3. Mandatory Development Rules

1. **Never delete working functionality.**
2. **Never overwrite original evidence files.** (Vaulted WORM storage).
3. **Never commit credentials.**
4. **Use environment variables.**
5. **Every evidence must have a unique `evidence_id`.**
6. **Every case must have a unique `case_id`.**
7. **Evidence integrity must use SHA-256.**
8. **Every important evidence action must be auditable.**
9. **AI results must remain linked to `evidence_id`.**
10. **API contracts must be documented.**
11. **Database changes must be documented.**
12. **Do not silently change response formats.**
13. **Do not invent AI accuracy.**
14. **Do not claim forensic certainty without evidence.**
15. **Keep modules independently testable.**

---

## 4. Commands to Run & Test the Project

### Initialize Database
```bash
python database/init_db.py
```

### Run Test Suite
```bash
python -m pytest
```

### Start Backend API Server
```bash
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation will be available at:
- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

### Start Frontend UI
```bash
# Serve static frontend on port 3000
python -m http.server 3000 --directory frontend
```
Access the investigator dashboard at `http://127.0.0.1:3000`.

### Production Deployment (Docker Compose)
```bash
cd deployment
docker-compose up --build -d
```
