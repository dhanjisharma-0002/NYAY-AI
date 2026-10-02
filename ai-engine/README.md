# NYAYAI — AI Analysis Engine (`ai-engine/`)

**Module Lead:** Ridhi Masih (Evidence Intelligence Lead)  
**Standard:** ISO/IEC 27037 & Bharatiya Sakshya Adhiniyam (BSA), 2023  
**Package:** `ai_engine`

---

## 1. Overview
The AI Engine performs heuristic screening on digital evidence items to identify potential indicators of digital tampering, editing artifacts, and generative AI synthesis.

## 2. Core Architectural Principles
1. **Case & Evidence Dual-Binding (Rule 9):** Every analysis strictly requires and binds to both `case_id` and `evidence_id`.
2. **Heuristic Screening, Not Certainty (Rule 14):** Risk scores are heuristic screening indices indicating areas of technical interest; they are **never** represented as empirical probabilities or absolute claims of criminality.
3. **No Fake Calibration (Rule 13):** No hardcoded pseudo-confidence numbers are asserted.
4. **Zero Evidence Mutation (Rule 2):** Operates on read-only byte streams and in-memory buffers; original evidence is never altered.
5. **Independent Testability (Rule 15):** The engine operates independently of databases, network gateways, and HTTP frameworks.

## 3. Analyzer Contract
```python
from ai_engine import BaselineTamperDetector

analyzer = BaselineTamperDetector()
result = analyzer.analyze(
    case_id="CR-2026-0042",
    evidence_id="EVD-2026-0001",
    metadata={
        "file_path": "/vault/path/to/evidence.jpg",
        "declared_mime": "image/jpeg",
        "magic_bytes_valid": True,
        "hash_mismatch": False,
        "anomalies": []
    }
)
```

## 4. Standard Response Envelope
```json
{
    "analysis_id": "AI-ANL-9F2B8317A54C",
    "case_id": "CR-2026-0042",
    "evidence_id": "EVD-2026-0001",
    "analysis_type": "tamper_synthesis_screening",
    "analyzer_version": "2.2.0",
    "analysis_timestamp": "2026-10-02T12:00:00Z",
    "risk_score": 0.35,
    "assessment": "medium_risk",
    "indicators": [
        "Editing software signatures identified in metadata streams: Adobe Photoshop."
    ],
    "forensic_conclusion": "Heuristic screening identified moderate anomalies...",
    "limitations": [
        "Risk score is a deterministic heuristic screening index, NOT an empirical probability.",
        "Under the Bharatiya Sakshya Adhiniyam, 2023, automated screening findings must be corroborated by an expert witness before judicial determination."
    ],
    "audit": {
        "action": "AI_TAMPER_SCREENING",
        "case_id": "CR-2026-0042",
        "evidence_id": "EVD-2026-0001",
        "timestamp": "2026-10-02T12:00:00Z"
    }
}
```
