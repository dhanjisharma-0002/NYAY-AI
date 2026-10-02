# NYAYAI — Multi-Evidence Correlation Engine (`correlation/`)

**Module Lead:** Ridhi Masih (Evidence Intelligence Lead)  
**Standard:** Bharatiya Sakshya Adhiniyam (BSA), 2023 & ISO/IEC 27037  
**Package:** `correlation`

---

## 1. Overview
The Evidence Correlation Engine cross-references multiple digital evidence records within a case docket to assemble unified chronological timelines, discover attribute matches, build network topology graphs, and flag objective forensic red flags.

## 2. Core Architectural Principles
1. **Case & Evidence Dual-Binding (Rule 9):** Every correlation operation strictly requires `case_id` and preserves `evidence_id` in every node, edge, and finding.
2. **Correlation Indicators vs. Proof (Rule 14):** Correlation indicators reflect observable technical/temporal associations; they are **never** represented as definitive forensic proof of guilt or criminality.
3. **No Timestamp Invention (Rule 14):** Missing or indeterminate timestamps are preserved as `None`; timestamps are never fabricated or guessed.
4. **Independent Testability (Rule 15):** The engine operates deterministically without relying on live databases or external microservices.

## 3. Usage Example
```python
from correlation import BaselineCorrelationEngine

engine = BaselineCorrelationEngine()
result = engine.correlate_case_evidence(
    case_id="CR-2026-0042",
    evidence_items=[
        {
            "evidence_id": "EVD-01",
            "filename": "surveillance_cam1.mp4",
            "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "created_at": "2026-10-02T10:00:00Z"
        },
        {
            "evidence_id": "EVD-02",
            "filename": "backup_cam1.mp4",
            "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "created_at": "2026-10-02T10:02:00Z"
        }
    ]
)

print(result["relationships"])  # Identifies IDENTICAL_FILE_HASH match
print(result["timeline"])       # Chronologically ordered sequence
print(result["graph"])          # Network nodes and edges for visualization
```
