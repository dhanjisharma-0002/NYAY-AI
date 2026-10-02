# NYAYAI — Court Admissibility Explainability Engine (`explainability/`)

**Module Lead:** Ridhi Masih (Evidence Intelligence Lead)  
**Standard:** Bharatiya Sakshya Adhiniyam (BSA), 2023 (Section 63 & 65B)  
**Package:** `explainability`

---

## 1. Overview
The Explainability Engine translates machine learning screening findings, Error Level Analysis (ELA) metrics, and forensic anomalies into plain-language legal rationales understandable by trial judges, public prosecutors, and defense advocates.

## 2. Core Architectural Principles
1. **Case & Evidence Dual-Binding (Rule 9):** Every explanation strictly preserves and references both `case_id` and `evidence_id`.
2. **Objective Legal Descriptions (Rule 14):** Translates technical indicators into factual observations; **never** turns a screening score into a definitive claim of forgery or criminality.
3. **Defense Safeguards & Limitations (Rule 14):** Explicitly lists technical caveats, including the benign impact of social media recompression (e.g. WhatsApp, Telegram) versus intentional tampering.
4. **Actionable Judicial Directives:** Generates concrete legal recommendations (e.g. summoning original device under BSA Section 63(4) or directing FSL laboratory testing).
5. **Independent Testability (Rule 15):** The engine is decoupled from database and networking layers.

## 3. Usage Example
```python
from explainability import BaselineCourtExplainer

explainer = BaselineCourtExplainer()
briefing = explainer.explain(
    case_id="CR-2026-0042",
    evidence_id="EVD-2026-0001",
    ai_data={
        "assessment": "high_risk",
        "risk_score": 0.85,
        "indicators": [
            "Synthetic media / Generative AI pipeline markers identified: Stable Diffusion."
        ],
        "details": {}
    },
    forensic_data={
        "anomalies": ["EXIF metadata stripped"]
    }
)

print(briefing["reasoning_summary"])
print(briefing["plain_language_explanations"])
print(briefing["judicial_recommendations"])
```
