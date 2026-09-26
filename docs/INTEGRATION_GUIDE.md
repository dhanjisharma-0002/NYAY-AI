# NYAYAI – System Integration Guide & Engine Protocols

This guide instructs each engineer on how to implement their assigned module so that the Backend Orchestrator (`backend/app/orchestrator/pipeline.py`) can invoke it seamlessly without tight coupling.

---

## 1. Integration Protocol Architecture

The backend orchestrator communicates with domain engines through **Python Protocols / Abstract Base Classes**. This allows engines to run in-process for speed or asynchronously via worker queues in production.

```
                    ┌────────────────────────────┐
                    │    Backend Orchestrator    │
                    └─────────────┬──────────────┘
                                  │
      ┌───────────────────────────┼───────────────────────────┐
      ▼                           ▼                           ▼
┌──────────────┐           ┌──────────────┐           ┌──────────────┐
│  Forensic    │           │      AI      │           │ Explain-     │
│  Engine      │           │    Engine    │           │ ability      │
│  (Anu)       │           │    (Anu)     │           │ (Ridhi)      │
└──────────────┘           └──────────────┘           └──────────────┘
      │                           │                           │
      └───────────────────────────┼───────────────────────────┘
                                  │
                    ┌─────────────┴──────────────┐
                    │    Correlation & Custody   │
                    │           (Ridhi)          │
                    └─────────────┬──────────────┘
                                  │
                    ┌─────────────┴──────────────┐
                    │       Report Engine        │
                    │        (Dhananjay)         │
                    └────────────────────────────┘
```

---

## 2. Anu Sharma's Engines: Forensic & AI

### 2.1 Forensic Engine Interface Contract
Located at `forensic-engine/forensic_engine/base.py`:

```python
from typing import Dict, Any, List
from abc import ABC, abstractmethod

class BaseForensicAnalyzer(ABC):
    @abstractmethod
    def calculate_sha256(self, file_path: str) -> str:
        """Stream hash computation without reading entire file into memory."""
        pass

    @abstractmethod
    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract EXIF, filesystem timestamps, and header attributes."""
        pass

    @abstractmethod
    def verify_file_signature(self, file_path: str, declared_mime: str) -> Dict[str, Any]:
        """Check magic bytes against declared MIME type to detect extension spoofing."""
        pass
```

### 2.2 AI Engine Interface Contract
Located at `ai-engine/ai_engine/base.py`:

```python
from typing import Dict, Any
from abc import ABC, abstractmethod

class BaseAIAnalyzer(ABC):
    @abstractmethod
    def detect_tampering(self, evidence_id: str, file_path: str) -> Dict[str, Any]:
        """
        Screen file for splicing, copy-move, or synthetic anomalies.
        Returns dictionary containing:
        - model_name: str
        - model_version: str
        - tamper_detected: bool
        - confidence_score: float (0.0 to 1.0)
        - findings: List[str]
        """
        pass
```

---

## 3. Ridhi Mashi's Engines: Custody, Correlation & Explainability

### 3.1 Chain of Custody Interface Contract
Located at `custody/custody/base.py`:

```python
from typing import Dict, Any, List
from abc import ABC, abstractmethod

class BaseCustodyLedger(ABC):
    @abstractmethod
    def record_event(
        self,
        evidence_id: str,
        action: str,
        actor_id: str,
        details: Dict[str, Any],
        previous_event_hash: str
    ) -> Dict[str, Any]:
        """
        Computes SHA256(prev_hash + timestamp + evidence_id + action + actor + details)
        Returns the created immutable event block dictionary.
        """
        pass

    @abstractmethod
    def verify_chain(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Recalculates every event hash in order from genesis block.
        Returns {"is_valid": bool, "verified_count": int, "broken_at_event_id": Optional[str]}
        """
        pass
```

### 3.2 Explainability Interface Contract
Located at `explainability/explainability/base.py`:

```python
from typing import Dict, Any
from abc import ABC, abstractmethod

class BaseExplainer(ABC):
    @abstractmethod
    def explain(
        self,
        evidence_id: str,
        forensic_data: Dict[str, Any],
        ai_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generates court-admissible human explanation, confidence bounds, and scientific limitations.
        Returns:
        - reasoning_summary: str
        - confidence_category: str ('HIGH'|'MEDIUM'|'LOW'|'INCONCLUSIVE')
        - key_factors: List[str]
        - limitations_disclaimer: str
        """
        pass
```

### 3.3 Correlation Engine Interface Contract
Located at `correlation/correlation/base.py`:

```python
from typing import Dict, Any, List
from abc import ABC, abstractmethod

class BaseCorrelationEngine(ABC):
    @abstractmethod
    def correlate_case_evidence(
        self,
        case_id: str,
        evidence_items: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Builds cross-evidence chronological timeline and links identical timestamps / locations.
        Returns:
        - timeline: List[Dict[str, Any]]
        - links: List[Dict[str, Any]]
        """
        pass
```

---

## 4. Ayushi Sharma: Frontend Client Integration

1. The frontend should connect to the backend server at `http://127.0.0.1:8000`.
2. All network calls are encapsulated in `frontend/js/api.js`:
   - `api.createCase(payload)`
   - `api.uploadEvidence(caseId, formData)`
   - `api.triggerAnalysis(evidenceId)`
   - `api.getCustodyLedger(evidenceId)`
   - `api.getReport(caseId)`
3. Client-Side Integrity Pre-Check:
   - When the user selects a file for upload, `frontend/js/app.js` calculates its SHA-256 hash using the native browser `crypto.subtle.digest("SHA-256", buffer)`.
   - The hash is transmitted alongside the file upload as `client_sha256`.
   - The backend validates that `server_sha256 == client_sha256`, guaranteeing no data corruption occurred in transit.

---

## 5. Dhananjay Sharma: Backend Orchestrator & Court Reports

1. Coordinates sequential execution in `backend/app/orchestrator/pipeline.py`:
   - Step 1: Verify file in Vault against registered SHA-256.
   - Step 2: Invoke `ForensicAnalyzer.extract_metadata` and `verify_file_signature`.
   - Step 3: Invoke `AIAnalyzer.detect_tampering`.
   - Step 4: Invoke `Explainer.explain` to generate legal rationale.
   - Step 5: Append `ANALYSIS_COMPLETED` block to `CustodyLedger`.
   - Step 6: Persist all records into `database/models.py`.
2. Report Generation (`reports/reports/generator.py`):
   - Compiles case metadata, SHA-256 ledger, forensic anomalies, and Section 63/65B BSA certificate.
   - Encodes public verification URL into a QR Code using `qrcode`.

---

## 6. Smoke Testing the Integrated Pipeline

To run the complete verification test across all modules:

```bash
# 1. Initialize Database
python database/init_db.py

# 2. Run Comprehensive Test Suite
pytest tests/ -v
```
