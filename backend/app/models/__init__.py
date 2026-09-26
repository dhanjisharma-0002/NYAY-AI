"""
NYAYAI - Database Models Package (Phase 2 Relational Schema)
Module: backend.app.models

Core Entities:
1. User
2. Role
3. Case
4. Evidence (EvidenceItem alias)
5. EvidenceMetadata (ForensicArtifact alias)
6. AnalysisResult (AIAnalysisResult alias)
7. CustodyEvent
8. AuditLog
9. Report (CourtReport alias)
10. VerificationRecord

Supplementary Entities:
- ExplainabilityRecord
- CorrelationLink
"""

from backend.app.database import Base
from .role import Role
from .user import User
from .case import Case
from .evidence import Evidence, EvidenceItem
from .evidence_metadata import EvidenceMetadata, ForensicArtifact
from .analysis_result import AnalysisResult, AIAnalysisResult
from .custody import CustodyEvent, CustodyEventType
from .audit import AuditLog
from .report import Report, CourtReport
from .verification import VerificationRecord
from .explainability import ExplainabilityRecord
from .correlation import CorrelationLink

__all__ = [
    "Base",
    # Core 10 Entities
    "User",
    "Role",
    "Case",
    "Evidence",
    "EvidenceMetadata",
    "AnalysisResult",
    "CustodyEvent",
    "CustodyEventType",
    "AuditLog",
    "Report",
    "VerificationRecord",
    # Aliases
    "EvidenceItem",
    "ForensicArtifact",
    "AIAnalysisResult",
    "CourtReport",
    # Intelligence Entities
    "ExplainabilityRecord",
    "CorrelationLink"
]
