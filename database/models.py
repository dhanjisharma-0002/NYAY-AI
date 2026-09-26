"""
NYAYAI - Database Models (Re-export from backend.app.models)
Module Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

from backend.app.models import (
    Base,
    User,
    Role,
    Case,
    Evidence,
    EvidenceItem,
    EvidenceMetadata,
    ForensicArtifact,
    AnalysisResult,
    AIAnalysisResult,
    CustodyEvent,
    AuditLog,
    Report,
    CourtReport,
    VerificationRecord,
    ExplainabilityRecord,
    CorrelationLink
)

__all__ = [
    "Base",
    "User",
    "Role",
    "Case",
    "Evidence",
    "EvidenceItem",
    "EvidenceMetadata",
    "ForensicArtifact",
    "AnalysisResult",
    "AIAnalysisResult",
    "CustodyEvent",
    "AuditLog",
    "Report",
    "CourtReport",
    "VerificationRecord",
    "ExplainabilityRecord",
    "CorrelationLink"
]
