"""
NYAYAI - Evidence Correlation & Intelligence Schemas (Phase 9)
Module: backend.app.schemas.correlation
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel


class CorrelationRequest(BaseModel):
    """Payload to trigger case-level evidence correlation analysis."""
    case_id: str


class TimelineEvent(BaseModel):
    """
    Chronological timeline item representing a documented evidence event.
    Strictly uses documented evidence/event timestamps.
    Never invents timestamps; null/unknown if unavailable.
    """
    sequence_index: int
    event_id: Optional[str] = None
    evidence_id: str
    filename: Optional[str] = None
    event_type: Optional[str] = None
    timestamp: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    source: Optional[str] = None

    class Config:
        from_attributes = True


class EvidenceRelationship(BaseModel):
    """
    Represents an observed relationship between evidence items.
    Format: Evidence A -> related_to -> Evidence B
    Stores the relationship reason.
    """
    source_evidence_id: str
    target_evidence_id: str
    related_to: str
    relationship_type: str
    reason: str
    confidence: float = 1.0
    notes: Optional[str] = None

    class Config:
        from_attributes = True


class CrossEvidenceMatch(BaseModel):
    """
    Identified common attribute or linkage matched across multiple evidence items.
    """
    match_type: str
    evidence_ids: List[str]
    matched_attribute: str
    matched_value: Any
    confidence: float
    description: str

    class Config:
        from_attributes = True


class RedFlagItem(BaseModel):
    """
    Evidence-based investigative anomaly or inconsistency.
    Objective, empirical observations only (Does NOT claim criminality).
    Examples: timestamp inconsistency, hash mismatch, metadata inconsistency,
    duplicate evidence, analysis anomaly.
    """
    flag_id: str
    flag_type: str
    evidence_id: Optional[str] = None
    severity: str
    description: str
    evidence_reference: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class CaseCorrelationResponse(BaseModel):
    """
    Standardized Evidence Correlation response schema (Phase 9).
    Guarantees:
    - timeline
    - relationships
    - cross_evidence_matches
    - red_flags
    """
    success: bool = True
    case_id: str
    timeline: List[TimelineEvent] = []
    relationships: List[EvidenceRelationship] = []
    cross_evidence_matches: List[CrossEvidenceMatch] = []
    red_flags: List[RedFlagItem] = []
    total_evidence_count: int = 0
    total_red_flags: int = 0

    # Backward compatibility aliases
    links: Optional[List[EvidenceRelationship]] = None
    total_items: Optional[int] = None
    data: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


# Backward compatibility alias
CorrelationResponse = CaseCorrelationResponse
