"""
NYAYAI - Custody Event Model (Cryptographic Chain of Custody)
Module: backend.app.models.custody
"""

from sqlalchemy import Column, String, Text, Integer, ForeignKey, Index
from sqlalchemy.orm import relationship, synonym
from backend.app.database import Base


class CustodyEventType:
    """Standardized event types supported in the NYAYAI Chain of Custody."""
    EVIDENCE_UPLOADED = "EVIDENCE_UPLOADED"
    EVIDENCE_VIEWED = "EVIDENCE_VIEWED"
    EVIDENCE_DOWNLOADED = "EVIDENCE_DOWNLOADED"
    INTEGRITY_VERIFIED = "INTEGRITY_VERIFIED"
    FORENSIC_ANALYSIS_STARTED = "FORENSIC_ANALYSIS_STARTED"
    FORENSIC_ANALYSIS_COMPLETED = "FORENSIC_ANALYSIS_COMPLETED"
    AI_ANALYSIS_STARTED = "AI_ANALYSIS_STARTED"
    AI_ANALYSIS_COMPLETED = "AI_ANALYSIS_COMPLETED"
    EVIDENCE_TRANSFERRED = "EVIDENCE_TRANSFERRED"
    REPORT_GENERATED = "REPORT_GENERATED"


class CustodyEvent(Base):
    """
    Append-only, immutable cryptographic audit trail.
    Each event links cryptographically to previous_hash via SHA-256.
    """
    __tablename__ = "custody_events"

    event_id = Column(String(64), primary_key=True, index=True)
    evidence_id = Column(String(64), ForeignKey("evidence.evidence_id"), nullable=False, index=True)
    sequence_number = Column(Integer, nullable=False, default=1)
    event_type = Column(String(64), nullable=False)
    user_id = Column(String(64), nullable=False)
    timestamp = Column(String(64), nullable=False)
    description = Column(Text, nullable=True)
    previous_hash = Column(String(64), nullable=False)
    event_hash = Column(String(64), nullable=False, unique=True, index=True)
    payload_json = Column(Text, nullable=False, default="{}")

    # Legacy synonyms for Phase 0/1 test compatibility
    action = synonym("event_type")
    actor_id = synonym("user_id")
    previous_event_hash = synonym("previous_hash")

    evidence = relationship("Evidence", back_populates="custody_events")

    __table_args__ = (
        Index("idx_custody_evid_seq", "evidence_id", "sequence_number", unique=True),
    )
