"""
NYAYAI - Correlation Link Model
Module: backend.app.models.correlation
"""

from sqlalchemy import Column, String, Text, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database import Base
from backend.app.models.base import utc_now


class CorrelationLink(Base):
    __tablename__ = "correlation_links"

    correlation_id = Column(String(64), primary_key=True, index=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False, index=True)
    source_evidence_id = Column(String(64), ForeignKey("evidence.evidence_id"), nullable=False)
    target_evidence_id = Column(String(64), ForeignKey("evidence.evidence_id"), nullable=False)
    relationship_type = Column(String(64), nullable=False)
    confidence = Column(Float, nullable=False)
    evidence_notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    case = relationship("Case", back_populates="correlations")
