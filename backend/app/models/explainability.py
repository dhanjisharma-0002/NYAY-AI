"""
NYAYAI - Explainability Record Model
Module: backend.app.models.explainability
"""

from sqlalchemy import Column, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database import Base
from backend.app.models.base import utc_now


class ExplainabilityRecord(Base):
    __tablename__ = "explainability_records"

    record_id = Column(String(64), primary_key=True, index=True)
    evidence_id = Column(String(64), ForeignKey("evidence.evidence_id"), nullable=False, index=True)
    reasoning_summary = Column(Text, nullable=False)
    confidence_category = Column(String(32), nullable=False)
    feature_attributions = Column(Text, nullable=True)
    limitations_disclaimer = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    evidence = relationship("Evidence", back_populates="explainability_records")
