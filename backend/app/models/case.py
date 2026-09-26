"""
NYAYAI - Case Model
Module: backend.app.models.case
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship, synonym
from backend.app.database import Base
from backend.app.models.base import utc_now


def generate_case_number():
    return f"CR-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:8].upper()}"


class Case(Base):
    __tablename__ = "cases"

    case_id = Column(String(64), primary_key=True, index=True)
    case_number = Column(String(64), unique=True, nullable=False, index=True, default=generate_case_number)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(32), default="OPEN", nullable=False)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=False)
    jurisdiction = Column(String(128), nullable=False, default="High Court of Delhi")
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    # Legacy synonym for Phase 0/1 backward compatibility
    investigator_id = synonym("created_by")

    creator = relationship("User", back_populates="cases", foreign_keys=[created_by])
    evidences = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="case", cascade="all, delete-orphan")
    correlations = relationship("CorrelationLink", back_populates="case", cascade="all, delete-orphan")

    # Property aliases for backward compatibility
    @property
    def investigator(self):
        return self.creator

    @property
    def evidence_items(self):
        return self.evidences
