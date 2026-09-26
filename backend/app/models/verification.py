"""
NYAYAI - Public QR Verification Record Model
Module: backend.app.models.verification
"""

import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, Index
from sqlalchemy.orm import relationship
from backend.app.database import Base
from backend.app.models.base import utc_now, JSONType


class VerificationRecord(Base):
    __tablename__ = "verification_records"

    verification_id = Column(String(64), primary_key=True, default=lambda: f"VER-{uuid.uuid4().hex[:12].upper()}", index=True)
    report_id = Column(String(64), ForeignKey("reports.report_id"), nullable=False, index=True)
    verification_method = Column(String(64), nullable=False, default="QR_CODE")
    verifier_identifier = Column(String(128), nullable=True)
    status = Column(String(32), nullable=False, default="VALID")
    ip_address = Column(String(64), nullable=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    # Column named 'metadata' in SQL, mapped to 'meta_data' in Python
    meta_data = Column("metadata", JSONType, nullable=True, default=dict)

    report = relationship("Report", back_populates="verifications")
