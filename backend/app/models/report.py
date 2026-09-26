"""
NYAYAI - Court Admissibility Report Model
Module: backend.app.models.report
"""

import uuid
from sqlalchemy import Column, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship, synonym
from backend.app.database import Base
from backend.app.models.base import utc_now


def generate_verification_code():
    return f"VERIFY-{uuid.uuid4().hex[:12].upper()}"


class Report(Base):
    __tablename__ = "reports"

    report_id = Column(String(64), primary_key=True, index=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False, index=True)
    report_type = Column(String(64), nullable=False, default="BSA_2023_SEC_63_65B")
    status = Column(String(32), nullable=False, default="GENERATED")
    storage_reference = Column(String(512), nullable=False)
    verification_code = Column(String(64), unique=True, nullable=False, index=True, default=generate_verification_code)
    report_sha256 = Column(String(64), nullable=False, unique=True, index=True)
    qr_code_data = Column(Text, nullable=True)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Legacy synonyms for Phase 0/1 test compatibility
    compliance_framework = synonym("report_type")
    pdf_path = synonym("storage_reference")
    certifying_officer_id = synonym("created_by")

    case = relationship("Case", back_populates="reports")
    creator = relationship("User", back_populates="reports", foreign_keys=[created_by])
    verifications = relationship("VerificationRecord", back_populates="report", cascade="all, delete-orphan")


# Backward-compatible alias
CourtReport = Report
