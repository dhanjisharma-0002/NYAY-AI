"""
NYAYAI - Evidence Model
Module: backend.app.models.evidence
"""

import uuid
from sqlalchemy import Column, String, Text, BigInteger, DateTime, ForeignKey
from sqlalchemy.orm import relationship, synonym
from backend.app.database import Base
from backend.app.models.base import utc_now


def generate_stored_filename():
    return f"vault_{uuid.uuid4().hex[:16]}"


class Evidence(Base):
    __tablename__ = "evidence"

    evidence_id = Column(String(64), primary_key=True, index=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False, index=True)
    original_filename = Column(String(256), nullable=False)
    stored_filename = Column(String(256), nullable=False, default=generate_stored_filename)
    media_type = Column(String(128), nullable=False)
    file_size = Column(BigInteger, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    storage_reference = Column(String(512), nullable=False)
    status = Column(String(32), default="SECURED", nullable=False)
    uploaded_by = Column(String(36), ForeignKey("users.id"), nullable=False)
    source_description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Synonyms for Phase 0/1 backward compatibility
    mime_type = synonym("media_type")
    file_size_bytes = synonym("file_size")
    vault_path = synonym("storage_reference")
    intake_by_user_id = synonym("uploaded_by")

    case = relationship("Case", back_populates="evidences")
    uploader = relationship("User", back_populates="uploaded_evidence", foreign_keys=[uploaded_by])
    metadata_record = relationship("EvidenceMetadata", back_populates="evidence", uselist=False, cascade="all, delete-orphan")
    analysis_results = relationship("AnalysisResult", back_populates="evidence", cascade="all, delete-orphan")
    custody_events = relationship("CustodyEvent", back_populates="evidence", order_by="CustodyEvent.sequence_number", cascade="all, delete-orphan")
    explainability_records = relationship("ExplainabilityRecord", back_populates="evidence", cascade="all, delete-orphan")

    # Property aliases
    @property
    def filename(self):
        return self.original_filename

    @property
    def forensic_artifacts(self):
        return self.metadata_record

    @property
    def ai_results(self):
        return self.analysis_results


# Backward-compatible alias
EvidenceItem = Evidence
