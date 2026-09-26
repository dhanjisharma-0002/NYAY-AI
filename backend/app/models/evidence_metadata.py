"""
NYAYAI - Evidence Metadata Model (Forensic Artifacts)
Module: backend.app.models.evidence_metadata
"""

import json
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship, synonym
from backend.app.database import Base
from backend.app.models.base import utc_now, JSONType


class EvidenceMetadata(Base):
    __tablename__ = "evidence_metadata"

    metadata_id = Column(String(64), primary_key=True, index=True)
    evidence_id = Column(String(64), ForeignKey("evidence.evidence_id"), nullable=False, unique=True, index=True)
    format_valid = Column(Boolean, nullable=False, default=True)
    magic_bytes = Column(String(64), nullable=False)
    exif_data = Column(JSONType, nullable=True, default=dict)
    timestamps_metadata = Column(JSONType, nullable=True, default=dict)
    anomalies = Column(JSONType, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Legacy synonym
    artifact_id = synonym("metadata_id")

    evidence = relationship("Evidence", back_populates="metadata_record")

    # JSON text properties for Phase 0/1 test compatibility
    @property
    def exif_metadata_json(self):
        return json.dumps(self.exif_data or {})

    @exif_metadata_json.setter
    def exif_metadata_json(self, value):
        if isinstance(value, str):
            try:
                self.exif_data = json.loads(value)
            except Exception:
                self.exif_data = {}
        else:
            self.exif_data = value

    @property
    def detected_timestamps(self):
        return json.dumps(self.timestamps_metadata or {})

    @detected_timestamps.setter
    def detected_timestamps(self, value):
        if isinstance(value, str):
            try:
                self.timestamps_metadata = json.loads(value)
            except Exception:
                self.timestamps_metadata = {}
        else:
            self.timestamps_metadata = value

    @property
    def hex_anomalies_json(self):
        return json.dumps(self.anomalies or [])

    @hex_anomalies_json.setter
    def hex_anomalies_json(self, value):
        if isinstance(value, str):
            try:
                self.anomalies = json.loads(value)
            except Exception:
                self.anomalies = [value]
        else:
            self.anomalies = value or []


# Backward-compatible alias
ForensicArtifact = EvidenceMetadata
