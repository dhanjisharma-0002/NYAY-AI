"""
NYAYAI - Audit Log Model
Module: backend.app.models.audit
"""

import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, Index
from sqlalchemy.orm import relationship, synonym
from backend.app.database import Base
from backend.app.models.base import utc_now, JSONType


class AuditLog(Base):
    __tablename__ = "audit_logs"

    audit_id = Column(String(64), primary_key=True, default=lambda: f"AUD-{uuid.uuid4().hex[:12].upper()}", index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(64), nullable=False, index=True)
    resource_type = Column(String(64), nullable=False, index=True)
    resource_id = Column(String(64), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    # Map SQL column 'metadata' to attribute 'meta_data' to avoid collision with DeclarativeBase.metadata
    meta_data = Column("metadata", JSONType, nullable=True, default=dict)

    user = relationship("User", back_populates="audit_logs")

    @property
    def metadata_payload(self):
        return self.meta_data

    @metadata_payload.setter
    def metadata_payload(self, value):
        self.meta_data = value
