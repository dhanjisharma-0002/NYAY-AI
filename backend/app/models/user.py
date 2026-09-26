"""
NYAYAI - User Model
Module: backend.app.models.user
"""

import uuid
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database import Base
from backend.app.models.base import utc_now


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(128), unique=True, nullable=False, index=True)
    hashed_password = Column(String(256), nullable=False)
    full_name = Column(String(128), nullable=False)
    badge_number = Column(String(64), nullable=True)
    role_id = Column(String(36), ForeignKey("roles.id"), nullable=True)
    role = Column(String(32), nullable=False, default="INVESTIGATOR")
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    role_rel = relationship("Role", back_populates="users")
    cases = relationship("Case", back_populates="creator", foreign_keys="Case.created_by")
    uploaded_evidence = relationship("Evidence", back_populates="uploader", foreign_keys="Evidence.uploaded_by")
    reports = relationship("Report", back_populates="creator", foreign_keys="Report.created_by")
    audit_logs = relationship("AuditLog", back_populates="user", foreign_keys="AuditLog.user_id")
