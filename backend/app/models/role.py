"""
NYAYAI - Role Model (RBAC)
Module: backend.app.models.role
"""

import uuid
from sqlalchemy import Column, String, DateTime
from sqlalchemy.orm import relationship
from backend.app.database import Base
from backend.app.models.base import utc_now, JSONType


class Role(Base):
    __tablename__ = "roles"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(64), unique=True, nullable=False, index=True)
    description = Column(String(256), nullable=True)
    permissions = Column(JSONType, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    users = relationship("User", back_populates="role_rel")
