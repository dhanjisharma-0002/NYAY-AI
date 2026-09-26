"""
NYAYAI - Base Model Utilities & Type Definitions
Module: backend.app.models.base
"""

from datetime import datetime, timezone
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from backend.app.database import Base

# Dialect-adaptive JSON type: native JSONB on PostgreSQL, JSON on SQLite/others
JSONType = JSON().with_variant(JSONB, "postgresql")


def utc_now():
    """Returns current UTC datetime object."""
    return datetime.now(timezone.utc)


def utc_now_iso():
    """Returns current UTC timestamp formatted as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()
