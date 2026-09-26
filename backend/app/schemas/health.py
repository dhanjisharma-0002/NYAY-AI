"""
NYAYAI - Health Schemas
Module: backend.app.schemas.health
"""

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "NYAYAI Backend"
