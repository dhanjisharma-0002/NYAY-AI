"""
NYAYAI - Health Endpoint
Module: backend.app.api.health
"""

from fastapi import APIRouter
from backend.app.schemas.health import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """
    Primary system health check.
    Returns: {"status": "ok", "service": "NYAYAI Backend"}
    """
    return HealthResponse(
        status="ok",
        service="NYAYAI Backend"
    )
