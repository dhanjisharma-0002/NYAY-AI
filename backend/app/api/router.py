"""
NYAYAI - Master API Router Assembly
Module: backend.app.api.router
"""

from fastapi import APIRouter
from backend.app.api.health import router as health_router
from backend.app.api.auth import router as auth_router
from backend.app.api.cases import router as cases_router
from backend.app.api.evidence import router as evidence_router
from backend.app.api.forensics import router as forensics_router
from backend.app.api.ai import router as ai_router
from backend.app.api.correlation import router as correlation_router
from backend.app.api.custody import router as custody_router
from backend.app.api.reports import router as reports_router
from backend.app.api.verification import router as verification_router
from backend.app.api.v1.pipeline import router as pipeline_router
from backend.app.api.rbac_demo import router as rbac_router
from backend.app.api.audit import router as audit_router

# Master API Router (mounted at /api)
api_router = APIRouter()

# Include health router
api_router.include_router(health_router)

# Include prepared domain routers
api_router.include_router(auth_router)
api_router.include_router(rbac_router)
api_router.include_router(cases_router)
api_router.include_router(evidence_router)
api_router.include_router(forensics_router)
api_router.include_router(ai_router)
api_router.include_router(correlation_router)
api_router.include_router(custody_router)
api_router.include_router(reports_router)
api_router.include_router(verification_router)
api_router.include_router(pipeline_router)
api_router.include_router(audit_router)

# Versioned router (mounted at /api/v1)
api_v1_router = APIRouter()
api_v1_router.include_router(health_router)
api_v1_router.include_router(auth_router)
api_v1_router.include_router(rbac_router)
api_v1_router.include_router(cases_router)
api_v1_router.include_router(evidence_router)
api_v1_router.include_router(forensics_router)
api_v1_router.include_router(ai_router)
api_v1_router.include_router(correlation_router)
api_v1_router.include_router(custody_router)
api_v1_router.include_router(reports_router)
api_v1_router.include_router(verification_router)
api_v1_router.include_router(pipeline_router)
api_v1_router.include_router(audit_router)

