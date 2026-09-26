"""
NYAYAI - Backend REST API & Master Orchestrator Service (Phase 1)
Module: backend.app.main
"""

import sys
import os

# Ensure sub-engine modules are discoverable
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

for engine_dir in ["forensic-engine", "ai-engine", "explainability", "correlation", "custody", "reports"]:
    p = os.path.join(ROOT_DIR, engine_dir)
    if p not in sys.path:
        sys.path.insert(0, p)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.config import settings
from backend.app.middleware.logging_middleware import LoggingMiddleware
from backend.app.middleware.error_handler import register_error_handlers
from backend.app.api.router import api_router, api_v1_router
from backend.app.schemas.health import HealthResponse
from backend.app.utils.logger import get_logger

logger = get_logger("main")

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Enterprise Digital Evidence AI Platform with Cryptographic Chain of Custody & BSA Admissibility",
    docs_url="/docs",
    redoc_url="/redoc"
)

# 1. Register Logging Middleware
app.add_middleware(LoggingMiddleware)

# 2. Cross-Origin Resource Sharing (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. Register Centralized Error Handlers (Consistent status, message, error_code; no stack traces)
register_error_handlers(app)

# 4. Mount Master API Routers
# /api/... (Primary API paths)
app.include_router(api_router, prefix=settings.API_PREFIX)

# /api/v1/... (Versioned API paths)
app.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)


# 5. Root Health Check for backward compatibility & direct load balancer probes
@app.get("/health", tags=["Health"])
def root_health():
    """Root health check reporting active engines and compliance status."""
    return {
        "status": "HEALTHY",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "compliance": "Bharatiya Sakshya Adhiniyam 2023 / ISO 27037",
        "engines_active": [
            "ForensicEngine (Anu Sharma)",
            "AIEngine (Anu Sharma)",
            "ExplainabilityEngine (Ridhi Mashi)",
            "CorrelationEngine (Ridhi Mashi)",
            "CustodyLedger (Ridhi Mashi)",
            "ReportGenerator (Dhananjay Sharma)"
        ]
    }


@app.on_event("startup")
async def startup_event():
    logger.info(
        f"Starting {settings.APP_NAME} v{settings.APP_VERSION} [env: {settings.ENVIRONMENT}]"
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.app.main:app",
        host=settings.BACKEND_HOST,
        port=settings.BACKEND_PORT,
        reload=settings.DEBUG
    )
