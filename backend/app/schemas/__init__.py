"""
NYAYAI - Schemas Package
Module: backend.app.schemas
"""

from .common import APIResponse, ErrorResponse
from .health import HealthResponse
from .auth import LoginRequest, TokenResponse, UserResponse
from .cases import CaseCreateRequest, CaseResponse, CaseListResponse
from .evidence import EvidenceResponse, EvidenceListResponse, EvidenceUploadResponse, EvidenceIntegrityResponse
from .forensics import ForensicInspectRequest, ForensicReportResponse, ForensicAnalysisResponse
from .ai import AITamperRequest, AITamperResponse, AIAnalysisResponse
from .correlation import (
    CorrelationRequest,
    CorrelationResponse,
    CaseCorrelationResponse,
    TimelineEvent,
    EvidenceRelationship,
    CrossEvidenceMatch,
    RedFlagItem
)
from .custody import (
    CustodyEventResponse,
    CustodyHistoryResponse,
    CustodyVerifyResponse,
    CustodyEventCreateRequest
)
from .reports import (
    ReportFormat,
    ReportGenerateRequest,
    ReportGenerateResponse,
    CourtReportRequest,
    CourtReportResponse
)
from .verification import VerificationResponse
from .case_intelligence import CaseIntelligenceSummaryResponse

__all__ = [
    "APIResponse",
    "ErrorResponse",
    "HealthResponse",
    "LoginRequest",
    "TokenResponse",
    "UserResponse",
    "CaseCreateRequest",
    "CaseResponse",
    "CaseListResponse",
    "CaseIntelligenceSummaryResponse",
    "EvidenceResponse",
    "EvidenceListResponse",
    "EvidenceUploadResponse",
    "EvidenceIntegrityResponse",
    "ForensicInspectRequest",
    "ForensicReportResponse",
    "ForensicAnalysisResponse",
    "AITamperRequest",
    "AITamperResponse",
    "AIAnalysisResponse",
    "CorrelationRequest",
    "CorrelationResponse",
    "CaseCorrelationResponse",
    "TimelineEvent",
    "EvidenceRelationship",
    "CrossEvidenceMatch",
    "RedFlagItem",
    "CustodyEventResponse",
    "CustodyHistoryResponse",
    "CustodyVerifyResponse",
    "CustodyEventCreateRequest",
    "ReportFormat",
    "ReportGenerateRequest",
    "ReportGenerateResponse",
    "CourtReportRequest",
    "CourtReportResponse",
    "VerificationResponse"
]
