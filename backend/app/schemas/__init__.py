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
from .operational_view import OperationalCaseViewResponse, CriticalAlert, PendingAction, FindingsSummary, SummaryMetrics
from .dashboard import OperationalDashboardResponse, UrgentCaseItem, EvidenceMetrics, PendingActionMetrics
from .pipeline_batch import CaseBatchPipelineRequest, CaseBatchPipelineResponse
from .case_finalization import CaseFinalizationRequest, CaseFinalizationResponse, DocketSealingManifestResponse
from .admissibility import (
    CaseAdmissibilityRequest,
    CaseAdmissibilityResponse,
    AdmissibilityCertificateResponse,
    AdmissibilityStatusEnum
)
from .export_bundle import (
    ExportBundleRequest,
    ExportBundleResponse,
    BundleManifestResponse,
    BundleArtifactItem
)
from .bundle_verification import (
    BundleVerificationStatusEnum,
    ArtifactVerificationItem,
    BundleVerificationChecks,
    BundleVerificationResponse,
    BundleManifestVerificationRequest,
    BundleManifestVerificationResponse
)
from .exhibit_marking import (
    ExhibitRulingEnum,
    TenderingPartyEnum,
    ExhibitItemTypeEnum,
    EvidenceTenderRequest,
    EvidenceTenderResponse,
    ExhibitMarkingRequest,
    ExhibitRecordResponse,
    EvidenceExhibitStatusResponse,
    CaseExhibitRegisterResponse
)
from .trial_disposition import (
    TrialVerdictEnum,
    ResolvedRulingEnum,
    DisposalTypeEnum,
    TrialVerdictRequest,
    TrialVerdictResponse,
    ObjectionResolutionRequest,
    ObjectionResolutionResponse,
    ExhibitDisposalOrderRequest,
    ExhibitDisposalOrderResponse,
    CaseArchivalRequest,
    CaseArchivalResponse,
    CaseTrialDispositionRegisterResponse
)

__all__ = [
    "TrialVerdictEnum",
    "ResolvedRulingEnum",
    "DisposalTypeEnum",
    "TrialVerdictRequest",
    "TrialVerdictResponse",
    "ObjectionResolutionRequest",
    "ObjectionResolutionResponse",
    "ExhibitDisposalOrderRequest",
    "ExhibitDisposalOrderResponse",
    "CaseArchivalRequest",
    "CaseArchivalResponse",
    "CaseTrialDispositionRegisterResponse",
    "ExhibitRulingEnum",
    "TenderingPartyEnum",
    "ExhibitItemTypeEnum",
    "EvidenceTenderRequest",
    "EvidenceTenderResponse",
    "ExhibitMarkingRequest",
    "ExhibitRecordResponse",
    "EvidenceExhibitStatusResponse",
    "CaseExhibitRegisterResponse",
    "BundleVerificationStatusEnum",
    "ArtifactVerificationItem",
    "BundleVerificationChecks",
    "BundleVerificationResponse",
    "BundleManifestVerificationRequest",
    "BundleManifestVerificationResponse",
    "ExportBundleRequest",
    "ExportBundleResponse",
    "BundleManifestResponse",
    "BundleArtifactItem",
    "CaseAdmissibilityRequest",
    "CaseAdmissibilityResponse",
    "AdmissibilityCertificateResponse",
    "AdmissibilityStatusEnum",
    "CaseFinalizationRequest",
    "CaseFinalizationResponse",
    "DocketSealingManifestResponse",
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
    "OperationalCaseViewResponse",
    "CriticalAlert",
    "PendingAction",
    "FindingsSummary",
    "SummaryMetrics",
    "OperationalDashboardResponse",
    "UrgentCaseItem",
    "EvidenceMetrics",
    "PendingActionMetrics",
    "CaseBatchPipelineRequest",
    "CaseBatchPipelineResponse",
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
