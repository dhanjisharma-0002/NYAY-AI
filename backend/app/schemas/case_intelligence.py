"""
NYAYAI - Case Intelligence Summary Schemas (Phase 13)
Module: backend.app.schemas.case_intelligence
Defines response contracts for the consolidated Case & Evidence Intelligence Summary layer.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class CaseSummaryInfo(BaseModel):
    case_id: str
    case_number: str
    title: str
    description: Optional[str] = None
    status: str
    jurisdiction: Optional[str] = None
    created_by: str
    created_at: str
    updated_at: str


class EvidenceItemSummary(BaseModel):
    evidence_id: str
    original_filename: str
    media_type: str
    mime_type: Optional[str] = None
    file_size_bytes: int
    sha256_hash: str
    status: str
    source_description: Optional[str] = None
    created_at: Optional[str] = None


class EvidenceStatistics(BaseModel):
    total_count: int = 0
    by_media_type: Dict[str, int] = Field(default_factory=dict)
    total_size_bytes: int = 0
    items: List[EvidenceItemSummary] = Field(default_factory=list)


class IntegritySummary(BaseModel):
    total_checked: int = 0
    intact_count: int = 0
    compromised_count: int = 0
    storage_error_count: int = 0
    integrity_status: str = "NO_EVIDENCE"  # INTACT | INTEGRITY_COMPROMISED | STORAGE_ERROR | NO_EVIDENCE


class ForensicItemSummary(BaseModel):
    evidence_id: str
    format_valid: bool = True
    magic_bytes: Optional[str] = None
    anomalies_count: int = 0
    anomalies: List[str] = Field(default_factory=list)


class ForensicSummary(BaseModel):
    inspected_count: int = 0
    anomalies_detected_count: int = 0
    format_valid_count: int = 0
    items: List[ForensicItemSummary] = Field(default_factory=list)


class AIAnalysisItemSummary(BaseModel):
    analysis_id: str
    evidence_id: str
    analysis_type: str
    prediction: Optional[str] = None
    confidence: float = 0.0
    risk_score: float = 0.0
    tamper_detected: bool = False
    findings: List[Any] = Field(default_factory=list)
    model_name: Optional[str] = None
    model_version: Optional[str] = None


class AIAnalysisSummary(BaseModel):
    analyzed_count: int = 0
    tamper_detected_count: int = 0
    average_risk_score: float = 0.0
    items: List[AIAnalysisItemSummary] = Field(default_factory=list)


class ExplainabilitySummary(BaseModel):
    records_count: int = 0
    available: bool = False
    categories: Dict[str, int] = Field(default_factory=dict)


class CorrelationSummary(BaseModel):
    timeline_events_count: int = 0
    relationships_count: int = 0
    cross_matches_count: int = 0
    red_flags_count: int = 0
    red_flags: List[Dict[str, Any]] = Field(default_factory=list)


class TimelineSummary(BaseModel):
    total_events: int = 0
    has_timeline: bool = False
    earliest_timestamp: Optional[str] = None
    latest_timestamp: Optional[str] = None


class CustodyChainItemSummary(BaseModel):
    evidence_id: str
    chain_intact: bool = True
    total_events: int = 0
    broken_at_event_id: Optional[str] = None


class CustodySummary(BaseModel):
    total_events: int = 0
    all_chains_intact: bool = True
    broken_chains_count: int = 0
    evidence_chains: List[CustodyChainItemSummary] = Field(default_factory=list)


class ReportItemSummary(BaseModel):
    report_id: str
    report_type: str
    status: str
    report_sha256: str
    verification_code: str
    created_at: Optional[str] = None


class ReportsSummary(BaseModel):
    total_reports: int = 0
    reports_list: List[ReportItemSummary] = Field(default_factory=list)


class VerificationItemSummary(BaseModel):
    verification_id: str
    report_id: str
    verification_method: str
    status: str
    timestamp: Optional[str] = None


class VerificationSummary(BaseModel):
    total_verifications: int = 0
    valid_verifications: int = 0
    tampered_verifications: int = 0
    recent_verifications: List[VerificationItemSummary] = Field(default_factory=list)


class AuditItemSummary(BaseModel):
    audit_id: str
    user_id: Optional[str] = None
    action: str
    resource_type: str
    resource_id: str
    timestamp: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AuditSummary(BaseModel):
    total_audit_events: int = 0
    recent_events: List[AuditItemSummary] = Field(default_factory=list)


class CaseIntelligenceSummaryResponse(BaseModel):
    """
    Consolidated Case & Evidence Intelligence Summary (Phase 13).
    Provides a comprehensive, read-only case-level view across 12 distinct intelligence domains.
    """
    success: bool = True
    case: CaseSummaryInfo
    evidence: EvidenceStatistics
    integrity: IntegritySummary
    forensic: ForensicSummary
    ai_analysis: AIAnalysisSummary
    explainability: ExplainabilitySummary
    correlation: CorrelationSummary
    timeline: TimelineSummary
    custody: CustodySummary
    reports: ReportsSummary
    verification: VerificationSummary
    audit: AuditSummary
    overall_status: str = "UNDER_ANALYSIS"
