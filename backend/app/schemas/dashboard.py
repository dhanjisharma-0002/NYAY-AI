"""
NYAYAI - Investigator Portfolio Operational Dashboard Schemas (Phase 15)
Module: backend.app.schemas.dashboard
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Typed Pydantic response models for cross-case operational dashboard & portfolio overview.
"""

from typing import Dict, List
from pydantic import BaseModel, Field


class UrgentCaseItem(BaseModel):
    """Summarized case docket presenting active high-severity alerts."""
    case_id: str
    case_number: str
    title: str
    status: str
    high_alert_types: List[str] = Field(default_factory=list)


class EvidenceMetrics(BaseModel):
    """Aggregate evidence health and cryptographic integrity counts."""
    total: int = 0
    verified: int = 0
    compromised: int = 0
    storage_errors: int = 0


class PendingActionMetrics(BaseModel):
    """System-wide pending investigative and reporting action counts."""
    forensic_analysis: int = 0
    ai_analysis: int = 0
    court_reports: int = 0


class OperationalDashboardResponse(BaseModel):
    """
    Cross-case operational dashboard and portfolio overview response.
    Deterministic, aggregated cross-case triage metrics without N+1 query amplification.
    """
    total_cases: int = 0
    status_counts: Dict[str, int] = Field(default_factory=dict)
    cases_requiring_attention: int = 0
    urgent_cases: List[UrgentCaseItem] = Field(default_factory=list)
    evidence_metrics: EvidenceMetrics = Field(default_factory=EvidenceMetrics)
    pending_actions: PendingActionMetrics = Field(default_factory=PendingActionMetrics)
