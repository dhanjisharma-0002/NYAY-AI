"""
NYAYAI - Investigator Operational Case View Schemas (Phase 14)
Module: backend.app.schemas.operational_view
Defines response contracts for the investigator operational query and triage layer.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from backend.app.schemas.case_intelligence import CaseIntelligenceSummaryResponse


class CriticalAlert(BaseModel):
    """Deterministic alert surfaced from persisted evidence or custody exceptions."""
    alert_type: str
    severity: str  # HIGH | MEDIUM
    resource_id: str
    description: str


class PendingAction(BaseModel):
    """Actionable operational task required for case readiness."""
    action_type: str
    resource_id: str
    description: str


class FindingsSummary(BaseModel):
    """Aggregated tallies of validated vs anomalous analytical findings."""
    validated_findings: int = 0
    anomalous_findings: int = 0
    red_flags: int = 0


class SummaryMetrics(BaseModel):
    """High-level evidence and processing metrics for quick overview."""
    total_evidence: int = 0
    verified_evidence: int = 0
    compromised_evidence: int = 0
    analyzed_evidence: int = 0
    active_red_flags: int = 0
    reports_generated: int = 0


class OperationalCaseViewResponse(BaseModel):
    """
    Investigator Operational Case View (Phase 14).
    Provides actionable triage information, critical alerts, pending actions,
    and key investigation metrics on top of the Phase 13 Case Intelligence Summary.
    """
    success: bool = True
    case_id: str
    case_number: str
    title: str
    overall_status: str
    attention_required: bool = False
    critical_alerts: List[CriticalAlert] = Field(default_factory=list)
    pending_actions: List[PendingAction] = Field(default_factory=list)
    findings_summary: FindingsSummary
    summary_metrics: SummaryMetrics
    intelligence_summary: CaseIntelligenceSummaryResponse
