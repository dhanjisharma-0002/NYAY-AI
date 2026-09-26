"""
NYAYAI - AI Analysis Schemas
Module: backend.app.schemas.ai
"""

from typing import Optional, List
from pydantic import BaseModel


class AITamperRequest(BaseModel):
    evidence_id: str
    model_name: Optional[str] = "TamperScreener-Baseline"


class AITamperResponse(BaseModel):
    evidence_id: str
    model_name: str
    model_version: str
    tamper_detected: bool
    confidence_score: float
    findings: List[str] = []
    limitations: str


class AIAnalysisResponse(BaseModel):
    """
    Standardized AI analysis response contract (Phase 7).
    Guarantees all required fields:
    evidence_id, analysis_type, prediction, confidence, risk_score, findings, explanation, model_version
    """
    evidence_id: str
    analysis_type: str = "TAMPER_DETECTION"
    prediction: str
    confidence: float
    risk_score: float
    findings: List[str] = []
    explanation: str
    model_version: str
    model_name: Optional[str] = "TamperScreener-Baseline"
    status: str = "COMPLETED"
    analysis_id: Optional[str] = None
    custody_event_id: Optional[str] = None
    created_at: Optional[str] = None

    class Config:
        from_attributes = True

