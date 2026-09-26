"""
NYAYAI - Analysis Result Model (AI & Forensic Inspection Findings)
Module: backend.app.models.analysis_result
"""

import json
from sqlalchemy import Column, String, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship, synonym
from backend.app.database import Base
from backend.app.models.base import utc_now, JSONType


class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    analysis_id = Column(String(64), primary_key=True, index=True)
    evidence_id = Column(String(64), ForeignKey("evidence.evidence_id"), nullable=False, index=True)
    analysis_type = Column(String(64), nullable=False, default="TAMPER_DETECTION")
    status = Column(String(32), nullable=False, default="COMPLETED")
    prediction = Column(String(64), nullable=True)
    confidence = Column(Float, nullable=False, default=0.0)
    risk_score = Column(Float, nullable=False, default=0.0)
    findings = Column(JSONType, nullable=False, default=list)
    explanation = Column(String(1024), nullable=True)
    model_name = Column(String(128), nullable=False, default="TamperScreener-Baseline")
    model_version = Column(String(32), nullable=False, default="0.1.0")
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Legacy synonyms for Phase 0/1 test compatibility
    result_id = synonym("analysis_id")
    confidence_score = synonym("confidence")

    evidence = relationship("Evidence", back_populates="analysis_results")

    @property
    def tamper_detected(self) -> bool:
        if self.prediction:
            return "TAMPER" in self.prediction.upper()
        # Fallback to findings inspection
        return self.risk_score > 0.5 or self.confidence > 0.7

    @tamper_detected.setter
    def tamper_detected(self, value: bool):
        self.prediction = "TAMPER_DETECTED" if value else "AUTHENTIC"
        if value and self.risk_score == 0.0:
            self.risk_score = 0.85

    @property
    def findings_json(self) -> str:
        return json.dumps(self.findings or [])

    @findings_json.setter
    def findings_json(self, value):
        if isinstance(value, str):
            try:
                self.findings = json.loads(value)
            except Exception:
                self.findings = [value]
        else:
            self.findings = value or []


# Backward-compatible alias
AIAnalysisResult = AnalysisResult
