"""
NYAYAI - Case Docket Batch Pipeline Schemas (Phase 16)
Module: backend.app.schemas.pipeline_batch
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Pydantic schemas for batch evidence processing across case dockets.
"""

from typing import Optional
from pydantic import BaseModel, Field


class CaseBatchPipelineRequest(BaseModel):
    """Optional execution options for case docket pipeline execution."""
    force_reanalysis: bool = Field(
        default=False,
        description="If True, reprocesses all evidence items; if False, processes only pending items."
    )


class CaseBatchPipelineResponse(BaseModel):
    """
    Execution summary returned after batch pipeline execution over a case docket.
    """
    case_id: str
    total_items: int = 0
    processed_count: int = 0
    anomalies_detected: int = 0
    tamper_detected_count: int = 0
    compromised_count: int = 0
    new_case_status: str
