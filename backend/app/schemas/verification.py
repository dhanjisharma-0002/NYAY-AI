"""
NYAYAI - Public QR Verification Schemas
Module: backend.app.schemas.verification
"""

from typing import Optional
from pydantic import BaseModel


class VerificationResponse(BaseModel):
    verified: bool
    report_id: str
    case_id: str
    case_title: Optional[str] = None
    official_report_sha256: str
    compliance_framework: str
    certified_evidence_count: int
    issued_at: str
    integrity_status: str
