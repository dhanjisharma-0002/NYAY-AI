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
    # Phase 11 safe public verification extensions
    verification_code: Optional[str] = None
    report_type: Optional[str] = None
    verification_id: Optional[str] = None
    verification_method: Optional[str] = None
    verified_at: Optional[str] = None


class VerificationRecordOut(BaseModel):
    verification_id: str
    report_id: str
    verification_method: str
    verifier_identifier: Optional[str] = None
    status: str
    ip_address: Optional[str] = None
    timestamp: str

