"""
NYAYAI - Reports & Legal Admissibility Schemas (Phase 10)
Module: backend.app.schemas.reports
"""

from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field


class ReportFormat(str, Enum):
    PDF = "PDF"
    DOCX = "DOCX"


class ReportGenerateRequest(BaseModel):
    format: Optional[str] = Field(default="PDF", description="Report output format: PDF or DOCX")
    certifying_officer_name: Optional[str] = Field(default="Dhananjay Sharma", description="Full legal name of the certifying forensic examiner")
    certifying_officer_designation: Optional[str] = Field(default="Forensic Systems Lead", description="Official title / designation")
    badge_number: Optional[str] = Field(default="INV-DL-9841", description="Investigator badge or examiner identification number")
    jurisdiction: Optional[str] = Field(default="High Court of Delhi", description="Relevant legal judicial jurisdiction")


class ReportGenerateResponse(BaseModel):
    report_id: str
    case_id: str
    case_number: Optional[str] = None
    report_type: str
    status: str
    storage_reference: str
    verification_code: str
    report_sha256: str
    created_by: str
    created_at: str
    download_url: Optional[str] = None
    qr_verification_url: Optional[str] = None


# Legacy compatibility schemas for Phase 0/1 tests
class CourtReportRequest(ReportGenerateRequest):
    pass


class CourtReportResponse(BaseModel):
    report_id: str
    case_id: str
    compliance_standard: str = "Bharatiya Sakshya Adhiniyam, 2023 (Section 63/65B Certificate)"
    report_sha256: str
    qr_verification_url: str
    report_file_path: str
    generated_at: str
