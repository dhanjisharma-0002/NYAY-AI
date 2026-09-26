"""
NYAYAI - Reports API Router (Phase 10)
Module: backend.app.api.reports
Module Lead: Dhananjay Sharma (Backend & System Integration Lead)

Provides REST endpoints for:
- POST /api/reports/generate/{case_id} : Court-ready report generation (PDF & DOCX)
- GET  /api/reports/download/{report_id} : Stream generated document artifact
- GET  /api/reports/{report_id}          : Report verification & metadata
- POST /api/cases/{case_id}/report       : Legacy endpoint for backward compatibility
- GET  /api/reports/verify/{code}        : Public verification gateway
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query, Header, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.user import User
from backend.app.core.security import get_current_user_optional, get_current_user_id
from backend.app.schemas.reports import (
    ReportGenerateRequest,
    CourtReportRequest,
    CourtReportResponse
)
from backend.app.services.report_service import ReportService

router = APIRouter(tags=["Court Reports"])


@router.post(
    "/reports/generate/{case_id}",
    status_code=status.HTTP_201_CREATED,
    summary="Generate court-ready electronic evidence admissibility report (PDF/DOCX)"
)
def generate_court_ready_report_endpoint(
    case_id: str,
    payload: Optional[ReportGenerateRequest] = None,
    format: Optional[str] = Query(None, description="Report format: PDF or DOCX"),
    authorization: Optional[str] = Header(None),
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Court-Ready Report Engine (Phase 10):
    Synthesizes a 12-section judicial admissibility report in PDF or DOCX format:
    1. Case Information
    2. Evidence Inventory
    3. SHA-256 Integrity Information
    4. Metadata Findings
    5. Forensic Findings
    6. AI Analysis
    7. Confidence / Risk Information
    8. Explainability References
    9. Evidence Correlation
    10. Timeline
    11. Chain of Custody
    12. Verification Information

    Guarantees:
    - Never invents findings; displays 'Analysis not available' when modules have no results.
    - Clearly distinguishes System-Generated Analysis, Metadata, User-Provided Information, and AI Output.
    - Full database record storage with immutable SHA-256 hash.
    """
    service = ReportService(db)

    # Determine user identity
    if current_user:
        user_id = current_user.id
    else:
        user_id = get_current_user_id(authorization)

    # Determine requested format (payload.format overrides query param if both provided)
    req_format = "PDF"
    if payload and payload.format:
        req_format = payload.format
    elif format:
        req_format = format

    officer_name = payload.certifying_officer_name if payload else "Dhananjay Sharma"
    officer_designation = payload.certifying_officer_designation if payload else "Forensic Systems Lead"
    badge_number = payload.badge_number if payload else "INV-DL-9841"
    jurisdiction = payload.jurisdiction if payload else "High Court of Delhi"

    report = service.generate_court_ready_report(
        case_id=case_id,
        report_format=req_format,
        certifying_officer_name=officer_name or "Dhananjay Sharma",
        certifying_officer_designation=officer_designation or "Forensic Systems Lead",
        badge_number=badge_number or "INV-DL-9841",
        jurisdiction=jurisdiction,
        user_id=user_id
    )

    data_payload = {
        "report_id": report.report_id,
        "case_id": report.case_id,
        "case_number": report.case.case_number if report.case else None,
        "report_type": report.report_type,
        "status": report.status,
        "storage_reference": report.storage_reference,
        "verification_code": report.verification_code,
        "report_sha256": report.report_sha256,
        "created_by": report.created_by,
        "created_at": report.created_at.isoformat(),
        "download_url": f"/api/reports/download/{report.report_id}",
        "qr_verification_url": report.qr_code_data
    }

    # Return unified response with both root and data keys for maximum client compatibility
    return {
        "success": True,
        **data_payload,
        "data": data_payload
    }


@router.get(
    "/reports/download/{report_id}",
    summary="Download the generated PDF or DOCX report document"
)
def download_report(report_id: str, db: Session = Depends(get_db)):
    """Streams the generated court-ready report file from secure storage."""
    service = ReportService(db)
    file_path, filename, media_type = service.get_report_file(report_id)
    return FileResponse(
        path=file_path,
        filename=filename,
        media_type=media_type
    )


# -----------------------------------------------------------------------------
# Backward Compatibility Endpoints for Phase 0/1 Test Suites
# -----------------------------------------------------------------------------

@router.post("/reports/cases/{case_id}", status_code=status.HTTP_201_CREATED)
@router.post("/cases/{case_id}/report", status_code=status.HTTP_201_CREATED)
def generate_court_report_legacy(
    case_id: str,
    payload: CourtReportRequest,
    db: Session = Depends(get_db)
):
    """Legacy report generation certificate under BSA 2023 / Section 65B."""
    service = ReportService(db)
    report = service.generate_court_report(
        case_id=case_id,
        certifying_officer_name=payload.certifying_officer_name or "Dhananjay Sharma",
        badge_number=payload.badge_number or "INV-DL-9841",
        jurisdiction=payload.jurisdiction or "High Court of Delhi",
        user_id="USR-SYSTEM-LEAD"
    )
    return {
        "success": True,
        "data": {
            "report_id": report.report_id,
            "case_id": report.case_id,
            "compliance_standard": report.compliance_framework,
            "report_sha256": report.report_sha256,
            "qr_verification_url": report.qr_code_data,
            "report_file_path": report.pdf_path,
            "generated_at": report.created_at.isoformat()
        }
    }


@router.get("/reports/{report_id}")
@router.get("/reports/verify/{report_id}")
def get_report_metadata(report_id: str, db: Session = Depends(get_db)):
    """Retrieve metadata and verification status of an issued court report certificate."""
    service = ReportService(db)
    return service.verify_report(report_id)
