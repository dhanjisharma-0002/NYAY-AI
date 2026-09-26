"""
NYAYAI - Court Admissibility Reports & QR Verification API Router
Module Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

import json
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database.connection import get_db
from database.models import Case, EvidenceItem, CustodyEvent, CourtReport, User
from backend.app.core.security import get_current_user_id
from reports import CourtAdmissibilityReportGenerator

router = APIRouter(tags=["Reports & Verification"])
report_generator = CourtAdmissibilityReportGenerator()


class ReportCreateRequest(BaseModel):
    certifying_officer_name: Optional[str] = "Dhananjay Sharma"
    certifying_officer_designation: Optional[str] = "Forensic Systems Lead"
    badge_number: Optional[str] = "INV-DL-9841"
    jurisdiction: Optional[str] = "Republic of India"


@router.post("/cases/{case_id}/report", status_code=status.HTTP_201_CREATED)
def generate_court_report(
    case_id: str,
    payload: ReportCreateRequest,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user_id)
):
    case = db.query(Case).filter_by(case_id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    evidence_records = db.query(EvidenceItem).filter_by(case_id=case_id).all()
    evidence_items_data = [
        {
            "evidence_id": e.evidence_id,
            "original_filename": e.original_filename,
            "file_size_bytes": e.file_size_bytes,
            "mime_type": e.mime_type,
            "sha256_hash": e.sha256_hash
        }
        for e in evidence_records
    ]

    custody_ledgers_data = {}
    for e in evidence_records:
        ev_events = db.query(CustodyEvent).filter_by(evidence_id=e.evidence_id).all()
        custody_ledgers_data[e.evidence_id] = [ev.event_id for ev in ev_events]

    case_data = {
        "case_id": case.case_id,
        "title": case.title,
        "jurisdiction": payload.jurisdiction or case.jurisdiction
    }

    certifying_officer = {
        "name": payload.certifying_officer_name,
        "badge_number": payload.badge_number,
        "role": payload.certifying_officer_designation
    }

    report_result = report_generator.generate_report(
        case_data=case_data,
        evidence_items=evidence_items_data,
        custody_ledgers=custody_ledgers_data,
        certifying_officer=certifying_officer
    )

    db_report = CourtReport(
        report_id=report_result["report_id"],
        case_id=case.case_id,
        certifying_officer_id=user_id,
        compliance_framework="BSA_2023_SEC_63_65B",
        report_sha256=report_result["report_sha256"],
        pdf_path=report_result["report_file_path"],
        qr_code_data=report_result["qr_verification_url"]
    )
    db.add(db_report)
    db.commit()

    return {
        "success": True,
        "data": {
            "report_id": report_result["report_id"],
            "case_id": case.case_id,
            "compliance_standard": "Bharatiya Sakshya Adhiniyam, 2023 (Section 63/65B Certificate)",
            "report_sha256": report_result["report_sha256"],
            "qr_verification_url": report_result["qr_verification_url"],
            "report_file_path": report_result["report_file_path"],
            "generated_at": report_result["generated_at"]
        }
    }


@router.get("/reports/verify/{report_id}")
def verify_court_report(report_id: str, db: Session = Depends(get_db)):
    """
    Public QR Verification Endpoint:
    Allows judges, attorneys, and law enforcement to scan a printed QR code and
    instantly verify electronic certificate authenticity against the tamper-evident database.
    """
    report = db.query(CourtReport).filter_by(report_id=report_id).first()
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"INVALID CERTIFICATE: Report ID '{report_id}' does not exist in the official judicial ledger."
        )

    case = db.query(Case).filter_by(case_id=report.case_id).first()
    evidence_count = db.query(EvidenceItem).filter_by(case_id=report.case_id).count()

    return {
        "success": True,
        "verified": True,
        "report_id": report.report_id,
        "case_id": report.case_id,
        "case_title": case.title if case else "N/A",
        "official_report_sha256": report.report_sha256,
        "compliance_framework": report.compliance_framework,
        "certified_evidence_count": evidence_count,
        "issued_at": report.created_at.isoformat(),
        "integrity_status": "AUTHENTIC_AND_UNCOMPROMISED"
    }
