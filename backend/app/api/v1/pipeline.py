"""
NYAYAI - Analysis Pipeline API Router
Module Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

import json
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database.connection import get_db
from database.models import (
    EvidenceItem,
    CustodyEvent,
    ForensicArtifact,
    AIAnalysisResult,
    ExplainabilityRecord
)
from backend.app.core.security import get_current_user_id
from backend.app.orchestrator.pipeline import EvidencePipelineOrchestrator

router = APIRouter(tags=["Pipeline"])
orchestrator = EvidencePipelineOrchestrator()


@router.post("/evidence/{evidence_id}/analyze", status_code=status.HTTP_200_OK)
def trigger_analysis(
    evidence_id: str,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user_id)
):
    evidence = db.query(EvidenceItem).filter_by(evidence_id=evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence '{evidence_id}' not found.")

    # Retrieve last custody event to obtain previous_event_hash and sequence number
    last_event = (
        db.query(CustodyEvent)
        .filter_by(evidence_id=evidence_id)
        .order_by(CustodyEvent.sequence_number.desc())
        .first()
    )
    last_hash = last_event.event_hash if last_event else ("0" * 64)
    next_seq = (last_event.sequence_number + 1) if last_event else 1

    try:
        pipeline_output = orchestrator.run_full_analysis(
            evidence_id=evidence.evidence_id,
            vault_path=evidence.vault_path,
            expected_sha256=evidence.sha256_hash,
            declared_mime=evidence.mime_type,
            actor_id=user_id,
            last_event_hash=last_hash,
            next_seq_num=next_seq
        )
    except ValueError as val_err:
        evidence.status = "INTEGRITY_COMPROMISED"
        db.commit()
        raise HTTPException(status_code=409, detail=str(val_err))

    # Persist or update Forensic Artifacts (Anu Sharma)
    forensic = pipeline_output["forensic_report"]
    fa_record = db.query(ForensicArtifact).filter_by(evidence_id=evidence_id).first()
    if fa_record:
        fa_record.format_valid = forensic.get("format_valid", True)
        fa_record.magic_bytes = forensic.get("magic_bytes", fa_record.magic_bytes)
        fa_record.exif_data = forensic.get("exif_metadata", {})
        fa_record.timestamps_metadata = forensic.get("filesystem_metadata", {})
        fa_record.anomalies = forensic.get("anomalies", [])
    else:
        fa_record = ForensicArtifact(
            artifact_id=f"FOR-{uuid.uuid4().hex[:8].upper()}",
            evidence_id=evidence_id,
            format_valid=forensic.get("format_valid", True),
            magic_bytes=forensic.get("magic_bytes", ""),
            exif_metadata_json=json.dumps(forensic.get("exif_metadata", {})),
            detected_timestamps=json.dumps(forensic.get("filesystem_metadata", {})),
            hex_anomalies_json=json.dumps(forensic.get("anomalies", []))
        )
        db.add(fa_record)

    # Persist AI Results (Anu Sharma)
    ai_res = pipeline_output["ai_analysis"]
    ai_record = AIAnalysisResult(
        result_id=f"AIR-{uuid.uuid4().hex[:8].upper()}",
        evidence_id=evidence_id,
        model_name=ai_res.get("model_name", "TamperScreener"),
        model_version=ai_res.get("model_version", "0.1.0"),
        tamper_detected=ai_res.get("tamper_detected", False),
        confidence_score=ai_res.get("confidence_score", 0.0),
        findings_json=json.dumps(ai_res.get("findings", []))
    )
    db.add(ai_record)

    # Persist Explainability (Ridhi Mashi)
    exp_res = pipeline_output["explainability"]
    exp_record = ExplainabilityRecord(
        record_id=f"EXP-{uuid.uuid4().hex[:8].upper()}",
        evidence_id=evidence_id,
        reasoning_summary=exp_res.get("reasoning_summary", ""),
        confidence_category=exp_res.get("confidence_category", "MEDIUM"),
        feature_attributions=json.dumps(exp_res.get("contributing_factors", [])),
        limitations_disclaimer=exp_res.get("limitations_disclaimer", "")
    )
    db.add(exp_record)

    # Persist Chained Custody Event (Ridhi Mashi)
    c_evt = pipeline_output["custody_event"]
    custody_db_event = CustodyEvent(
        event_id=c_evt["event_id"],
        evidence_id=evidence_id,
        sequence_number=c_evt["sequence_number"],
        action=c_evt["action"],
        actor_id=c_evt["actor_id"],
        timestamp=c_evt["timestamp"],
        previous_event_hash=c_evt["previous_event_hash"],
        event_hash=c_evt["event_hash"],
        payload_json=json.dumps(c_evt["payload_json"])
    )
    db.add(custody_db_event)

    # Update evidence status
    evidence.status = "ANALYZED"
    db.commit()

    return {
        "success": True,
        "data": {
            "evidence_id": evidence_id,
            "status": "ANALYZED",
            "forensic_report": forensic,
            "ai_analysis": ai_res,
            "explainability": exp_res,
            "custody_event_hash": c_evt["event_hash"]
        }
    }


@router.get("/evidence/{evidence_id}/analysis")
def get_analysis_results(evidence_id: str, db: Session = Depends(get_db)):
    evidence = db.query(EvidenceItem).filter_by(evidence_id=evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence '{evidence_id}' not found.")

    fa = db.query(ForensicArtifact).filter_by(evidence_id=evidence_id).first()
    ai = db.query(AIAnalysisResult).filter_by(evidence_id=evidence_id).first()
    exp = db.query(ExplainabilityRecord).filter_by(evidence_id=evidence_id).first()

    return {
        "success": True,
        "data": {
            "evidence_id": evidence_id,
            "sha256_hash": evidence.sha256_hash,
            "forensic_report": {
                "format_valid": fa.format_valid if fa else None,
                "magic_bytes": fa.magic_bytes if fa else None,
                "anomalies": json.loads(fa.hex_anomalies_json) if (fa and fa.hex_anomalies_json) else []
            } if fa else None,
            "ai_analysis": {
                "tamper_detected": ai.tamper_detected if ai else None,
                "confidence_score": ai.confidence_score if ai else None,
                "findings": json.loads(ai.findings_json) if (ai and ai.findings_json) else []
            } if ai else None,
            "explainability": {
                "summary": exp.reasoning_summary if exp else None,
                "confidence_category": exp.confidence_category if exp else None,
                "limitations": exp.limitations_disclaimer if exp else None
            } if exp else None
        }
    }
