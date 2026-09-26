"""
NYAYAI - Chain of Custody API Router
Module Lead: Ridhi Mashi (Evidence Intelligence & Chain-of-Custody Engineer)
"""

import json
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database.connection import get_db
from database.models import EvidenceItem, CustodyEvent
from custody import CryptographicCustodyLedger

router = APIRouter(tags=["Chain of Custody"])
custody_ledger = CryptographicCustodyLedger()


@router.get("/evidence/{evidence_id}/custody")
def get_custody_ledger(evidence_id: str, db: Session = Depends(get_db)):
    evidence = db.query(EvidenceItem).filter_by(evidence_id=evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence '{evidence_id}' not found.")

    events = (
        db.query(CustodyEvent)
        .filter_by(evidence_id=evidence_id)
        .order_by(CustodyEvent.sequence_number.asc())
        .all()
    )

    ledger = []
    events_for_verification = []
    for ev in events:
        try:
            payload = json.loads(ev.payload_json) if isinstance(ev.payload_json, str) else ev.payload_json
        except Exception:
            payload = {"raw": ev.payload_json}

        ts_str = ev.timestamp if isinstance(ev.timestamp, str) else ev.timestamp.isoformat()
        item_dict = {
            "event_id": ev.event_id,
            "evidence_id": ev.evidence_id,
            "sequence_number": ev.sequence_number,
            "action": ev.action,
            "actor_id": ev.actor_id,
            "timestamp": ts_str,
            "previous_event_hash": ev.previous_event_hash,
            "event_hash": ev.event_hash,
            "payload_json": payload
        }
        ledger.append(item_dict)
        events_for_verification.append(item_dict)

    verification = custody_ledger.verify_chain(events_for_verification)

    return {
        "success": True,
        "evidence_id": evidence_id,
        "chain_intact": verification["is_valid"],
        "total_events": len(ledger),
        "ledger": ledger
    }


@router.post("/evidence/{evidence_id}/custody/verify")
def verify_custody_chain(evidence_id: str, db: Session = Depends(get_db)):
    evidence = db.query(EvidenceItem).filter_by(evidence_id=evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Evidence '{evidence_id}' not found.")

    events = (
        db.query(CustodyEvent)
        .filter_by(evidence_id=evidence_id)
        .order_by(CustodyEvent.sequence_number.asc())
        .all()
    )

    events_for_verification = []
    for ev in events:
        try:
            payload = json.loads(ev.payload_json) if isinstance(ev.payload_json, str) else ev.payload_json
        except Exception:
            payload = {"raw": ev.payload_json}

        ts_str = ev.timestamp if isinstance(ev.timestamp, str) else ev.timestamp.isoformat()
        events_for_verification.append({
            "event_id": ev.event_id,
            "evidence_id": ev.evidence_id,
            "sequence_number": ev.sequence_number,
            "action": ev.action,
            "actor_id": ev.actor_id,
            "timestamp": ts_str,
            "previous_event_hash": ev.previous_event_hash,
            "event_hash": ev.event_hash,
            "payload_json": payload
        })

    verification_result = custody_ledger.verify_chain(events_for_verification)

    return {
        "success": True,
        "evidence_id": evidence_id,
        "is_valid": verification_result["is_valid"],
        "verified_blocks": verification_result["verified_count"],
        "broken_at_event_id": verification_result["broken_at_event_id"],
        "diagnostic_message": verification_result["reason"]
    }
