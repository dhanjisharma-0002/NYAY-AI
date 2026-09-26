"""
NYAYAI - Chain of Custody Schemas (Phase 8)
Module: backend.app.schemas.custody
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel


class CustodyEventResponse(BaseModel):
    """
    Standardized Chain of Custody Event representation (Phase 8).
    Guarantees all required fields:
    event_id, evidence_id, user_id, event_type, timestamp, description, previous_hash, event_hash
    """
    event_id: str
    evidence_id: str
    user_id: str
    event_type: str
    timestamp: str
    description: Optional[str] = None
    previous_hash: str
    event_hash: str

    # Backward compatibility attributes
    sequence_number: Optional[int] = None
    action: Optional[str] = None
    actor_id: Optional[str] = None
    previous_event_hash: Optional[str] = None
    payload_json: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class CustodyHistoryResponse(BaseModel):
    """
    Chronological custody history response.
    """
    success: bool = True
    evidence_id: str
    chain_intact: bool
    total_events: int
    history: List[CustodyEventResponse]
    events: List[CustodyEventResponse]
    ledger: Optional[List[Dict[str, Any]]] = None

    class Config:
        from_attributes = True


class CustodyVerifyResponse(BaseModel):
    """
    Chain verification report.
    """
    evidence_id: str
    is_valid: bool
    verified_blocks: int
    broken_at_event_id: Optional[str] = None
    diagnostic_message: str

    class Config:
        from_attributes = True


class CustodyEventCreateRequest(BaseModel):
    """
    Request payload to append a custody event (e.g. transfer, view, download).
    """
    event_type: str
    description: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
