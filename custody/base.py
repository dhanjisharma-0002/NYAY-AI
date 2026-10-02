"""
NYAYAI - Cryptographic Chain of Custody Interface Contract
Module Lead: Ridhi Masih (Evidence Intelligence Lead)

Adheres to:
- Rule 7: Evidence integrity must use SHA-256
- Rule 8: Every important evidence action must be auditable
- Rule 9: Every custody event must remain linked to both case_id and evidence_id
- Independent testability
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional


class BaseCustodyLedger(ABC):
    """
    Abstract interface for immutable cryptographic custody ledger.
    Every event block must strictly bind to both case_id and evidence_id.
    """

    @abstractmethod
    def create_event(
        self,
        case_id: str,
        evidence_id: str,
        sequence_number: int,
        action: str,
        actor_id: str,
        details: Dict[str, Any],
        previous_event_hash: str,
        timestamp_override: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Creates and cryptographically seals a new custody block linked to case_id and evidence_id.
        """
        pass

    @abstractmethod
    def verify_chain(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validates all blocks in the custody chain from genesis forward.
        """
        pass
