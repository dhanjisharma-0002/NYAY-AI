"""
NYAYAI - Chain of Custody Interface Contract
Module Lead: Ridhi Mashi (Evidence Intelligence & Chain-of-Custody Engineer)

Adheres to:
- Rule 7: Evidence integrity must use SHA-256
- Rule 8: Every important evidence action must be auditable
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List


class BaseCustodyLedger(ABC):
    """
    Abstract interface for immutable cryptographic custody ledger.
    """

    @abstractmethod
    def create_event(
        self,
        evidence_id: str,
        sequence_number: int,
        action: str,
        actor_id: str,
        details: Dict[str, Any],
        previous_event_hash: str
    ) -> Dict[str, Any]:
        """Creates and cryptographically seals a new custody block."""
        pass

    @abstractmethod
    def verify_chain(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validates all blocks in the custody chain from genesis forward."""
        pass
