"""
NYAYAI - Evidence Correlation Engine Interface Contract
Module Lead: Ridhi Masih (Evidence Intelligence Lead)

Adheres to:
- Rule 9: Every correlation reference must preserve case_id and evidence_id
- Rule 14: Do not claim forensic certainty without evidence
- Independent testability
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List


class BaseCorrelationEngine(ABC):
    """
    Abstract interface for cross-evidence correlation, multi-evidence attribute matching,
    and chronological timeline assembly.
    """

    @abstractmethod
    def correlate_case_evidence(
        self,
        case_id: str,
        evidence_items: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Builds a chronological timeline and computes cross-evidence links for a case.
        Strictly requires case_id and preserves evidence_id references.
        """
        pass
