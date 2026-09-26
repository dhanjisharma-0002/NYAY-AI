"""
NYAYAI - Correlation Engine Interface Contract
Module Lead: Ridhi Mashi (Evidence Intelligence & Chain-of-Custody Engineer)
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List


class BaseCorrelationEngine(ABC):
    """
    Abstract interface for cross-evidence correlation and chronological timeline assembly.
    """

    @abstractmethod
    def correlate_case_evidence(
        self,
        case_id: str,
        evidence_items: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Builds a chronological timeline and computes cross-evidence links.
        """
        pass
