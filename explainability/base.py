"""
NYAYAI - Court Admissibility Explainability Interface Contract
Module Lead: Ridhi Masih (Evidence Intelligence Lead)

Adheres to:
- Rule 9: Every explanation must preserve both case_id and evidence_id
- Rule 13: Do not invent AI accuracy
- Rule 14: Do not claim forensic certainty without evidence
- Independent testability
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class BaseExplainer(ABC):
    """
    Abstract interface for generating judicial explanations from forensic metadata and AI screening results.
    Preserves both case_id and evidence_id.
    """

    @abstractmethod
    def explain(
        self,
        case_id: str,
        evidence_id: str,
        ai_data: Dict[str, Any],
        forensic_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Translates raw AI screening and forensic findings into court-admissible explanation.
        Must strictly preserve case_id and evidence_id.
        """
        pass
