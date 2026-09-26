"""
NYAYAI - Explainability Engine Interface Contract
Module Lead: Ridhi Mashi (Evidence Intelligence & Chain-of-Custody Engineer)

Adheres to:
- Rule 13: Do not invent AI accuracy
- Rule 14: Do not claim forensic certainty without evidence
"""

from abc import ABC, abstractmethod
from typing import Dict, Any


class BaseExplainer(ABC):
    """
    Abstract interface for generating judicial explanations from forensic and AI outputs.
    """

    @abstractmethod
    def explain(
        self,
        evidence_id: str,
        forensic_data: Dict[str, Any],
        ai_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Translates raw findings into court-admissible explanation.
        """
        pass
