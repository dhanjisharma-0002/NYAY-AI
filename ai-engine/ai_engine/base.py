"""
NYAYAI - AI Analysis Engine Interface Contract
Module Lead: Ridhi Masih (Evidence Intelligence Lead)

Adheres to:
- Rule 9: AI results must remain linked to both case_id and evidence_id
- Rule 13: Do not invent AI accuracy (no fake or calibrated confidence values)
- Rule 14: Do not claim forensic certainty without evidence
- Independent testability
"""

from abc import ABC, abstractmethod
from typing import Dict, Any


class BaseAIAnalyzer(ABC):
    """
    Abstract interface for AI analysis models (tamper screening, synthesis detection).
    Every analyzer implementation must strictly accept both case_id and evidence_id.
    """

    @abstractmethod
    def analyze(
        self,
        case_id: str,
        evidence_id: str,
        metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Screen evidence for potential tampering or synthesis using forensic metadata.
        
        Args:
            case_id: Mandatory unique case identifier
            evidence_id: Mandatory unique evidence identifier
            metadata: Metadata dictionary supplied by forensic/integrity layers
            
        Returns:
            Auditable analysis record containing risk score, indicators, and limitations.
        """
        pass
