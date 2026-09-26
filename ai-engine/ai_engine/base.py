"""
NYAYAI - AI Analysis Engine Interface Contract
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Adheres to:
- Rule 9: AI results must remain linked to evidence_id
- Rule 13: Do not invent AI accuracy
- Rule 14: Do not claim forensic certainty without evidence
"""

from abc import ABC, abstractmethod
from typing import Dict, Any


class BaseAIAnalyzer(ABC):
    """
    Abstract interface for AI analysis models (tamper detection, deepfakes, transcripts).
    """

    @abstractmethod
    def detect_tampering(self, evidence_id: str, file_path: str) -> Dict[str, Any]:
        """
        Screen the target file for digital tampering or synthesis.
        Must return structured output containing:
        - evidence_id: str
        - model_name: str
        - model_version: str
        - tamper_detected: bool
        - confidence_score: float (0.0 to 1.0)
        - findings: List[str]
        - limitations: str
        """
        pass
