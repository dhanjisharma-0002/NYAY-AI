"""
NYAYAI - AI Analysis Engine Service Gateway
Module Lead: Ridhi Masih (Evidence Intelligence Lead)

Coordinates AI inference modules, tamper screening, and multimodal inspection.
"""

from typing import Any, Dict, Optional
from .tamper_detector import BaselineTamperDetector


class AIAnalysisService:
    """
    High-level facade for AI Evidence Intelligence operations.
    Directly managed by Ridhi Masih.
    """

    def __init__(self, detector: Optional[BaselineTamperDetector] = None):
        self.tamper_detector = detector or BaselineTamperDetector()

    def analyze_evidence(
        self,
        evidence_id: str,
        file_path: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes end-to-end AI screening on an evidence file.
        Returns standardized, calibrated evidence intelligence dictionary.
        """
        return self.tamper_detector.detect_tampering(
            evidence_id=evidence_id,
            file_path=file_path
        )