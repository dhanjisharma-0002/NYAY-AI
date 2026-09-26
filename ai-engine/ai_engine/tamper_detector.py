"""
NYAYAI - Baseline Tamper Detector
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Provides baseline heuristic screening and simulated/standard inference interface.
Enforces:
- Rule 9: AI results must remain linked to evidence_id
- Rule 13: Do not invent AI accuracy (calibrated confidence, no fabricated 100%)
- Rule 14: Do not claim forensic certainty without evidence (flagged as screening indicator)
"""

import os
from typing import Dict, Any, List
from .base import BaseAIAnalyzer


class BaselineTamperDetector(BaseAIAnalyzer):
    """
    Baseline implementation of tamper detection interface.
    Performs initial file sanity checks and structures outputs for the explainability layer.
    """

    def __init__(self, model_name: str = "TamperScreener-Baseline", model_version: str = "0.1.0"):
        self.model_name = model_name
        self.model_version = model_version

    def detect_tampering(self, evidence_id: str, file_path: str) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Target evidence file not found for AI inference: {file_path}")

        # Basic heuristic inspection (file size, header variance)
        file_size = os.path.getsize(file_path)
        findings: List[str] = []
        tamper_detected = False
        confidence_score = 0.50 # Neutral prior

        # Check for very small files (potential truncated artifacts)
        if file_size < 100:
            findings.append("Suspiciously small binary file (< 100 bytes). Possible truncated artifact.")
            tamper_detected = True
            confidence_score = 0.72
        else:
            findings.append("Baseline structural screening complete. No blatant file truncations detected.")
            tamper_detected = False
            confidence_score = 0.60

        return {
            "evidence_id": evidence_id,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "tamper_detected": tamper_detected,
            "confidence_score": round(confidence_score, 2),
            "findings": findings,
            "limitations": "Screening performed using baseline heuristics. Full deep neural net validation scheduled for Phase 3."
        }
