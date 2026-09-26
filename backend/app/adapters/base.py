"""
NYAYAI - Base Engine Adapter Interfaces
Module: backend.app.adapters.base
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Enforces:
- Backend remains model-agnostic and acts strictly as an orchestration layer
- Clean adapter interface for Anu Sharma's forensic and AI engines
- No forensic algorithms or model weights inside the backend
"""

from abc import ABC, abstractmethod
from typing import Dict, Any


def normalize_media_category(media_type: str) -> str:
    """
    Normalizes MIME types (e.g. 'image/png', 'application/pdf') or extensions
    into canonical uppercase media categories: 'IMAGE', 'VIDEO', 'AUDIO', 'DOCUMENT'.
    """
    m = (media_type or "").upper().strip()
    if m.startswith("IMAGE") or m in ["JPG", "JPEG", "PNG", "WEBP"]:
        return "IMAGE"
    if m.startswith("VIDEO") or m in ["MP4", "MOV", "AVI"]:
        return "VIDEO"
    if m.startswith("AUDIO") or m in ["MP3", "WAV", "M4A"]:
        return "AUDIO"
    if (
        m.startswith("APPLICATION/PDF")
        or m.startswith("TEXT")
        or m.startswith("DOCUMENT")
        or "WORD" in m
        or m in ["PDF", "DOCX", "TXT"]
    ):
        return "DOCUMENT"
    return m


class BaseForensicEngineAdapter(ABC):
    """
    Abstract adapter for forensic engines.
    Isolates low-level byte and metadata extraction from backend orchestration.
    """

    @abstractmethod
    def analyze(
        self,
        evidence_id: str,
        file_path: str,
        media_type: str,
        declared_mime: str
    ) -> Dict[str, Any]:
        """
        Sends evidence reference to forensic engine and returns structured inspection output:
        - format_valid: bool
        - magic_bytes: str
        - detected_mime: str
        - anomalies: List[str]
        - metadata: Dict[str, Any]
        - risk_score: float
        """
        pass


class BaseAIEngineAdapter(ABC):
    """
    Abstract adapter for AI analysis engines.
    Enforces standardized inference output without hardcoding model weights.
    """

    @abstractmethod
    def analyze(
        self,
        evidence_id: str,
        file_path: str,
        media_type: str,
        analysis_type: str = "TAMPER_DETECTION"
    ) -> Dict[str, Any]:
        """
        Sends evidence reference to AI engine and returns structured inference output:
        - evidence_id: str
        - analysis_type: str
        - prediction: str
        - confidence: float
        - risk_score: float
        - findings: List[str]
        - explanation: str
        - model_version: str
        """
        pass
