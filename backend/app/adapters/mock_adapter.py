"""
NYAYAI - Controlled Mock Engine Adapters (For Testing Purposes ONLY)
Module: backend.app.adapters.mock_adapter
Lead: Dhananjay Sharma (Backend & System Integration Lead)

CRITICAL NOTICE:
- Used ONLY for unit & integration testing of error paths and lifecycle orchestration.
- NEVER present mock output as real AI output.
- All mock outputs explicitly declare testing provenance in model_name.
"""

from typing import Dict, Any, List
from .base import BaseForensicEngineAdapter, BaseAIEngineAdapter
from .exceptions import (
    EngineUnavailableException,
    EngineTimeoutException,
    InvalidEngineResponseException,
    UnsupportedMediaException,
    AnalysisFailureException
)


class MockForensicEngineAdapter(BaseForensicEngineAdapter):
    """
    Controlled mock adapter for testing forensic orchestration and failure handling.
    """

    def __init__(self, mode: str = "success", custom_data: Dict[str, Any] = None):
        self.mode = mode  # success, engine_unavailable, timeout, invalid_response, unsupported_media, failure
        self.custom_data = custom_data or {}

    def analyze(
        self,
        evidence_id: str,
        file_path: str,
        media_type: str,
        declared_mime: str
    ) -> Dict[str, Any]:
        if self.mode == "engine_unavailable":
            raise EngineUnavailableException(
                engine_name="MockForensicEngine",
                message="Simulated connection refusal: Forensic worker pool exhausted."
            )
        elif self.mode == "timeout":
            raise EngineTimeoutException(
                engine_name="MockForensicEngine",
                timeout_seconds=5.0
            )
        elif self.mode == "invalid_response":
            raise InvalidEngineResponseException(
                engine_name="MockForensicEngine",
                details="Received corrupt non-JSON binary frame from worker."
            )
        elif self.mode == "unsupported_media":
            raise UnsupportedMediaException(
                media_type=media_type,
                supported_types=["IMAGE", "DOCUMENT"]
            )
        elif self.mode == "failure":
            raise AnalysisFailureException(
                engine_name="MockForensicEngine",
                error_details="Simulated native C-library segmentation fault during byte parsing."
            )

        # Default: success
        return {
            "evidence_id": evidence_id,
            "analysis_type": "FORENSIC_INSPECTION",
            "format_valid": True,
            "magic_bytes": "89504e47",
            "detected_mime": declared_mime,
            "anomalies": [],
            "metadata": {"filesystem": {"mock": True}, "exif": {}},
            "prediction": "STRUCTURALLY_CONSISTENT",
            "confidence": 0.95,
            "risk_score": 0.05,
            "findings": ["Controlled mock: Validated header signature."],
            "explanation": "Test verification run: structural consistency confirmed.",
            "model_name": "MockForensicEngine-TestingOnly",
            "model_version": "0.0.1-test",
            "status": "COMPLETED",
            **self.custom_data
        }


class MockAIEngineAdapter(BaseAIEngineAdapter):
    """
    Controlled mock adapter for testing AI orchestration and failure handling.
    """

    def __init__(self, mode: str = "success", custom_data: Dict[str, Any] = None):
        self.mode = mode
        self.custom_data = custom_data or {}

    def analyze(
        self,
        evidence_id: str,
        file_path: str,
        media_type: str,
        analysis_type: str = "TAMPER_DETECTION"
    ) -> Dict[str, Any]:
        if self.mode == "engine_unavailable":
            raise EngineUnavailableException(
                engine_name="MockAIEngine",
                message="Simulated GPU worker pod disconnected."
            )
        elif self.mode == "timeout":
            raise EngineTimeoutException(
                engine_name="MockAIEngine",
                timeout_seconds=10.0
            )
        elif self.mode == "invalid_response":
            raise InvalidEngineResponseException(
                engine_name="MockAIEngine",
                details="Model output logits contained NaN values."
            )
        elif self.mode == "unsupported_media":
            raise UnsupportedMediaException(
                media_type=media_type,
                supported_types=["IMAGE", "VIDEO"]
            )
        elif self.mode == "failure":
            raise AnalysisFailureException(
                engine_name="MockAIEngine",
                error_details="CUDA out of memory error during tensor allocation."
            )

        # Default: success
        return {
            "evidence_id": evidence_id,
            "analysis_type": analysis_type,
            "prediction": self.custom_data.get("prediction", "NO_TAMPER_INDICATIONS_DETECTED"),
            "confidence": self.custom_data.get("confidence", 0.65),
            "risk_score": self.custom_data.get("risk_score", 0.35),
            "findings": self.custom_data.get("findings", ["Controlled mock test finding: baseline heuristics satisfied."]),
            "explanation": self.custom_data.get("explanation", "Test verification run: screening indicates authentic pattern."),
            "model_version": "0.1.0-test",
            "model_name": "MockAIEngine-TestingOnly",
            "status": "COMPLETED",
            **self.custom_data
        }
