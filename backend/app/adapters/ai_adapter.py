"""
NYAYAI - AI Analysis Engine Adapter
Module: backend.app.adapters.ai_adapter
Lead: Dhananjay Sharma (Backend & System Integration Lead)
Plugs into: Anu Sharma's AI Engine (ai_engine)

Enforces:
- Rule 13: Do not invent AI accuracy or fabricate 100% confidence
- Rule 14: Do not claim forensic certainty without evidence
- Standardized structured response schema:
  evidence_id, analysis_type, prediction, confidence, risk_score, findings, explanation, model_version
"""

import os
from typing import Dict, Any, List
from backend.app.utils.logger import get_logger
from .base import BaseAIEngineAdapter, normalize_media_category
from .exceptions import (
    EngineUnavailableException,
    EngineTimeoutException,
    InvalidEngineResponseException,
    UnsupportedMediaException,
    AnalysisFailureException
)

logger = get_logger("ai_adapter")

SUPPORTED_AI_MEDIA_TYPES = ["IMAGE", "VIDEO", "AUDIO", "DOCUMENT"]


class AIEngineAdapter(BaseAIEngineAdapter):
    """
    Adapter interfacing with Anu Sharma's AI Engine.
    Handles media type validation, inference dispatch, calibrated metrics, and error translation.
    """

    def __init__(self, detector=None):
        self._detector = detector
        self._init_engine()

    def _init_engine(self):
        if self._detector is not None:
            return
        try:
            from ai_engine import BaselineTamperDetector
            self._detector = BaselineTamperDetector()
            logger.info("AIEngineAdapter successfully connected to BaselineTamperDetector.")
        except ImportError as ie:
            logger.warning(f"AI engine package not found: {ie}")
            self._detector = None
        except Exception as e:
            logger.error(f"Error initializing AI engine: {e}")
            self._detector = None

    def analyze(
        self,
        evidence_id: str,
        file_path: str,
        media_type: str,
        analysis_type: str = "TAMPER_DETECTION"
    ) -> Dict[str, Any]:
        """
        Dispatches file to BaselineTamperDetector and normalizes into structured output.
        """
        # 1. Media Type Validation
        norm_media = normalize_media_category(media_type)
        if norm_media not in SUPPORTED_AI_MEDIA_TYPES:
            raise UnsupportedMediaException(
                media_type=norm_media,
                supported_types=SUPPORTED_AI_MEDIA_TYPES
            )

        # 2. Engine Availability Check
        if self._detector is None:
            raise EngineUnavailableException(
                engine_name="AIEngine",
                message="AI inference engine is not available or failed initialization."
            )

        # 3. File existence check
        if not os.path.exists(file_path):
            raise AnalysisFailureException(
                engine_name="AIEngine",
                error_details=f"Target file does not exist at path: {file_path}"
            )

        # 4. Dispatch to Model Inference
        try:
            raw_result = self._detector.detect_tampering(evidence_id=evidence_id, file_path=file_path)
        except TimeoutError:
            raise EngineTimeoutException(engine_name="AIEngine", timeout_seconds=30.0)
        except Exception as exc:
            logger.error(f"AI engine inference failed on {evidence_id}: {exc}")
            raise AnalysisFailureException(engine_name="AIEngine", error_details=str(exc))

        # 5. Contract Validation
        if not isinstance(raw_result, dict):
            raise InvalidEngineResponseException(
                engine_name="AIEngine",
                details="Expected dictionary response from model."
            )

        tamper_detected = raw_result.get("tamper_detected", False)
        confidence = float(raw_result.get("confidence_score", 0.50))
        findings = raw_result.get("findings", [])
        model_version = raw_result.get("model_version", "0.1.0")
        model_name = raw_result.get("model_name", "TamperScreener-Baseline")
        limitations = raw_result.get("limitations", "Baseline screening indicators.")

        # Determine calibrated prediction and risk score
        if tamper_detected:
            prediction = "TAMPER_DETECTED"
            risk_score = round(confidence, 2)
            explanation = (
                f"Statistical heuristic screening flagged potential manipulation indicators "
                f"with confidence {confidence:.2f}. {limitations}"
            )
        else:
            prediction = "NO_TAMPER_INDICATIONS_DETECTED"
            risk_score = round(1.0 - confidence, 2)
            explanation = (
                f"Statistical heuristic screening found no structural manipulation markers "
                f"with confidence {confidence:.2f}. {limitations}"
            )

        return {
            "evidence_id": evidence_id,
            "analysis_type": analysis_type,
            "prediction": prediction,
            "confidence": round(confidence, 2),
            "risk_score": risk_score,
            "findings": findings,
            "explanation": explanation,
            "model_version": model_version,
            "model_name": model_name,
            "status": "COMPLETED"
        }
