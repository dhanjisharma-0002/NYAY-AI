"""
NYAYAI - Forensic Engine Adapter
Module: backend.app.adapters.forensic_adapter
Lead: Dhananjay Sharma (Backend & System Integration Lead)
Plugs into: Anu Sharma's Forensic Engine (forensic_engine)
"""

import os
from typing import Dict, Any, List
from backend.app.utils.logger import get_logger
from .base import BaseForensicEngineAdapter, normalize_media_category
from .exceptions import (
    EngineUnavailableException,
    EngineTimeoutException,
    InvalidEngineResponseException,
    UnsupportedMediaException,
    AnalysisFailureException
)

logger = get_logger("forensic_adapter")

SUPPORTED_FORENSIC_MEDIA_TYPES = ["IMAGE", "VIDEO", "AUDIO", "DOCUMENT"]


class ForensicEngineAdapter(BaseForensicEngineAdapter):
    """
    Adapter interfacing with Anu Sharma's Forensic Engine.
    Handles media type validation, engine dispatch, and error translation.
    """

    def __init__(self, extractor=None):
        self._extractor = extractor
        self._init_engine()

    def _init_engine(self):
        if self._extractor is not None:
            return
        try:
            from forensic_engine import ForensicMetadataExtractor
            self._extractor = ForensicMetadataExtractor()
            logger.info("ForensicEngineAdapter successfully connected to ForensicMetadataExtractor.")
        except ImportError as ie:
            logger.warning(f"Forensic engine package not found: {ie}")
            self._extractor = None
        except Exception as e:
            logger.error(f"Error initializing forensic engine: {e}")
            self._extractor = None

    def analyze(
        self,
        evidence_id: str,
        file_path: str,
        media_type: str,
        declared_mime: str
    ) -> Dict[str, Any]:
        """
        Dispatches file to ForensicMetadataExtractor and returns structured result.
        """
        # 1. Media Type Validation
        norm_media = normalize_media_category(media_type)
        if norm_media not in SUPPORTED_FORENSIC_MEDIA_TYPES:
            raise UnsupportedMediaException(
                media_type=norm_media,
                supported_types=SUPPORTED_FORENSIC_MEDIA_TYPES
            )

        # 2. Engine Availability Check
        if self._extractor is None:
            raise EngineUnavailableException(
                engine_name="ForensicEngine",
                message="Forensic analyzer module is not available or failed initialization."
            )

        # 3. File existence check
        if not os.path.exists(file_path):
            raise AnalysisFailureException(
                engine_name="ForensicEngine",
                error_details=f"Target file does not exist at path: {file_path}"
            )

        # 4. Dispatch to Engine
        try:
            raw_result = self._extractor.analyze(file_path=file_path, declared_mime=declared_mime)
        except TimeoutError:
            raise EngineTimeoutException(engine_name="ForensicEngine", timeout_seconds=30.0)
        except Exception as exc:
            logger.error(f"Forensic engine execution failed on {evidence_id}: {exc}")
            raise AnalysisFailureException(engine_name="ForensicEngine", error_details=str(exc))

        # 5. Contract Validation
        if not isinstance(raw_result, dict):
            raise InvalidEngineResponseException(
                engine_name="ForensicEngine",
                details="Expected dictionary response from analyzer."
            )

        anomalies = raw_result.get("anomalies", [])
        format_valid = raw_result.get("format_valid", True)
        magic_bytes = raw_result.get("magic_bytes", "")
        detected_mime = raw_result.get("detected_mime", declared_mime)
        fs_meta = raw_result.get("filesystem_metadata", {})
        exif_meta = raw_result.get("exif_metadata", {})

        # Compute objective risk score based on detected anomalies (without claiming false certainty)
        anomaly_count = len(anomalies)
        if not format_valid:
            risk_score = 0.90
            prediction = "FORMAT_ANOMALY_DETECTED"
            explanation = "File header signature does not match declared MIME type. Potential spoofing detected."
        elif anomaly_count > 0:
            risk_score = min(0.50 + (anomaly_count * 0.15), 0.85)
            prediction = "METADATA_ANOMALIES_OBSERVED"
            explanation = f"Detected {anomaly_count} low-level anomaly indicator(s) in structural metadata."
        else:
            risk_score = 0.10
            prediction = "STRUCTURALLY_CONSISTENT"
            explanation = "File header, signature bytes, and structural metadata are consistent with declared format."

        return {
            "evidence_id": evidence_id,
            "analysis_type": "FORENSIC_INSPECTION",
            "format_valid": format_valid,
            "magic_bytes": magic_bytes,
            "detected_mime": detected_mime,
            "anomalies": anomalies,
            "metadata": {
                "filesystem": fs_meta,
                "exif": exif_meta
            },
            "prediction": prediction,
            "confidence": 0.95, # High determinism for static byte inspection
            "risk_score": round(risk_score, 2),
            "findings": anomalies if anomalies else ["Binary header and metadata validated against format specification."],
            "explanation": explanation,
            "model_name": "ForensicMetadataExtractor",
            "model_version": "0.1.0",
            "status": "COMPLETED"
        }
