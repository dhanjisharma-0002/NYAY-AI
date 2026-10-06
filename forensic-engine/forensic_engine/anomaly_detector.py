"""
NYAYAI - Forensic Anomaly Detection
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Detects forensic inconsistencies from existing analysis findings.

The detector does not modify evidence files.
It only evaluates analysis results and returns anomaly messages.
"""

from typing import Any, Dict, List


class ForensicAnomalyDetector:
    """Detect suspicious or inconsistent forensic findings."""

    def detect_file_anomalies(
        self,
        integrity: Dict[str, Any],
    ) -> List[str]:
        """
        Detect anomalies from file integrity findings.
        """
        anomalies: List[str] = []

        if not integrity:
            return anomalies

        if integrity.get("matches_declared_mime") is False:
            anomalies.append(
                "Declared MIME type does not match the file signature."
            )

        if integrity.get("is_intact") is False:
            anomalies.append(
                "Evidence SHA-256 hash does not match the expected hash."
            )

        return anomalies

    def detect_image_anomalies(
        self,
        image_analysis: Dict[str, Any],
    ) -> List[str]:
        """
        Detect anomalies from image analysis findings.
        """
        anomalies: List[str] = []

        if not image_analysis:
            return anomalies

        existing_anomalies = image_analysis.get("anomalies", [])

        if existing_anomalies:
            anomalies.extend(existing_anomalies)

        if image_analysis.get("format") is None:
            anomalies.append(
                "Unable to determine the image format."
            )

        if image_analysis.get("width") is not None:
            if image_analysis["width"] <= 0:
                anomalies.append(
                    "Image width is invalid."
                )

        if image_analysis.get("height") is not None:
            if image_analysis["height"] <= 0:
                anomalies.append(
                    "Image height is invalid."
                )

        return anomalies

    def detect(
        self,
        integrity: Dict[str, Any] | None = None,
        image_analysis: Dict[str, Any] | None = None,
    ) -> List[str]:
        """
        Consolidate anomalies from available forensic findings.
        """
        anomalies: List[str] = []

        anomalies.extend(
            self.detect_file_anomalies(integrity or {})
        )

        anomalies.extend(
            self.detect_image_anomalies(image_analysis or {})
        )

        return list(dict.fromkeys(anomalies))
