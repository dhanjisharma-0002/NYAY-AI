"""Tests for the forensic anomaly detection module."""

from forensic_engine.anomaly_detector import ForensicAnomalyDetector


def test_clean_integrity_has_no_anomalies():
    """Verify clean integrity findings produce no anomalies."""
    detector = ForensicAnomalyDetector()

    anomalies = detector.detect_file_anomalies(
        {
            "matches_declared_mime": True,
            "is_intact": True,
        }
    )

    assert anomalies == []


def test_mime_mismatch_is_detected():
    """Verify MIME signature mismatch is detected."""
    detector = ForensicAnomalyDetector()

    anomalies = detector.detect_file_anomalies(
        {
            "matches_declared_mime": False,
            "is_intact": True,
        }
    )

    assert anomalies == [
        "Declared MIME type does not match the file signature."
    ]


def test_hash_mismatch_is_detected():
    """Verify SHA-256 mismatch is detected."""
    detector = ForensicAnomalyDetector()

    anomalies = detector.detect_file_anomalies(
        {
            "matches_declared_mime": True,
            "is_intact": False,
        }
    )

    assert anomalies == [
        "Evidence SHA-256 hash does not match the expected hash."
    ]


def test_invalid_image_format_is_detected():
    """Verify an unavailable image format is reported."""
    detector = ForensicAnomalyDetector()

    anomalies = detector.detect_image_anomalies(
        {
            "format": None,
            "width": None,
            "height": None,
            "anomalies": [],
        }
    )

    assert anomalies == [
        "Unable to determine the image format."
    ]


def test_invalid_image_dimensions_are_detected():
    """Verify invalid image dimensions are reported."""
    detector = ForensicAnomalyDetector()

    anomalies = detector.detect_image_anomalies(
        {
            "format": "PNG",
            "width": 0,
            "height": -10,
            "anomalies": [],
        }
    )

    assert "Image width is invalid." in anomalies
    assert "Image height is invalid." in anomalies


def test_combined_anomalies_are_deduplicated():
    """Verify combined findings produce unique anomaly messages."""
    detector = ForensicAnomalyDetector()

    anomalies = detector.detect(
        integrity={
            "matches_declared_mime": False,
            "is_intact": False,
        },
        image_analysis={
            "format": None,
            "width": 100,
            "height": 100,
            "anomalies": [
                "Existing image anomaly."
            ],
        },
    )

    assert len(anomalies) == 4
    assert "Declared MIME type does not match the file signature." in anomalies
    assert "Evidence SHA-256 hash does not match the expected hash." in anomalies
    assert "Unable to determine the image format." in anomalies
    assert "Existing image anomaly." in anomalies
