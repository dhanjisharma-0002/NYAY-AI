"""
NYAYAI - Local Module Unit Tests: AI Tamper Detector
Module Lead: Ridhi Masih (Evidence Intelligence Lead)
"""

import os
import tempfile
import pytest
from ai_engine.base import BaseAIAnalyzer
from ai_engine.tamper_detector import BaselineTamperDetector


def test_tamper_detector_inheritance():
    """Verify BaselineTamperDetector implements BaseAIAnalyzer interface."""
    detector = BaselineTamperDetector()
    assert isinstance(detector, BaseAIAnalyzer)


def test_tamper_detector_mandatory_ids():
    """Test that missing case_id or evidence_id raises ValueError."""
    detector = BaselineTamperDetector()

    with pytest.raises(ValueError, match="case_id is required"):
        detector.analyze(case_id="", evidence_id="EVID-001", metadata={})

    with pytest.raises(ValueError, match="case_id is required"):
        detector.analyze(case_id=None, evidence_id="EVID-001", metadata={})

    with pytest.raises(ValueError, match="evidence_id is required"):
        detector.analyze(case_id="CASE-001", evidence_id="", metadata={})

    with pytest.raises(ValueError, match="evidence_id is required"):
        detector.analyze(case_id="CASE-001", evidence_id=None, metadata={})


def test_tamper_detector_invalid_metadata():
    """Test that invalid metadata raises ValueError."""
    detector = BaselineTamperDetector()
    with pytest.raises(ValueError, match="metadata must be a dictionary"):
        detector.analyze(case_id="CASE-001", evidence_id="EVID-001", metadata=None)


def test_tamper_detector_conceptual_output_schema():
    """Verify full conceptual output schema matching judicial requirements."""
    detector = BaselineTamperDetector()
    result = detector.analyze(
        case_id="CASE-2026-UNIT",
        evidence_id="EVID-UNIT-01",
        metadata={"file_size": 2048, "mime_type": "image/jpeg"}
    )

    required_keys = [
        "analysis_id", "case_id", "evidence_id", "analysis_type",
        "analyzer_version", "analysis_timestamp", "risk_score",
        "assessment", "indicators", "forensic_conclusion", "limitations", "audit"
    ]
    for key in required_keys:
        assert key in result, f"Missing key: {key}"

    assert result["case_id"] == "CASE-2026-UNIT"
    assert result["evidence_id"] == "EVID-UNIT-01"
    assert result["analysis_type"] == "tamper_synthesis_screening"
    assert isinstance(result["risk_score"], float)
    assert 0.0 <= result["risk_score"] <= 1.0
    assert result["assessment"] in ["low_risk", "medium_risk", "high_risk"]
    assert isinstance(result["indicators"], list)
    assert isinstance(result["limitations"], list)
    assert result["audit"]["action"] == "AI_TAMPER_SCREENING"


def test_tamper_detector_hash_mismatch_integrity_indicator():
    """Verify hash mismatch is treated as an integrity indicator, NOT proof of tampering."""
    detector = BaselineTamperDetector()
    result = detector.analyze(
        case_id="CASE-HASH",
        evidence_id="EVID-HASH",
        metadata={"hash_mismatch": True}
    )

    assert result["risk_score"] > 0.0
    text = " ".join(result["indicators"]).lower()
    assert "hash mismatch" in text
    conclusion = result["forensic_conclusion"].lower()
    assert "definitely forged" not in conclusion


def test_tamper_detector_zero_mutation():
    """Verify target evidence file is strictly read-only and never mutated."""
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write(b"Strictly immutable evidence payload.")
        tmp_name = f.name

    try:
        with open(tmp_name, "rb") as f:
            original = f.read()

        detector = BaselineTamperDetector()
        detector.analyze(
            case_id="CASE-IMMUTABLE",
            evidence_id="EVID-IMMUTABLE",
            metadata={"file_path": tmp_name}
        )

        with open(tmp_name, "rb") as f:
            after = f.read()

        assert original == after
    finally:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)
