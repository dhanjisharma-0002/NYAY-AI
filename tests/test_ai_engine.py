import os
import tempfile
import pytest
from ai_engine.tamper_detector import BaselineTamperDetector
from ai_engine.base import BaseAIAnalyzer

def test_tamper_detector_inheritance():
    """Verify BaselineTamperDetector inherits from BaseAIAnalyzer."""
    detector = BaselineTamperDetector()
    assert isinstance(detector, BaseAIAnalyzer)

def test_tamper_detector_contract_validation():
    """Verify that case_id and evidence_id are strictly required."""
    detector = BaselineTamperDetector()

    with pytest.raises(ValueError, match="case_id is required"):
        detector.analyze("", "EVID-001", {})

    with pytest.raises(ValueError, match="evidence_id is required"):
        detector.analyze("CASE-001", "", {})

    with pytest.raises(ValueError, match="case_id is required"):
        detector.analyze(None, "EVID-001", {})

def test_tamper_detector_output_schema():
    """Verify conceptual output schema matching judicial requirements."""
    detector = BaselineTamperDetector()
    
    metadata = {
        "integrity": {
            "hash_mismatch": False,
            "calculated_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "recorded_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        },
        "file_type": "image/jpeg",
        "file_size": 1024
    }
    
    result = detector.analyze(
        case_id="CASE-2026-DEL-001",
        evidence_id="EVID-IMG-001",
        metadata=metadata
    )
    
    # Required top-level keys
    required_keys = [
        "analysis_id",
        "case_id",
        "evidence_id",
        "analysis_type",
        "analyzer_version",
        "analysis_timestamp",
        "risk_score",
        "assessment",
        "indicators",
        "forensic_conclusion",
        "limitations",
        "audit"
    ]
    for key in required_keys:
        assert key in result, f"Missing required key: {key}"
        
    assert result["case_id"] == "CASE-2026-DEL-001"
    assert result["evidence_id"] == "EVID-IMG-001"
    assert result["analysis_type"] == "tamper_synthesis_screening"
    assert isinstance(result["risk_score"], float)
    assert 0.0 <= result["risk_score"] <= 1.0
    assert result["assessment"] in ["low_risk", "medium_risk", "high_risk"]
    assert isinstance(result["indicators"], list)
    assert isinstance(result["limitations"], list)
    assert len(result["limitations"]) > 0
    
    # Audit record validation
    audit = result["audit"]
    assert audit["action"] == "AI_TAMPER_SCREENING"
    assert audit["case_id"] == "CASE-2026-DEL-001"
    assert audit["evidence_id"] == "EVID-IMG-001"
    assert "timestamp" in audit

def test_tamper_detector_hash_mismatch_as_indicator():
    """Verify hash mismatch is treated as an integrity indicator, NOT proof of tampering."""
    detector = BaselineTamperDetector()
    
    metadata = {
        "integrity": {
            "hash_mismatch": True,
            "calculated_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
            "recorded_sha256": "2222222222222222222222222222222222222222222222222222222222222222"
        }
    }
    
    result = detector.analyze(
        case_id="CASE-2026-002",
        evidence_id="EVID-DOC-002",
        metadata=metadata
    )
    
    assert result["risk_score"] > 0.0
    indicators_text = " ".join(result["indicators"]).lower()
    assert "hash mismatch" in indicators_text
    
    # Crucial: Must state that hash mismatch alone is an integrity anomaly, not conclusive proof
    concl = result["forensic_conclusion"].lower()
    assert "indicat" in concl or "risk" in concl or "screen" in concl
    assert "definitely forged" not in concl

def test_tamper_detector_zero_evidence_mutation():
    """Verify that analysis never alters the target evidence file."""
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write(b"Original inviolable forensic evidence payload.")
        test_path = f.name
        
    try:
        with open(test_path, "rb") as f:
            original_bytes = f.read()
            
        detector = BaselineTamperDetector()
        result = detector.analyze(
            case_id="CASE-MUTATION-TEST",
            evidence_id="EVID-FILE-001",
            metadata={"file_path": test_path}
        )
        
        with open(test_path, "rb") as f:
            post_analysis_bytes = f.read()
            
        assert original_bytes == post_analysis_bytes, "Evidence file was modified during analysis!"
    finally:
        if os.path.exists(test_path):
            os.remove(test_path)

def test_tamper_detector_backward_compatibility():
    """Verify legacy detect_tampering() method still functions."""
    detector = BaselineTamperDetector()
    metadata = {
        "file_size": 2048,
        "mime_type": "image/png"
    }
    res = detector.detect_tampering(metadata)
    assert "tamper_detected" in res or "risk_score" in res
    assert "confidence" in res or "risk_score" in res
