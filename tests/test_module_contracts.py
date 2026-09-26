"""
NYAYAI - Test Suite: Module Contracts & Interface Compliance
Tests adherence to Rule 9, Rule 13, Rule 14, and Rule 15 (Independent Testability)
"""

import pytest
import sys
import os
import tempfile

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for d in ["forensic-engine", "ai-engine", "custody", "correlation", "explainability", "reports"]:
    p = os.path.join(ROOT_DIR, d)
    if p not in sys.path:
        sys.path.insert(0, p)

from ai_engine.base import BaseAIAnalyzer
from ai_engine.tamper_detector import BaselineTamperDetector
from explainability.base import BaseExplainer
from explainability.explainer import BaselineCourtExplainer
from correlation.base import BaseCorrelationEngine
from correlation.engine import BaselineCorrelationEngine
from reports.base import BaseReportGenerator
from reports.generator import CourtAdmissibilityReportGenerator


def test_ai_engine_contract_compliance():
    """Rule 9 & Rule 13: Validate AI Engine outputs."""
    detector = BaselineTamperDetector()
    assert isinstance(detector, BaseAIAnalyzer)

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"SAMPLE EVIDENCE DATA FOR AI TAMPER SCREENING")
        tmp_path = tmp.name

    try:
        evidence_id = "EVD-2026-TESTAI"
        result = detector.detect_tampering(evidence_id, tmp_path)

        # Rule 9: Must be linked to evidence_id
        assert result["evidence_id"] == evidence_id
        assert "tamper_detected" in result
        assert "confidence_score" in result

        # Rule 13: Calibrated confidence between 0.0 and 1.0
        conf = result["confidence_score"]
        assert 0.0 <= conf <= 1.0
        assert "limitations" in result
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_explainability_contract_compliance():
    """Rule 14: Ensure Explainability provides court-admissible plain rationale and caveats."""
    explainer = BaselineCourtExplainer()
    assert isinstance(explainer, BaseExplainer)

    forensic_data = {
        "format_valid": True,
        "anomalies": ["Magic bytes valid, but timestamp mismatch observed."]
    }
    ai_data = {
        "tamper_detected": True,
        "confidence_score": 0.85,
        "findings": ["High pixel inconsistency in header metadata"]
    }

    evidence_id = "EVD-2026-EXP"
    explanation = explainer.explain(evidence_id, forensic_data, ai_data)

    assert explanation["evidence_id"] == evidence_id
    assert explanation["confidence_category"] == "HIGH"
    assert "reasoning_summary" in explanation
    assert len(explanation["contributing_factors"]) > 0
    # Rule 14: Limitations must be clearly stated
    assert "limitations_disclaimer" in explanation
    assert "Bharatiya Sakshya Adhiniyam" in explanation["limitations_disclaimer"]


def test_correlation_engine_contract_compliance():
    """Verify Correlation Engine builds chronological timeline and links identical evidence."""
    engine = BaselineCorrelationEngine()
    assert isinstance(engine, BaseCorrelationEngine)

    evidence_items = [
        {
            "evidence_id": "EVD-001",
            "filename": "camera_a.png",
            "mime_type": "image/png",
            "sha256_hash": "hash_identical",
            "created_at": "2026-09-26T12:00:00Z"
        },
        {
            "evidence_id": "EVD-002",
            "filename": "camera_b.png",
            "mime_type": "image/png",
            "sha256_hash": "hash_identical",
            "created_at": "2026-09-26T12:05:00Z"
        }
    ]

    res = engine.correlate_case_evidence("CASE-TEST", evidence_items)
    assert res["total_items"] == 2
    assert len(res["timeline"]) == 2
    assert res["timeline"][0]["evidence_id"] == "EVD-001"

    # Must detect identical file hash link
    links = res["links"]
    assert any(l["relationship_type"] == "IDENTICAL_FILE_HASH" for l in links)


def test_reports_engine_contract_compliance():
    """Verify Court Report Generator produces SHA-256 certificate and verification URL."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        generator = CourtAdmissibilityReportGenerator(output_dir=tmp_dir)
        assert isinstance(generator, BaseReportGenerator)

        case_data = {"case_id": "CASE-2026-01", "title": "Cyber Extortion Trial"}
        evidence_items = [
            {"evidence_id": "EVD-01", "original_filename": "screen.png", "sha256_hash": "abc"}
        ]
        custody_data = {"EVD-01": ["EVT-1", "EVT-2"]}
        officer = {"name": "Dhananjay Sharma", "badge_number": "INV-DL-9841", "role": "Lead"}

        report = generator.generate_report(case_data, evidence_items, custody_data, officer)

        assert "report_id" in report
        assert "report_sha256" in report
        assert len(report["report_sha256"]) == 64
        assert "qr_verification_url" in report
        assert os.path.exists(report["report_file_path"])
