"""
NYAYAI - Comprehensive Test Suite: Advanced AI Evidence Intelligence Engine
Module Lead: Ridhi Masih (Evidence Intelligence Lead)

Validates:
1. Error Level Analysis (ELA) for image artifacts
2. Software & Generative AI signature identification
3. Shannon byte entropy structural analysis
4. Rule 13 compliance: calibrated confidence bounds (no 1.0 or 0.0 hallucinations)
5. Rule 14 compliance: factual findings, explicit limitations, BSA 2023 legal framing
6. AIAnalysisService gateway functionality
"""

import os
import io
import sys
import tempfile
import pytest
from PIL import Image

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for d in ["forensic-engine", "ai-engine", "custody", "correlation", "explainability", "reports"]:
    p = os.path.join(ROOT_DIR, d)
    if p not in sys.path:
        sys.path.insert(0, p)

from ai_engine.tamper_detector import (
    BaselineTamperDetector,
    ErrorLevelAnalysis,
    ByteEntropyAnalyzer
)
from ai_engine.service import AIAnalysisService


def test_byte_entropy_calculation():
    """Verify Shannon entropy correctly measures information density."""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        # Uniform bytes -> entropy should be 0.0
        tmp.write(b"A" * 1000)
        tmp_path = tmp.name

    try:
        entropy = ByteEntropyAnalyzer.calculate_entropy(tmp_path)
        assert entropy == 0.0

        # Mixed bytes -> entropy should be significantly higher
        with open(tmp_path, "wb") as f:
            f.write(bytes(range(256)) * 4)
        entropy_mixed = ByteEntropyAnalyzer.calculate_entropy(tmp_path)
        assert 7.9 <= entropy_mixed <= 8.0
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_error_level_analysis_clean_image():
    """Verify ELA runs cleanly on standard RGB image."""
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
        img = Image.new("RGB", (128, 128), color=(200, 100, 50))
        img.save(tmp, format="JPEG", quality=95)
        tmp_path = tmp.name

    try:
        ela_res = ErrorLevelAnalysis.compute_ela(tmp_path)
        assert ela_res["ela_performed"] is True
        assert "mean_error" in ela_res
        assert "max_error" in ela_res
        assert ela_res["suspicious_variance"] is False
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_generative_ai_marker_detection():
    """Verify screening flags generative model signatures in metadata."""
    detector = BaselineTamperDetector()
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        tmp.write(b"\x89PNG\r\n\x1a\n" + b"Prompt: A courtroom scene; parameters: Stable Diffusion v2.1 cfg=7.5")
        tmp_path = tmp.name

    try:
        res = detector.detect_tampering("EVD-SD-TEST", tmp_path)
        assert res["tamper_detected"] is True
        assert any("Stable Diffusion" in f or "Synthetic media" in f for f in res["findings"])
        assert res["confidence_score"] >= 0.80
        assert res["confidence_score"] < 1.0  # Rule 13: Never invent 100%
        assert "Bharatiya Sakshya Adhiniyam" in res["limitations"]
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_editing_software_signature_detection():
    """Verify screening flags Photoshop / photo editor signatures."""
    detector = BaselineTamperDetector()
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
        tmp.write(b"\xff\xd8\xff\xe1" + b"Created with Adobe Photoshop 2024 for Mac" + b"\xff\xd9")
        tmp_path = tmp.name

    try:
        res = detector.detect_tampering("EVD-PS-TEST", tmp_path)
        assert res["tamper_detected"] is True
        assert any("Adobe Photoshop" in f for f in res["findings"])
        assert res["risk_score"] > 0.60
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_ai_analysis_service_facade():
    """Verify AIAnalysisService properly invokes underlying detector."""
    service = AIAnalysisService()
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
        tmp.write(b"Forensic investigation notes log entry.")
        tmp_path = tmp.name

    try:
        res = service.analyze_evidence(evidence_id="EVD-SRV-01", file_path=tmp_path)
        assert res["evidence_id"] == "EVD-SRV-01"
        assert "confidence_score" in res
        assert "findings" in res
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
