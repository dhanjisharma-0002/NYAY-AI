"""
NYAYAI - Comprehensive Test Suite: Advanced Court Admissibility Explainer
Module Lead: Ridhi Masih (Evidence Intelligence Lead)

Validates:
1. Explainability output with Error Level Analysis (ELA) inputs
2. Plain-language judicial narratives for Generative AI markers
3. Confidence & legal weight tiering (HIGH, MEDIUM, LOW, INCONCLUSIVE)
4. BSA 2023 Section 63/65B statutory compliance & limitations disclaimer
5. Actionable judicial recommendations for magistrates & trial judges
"""

import os
import sys
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for d in ["forensic-engine", "ai-engine", "custody", "correlation", "explainability", "reports"]:
    p = os.path.join(ROOT_DIR, d)
    if p not in sys.path:
        sys.path.insert(0, p)

from explainability.explainer import BaselineCourtExplainer
from explainability.base import BaseExplainer


def test_explainer_with_generative_ai_markers():
    """Verify explainer produces judicial narrative when generative AI is flagged."""
    explainer = BaselineCourtExplainer()
    assert isinstance(explainer, BaseExplainer)

    forensic_data = {
        "format_valid": True,
        "anomalies": []
    }
    ai_data = {
        "tamper_detected": True,
        "confidence_score": 0.88,
        "findings": ["Synthetic media / Generative AI pipeline markers identified: Stable Diffusion."],
        "details": {
            "tamper_flags": ["GENERATIVE_AI_MARKER"],
            "shannon_entropy": 7.42,
            "ela_metrics": None
        }
    }

    explanation = explainer.explain("EVD-GENAI-001", forensic_data, ai_data)

    assert explanation["evidence_id"] == "EVD-GENAI-001"
    assert explanation["confidence_category"] == "HIGH"
    assert explanation["legal_weight"] == "HIGH_PROBATIVE_CONCERN"
    assert any("Synthetic Media Alert" in p for p in explanation["plain_language_explanations"])
    assert "Bharatiya Sakshya Adhiniyam" in explanation["limitations_disclaimer"]
    assert any("summons for original capture device" in r.lower() for r in explanation["judicial_recommendations"])


def test_explainer_with_ela_metrics():
    """Verify explainer articulates localized compression discrepancies in plain language."""
    explainer = BaselineCourtExplainer()

    forensic_data = {
        "format_valid": True,
        "anomalies": ["EXIF camera metadata missing"]
    }
    ai_data = {
        "tamper_detected": True,
        "confidence_score": 0.74,
        "findings": ["Error Level Analysis flagged localized compression disparities."],
        "details": {
            "tamper_flags": ["ELA_LOCALIZED_DISPARITY", "EDITING_SOFTWARE_METADATA"],
            "ela_metrics": {
                "ela_performed": True,
                "mean_error": 3.4,
                "max_error": 68.2,
                "std_error": 12.8,
                "suspicious_variance": True
            }
        }
    }

    explanation = explainer.explain("EVD-ELA-002", forensic_data, ai_data)

    assert explanation["confidence_category"] == "MEDIUM"
    assert any("Error Level Analysis (ELA) Discrepancy" in p for p in explanation["plain_language_explanations"])
    assert any("Digital Editing Traces" in p for p in explanation["plain_language_explanations"])
    assert len(explanation["contributing_factors"]) >= 2


def test_explainer_authentic_evidence():
    """Verify explainer validates clean electronic records without false alerts."""
    explainer = BaselineCourtExplainer()

    forensic_data = {
        "format_valid": True,
        "anomalies": []
    }
    ai_data = {
        "tamper_detected": False,
        "confidence_score": 0.65,
        "findings": ["Structural integrity verified."],
        "details": {
            "tamper_flags": [],
            "shannon_entropy": 7.6
        }
    }

    explanation = explainer.explain("EVD-CLEAN-003", forensic_data, ai_data)

    assert explanation["confidence_category"] == "MEDIUM"
    assert "shows no obvious automated indicators of tampering" in explanation["reasoning_summary"]
    assert any("Admissible as prima facie" in r for r in explanation["judicial_recommendations"])
