"""
NYAYAI - Local Module Unit Tests: Court Explainability Engine
Module Lead: Ridhi Masih (Evidence Intelligence Lead)
"""

import pytest
from explainability.base import BaseExplainer
from explainability.explainer import BaselineCourtExplainer


def test_explainer_inheritance():
    """Verify BaselineCourtExplainer implements BaseExplainer interface."""
    explainer = BaselineCourtExplainer()
    assert isinstance(explainer, BaseExplainer)


def test_explainer_mandatory_identifiers():
    """Test validation of mandatory case_id and evidence_id."""
    explainer = BaselineCourtExplainer()

    with pytest.raises(ValueError, match="evidence_id is required"):
        explainer.explain(case_id="CASE-001", evidence_id="")

    with pytest.raises(ValueError, match="case_id is required"):
        explainer.explain(case_id="", evidence_id="EVID-001")


def test_explainer_output_preserves_ids():
    """Verify explanations preserve both case_id and evidence_id."""
    explainer = BaselineCourtExplainer()
    explanation = explainer.explain(
        case_id="CASE-EXP-01",
        evidence_id="EVID-EXP-01",
        ai_data={"risk_score": 0.2, "assessment": "low_risk", "indicators": []}
    )

    assert explanation["case_id"] == "CASE-EXP-01"
    assert explanation["evidence_id"] == "EVID-EXP-01"
    assert explanation["legal_weight"] == "HIGH_RELIABILITY"
    assert explanation["admissibility_flag"] == "PRESUMPTIVE_INTEGRITY"


def test_explainer_plain_language_and_limitations():
    """Verify technical findings are converted into plain language with explicit defense caveats."""
    explainer = BaselineCourtExplainer()
    explanation = explainer.explain(
        case_id="CASE-HIGH",
        evidence_id="EVID-HIGH",
        ai_data={
            "risk_score": 0.85,
            "assessment": "high_risk",
            "indicators": ["Generative AI Marker in header"]
        }
    )

    assert explanation["legal_weight"] == "HIGH_PROBATIVE_CONCERN"
    assert explanation["admissibility_flag"] == "MANUAL_SCRUTINY_MANDATED"
    plain_text = " ".join(explanation["plain_language_explanations"]).lower()
    assert "generative ai" in plain_text or "synthetic" in plain_text

    # Statutory limitations check
    limitations = explanation["limitations_disclaimer"]
    assert "Bharatiya Sakshya Adhiniyam" in limitations
    assert "screening" in limitations.lower()

    # Recommendations
    assert len(explanation["judicial_recommendations"]) > 0
