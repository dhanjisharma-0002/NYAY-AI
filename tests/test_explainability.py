import pytest
from explainability.explainer import BaselineCourtExplainer
from explainability.base import BaseExplainer

def test_court_explainer_inheritance():
    """Verify BaselineCourtExplainer implements BaseExplainer."""
    explainer = BaselineCourtExplainer()
    assert isinstance(explainer, BaseExplainer)

def test_court_explainer_validation():
    """Verify mandatory case_id and evidence_id validation."""
    explainer = BaselineCourtExplainer()

    with pytest.raises(ValueError, match="evidence_id is required"):
        explainer.explain(case_id="CASE-001", evidence_id="")

    with pytest.raises(ValueError, match="case_id is required"):
        explainer.explain(case_id="", evidence_id="EVID-001")

def test_court_explainer_plain_language_cues():
    """Verify conversion of technical cues (ELA, GenAI, Entropy, Hash Mismatch) into plain legal language."""
    explainer = BaselineCourtExplainer()
    
    ai_data = {
        "risk_score": 0.82,
        "assessment": "high_risk",
        "indicators": [
            "Generative AI Marker in header",
            "Error Level Analysis compression disparity",
            "Cryptographic hash mismatch"
        ],
        "details": {
            "ela_metrics": {"max_error": 68.4},
            "shannon_entropy": 7.91
        }
    }
    
    forensic_data = {
        "anomalies": ["Container magic byte mismatch"]
    }
    
    explanation = explainer.explain(
        case_id="CASE-2026-DEL-COURT",
        evidence_id="EVID-EXHIBIT-A",
        ai_data=ai_data,
        forensic_data=forensic_data
    )
    
    assert explanation["case_id"] == "CASE-2026-DEL-COURT"
    assert explanation["evidence_id"] == "EVID-EXHIBIT-A"
    assert explanation["legal_weight"] == "HIGH_PROBATIVE_CONCERN"
    assert explanation["admissibility_flag"] == "MANUAL_SCRUTINY_MANDATED"
    
    plain_texts = " ".join(explanation["plain_language_explanations"]).lower()
    assert "generative ai" in plain_texts or "synthetic" in plain_texts
    assert "compression disparity" in plain_texts or "ela" in plain_texts
    assert "integrity screening flag" in plain_texts or "hash" in plain_texts

def test_court_explainer_statutory_limitations_and_recommendations():
    """Verify statutory defense safeguards under BSA 2023 and judicial recommendations."""
    explainer = BaselineCourtExplainer()
    
    explanation = explainer.explain(
        case_id="CASE-HIGH-RISK",
        evidence_id="EVID-DOC-9",
        ai_data={"risk_score": 0.75, "assessment": "high_risk", "indicators": ["Photoshop metadata"]}
    )
    
    # Limitations check
    limitations = explanation["limitations_disclaimer"]
    assert "Bharatiya Sakshya Adhiniyam" in limitations
    assert "corroborate" in limitations.lower()
    
    # Judicial recommendations check
    recommendations = explanation["judicial_recommendations"]
    assert len(recommendations) > 0
    assert any("summons" in r.lower() or "fsl" in r.lower() or "custody" in r.lower() for r in recommendations)

def test_court_explainer_low_risk_presumption():
    """Verify clean evidence produces presumptive integrity status."""
    explainer = BaselineCourtExplainer()
    
    explanation = explainer.explain(
        case_id="CASE-CLEAN",
        evidence_id="EVID-CLEAN-01",
        ai_data={"risk_score": 0.05, "assessment": "low_risk", "indicators": []}
    )
    
    assert explanation["legal_weight"] == "HIGH_RELIABILITY"
    assert explanation["admissibility_flag"] == "PRESUMPTIVE_INTEGRITY"
    assert "prima facie" in explanation["judicial_recommendations"][0].lower()

def test_court_explainer_backward_compatibility():
    """Verify legacy 3-argument call signature: explain(evidence_id, forensic_data, ai_data)."""
    explainer = BaselineCourtExplainer()
    
    explanation = explainer.explain(
        "EVID-LEGACY-01",
        {"anomalies": []},
        {"risk_score": 0.1, "assessment": "low_risk"},
        case_id="CASE-LEGACY-PASS"
    )
    
    assert explanation["case_id"] == "CASE-LEGACY-PASS"
    assert explanation["evidence_id"] == "EVID-LEGACY-01"
