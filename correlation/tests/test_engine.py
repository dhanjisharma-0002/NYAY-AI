"""
NYAYAI - Local Module Unit Tests: Evidence Correlation Engine
Module Lead: Ridhi Masih (Evidence Intelligence Lead)
"""

import pytest
from correlation.base import BaseCorrelationEngine
from correlation.engine import BaselineCorrelationEngine


def test_correlation_engine_inheritance():
    """Verify BaselineCorrelationEngine implements BaseCorrelationEngine."""
    engine = BaselineCorrelationEngine()
    assert isinstance(engine, BaseCorrelationEngine)


def test_correlation_engine_mandatory_case_id():
    """Test validation of mandatory case_id."""
    engine = BaselineCorrelationEngine()

    with pytest.raises(ValueError, match="case_id is required"):
        engine.correlate_case_evidence(case_id="", evidence_items=[])

    with pytest.raises(ValueError, match="case_id is required"):
        engine.correlate_case_evidence(case_id=None, evidence_items=[])


def test_correlation_multi_evidence_and_timeline():
    """Verify processing multiple evidence items and timeline ordering without timestamp invention."""
    engine = BaselineCorrelationEngine()

    items = [
        {"evidence_id": "EVID-B", "original_filename": "b.jpg", "created_at": "2026-10-01T11:00:00+00:00"},
        {"evidence_id": "EVID-A", "original_filename": "a.jpg", "created_at": "2026-10-01T10:00:00+00:00"},
        {"evidence_id": "EVID-C", "original_filename": "c.jpg", "created_at": None}
    ]

    result = engine.correlate_case_evidence(case_id="CASE-CORR-01", evidence_items=items)

    assert result["success"] is True
    assert result["case_id"] == "CASE-CORR-01"
    timeline = result["timeline"]
    assert len(timeline) == 3
    # A (10:00) before B (11:00)
    assert timeline[0]["evidence_id"] == "EVID-A"
    assert timeline[1]["evidence_id"] == "EVID-B"
    # C has no timestamp, preserved as None
    assert timeline[2]["evidence_id"] == "EVID-C"
    assert timeline[2]["timestamp"] is None


def test_correlation_cross_evidence_relationships():
    """Verify relationship discovery across multiple artifacts."""
    engine = BaselineCorrelationEngine()
    shared_hash = "f" * 64
    items = [
        {"evidence_id": "E1", "sha256_hash": shared_hash, "created_at": "2026-10-01T10:00:00+00:00"},
        {"evidence_id": "E2", "sha256_hash": shared_hash, "created_at": "2026-10-01T10:01:00+00:00"}
    ]

    result = engine.correlate_case_evidence(case_id="CASE-REL", evidence_items=items)
    rel_types = [r["relationship_type"] for r in result["relationships"]]
    assert "IDENTICAL_FILE_HASH" in rel_types
    assert "TEMPORAL_PROXIMITY" in rel_types


def test_correlation_proof_disclaimer():
    """Verify clear distinction that correlations are investigative leads, not criminal conclusions."""
    engine = BaselineCorrelationEngine()
    result = engine.correlate_case_evidence(case_id="CASE-DISC", evidence_items=[])
    disclaimer = result["correlation_disclaimer"].lower()
    assert "investigative leads" in disclaimer
    assert "not" in disclaimer
    assert "proof" in disclaimer
