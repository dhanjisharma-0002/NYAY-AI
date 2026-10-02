import pytest
from correlation.engine import BaselineCorrelationEngine
from correlation.base import BaseCorrelationEngine

def test_correlation_engine_inheritance():
    """Verify BaselineCorrelationEngine implements BaseCorrelationEngine."""
    engine = BaselineCorrelationEngine()
    assert isinstance(engine, BaseCorrelationEngine)

def test_correlation_engine_validation():
    """Verify validation of case_id and evidence_items."""
    engine = BaselineCorrelationEngine()

    with pytest.raises(ValueError, match="case_id is required"):
        engine.correlate_case_evidence(case_id="", evidence_items=[])

    with pytest.raises(ValueError, match="evidence_items must be a list"):
        engine.correlate_case_evidence(case_id="CASE-001", evidence_items=None)

def test_correlation_timeline_without_timestamp_invention():
    """Verify chronological timeline assembly and that missing timestamps are never invented."""
    engine = BaselineCorrelationEngine()
    
    evidence_items = [
        {
            "evidence_id": "EVID-001",
            "original_filename": "cctv_clip1.mp4",
            "created_at": "2026-10-01T10:00:00+00:00"
        },
        {
            "evidence_id": "EVID-002",
            "original_filename": "suspect_phone.jpg",
            "created_at": None  # Timestamp unknown
        },
        {
            "evidence_id": "EVID-003",
            "original_filename": "dashcam.mp4",
            "created_at": "2026-10-01T09:30:00+00:00"
        }
    ]
    
    result = engine.correlate_case_evidence(case_id="CASE-2026-001", evidence_items=evidence_items)
    
    assert result["success"] is True
    assert result["case_id"] == "CASE-2026-001"
    timeline = result["timeline"]
    assert len(timeline) == 3
    
    # EVID-003 (09:30) must precede EVID-001 (10:00)
    assert timeline[0]["evidence_id"] == "EVID-003"
    assert timeline[1]["evidence_id"] == "EVID-001"
    # EVID-002 has no timestamp; must be sorted after known times and its timestamp must remain None
    assert timeline[2]["evidence_id"] == "EVID-002"
    assert timeline[2]["timestamp"] is None

def test_cross_evidence_matching_and_relationships():
    """Verify detection of cryptographic hash duplicates, shared serials, and temporal proximity."""
    engine = BaselineCorrelationEngine()
    
    shared_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    evidence_items = [
        {
            "evidence_id": "EVID-A",
            "original_filename": "file_a.jpg",
            "sha256_hash": shared_hash,
            "created_at": "2026-10-01T12:00:00+00:00",
            "metadata": {
                "exif_metadata": {"camera_serial_number": "SONY-ALPHA-9988"}
            }
        },
        {
            "evidence_id": "EVID-B",
            "original_filename": "file_b.jpg",
            "sha256_hash": shared_hash,
            "created_at": "2026-10-01T12:02:00+00:00",  # Within 300 seconds
            "metadata": {
                "exif_metadata": {"camera_serial_number": "SONY-ALPHA-9988"}
            }
        }
    ]
    
    result = engine.correlate_case_evidence(case_id="CASE-2026-002", evidence_items=evidence_items)
    
    rel_types = [r["relationship_type"] for r in result["relationships"]]
    assert "IDENTICAL_FILE_HASH" in rel_types
    assert "TEMPORAL_PROXIMITY" in rel_types
    assert "SHARED_HARDWARE_SERIAL" in rel_types

def test_evidence_red_flags_detection():
    """Verify red flag identification for tampered status and elevated AI risk scores."""
    engine = BaselineCorrelationEngine()
    
    evidence_items = [
        {
            "evidence_id": "EVID-COMPROMISED",
            "original_filename": "tampered_receipt.pdf",
            "status": "COMPROMISED",
            "created_at": "2026-10-01T10:00:00+00:00",
            "ai_analysis": {
                "risk_score": 0.85,
                "assessment": "high_risk",
                "indicators": [{"indicator": "ela_anomaly"}]
            }
        }
    ]
    
    result = engine.correlate_case_evidence(case_id="CASE-2026-003", evidence_items=evidence_items)
    assert result["total_red_flags"] >= 2
    flag_types = [rf["flag_type"] for rf in result["red_flags"]]
    assert "HASH_MISMATCH" in flag_types
    assert "ANALYSIS_ANOMALY" in flag_types

def test_correlation_disclaimer_and_graph_topology():
    """Verify explicit proof distinction disclaimer and visual graph payload."""
    engine = BaselineCorrelationEngine()
    
    result = engine.correlate_case_evidence(case_id="CASE-2026-GRAPH", evidence_items=[
        {"evidence_id": "EVID-G1", "original_filename": "g1.jpg"},
        {"evidence_id": "EVID-G2", "original_filename": "g2.jpg"}
    ])
    
    # Disclaimer check
    disclaimer = result["correlation_disclaimer"]
    assert "investigative leads" in disclaimer.lower()
    assert "not" in disclaimer.lower()
    assert "proof" in disclaimer.lower()
    
    # Graph check
    graph = result["graph"]
    assert "nodes" in graph
    assert "edges" in graph
    assert len(graph["nodes"]) == 2
    assert graph["nodes"][0]["case_id"] == "CASE-2026-GRAPH"
