"""Unit tests for the standardized forensic report model."""

from forensic_engine.forensic_report import ForensicReport


def test_forensic_report_initialization():
    """Verify forensic report fields are initialized correctly."""
    report = ForensicReport(
        evidence_id="EVD-001",
        file_path="sample.jpg",
        sha256="abc123",
        metadata={"file_size": 1024},
        integrity={"sha256_match": True},
        image_analysis={"format": "JPEG"},
    )

    assert report.evidence_id == "EVD-001"
    assert report.file_path == "sample.jpg"
    assert report.sha256 == "abc123"
    assert report.metadata["file_size"] == 1024
    assert report.integrity["sha256_match"] is True
    assert report.image_analysis["format"] == "JPEG"
    assert report.anomalies == []


def test_add_anomaly():
    """Verify forensic anomalies are recorded without duplicates."""
    report = ForensicReport(
        evidence_id="EVD-002",
        file_path="evidence.bin",
        sha256="def456",
    )

    report.add_anomaly("MIME type mismatch")
    report.add_anomaly("MIME type mismatch")

    assert report.anomalies == ["MIME type mismatch"]


def test_to_dict():
    """Verify forensic report can be serialized to a dictionary."""
    report = ForensicReport(
        evidence_id="EVD-003",
        file_path="evidence.png",
        sha256="789abc",
        metadata={"file_size": 2048},
        integrity={"sha256_match": True},
        image_analysis={"format": "PNG"},
    )

    report.add_anomaly("Metadata anomaly")

    result = report.to_dict()

    assert result["evidence_id"] == "EVD-003"
    assert result["file_path"] == "evidence.png"
    assert result["sha256"] == "789abc"
    assert result["metadata"]["file_size"] == 2048
    assert result["integrity"]["sha256_match"] is True
    assert result["image_analysis"]["format"] == "PNG"
    assert result["anomalies"] == ["Metadata anomaly"]
