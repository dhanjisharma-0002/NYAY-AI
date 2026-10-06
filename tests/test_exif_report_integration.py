"""Integration tests for EXIF metadata and forensic reports."""

from PIL import Image

from forensic_engine.forensic_report import ForensicReport
from forensic_engine.image_analyzer import ForensicImageAnalyzer


def test_exif_metadata_can_be_stored_in_forensic_report(tmp_path):
    """Verify EXIF findings can populate a forensic report."""
    evidence_file = tmp_path / "evidence.jpg"

    image = Image.new("RGB", (120, 80))
    image.save(evidence_file, format="JPEG")

    analyzer = ForensicImageAnalyzer()
    image_analysis = analyzer.analyze(str(evidence_file))

    report = ForensicReport(
        evidence_id="EVD-EXIF-001",
        file_path=str(evidence_file),
        sha256="",
        image_analysis=image_analysis,
    )

    assert report.evidence_id == "EVD-EXIF-001"
    assert report.image_analysis["analysis_type"] == "image"
    assert report.image_analysis["format"] == "JPEG"
    assert report.image_analysis["width"] == 120
    assert report.image_analysis["height"] == 80

    assert "exif_metadata" in report.image_analysis
    assert isinstance(report.image_analysis["exif_metadata"], dict)


def test_missing_exif_does_not_create_false_anomaly(tmp_path):
    """Verify missing EXIF metadata is not treated as an anomaly."""
    evidence_file = tmp_path / "no_exif.jpg"

    image = Image.new("RGB", (100, 60))
    image.save(evidence_file, format="JPEG")

    analyzer = ForensicImageAnalyzer()
    image_analysis = analyzer.analyze(str(evidence_file))

    report = ForensicReport(
        evidence_id="EVD-EXIF-002",
        file_path=str(evidence_file),
        sha256="",
        image_analysis=image_analysis,
    )

    assert report.image_analysis["has_exif"] is False
    assert report.image_analysis["exif_metadata"] == {}
    assert report.anomalies == []
