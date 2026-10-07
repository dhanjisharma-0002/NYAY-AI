"""Integration tests for image analysis and forensic reports."""

import hashlib

from PIL import Image

from forensic_engine.forensic_report import ForensicReport
from forensic_engine.image_analyzer import ForensicImageAnalyzer


def test_image_analysis_can_be_stored_in_forensic_report(tmp_path):
    """Verify image findings can populate a forensic report."""
    evidence_file = tmp_path / "evidence.png"

    image = Image.new("RGB", (120, 80))
    image.save(evidence_file, format="PNG")

    analyzer = ForensicImageAnalyzer()
    image_analysis = analyzer.analyze(str(evidence_file))

    with open(evidence_file, "rb") as evidence:
        sha256 = hashlib.sha256(evidence.read()).hexdigest()

    report = ForensicReport(
        evidence_id="EVD-IMG-001",
        file_path=str(evidence_file),
        sha256=sha256,
        image_analysis=image_analysis,
    )

    assert report.evidence_id == "EVD-IMG-001"
    assert report.file_path == str(evidence_file)
    assert report.sha256 == sha256

    assert report.image_analysis["analysis_type"] == "image"
    assert report.image_analysis["format"] == "PNG"
    assert report.image_analysis["width"] == 120
    assert report.image_analysis["height"] == 80
    assert report.image_analysis["mode"] == "RGB"
    assert report.image_analysis["anomalies"] == []


def test_image_anomalies_can_be_added_to_forensic_report(tmp_path):
    """Verify image analysis anomalies can be consolidated."""
    evidence_file = tmp_path / "invalid.png"
    evidence_file.write_bytes(b"not a valid image")

    analyzer = ForensicImageAnalyzer()
    image_analysis = analyzer.analyze(str(evidence_file))

    report = ForensicReport(
        evidence_id="EVD-IMG-002",
        file_path=str(evidence_file),
        sha256="",
        image_analysis=image_analysis,
    )

    for anomaly in image_analysis["anomalies"]:
        report.add_anomaly(anomaly)

    assert len(report.anomalies) == 1
    assert report.anomalies[0].startswith(
        "Unable to analyze image:"
    )
