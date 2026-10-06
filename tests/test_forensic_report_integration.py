"""Integration tests for the standardized forensic report."""

import hashlib

from forensic_engine.file_analyzer import FileForensicAnalyzer
from forensic_engine.forensic_report import ForensicReport


def test_file_analysis_can_be_consolidated_into_report(tmp_path):
    """Verify file-level findings can populate a forensic report."""
    evidence_file = tmp_path / "evidence.txt"
    content = b"NYAY-AI forensic evidence"
    evidence_file.write_bytes(content)

    analyzer = FileForensicAnalyzer()

    sha256 = analyzer.calculate_sha256(str(evidence_file))
    metadata = analyzer.extract_metadata(str(evidence_file))
    integrity = analyzer.verify_file_signature(
        str(evidence_file),
        "text/plain",
    )

    report = ForensicReport(
        evidence_id="EVD-INT-001",
        file_path=str(evidence_file),
        sha256=sha256,
        metadata=metadata,
        integrity=integrity,
    )

    assert report.evidence_id == "EVD-INT-001"
    assert report.file_path == str(evidence_file)
    assert report.sha256 == hashlib.sha256(content).hexdigest()

    assert report.metadata["file_size_bytes"] == len(content)
    assert report.metadata["sha256"] == report.sha256

    assert report.integrity["declared_mime"] == "text/plain"
    assert report.integrity["matches_declared_mime"] is True


def test_file_analysis_mismatch_becomes_report_anomaly(tmp_path):
    """Verify MIME mismatch can be recorded as a report anomaly."""
    evidence_file = tmp_path / "evidence.png"

    png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    evidence_file.write_bytes(png_header)

    analyzer = FileForensicAnalyzer()

    integrity = analyzer.verify_file_signature(
        str(evidence_file),
        "application/pdf",
    )

    report = ForensicReport(
        evidence_id="EVD-INT-002",
        file_path=str(evidence_file),
        sha256=analyzer.calculate_sha256(str(evidence_file)),
        integrity=integrity,
    )

    if not integrity["matches_declared_mime"]:
        report.add_anomaly(
            "Declared MIME type does not match the file signature."
        )

    assert report.integrity["matches_declared_mime"] is False
    assert report.anomalies == [
        "Declared MIME type does not match the file signature."
    ]
