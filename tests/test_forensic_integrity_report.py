"""Tests for forensic integrity verification and report integration."""

from forensic_engine.forensic_report import ForensicReport
from forensic_engine.integrity import calculate_sha256, verify_sha256


def test_sha256_can_be_stored_in_forensic_report(tmp_path):
    """Verify SHA-256 integrity findings can populate a forensic report."""
    evidence_file = tmp_path / "evidence.txt"
    evidence_file.write_bytes(b"NYAY-AI forensic evidence")

    calculated_hash = calculate_sha256(str(evidence_file))

    is_intact, current_hash = verify_sha256(
        str(evidence_file),
        calculated_hash,
    )

    report = ForensicReport(
        evidence_id="EVD-INTEGRITY-001",
        file_path=str(evidence_file),
        sha256=current_hash,
        integrity={
            "algorithm": "SHA-256",
            "expected_hash": calculated_hash,
            "current_hash": current_hash,
            "is_intact": is_intact,
        },
    )

    assert report.sha256 == calculated_hash
    assert report.integrity["algorithm"] == "SHA-256"
    assert report.integrity["is_intact"] is True
    assert report.integrity["current_hash"] == calculated_hash


def test_modified_evidence_is_detected(tmp_path):
    """Verify modification of evidence is detected by SHA-256 verification."""
    evidence_file = tmp_path / "evidence.txt"
    evidence_file.write_bytes(b"Original evidence")

    original_hash = calculate_sha256(str(evidence_file))

    evidence_file.write_bytes(b"Modified evidence")

    is_intact, current_hash = verify_sha256(
        str(evidence_file),
        original_hash,
    )

    report = ForensicReport(
        evidence_id="EVD-INTEGRITY-002",
        file_path=str(evidence_file),
        sha256=original_hash,
        integrity={
            "algorithm": "SHA-256",
            "expected_hash": original_hash,
            "current_hash": current_hash,
            "is_intact": is_intact,
        },
    )

    if not is_intact:
        report.add_anomaly(
            "Evidence SHA-256 hash does not match the expected hash."
        )

    assert is_intact is False
    assert current_hash != original_hash
    assert report.integrity["is_intact"] is False
    assert report.anomalies == [
        "Evidence SHA-256 hash does not match the expected hash."
    ]
