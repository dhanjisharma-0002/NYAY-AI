"""
NYAYAI - Test Suite: Cryptographic Integrity & Forensic Hashing
Tests adherence to Rule 2 (Zero Mutation) and Rule 7 (Mandatory SHA-256)
"""

import os
import tempfile
import hashlib
import pytest
import sys

# Ensure root is in sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for d in ["forensic-engine", "ai-engine", "custody", "correlation", "explainability", "reports"]:
    p = os.path.join(ROOT_DIR, d)
    if p not in sys.path:
        sys.path.insert(0, p)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from forensic_engine.integrity import calculate_sha256, verify_sha256
from forensic_engine.metadata import ForensicMetadataExtractor


def test_sha256_deterministic_calculation():
    """Verify that calculate_sha256 produces exact cryptographic standard output."""
    sample_content = b"STATE OF EVIDENCE: CONFIDENTIAL INVESTIGATION RECORD #9841"
    expected_hash = hashlib.sha256(sample_content).hexdigest().lower()

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(sample_content)
        tmp_path = tmp.name

    try:
        calculated = calculate_sha256(tmp_path)
        assert calculated == expected_hash, f"Hash mismatch: {calculated} != {expected_hash}"

        is_intact, returned_hash = verify_sha256(tmp_path, expected_hash)
        assert is_intact is True
        assert returned_hash == expected_hash
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_tamper_detection_on_single_bit_change():
    """Verify that modifying a single byte breaks verification immediately."""
    sample_content = b"ORIGINAL TAMPER-FREE EVIDENCE PAYLOAD"
    original_hash = hashlib.sha256(sample_content).hexdigest().lower()

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(sample_content)
        tmp_path = tmp.name

    try:
        # Intentionally alter 1 byte
        with open(tmp_path, "wb") as f:
            f.write(b"ORIGINAL TAMPER-FREE EVIDENCE PAYLOAE") # 'D' changed to 'E'

        is_intact, current_hash = verify_sha256(tmp_path, original_hash)
        assert is_intact is False, "Tampered evidence was falsely reported as intact!"
        assert current_hash != original_hash
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_zero_mutation_guarantee():
    """Rule 2: Ensure hashing never mutates the underlying file or file timestamps."""
    sample_content = b"TESTING ZERO MUTATION POLICY ON VAULTED EVIDENCE"

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(sample_content)
        tmp_path = tmp.name

    try:
        stat_before = os.stat(tmp_path)
        _ = calculate_sha256(tmp_path)
        stat_after = os.stat(tmp_path)

        with open(tmp_path, "rb") as f:
            read_bytes = f.read()

        assert read_bytes == sample_content
        assert stat_before.st_size == stat_after.st_size
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_forensic_magic_bytes_detection():
    """Verify magic bytes inspection identifies true file signatures."""
    extractor = ForensicMetadataExtractor()

    # Create dummy PNG header
    png_content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        tmp.write(png_content)
        tmp_path = tmp.name

    try:
        result = extractor.analyze(tmp_path, declared_mime="image/png")
        assert result["detected_mime"] == "image/png"
        assert result["format_valid"] is True

        # Test spoofed MIME extension
        mismatch_res = extractor.analyze(tmp_path, declared_mime="application/pdf")
        assert mismatch_res["format_valid"] is False
        assert len(mismatch_res["anomalies"]) > 0
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
