"""
NYAYAI - Forensic Engine Test Suite

Tests:
- FileForensicAnalyzer
- ForensicMetadataExtractor
- ForensicImageAnalyzer
- SHA-256 integrity
- Magic-byte signature verification
- Metadata extraction
- Non-destructive evidence handling
"""

import hashlib
import os
import sys
import tempfile

import pytest
from PIL import Image

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

for directory in [
    "forensic-engine",
    "ai-engine",
    "custody",
    "correlation",
    "explainability",
    "reports",
]:
    path = os.path.join(ROOT_DIR, directory)
    if path not in sys.path:
        sys.path.insert(0, path)

if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from forensic_engine.file_analyzer import FileForensicAnalyzer
from forensic_engine.image_analyzer import ForensicImageAnalyzer
from forensic_engine.metadata import ForensicMetadataExtractor


def create_temp_file(content: bytes, suffix: str = ""):
    """Create a temporary evidence file and return its path."""
    with tempfile.NamedTemporaryFile(
        suffix=suffix,
        delete=False,
    ) as temp_file:
        temp_file.write(content)
        return temp_file.name


def test_file_analyzer_sha256():
    """Verify FileForensicAnalyzer calculates the correct SHA-256 hash."""
    content = b"NYAYAI FORENSIC EVIDENCE"

    file_path = create_temp_file(content)

    try:
        analyzer = FileForensicAnalyzer()

        expected_hash = hashlib.sha256(content).hexdigest()
        actual_hash = analyzer.calculate_sha256(file_path)

        assert actual_hash == expected_hash
    finally:
        os.remove(file_path)


def test_file_analyzer_metadata():
    """Verify file metadata extraction returns expected attributes."""
    content = b"FORENSIC METADATA TEST"

    file_path = create_temp_file(
        content,
        suffix=".txt",
    )

    try:
        analyzer = FileForensicAnalyzer()
        metadata = analyzer.extract_metadata(file_path)

        assert metadata["file_path"] == file_path
        assert metadata["file_name"].endswith(".txt")
        assert metadata["file_size_bytes"] == len(content)
        assert metadata["file_extension"] == ".txt"
        assert metadata["sha256"] == hashlib.sha256(content).hexdigest()
        assert metadata["is_regular_file"] is True
    finally:
        os.remove(file_path)


def test_file_analyzer_missing_file():
    """Verify missing evidence raises FileNotFoundError."""
    analyzer = FileForensicAnalyzer()

    with pytest.raises(FileNotFoundError):
        analyzer.calculate_sha256("missing_evidence_file.bin")


def test_file_signature_verification():
    """Verify magic bytes are compared with the declared MIME type."""
    png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"

    file_path = create_temp_file(
        png_header,
        suffix=".png",
    )

    try:
        analyzer = FileForensicAnalyzer()

        result = analyzer.verify_file_signature(
            file_path,
            "image/png",
        )

        assert result["detected_mime"] == "image/png"
        assert result["matches_declared_mime"] is True
        assert result["magic_bytes_hex"].startswith(
            "89504e470d0a1a0a"
        )
    finally:
        os.remove(file_path)


def test_file_signature_mismatch():
    """Verify a mismatched declared MIME type is detected."""
    png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"

    file_path = create_temp_file(
        png_header,
        suffix=".png",
    )

    try:
        analyzer = FileForensicAnalyzer()

        result = analyzer.verify_file_signature(
            file_path,
            "application/pdf",
        )

        assert result["detected_mime"] == "image/png"
        assert result["matches_declared_mime"] is False
    finally:
        os.remove(file_path)


def test_magic_bytes_detection():
    """Verify metadata extractor identifies a PNG signature."""
    png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"

    file_path = create_temp_file(
        png_header,
        suffix=".png",
    )

    try:
        extractor = ForensicMetadataExtractor()

        result = extractor.inspect_magic_bytes(file_path)

        assert result["detected_mime"] == "image/png"
        assert result["signature_matched"] is True
        assert result["magic_bytes_hex"].startswith(
            "89504e470d0a1a0a"
        )
    finally:
        os.remove(file_path)


def test_metadata_analyze_mime_mismatch():
    """Verify metadata analysis reports MIME mismatch as an anomaly."""
    png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"

    file_path = create_temp_file(
        png_header,
        suffix=".png",
    )

    try:
        extractor = ForensicMetadataExtractor()

        result = extractor.analyze(
            file_path,
            declared_mime="application/pdf",
        )

        assert result["format_valid"] is False
        assert len(result["anomalies"]) > 0
        assert result["detected_mime"] == "image/png"
    finally:
        os.remove(file_path)


def test_image_analyzer_basic_properties():
    """Verify basic image properties are extracted."""
    file_path = create_temp_file(
        b"",
        suffix=".png",
    )

    try:
        image = Image.new("RGB", (100, 50))
        image.save(file_path, format="PNG")

        analyzer = ForensicImageAnalyzer()
        result = analyzer.analyze(file_path)

        assert result["analysis_type"] == "image"
        assert result["format"] == "PNG"
        assert result["width"] == 100
        assert result["height"] == 50
        assert result["mode"] == "RGB"
        assert result["anomalies"] == []
    finally:
        os.remove(file_path)


def test_image_analyzer_missing_file():
    """Verify missing image evidence raises FileNotFoundError."""
    analyzer = ForensicImageAnalyzer()

    with pytest.raises(FileNotFoundError):
        analyzer.analyze("missing_evidence_image.png")


def test_image_analysis_is_non_destructive():
    """Verify image analysis does not change the evidence file."""
    image = Image.new("RGB", (40, 40))

    with tempfile.NamedTemporaryFile(
        suffix=".png",
        delete=False,
    ) as temp_file:
        file_path = temp_file.name

    try:
        image.save(file_path, format="PNG")

        with open(file_path, "rb") as evidence_file:
            before = evidence_file.read()

        analyzer = ForensicImageAnalyzer()
        analyzer.analyze(file_path)

        with open(file_path, "rb") as evidence_file:
            after = evidence_file.read()

        assert before == after
    finally:
        os.remove(file_path)
