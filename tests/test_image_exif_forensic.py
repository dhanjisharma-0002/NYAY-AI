"""Tests for forensic image EXIF analysis."""

from PIL import Image

from forensic_engine.image_analyzer import ForensicImageAnalyzer


def test_image_without_exif_returns_empty_exif_metadata(tmp_path):
    """Verify an image without EXIF metadata is handled safely."""
    evidence_file = tmp_path / "no_exif.png"

    image = Image.new("RGB", (100, 60))
    image.save(evidence_file, format="PNG")

    analyzer = ForensicImageAnalyzer()
    result = analyzer.analyze(str(evidence_file))

    assert result["analysis_type"] == "image"
    assert result["format"] == "PNG"
    assert result["has_exif"] is False
    assert result["exif_metadata"] == {}


def test_extract_exif_returns_dictionary():
    """Verify EXIF extraction always returns a dictionary."""
    image = Image.new("RGB", (50, 50))

    analyzer = ForensicImageAnalyzer()
    result = analyzer.extract_exif(image)

    assert isinstance(result, dict)
