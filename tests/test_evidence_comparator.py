"""Tests for the forensic evidence comparison module."""

from forensic_engine.evidence_comparator import EvidenceComparator


def test_identical_hashes_are_detected():
    """Verify identical SHA-256 hashes are reported as equal."""
    comparator = EvidenceComparator()

    result = comparator.compare_hashes(
        "ABC123",
        "abc123",
    )

    assert result["same"] is True
    assert result["first_hash"] == "abc123"
    assert result["second_hash"] == "abc123"


def test_different_hashes_are_detected():
    """Verify different SHA-256 hashes are reported."""
    comparator = EvidenceComparator()

    result = comparator.compare_hashes(
        "abc123",
        "def456",
    )

    assert result["same"] is False


def test_metadata_differences_are_detected():
    """Verify file metadata differences are identified."""
    comparator = EvidenceComparator()

    differences = comparator.compare_metadata(
        {
            "file_name": "evidence_a.png",
            "file_size_bytes": 1000,
            "file_extension": ".png",
            "mime_type": "image/png",
        },
        {
            "file_name": "evidence_b.png",
            "file_size_bytes": 2000,
            "file_extension": ".png",
            "mime_type": "image/png",
        },
    )

    assert "file_name differs between the evidence items." in differences
    assert (
        "file_size_bytes differs between the evidence items."
        in differences
    )
    assert len(differences) == 2


def test_image_differences_are_detected():
    """Verify image forensic differences are identified."""
    comparator = EvidenceComparator()

    differences = comparator.compare_images(
        {
            "format": "PNG",
            "width": 100,
            "height": 100,
            "mode": "RGB",
            "has_exif": False,
            "exif_metadata": {},
        },
        {
            "format": "PNG",
            "width": 200,
            "height": 100,
            "mode": "RGB",
            "has_exif": True,
            "exif_metadata": {"Camera": "Example"},
        },
    )

    assert "image width differs between the evidence items." in differences
    assert "image has_exif differs between the evidence items." in differences
    assert (
        "image EXIF metadata differs between the evidence items."
        in differences
    )


def test_identical_evidence_has_no_differences():
    """Verify identical forensic findings produce no differences."""
    comparator = EvidenceComparator()

    result = comparator.compare(
        first_hash="abc123",
        second_hash="abc123",
        first_metadata={
            "file_name": "evidence.png",
            "file_size_bytes": 1000,
            "file_extension": ".png",
            "mime_type": "image/png",
        },
        second_metadata={
            "file_name": "evidence.png",
            "file_size_bytes": 1000,
            "file_extension": ".png",
            "mime_type": "image/png",
        },
    )

    assert result["identical_hash"] is True
    assert result["has_differences"] is False
    assert result["differences"] == []


def test_modified_evidence_produces_consolidated_differences():
    """Verify changed evidence produces consolidated findings."""
    comparator = EvidenceComparator()

    result = comparator.compare(
        first_hash="original-hash",
        second_hash="modified-hash",
        first_metadata={
            "file_name": "evidence.png",
            "file_size_bytes": 1000,
            "file_extension": ".png",
            "mime_type": "image/png",
        },
        second_metadata={
            "file_name": "evidence.png",
            "file_size_bytes": 1500,
            "file_extension": ".png",
            "mime_type": "image/png",
        },
        first_image={
            "format": "PNG",
            "width": 100,
            "height": 100,
            "mode": "RGB",
            "has_exif": False,
            "exif_metadata": {},
        },
        second_image={
            "format": "PNG",
            "width": 200,
            "height": 100,
            "mode": "RGB",
            "has_exif": False,
            "exif_metadata": {},
        },
    )

    assert result["identical_hash"] is False
    assert result["has_differences"] is True

    assert (
        "file_size_bytes differs between the evidence items."
        in result["differences"]
    )
    assert (
        "image width differs between the evidence items."
        in result["differences"]
    )
