"""
NYAYAI - Forensic Evidence Comparison
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Compares forensic findings from two evidence items.

The comparator is non-destructive:
- Original evidence files are never modified.
- Comparison operates only on supplied forensic findings.
- Differences are reported explicitly for investigator review.
"""

from typing import Any, Dict, List


class EvidenceComparator:
    """Compare forensic findings from two evidence items."""

    def compare_hashes(
        self,
        first_hash: str,
        second_hash: str,
    ) -> Dict[str, Any]:
        """Compare SHA-256 hashes of two evidence items."""
        first_normalized = first_hash.lower()
        second_normalized = second_hash.lower()

        return {
            "same": first_normalized == second_normalized,
            "first_hash": first_normalized,
            "second_hash": second_normalized,
        }

    def compare_metadata(
        self,
        first_metadata: Dict[str, Any],
        second_metadata: Dict[str, Any],
    ) -> List[str]:
        """Identify differences in forensic file metadata."""
        differences: List[str] = []

        fields_to_compare = (
            "file_name",
            "file_size_bytes",
            "file_extension",
            "mime_type",
        )

        for field in fields_to_compare:
            first_value = first_metadata.get(field)
            second_value = second_metadata.get(field)

            if first_value != second_value:
                differences.append(
                    f"{field} differs between the evidence items."
                )

        return differences

    def compare_images(
        self,
        first_image: Dict[str, Any],
        second_image: Dict[str, Any],
    ) -> List[str]:
        """Identify differences in image forensic findings."""
        differences: List[str] = []

        fields_to_compare = (
            "format",
            "width",
            "height",
            "mode",
            "has_exif",
        )

        for field in fields_to_compare:
            first_value = first_image.get(field)
            second_value = second_image.get(field)

            if first_value != second_value:
                differences.append(
                    f"image {field} differs between the evidence items."
                )

        first_exif = first_image.get("exif_metadata", {})
        second_exif = second_image.get("exif_metadata", {})

        if first_exif != second_exif:
            differences.append(
                "image EXIF metadata differs between the evidence items."
            )

        return differences

    def compare(
        self,
        first_hash: str,
        second_hash: str,
        first_metadata: Dict[str, Any] | None = None,
        second_metadata: Dict[str, Any] | None = None,
        first_image: Dict[str, Any] | None = None,
        second_image: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Return a consolidated comparison of two evidence items."""
        hash_comparison = self.compare_hashes(
            first_hash,
            second_hash,
        )

        metadata_differences = self.compare_metadata(
            first_metadata or {},
            second_metadata or {},
        )

        image_differences = self.compare_images(
            first_image or {},
            second_image or {},
        )

        differences = list(
            dict.fromkeys(
                metadata_differences + image_differences
            )
        )

        return {
            "hash_comparison": hash_comparison,
            "metadata_differences": metadata_differences,
            "image_differences": image_differences,
            "differences": differences,
            "identical_hash": hash_comparison["same"],
            "has_differences": bool(differences)
            or not hash_comparison["same"],
        }
