```python
"""
NYAYAI - Forensic Metadata & Magic Byte Analyzer
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Provides deterministic format verification and metadata extraction
without mutating evidence.
"""

import mimetypes
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from PIL import ExifTags, Image


# Standard magic byte signatures for common digital evidence formats
MAGIC_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": ("image/png", "PNG Image"),
    b"\xff\xd8\xff": ("image/jpeg", "JPEG Image"),
    b"%PDF-": ("application/pdf", "PDF Document"),
    b"RIFF": ("audio/wav_or_avi", "RIFF Container (WAV/AVI)"),
    b"ID3": ("audio/mp3", "MP3 Audio (with ID3)"),
    b"\xff\xfb": ("audio/mp3", "MP3 Audio"),
    b"\x00\x00\x00\x18ftyp": ("video/mp4", "MP4 Video Container"),
    b"\x00\x00\x00\x20ftyp": ("video/mp4", "MP4 Video Container"),
    b"PK\x03\x04": ("application/zip", "ZIP Archive / OpenDocument"),
}


class ForensicMetadataExtractor:
    """Baseline extractor for forensic metadata and signature checking."""

    def inspect_magic_bytes(self, file_path: str) -> Dict[str, Any]:
        """Read the first 32 bytes and identify the binary signature."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(
                f"Evidence file not found: {file_path}"
            )

        with open(file_path, "rb") as file:
            header = file.read(32)

        matched_mime = "application/octet-stream"
        matched_description = "Unknown Binary Stream"
        match_found = False

        for magic, (mime, description) in MAGIC_SIGNATURES.items():
            if header.startswith(magic):
                matched_mime = mime
                matched_description = description
                match_found = True
                break

        return {
            "magic_bytes_hex": header[:16].hex(),
            "detected_mime": matched_mime,
            "detected_description": matched_description,
            "signature_matched": match_found,
            "sample_ascii": "".join(
                chr(byte) if 32 <= byte <= 126 else "."
                for byte in header[:16]
            ),
        }

    def extract_filesystem_metadata(
        self, file_path: str
    ) -> Dict[str, Any]:
        """Gather immutable filesystem metadata."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(
                f"Evidence file not found: {file_path}"
            )

        stat = os.stat(file_path)

        return {
            "file_size_bytes": stat.st_size,
            "system_ctime_utc": datetime.fromtimestamp(
                stat.st_ctime, tz=timezone.utc
            ).isoformat(),
            "system_mt_
```
