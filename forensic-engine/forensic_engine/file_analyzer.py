"""
NYAYAI - File Forensic Analyzer
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Provides file-level forensic inspection including:
- SHA-256 hashing
- Filesystem metadata
- File type detection
- Magic-byte signature verification
- MIME mismatch detection

The original evidence file is never modified.
"""

from __future__ import annotations

import hashlib
import mimetypes
import os
from typing import Any, Dict

from .base import BaseForensicAnalyzer
from .metadata import ForensicMetadataExtractor


class FileForensicAnalyzer(BaseForensicAnalyzer):
    """Perform forensic analysis on file-based evidence."""

    CHUNK_SIZE = 64 * 1024

    def calculate_sha256(self, file_path: str) -> str:
        """Calculate a deterministic SHA-256 hash using streaming reads."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(
                f"Evidence file not found: {file_path}"
            )

        digest = hashlib.sha256()

        with open(file_path, "rb") as handle:
            for chunk in iter(
                lambda: handle.read(self.CHUNK_SIZE),
                b"",
            ):
                digest.update(chunk)

        return digest.hexdigest()

    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract filesystem metadata and file information."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(
                f"Evidence file not found: {file_path}"
            )

        stat_result = os.stat(file_path)
        guessed_mime, _ = mimetypes.guess_type(file_path)

        return {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "file_size_bytes": stat_result.st_size,
            "file_extension": os.path.splitext(file_path)[1].lower(),
            "mime_type": guessed_mime,
            "sha256": self.calculate_sha256(file_path),
            "created_at": stat_result.st_ctime,
            "modified_at": stat_result.st_mtime,
            "accessed_at": stat_result.st_atime,
            "inode": stat_result.st_ino,
            "is_regular_file": os.path.isfile(file_path),
        }

    def verify_file_signature(
        self,
        file_path: str,
        declared_mime: str,
    ) -> Dict[str, Any]:
        """Verify the file signature against the declared MIME type."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(
                f"Evidence file not found: {file_path}"
            )

        metadata_extractor = ForensicMetadataExtractor()
        magic_info = metadata_extractor.inspect_magic_bytes(file_path)

        detected_mime = magic_info["detected_mime"]
        matches = (
            detected_mime.lower() == declared_mime.lower()
        )

        return {
            "file_path": file_path,
            "declared_mime": declared_mime,
            "detected_mime": detected_mime,
            "matches_declared_mime": matches,
            "magic_bytes_hex": magic_info["magic_bytes_hex"],
            "note": (
                "Signature verified against declared MIME type."
                if matches
                else (
                    "Declared MIME type does not match "
                    "the file signature."
                )
            ),
        }
