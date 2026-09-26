"""
NYAYAI - Forensic Metadata & Magic Byte Analyzer
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Provides deterministic format verification and metadata extraction without mutating evidence.
"""

import os
import mimetypes
from typing import Dict, Any, List
from datetime import datetime, timezone


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
    """
    Baseline extractor for forensic metadata and signature integrity checking.
    """

    def inspect_magic_bytes(self, file_path: str) -> Dict[str, Any]:
        """
        Reads first 32 bytes to identify actual binary signature.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Evidence file not found: {file_path}")

        with open(file_path, "rb") as f:
            header = f.read(32)

        matched_mime = "application/octet-stream"
        matched_description = "Unknown Binary Stream"
        match_found = False

        for magic, (mime, desc) in MAGIC_SIGNATURES.items():
            if header.startswith(magic):
                matched_mime = mime
                matched_description = desc
                match_found = True
                break

        return {
            "magic_bytes_hex": header[:16].hex(),
            "detected_mime": matched_mime,
            "detected_description": matched_description,
            "signature_matched": match_found,
            "sample_ascii": "".join([chr(b) if 32 <= b <= 126 else "." for b in header[:16]])
        }

    def extract_filesystem_metadata(self, file_path: str) -> Dict[str, Any]:
        """
        Gathers immutable filesystem metadata (size, created/modified dates).
        """
        stat = os.stat(file_path)
        return {
            "file_size_bytes": stat.st_size,
            "system_ctime_utc": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
            "system_mtime_utc": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "system_atime_utc": datetime.fromtimestamp(stat.st_atime, tz=timezone.utc).isoformat(),
        }

    def analyze(self, file_path: str, declared_mime: str = "") -> Dict[str, Any]:
        """
        Comprehensive forensic inspection.
        """
        fs_meta = self.extract_filesystem_metadata(file_path)
        magic_info = self.inspect_magic_bytes(file_path)

        anomalies: List[str] = []
        if declared_mime and magic_info["signature_matched"]:
            if declared_mime.lower() != magic_info["detected_mime"].lower():
                anomalies.append(
                    f"MIME mismatch: File declared as '{declared_mime}', but magic bytes indicate '{magic_info['detected_mime']}'."
                )

        return {
            "format_valid": len(anomalies) == 0,
            "magic_bytes": magic_info["magic_bytes_hex"],
            "detected_mime": magic_info["detected_mime"],
            "filesystem_metadata": fs_meta,
            "anomalies": anomalies,
            "exif_metadata": {} # Extended in Phase 2
        }
