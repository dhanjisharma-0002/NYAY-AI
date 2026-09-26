"""
NYAYAI - Evidence File Validation & Security Inspector
Module: backend.app.utils.file_validation
Enforces strict file type whitelisting, blocks executable payloads,
and verifies file size limits per forensic standards.
"""

import os
from typing import Tuple, Dict, Any
from backend.app.config import settings
from backend.app.utils.exceptions import ValidationException, AppException

# Whitelist of permitted evidence extensions and canonical MIME types
SUPPORTED_EXTENSIONS: Dict[str, str] = {
    # Images
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "png": "image/png",
    "webp": "image/webp",
    # Videos
    "mp4": "video/mp4",
    "mov": "video/quicktime",
    "avi": "video/x-msvideo",
    # Audio
    "mp3": "audio/mpeg",
    "wav": "audio/wav",
    "m4a": "audio/mp4",
    # Documents
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "txt": "text/plain",
}

# Known executable and script extensions prohibited from intake
DISALLOWED_EXTENSIONS = {
    "exe", "bat", "cmd", "sh", "bin", "com", "msi", "dll", "vbs", "ps1",
    "scr", "jar", "apk", "pif", "so", "dylib", "elf", "hta", "cpl"
}

# Dangerous binary signatures (magic bytes) to reject regardless of extension
DISALLOWED_MAGIC = [
    (b"MZ", "DOS/Windows PE Executable / DLL"),
    (b"\x7fELF", "Linux ELF Executable"),
    (b"#!", "Shell / Script Executable"),
    (b"\xca\xfe\xba\xbe", "Java Class / Mach-O Fat Binary"),
    (b"\xfe\xed\xfa\xce", "Mach-O Binary (32-bit)"),
    (b"\xfe\xed\xfa\xcf", "Mach-O Binary (64-bit)"),
]


def validate_evidence_file(
    filename: str,
    header_bytes: bytes,
    file_size_bytes: int,
    max_size_mb: int = settings.MAX_EVIDENCE_FILE_SIZE_MB
) -> str:
    """
    Validates uploaded file against allowed evidence types and size limits.
    Returns the resolved media_type string.
    Raises:
    - ValidationException (422) if extension is unsupported or executable signature is detected.
    - AppException (413) if file size exceeds configured limits.
    """
    if not filename or "." not in filename:
        raise ValidationException("File must have a valid extension.")

    # 1. Extension Whitelist Check
    ext = filename.rsplit(".", 1)[-1].lower().strip()

    if ext in DISALLOWED_EXTENSIONS:
        raise ValidationException(
            f"Arbitrary executable files ('.{ext}') are strictly prohibited."
        )

    if ext not in SUPPORTED_EXTENSIONS:
        raise ValidationException(
            f"Unsupported file type '.{ext}'. Supported formats: "
            "Images (JPG, JPEG, PNG, WEBP), Videos (MP4, MOV, AVI), "
            "Audio (MP3, WAV, M4A), Documents (PDF, DOCX, TXT)."
        )

    # 2. Executable Header / Magic Byte Inspection
    for magic, desc in DISALLOWED_MAGIC:
        if header_bytes.startswith(magic):
            raise ValidationException(
                f"Binary inspection rejected file: detected {desc} signature. "
                "Arbitrary executable files are strictly prohibited."
            )

    # 3. File Size Validation
    max_bytes = max_size_mb * 1024 * 1024
    if file_size_bytes > max_bytes:
        raise AppException(
            message=f"File size ({file_size_bytes} bytes) exceeds maximum configured limit of {max_size_mb}MB.",
            status_code=413,
            error_code="FILE_OVERSIZED",
            details={"file_size_bytes": file_size_bytes, "max_allowed_mb": max_size_mb}
        )

    if file_size_bytes == 0:
        raise ValidationException("Uploaded evidence file cannot be empty (0 bytes).")

    # Resolved canonical media type
    return SUPPORTED_EXTENSIONS[ext]
