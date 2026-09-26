"""
NYAYAI - Cryptographic Hash Integrity Verifier
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Enforces:
- Rule 7: Evidence integrity must use SHA-256
- Rule 2: Never overwrite original evidence files (open in strict read-only mode 'rb')
"""

import hashlib
import os
from typing import Tuple


DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KB chunks for memory-safe streaming


def calculate_sha256(file_path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """
    Computes a deterministic SHA-256 hex digest of a file using streaming reads.
    Guarantees no modification of the underlying file.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def verify_sha256(file_path: str, expected_hash: str) -> Tuple[bool, str]:
    """
    Verifies that the file at file_path matches expected_hash.
    Returns (is_intact: bool, current_hash: str).
    """
    current_hash = calculate_sha256(file_path)
    is_intact = (current_hash.lower() == expected_hash.lower())
    return is_intact, current_hash
