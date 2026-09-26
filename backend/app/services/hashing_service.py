"""
NYAYAI - Cryptographic Hashing Service
Module: backend.app.services.hashing_service
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Enforces:
- Rule 7: Digital evidence integrity must use SHA-256 (ISO/IEC 27037 & BSA 2023 compliant)
- Rule 2: Zero mutation guarantee on vaulted artifacts
- Constant-time verification comparisons against timing attacks
"""

import os
import hmac
import hashlib
from typing import BinaryIO, Tuple, Optional
from backend.app.utils.logger import get_logger

logger = get_logger("hashing_service")

DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunks


class HashingService:
    """
    Reusable, production-grade cryptographic hashing service.
    Guarantees deterministic, tamper-evident SHA-256 hash generation and verification.
    """

    ALGORITHM = "SHA-256"

    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE):
        self.chunk_size = chunk_size

    def compute_bytes_hash(self, data: bytes) -> str:
        """
        Computes deterministic SHA-256 hex digest for in-memory bytes.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Data to hash must be bytes or bytearray")
        return hashlib.sha256(data).hexdigest().lower()

    def compute_file_hash(self, file_path: str) -> str:
        """
        Computes SHA-256 digest of a file using chunked streaming reads.
        Guarantees memory-safe execution on large evidence files up to configured limits.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found for hash calculation: {file_path}")

        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(self.chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest().lower()

    def compute_stream_hash(self, stream: BinaryIO) -> str:
        """
        Computes SHA-256 digest directly from an open binary stream.
        """
        hasher = hashlib.sha256()
        # Save stream position if seekable
        seekable = hasattr(stream, "seekable") and stream.seekable()
        original_pos = stream.tell() if seekable else 0

        try:
            while chunk := stream.read(self.chunk_size):
                hasher.update(chunk)
            return hasher.hexdigest().lower()
        finally:
            if seekable:
                stream.seek(original_pos)

    def verify_hash(self, computed_hash: str, expected_hash: str) -> bool:
        """
        Constant-time string comparison to prevent timing analysis attacks.
        """
        if not computed_hash or not expected_hash:
            return False
        return hmac.compare_digest(computed_hash.strip().lower(), expected_hash.strip().lower())

    def verify_file_hash(self, file_path: str, expected_hash: str) -> Tuple[bool, str]:
        """
        Computes file hash and verifies against expected hash.
        Returns: (is_valid: bool, current_hash: str)
        """
        current_hash = self.compute_file_hash(file_path)
        is_valid = self.verify_hash(current_hash, expected_hash)
        return is_valid, current_hash

    # Static convenience methods
    @classmethod
    def hash_bytes(cls, data: bytes) -> str:
        return cls().compute_bytes_hash(data)

    @classmethod
    def hash_file(cls, file_path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
        return cls(chunk_size=chunk_size).compute_file_hash(file_path)

    @classmethod
    def compare(cls, hash1: str, hash2: str) -> bool:
        return cls().verify_hash(hash1, hash2)
