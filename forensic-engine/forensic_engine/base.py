"""
NYAYAI - Forensic Analyzer Interface Contract
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)
"""

from abc import ABC, abstractmethod
from typing import Dict, Any


class BaseForensicAnalyzer(ABC):
    """
    Abstract interface for forensic engines.
    Adheres to:
    - Rule 2: Never overwrite original evidence files.
    - Rule 7: Evidence integrity must use SHA-256.
    - Rule 14: Do not claim forensic certainty without evidence.
    """

    @abstractmethod
    def calculate_sha256(self, file_path: str) -> str:
        """Calculate deterministic SHA-256 hash using streaming chunks."""
        pass

    @abstractmethod
    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract EXIF, filesystem timestamps, and header attributes."""
        pass

    @abstractmethod
    def verify_file_signature(self, file_path: str, declared_mime: str) -> Dict[str, Any]:
        """Verify magic bytes against declared MIME type to detect extension spoofing."""
        pass
