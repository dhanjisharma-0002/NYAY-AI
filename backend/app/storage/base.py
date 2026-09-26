"""
NYAYAI - Base Storage Driver Interface
Module: backend.app.storage.base
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Defines unified interface for:
- Local filesystem (WORM mode)
- AWS S3-compatible cloud storage
- MinIO object storage
"""

from abc import ABC, abstractmethod
from typing import BinaryIO, Optional, Dict, Any
from .exceptions import StoragePermissionException


class BaseStorageDriver(ABC):
    """
    Abstract interface for evidence storage backends.
    Enforces Write-Once-Read-Many (WORM) semantics across all drivers.
    """

    @abstractmethod
    def store(self, relative_path: str, content: bytes, metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Persists content to storage at relative_path.
        Returns canonical storage_reference.
        Must enforce write-once guarantee (rejecting overwrite if already exists).
        """
        pass

    @abstractmethod
    def retrieve(self, storage_reference: str) -> bytes:
        """
        Retrieves raw binary content for given storage_reference.
        Must open and read in strict read-only mode without mutating the file.
        """
        pass

    @abstractmethod
    def retrieve_stream(self, storage_reference: str) -> BinaryIO:
        """
        Returns a readable binary stream for the artifact.
        """
        pass

    @abstractmethod
    def exists(self, storage_reference: str) -> bool:
        """
        Checks whether the storage_reference currently exists in storage.
        """
        pass

    @abstractmethod
    def get_size(self, storage_reference: str) -> int:
        """
        Returns size in bytes of the stored artifact.
        """
        pass

    @abstractmethod
    def get_local_path(self, storage_reference: str) -> Optional[str]:
        """
        Returns local filesystem path if available, or None if remote-only.
        """
        pass

    def delete(self, storage_reference: str) -> bool:
        """
        Strict WORM compliance: Evidence files must NEVER be deleted.
        """
        raise StoragePermissionException(
            f"WORM Compliance Violation: Deletion of evidence artifacts is strictly prohibited ({storage_reference})."
        )
