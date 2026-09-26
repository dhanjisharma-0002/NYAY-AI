"""
NYAYAI - Local Filesystem WORM Storage Driver
Module: backend.app.storage.local
Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

import os
import stat
from typing import BinaryIO, Optional, Dict, Any
from backend.app.config import settings
from backend.app.utils.logger import get_logger
from .base import BaseStorageDriver
from .exceptions import (
    StorageException,
    StorageFileNotFoundException,
    StoragePermissionException
)

logger = get_logger("storage_local")


class LocalStorageDriver(BaseStorageDriver):
    """
    Local filesystem storage driver enforcing Write-Once-Read-Many (WORM) constraints.
    """

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = os.path.abspath(base_dir or settings.EVIDENCE_VAULT_PATH)
        os.makedirs(self.base_dir, exist_ok=True)

    def _resolve_path(self, storage_reference: str) -> str:
        """
        Resolves storage reference to an absolute filesystem path.
        Supports both absolute paths and paths relative to base_dir.
        Prevents directory traversal attacks.
        """
        if os.path.isabs(storage_reference):
            target_path = os.path.abspath(storage_reference)
        else:
            clean_rel = os.path.normpath(storage_reference).lstrip("\\/").replace("..", "")
            target_path = os.path.abspath(os.path.join(self.base_dir, clean_rel))

        return target_path

    def store(self, relative_path: str, content: bytes, metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Persists content to local disk with WORM read-only permissions.
        Fails if destination already exists.
        """
        target_path = self._resolve_path(relative_path)

        if os.path.exists(target_path):
            raise StoragePermissionException(
                f"WORM Violation: Evidence file already exists at '{target_path}'. Replacement forbidden."
            )

        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        try:
            with open(target_path, "wb") as f:
                f.write(content)

            # Apply read-only WORM filesystem permissions (0o444)
            try:
                os.chmod(target_path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
            except Exception as perm_err:
                logger.warning(f"Could not set read-only permissions on '{target_path}': {perm_err}")

            logger.info(f"Artifact stored successfully in local WORM vault: {target_path}")
            return target_path

        except Exception as e:
            if isinstance(e, StoragePermissionException):
                raise
            raise StorageException(f"Failed to write file to local vault: {str(e)}")

    def retrieve(self, storage_reference: str) -> bytes:
        """
        Reads binary file contents in strict read-only mode ('rb').
        """
        target_path = self._resolve_path(storage_reference)
        if not os.path.isfile(target_path):
            raise StorageFileNotFoundException(storage_reference)

        try:
            with open(target_path, "rb") as f:
                return f.read()
        except PermissionError as pe:
            # Handle if file permission forbids read (should rarely happen with 0o444)
            raise StorageException(f"Permission denied reading file: {str(pe)}")
        except Exception as e:
            raise StorageException(f"Error reading file from storage: {str(e)}")

    def retrieve_stream(self, storage_reference: str) -> BinaryIO:
        """
        Opens a readable binary stream for the artifact.
        """
        target_path = self._resolve_path(storage_reference)
        if not os.path.isfile(target_path):
            raise StorageFileNotFoundException(storage_reference)

        return open(target_path, "rb")

    def exists(self, storage_reference: str) -> bool:
        """
        Checks whether file exists.
        """
        target_path = self._resolve_path(storage_reference)
        return os.path.isfile(target_path)

    def get_size(self, storage_reference: str) -> int:
        """
        Returns size in bytes.
        """
        target_path = self._resolve_path(storage_reference)
        if not os.path.isfile(target_path):
            raise StorageFileNotFoundException(storage_reference)
        return os.path.getsize(target_path)

    def get_local_path(self, storage_reference: str) -> Optional[str]:
        """
        Returns resolved local filesystem path.
        """
        return self._resolve_path(storage_reference)
