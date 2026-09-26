"""
NYAYAI - Storage Abstraction Package
Module: backend.app.storage
Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

from .base import BaseStorageDriver
from .local import LocalStorageDriver
from .s3 import S3StorageDriver
from .minio import MinIOStorageDriver
from .factory import get_storage_driver
from .exceptions import (
    StorageException,
    StorageFileNotFoundException,
    StoragePermissionException,
    StorageConfigurationException
)

__all__ = [
    "BaseStorageDriver",
    "LocalStorageDriver",
    "S3StorageDriver",
    "MinIOStorageDriver",
    "get_storage_driver",
    "StorageException",
    "StorageFileNotFoundException",
    "StoragePermissionException",
    "StorageConfigurationException"
]
