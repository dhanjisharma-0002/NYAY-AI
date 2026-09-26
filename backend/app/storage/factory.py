"""
NYAYAI - Storage Driver Factory
Module: backend.app.storage.factory
Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

import os
from typing import Optional
from backend.app.config import settings
from .base import BaseStorageDriver
from .local import LocalStorageDriver
from .s3 import S3StorageDriver
from .minio import MinIOStorageDriver
from .exceptions import StorageConfigurationException

_driver_instances = {}


def get_storage_driver(backend_name: Optional[str] = None, force_new: bool = False) -> BaseStorageDriver:
    """
    Factory function returning the active storage driver based on configuration.
    Supported backends: 'local', 's3', 'minio'.
    """
    name = (backend_name or os.getenv("STORAGE_BACKEND") or settings.STORAGE_BACKEND or "local").lower()

    if not force_new and name in _driver_instances:
        return _driver_instances[name]

    if name == "local":
        driver = LocalStorageDriver()
    elif name == "s3":
        driver = S3StorageDriver()
    elif name == "minio":
        driver = MinIOStorageDriver()
    else:
        raise StorageConfigurationException(
            f"Unsupported storage backend '{name}'. Must be one of: 'local', 's3', 'minio'."
        )

    if not force_new:
        _driver_instances[name] = driver

    return driver
