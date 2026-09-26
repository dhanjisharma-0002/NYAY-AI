"""
NYAYAI - Storage Abstraction Exceptions
Module: backend.app.storage.exceptions
"""

from backend.app.utils.exceptions import AppException


class StorageException(AppException):
    """Base exception for storage errors."""
    def __init__(self, message: str, details: dict = None):
        super().__init__(
            message=message,
            status_code=500,
            error_code="STORAGE_ERROR",
            details=details or {}
        )


class StorageFileNotFoundException(StorageException):
    """Raised when an artifact cannot be located in the storage backend."""
    def __init__(self, storage_reference: str):
        super().__init__(
            message=f"Vaulted evidence artifact not found in storage: {storage_reference}",
            details={"storage_reference": storage_reference}
        )
        self.status_code = 404
        self.error_code = "STORAGE_FILE_NOT_FOUND"


class StoragePermissionException(StorageException):
    """Raised when a storage operation violates WORM or permission policies."""
    def __init__(self, message: str):
        super().__init__(
            message=message,
            details={}
        )
        self.status_code = 403
        self.error_code = "STORAGE_POLICY_VIOLATION"


class StorageConfigurationException(StorageException):
    """Raised when cloud or storage driver configuration is invalid."""
    def __init__(self, message: str):
        super().__init__(
            message=message,
            details={}
        )
        self.status_code = 500
        self.error_code = "STORAGE_CONFIGURATION_ERROR"
