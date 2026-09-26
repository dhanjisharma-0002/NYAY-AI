"""
NYAYAI - Custom Application Exceptions
Module: backend.app.utils.exceptions
"""

from typing import Optional, Any, Dict


class AppException(Exception):
    """Base application exception with standardized error details."""

    def __init__(
        self,
        message: str,
        status_code: int = 500,
        error_code: str = "INTERNAL_SERVER_ERROR",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details or {}


class EntityNotFoundException(AppException):
    def __init__(self, entity_name: str, identifier: str):
        super().__init__(
            message=f"{entity_name} '{identifier}' was not found.",
            status_code=404,
            error_code=f"{entity_name.upper()}_NOT_FOUND",
            details={"entity": entity_name, "identifier": identifier}
        )


class IntegrityException(AppException):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            status_code=409,
            error_code="EVIDENCE_INTEGRITY_VIOLATION",
            details=details
        )


class AuthenticationException(AppException):
    def __init__(self, message: str = "Invalid or expired authentication credentials."):
        super().__init__(
            message=message,
            status_code=401,
            error_code="AUTHENTICATION_FAILED"
        )


class PermissionDeniedException(AppException):
    def __init__(self, message: str = "Insufficient permissions to perform this action."):
        super().__init__(
            message=message,
            status_code=403,
            error_code="PERMISSION_DENIED"
        )


class ValidationException(AppException):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            status_code=422,
            error_code="VALIDATION_ERROR",
            details=details
        )
