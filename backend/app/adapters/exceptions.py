"""
NYAYAI - Forensic & AI Engine Adapter Exceptions
Module: backend.app.adapters.exceptions
Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

from backend.app.utils.exceptions import AppException


class EngineUnavailableException(AppException):
    """Raised when the forensic or AI inference engine cannot be reached or is offline."""
    def __init__(self, engine_name: str, message: str = "Analysis engine is currently offline or unreachable"):
        super().__init__(
            message=f"{engine_name}: {message}",
            status_code=503,
            error_code="ENGINE_UNAVAILABLE",
            details={"engine": engine_name}
        )


class EngineTimeoutException(AppException):
    """Raised when an analysis engine exceeds the maximum processing timeout."""
    def __init__(self, engine_name: str, timeout_seconds: float = 30.0):
        super().__init__(
            message=f"{engine_name} timed out after {timeout_seconds} seconds without producing an artifact.",
            status_code=504,
            error_code="ENGINE_TIMEOUT",
            details={"engine": engine_name, "timeout_seconds": timeout_seconds}
        )


class InvalidEngineResponseException(AppException):
    """Raised when an engine returns malformed or non-contract-compliant output."""
    def __init__(self, engine_name: str, details: str):
        super().__init__(
            message=f"{engine_name} returned invalid or malformed output structure: {details}",
            status_code=502,
            error_code="INVALID_ENGINE_RESPONSE",
            details={"engine": engine_name, "reason": details}
        )


class UnsupportedMediaException(AppException):
    """Raised when an engine does not support the given media type."""
    def __init__(self, media_type: str, supported_types: list = None):
        super().__init__(
            message=f"Media type '{media_type}' is not supported by the requested analysis engine.",
            status_code=415,
            error_code="UNSUPPORTED_MEDIA_TYPE",
            details={"media_type": media_type, "supported_types": supported_types or []}
        )


class AnalysisFailureException(AppException):
    """Raised when an engine encounters an internal unrecoverable failure during inference."""
    def __init__(self, engine_name: str, error_details: str):
        super().__init__(
            message=f"{engine_name} failed during analysis: {error_details}",
            status_code=500,
            error_code="ANALYSIS_FAILED",
            details={"engine": engine_name, "error": error_details}
        )
