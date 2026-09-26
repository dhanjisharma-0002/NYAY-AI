"""
NYAYAI - Centralized Error Handler Middleware
Module: backend.app.middleware.error_handler

Enforces:
- Consistent API error response: status, message, error_code
- Zero exposure of internal stack traces to clients
"""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from backend.app.utils.exceptions import AppException
from backend.app.utils.logger import get_logger

logger = get_logger("error_handler")


def register_error_handlers(app: FastAPI) -> None:
    """Registers standard exception handlers on the FastAPI application."""

    @app.exception_handler(AppException)
    async def app_exception_handler(request: Request, exc: AppException):
        logger.warning(
            f"AppException: {exc.error_code} - {exc.message} on {request.method} {request.url.path}"
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "status": exc.status_code,
                "message": exc.message,
                "error_code": exc.error_code,
                "success": False,
                "error": {
                    "code": exc.error_code,
                    "message": exc.message,
                    "details": exc.details
                }
            }
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        # Derive error_code from HTTP status
        code_map = {
            400: "BAD_REQUEST",
            401: "UNAUTHORIZED",
            403: "FORBIDDEN",
            404: "NOT_FOUND",
            405: "METHOD_NOT_ALLOWED",
            409: "CONFLICT",
            422: "UNPROCESSABLE_ENTITY",
            500: "INTERNAL_SERVER_ERROR"
        }
        error_code = code_map.get(exc.status_code, f"HTTP_{exc.status_code}")
        message = str(exc.detail) if exc.detail else "An HTTP error occurred."

        logger.warning(f"HTTPException: {exc.status_code} - {message} on {request.method} {request.url.path}")

        return JSONResponse(
            status_code=exc.status_code,
            content={
                "status": exc.status_code,
                "message": message,
                "error_code": error_code,
                "success": False,
                "error": {
                    "code": error_code,
                    "message": message
                }
            }
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        # Format validation error messages without leaking internals
        errors = []
        for err in exc.errors():
            loc = " -> ".join([str(l) for l in err.get("loc", [])])
            msg = err.get("msg", "Invalid value")
            errors.append(f"{loc}: {msg}")
        message = "Validation failed: " + "; ".join(errors) if errors else "Invalid request payload."

        logger.info(f"Validation error on {request.method} {request.url.path}: {message}")

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "status": status.HTTP_422_UNPROCESSABLE_ENTITY,
                "message": message,
                "error_code": "VALIDATION_ERROR",
                "success": False,
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": message,
                    "details": {"validation_errors": errors}
                }
            }
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        # Log complete stack trace internally for developers
        logger.error(
            f"Unhandled exception processing {request.method} {request.url.path}: {str(exc)}",
            exc_info=True
        )
        # Never expose internal stack traces to clients
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "message": "An internal server error occurred. Please contact the system administrator.",
                "error_code": "INTERNAL_SERVER_ERROR",
                "success": False,
                "error": {
                    "code": "INTERNAL_SERVER_ERROR",
                    "message": "An internal server error occurred."
                }
            }
        )
