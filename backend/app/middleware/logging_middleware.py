"""
NYAYAI - Structured Request Logging Middleware
Module: backend.app.middleware.logging_middleware
"""

import time
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from backend.app.utils.logger import get_logger

logger = get_logger("http_access")


class LoggingMiddleware(BaseHTTPMiddleware):
    """Logs incoming HTTP requests and responses with latency, masking sensitive headers."""

    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.perf_counter()
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

        # Mask client IP and query parameters if needed
        client_host = request.client.host if request.client else "unknown"
        method = request.method
        path = request.url.path

        try:
            response = await call_next(request)
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            # Attach request ID to response header
            response.headers["X-Request-ID"] = request_id

            logger.info(
                f"{method} {path} -> {response.status_code} [{duration_ms:.2f}ms] (client: {client_host})",
                extra={"request_id": request_id}
            )
            return response
        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error(
                f"{method} {path} -> FAILED [{duration_ms:.2f}ms] (client: {client_host})",
                extra={"request_id": request_id}
            )
            raise exc
