"""
NYAYAI - Structured Application Logging with Redaction Filter
Module: backend.app.utils.logger

Enforces strict redaction of:
- passwords / hashes
- tokens / JWTs / bearer tokens
- API keys / secret keys
- private credentials
- raw sensitive evidence contents / bytes
"""

import json
import logging
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict

# Regex pattern matching sensitive key names
SENSITIVE_KEY_PATTERN = re.compile(
    r"(password|passwd|pwd|token|access_token|refresh_token|bearer|jwt|"
    r"api[_-]?key|secret|private[_-]?key|credential|auth_header|"
    r"evidence_payload|raw_evidence|raw_bytes|file_bytes)",
    re.IGNORECASE
)

# Regex pattern matching Bearer tokens in text
BEARER_PATTERN = re.compile(r"Bearer\s+([A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE)


def redact_sensitive_data(data: Any) -> Any:
    """Recursively traverses data structures and redacts sensitive keys and values."""
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if isinstance(v, bytes):
                cleaned[k] = f"[BINARY_DATA: {len(v)} bytes REDACTED]"
            elif SENSITIVE_KEY_PATTERN.search(str(k)):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = redact_sensitive_data(v)
        return cleaned
    elif isinstance(data, (list, tuple, set)):
        return [redact_sensitive_data(item) for item in data]
    elif isinstance(data, str):
        # Redact embedded bearer tokens
        cleaned_str = BEARER_PATTERN.sub("Bearer [REDACTED]", data)
        return cleaned_str
    elif isinstance(data, bytes):
        # Never log raw binary evidence
        return f"[BINARY_DATA: {len(data)} bytes REDACTED]"
    return data


class SensitiveDataFilter(logging.Filter):
    """Logging filter that sanitizes records before they are emitted."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = BEARER_PATTERN.sub("Bearer [REDACTED]", record.msg)
            # Redact common key=value patterns in log strings
            record.msg = re.sub(
                r"(?i)(password|token|key|secret)=([^\s&]+)",
                r"\1=[REDACTED]",
                record.msg
            )
        elif isinstance(record.msg, (dict, list)):
            record.msg = redact_sensitive_data(record.msg)

        if record.args:
            if isinstance(record.args, dict):
                record.args = redact_sensitive_data(record.args)
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(redact_sensitive_data(list(record.args)))
        return True


class JsonFormatter(logging.Formatter):
    """Outputs log events as structured JSON."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "request_id"):
            log_obj["request_id"] = record.request_id
        if hasattr(record, "extra_data"):
            log_obj["data"] = redact_sensitive_data(record.extra_data)
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)


def get_logger(name: str = "nyayai") -> logging.Logger:
    """Provides a configured structured logger with sensitive data filtering."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        handler.addFilter(SensitiveDataFilter())
        formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.propagate = False
    return logger
