"""
NYAYAI - Engine Adapters Package
Module: backend.app.adapters
Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

from .base import BaseForensicEngineAdapter, BaseAIEngineAdapter
from .forensic_adapter import ForensicEngineAdapter
from .ai_adapter import AIEngineAdapter
from .mock_adapter import MockForensicEngineAdapter, MockAIEngineAdapter
from .exceptions import (
    EngineUnavailableException,
    EngineTimeoutException,
    InvalidEngineResponseException,
    UnsupportedMediaException,
    AnalysisFailureException
)

__all__ = [
    "BaseForensicEngineAdapter",
    "BaseAIEngineAdapter",
    "ForensicEngineAdapter",
    "AIEngineAdapter",
    "MockForensicEngineAdapter",
    "MockAIEngineAdapter",
    "EngineUnavailableException",
    "EngineTimeoutException",
    "InvalidEngineResponseException",
    "UnsupportedMediaException",
    "AnalysisFailureException"
]
