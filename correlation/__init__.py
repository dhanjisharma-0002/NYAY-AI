"""
NYAYAI - Evidence Correlation & Multi-Evidence Cross-Referencing
Module Lead: Ridhi Masih (Evidence Intelligence Lead)
"""

from .correlation.base import BaseCorrelationEngine
from .correlation.engine import BaselineCorrelationEngine
from .correlation import base, engine

__all__ = ["BaseCorrelationEngine", "BaselineCorrelationEngine", "base", "engine"]
