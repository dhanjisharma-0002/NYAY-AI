"""
NYAYAI - Court Admissibility Report Engine Package
Module Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

from .base import BaseReportGenerator
from .generator import CourtAdmissibilityReportGenerator

__all__ = ["BaseReportGenerator", "CourtAdmissibilityReportGenerator"]
