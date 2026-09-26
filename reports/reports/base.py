"""
NYAYAI - Court Report Generator Interface Contract
Module Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List


class BaseReportGenerator(ABC):
    """
    Abstract interface for generating legal admissibility certificates and tamper-evident QR codes.
    """

    @abstractmethod
    def generate_report(
        self,
        case_data: Dict[str, Any],
        evidence_items: List[Dict[str, Any]],
        custody_ledgers: Dict[str, List[Dict[str, Any]]],
        certifying_officer: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generates court certificate, computes its SHA-256 hash, and generates QR code data.
        """
        pass
