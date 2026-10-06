
"""Standardized forensic analysis report model."""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ForensicReport:
    """Represent consolidated findings from forensic evidence analysis."""

    evidence_id: str
    file_path: str
    sha256: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    integrity: Dict[str, Any] = field(default_factory=dict)
    image_analysis: Dict[str, Any] = field(default_factory=dict)
    anomalies: List[str] = field(default_factory=list)

    def add_anomaly(self, message: str) -> None:
        """Add a forensic anomaly without modifying existing findings."""
        if message and message not in self.anomalies:
            self.anomalies.append(message)

    def to_dict(self) -> Dict[str, Any]:
        """Return the forensic report as a serializable dictionary."""
        return {
            "evidence_id": self.evidence_id,
            "file_path": self.file_path,
            "sha256": self.sha256,
            "metadata": self.metadata,
            "integrity": self.integrity,
            "image_analysis": self.image_analysis,
            "anomalies": list(self.anomalies),
        }
