"""
NYAYAI - Forensic Report Integration
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Integrates evidence comparison findings into a ForensicReport.

This module does not modify original evidence files.
"""

from typing import Any, Dict

from .forensic_report import ForensicReport


class ForensicReportIntegrator:
    """Integrate forensic comparison findings into a report."""

    def add_comparison_findings(
        self,
        report: ForensicReport,
        comparison_result: Dict[str, Any],
    ) -> ForensicReport:
        """
        Add evidence comparison differences to a forensic report.
        """
        differences = comparison_result.get("differences", [])

        for difference in differences:
            report.add_anomaly(
                f"Evidence comparison: {difference}"
            )

        return report
