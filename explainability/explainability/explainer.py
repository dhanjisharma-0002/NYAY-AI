"""
NYAYAI - Baseline Court Admissibility Explainer
Module Lead: Ridhi Mashi (Evidence Intelligence & Chain-of-Custody Engineer)

Transforms statistical and metadata findings into clear judicial explanations.
Strictly respects Rule 13 & 14 by providing confidence levels and documented limitations.
"""

from typing import Dict, Any, List
from .base import BaseExplainer


class BaselineCourtExplainer(BaseExplainer):
    """
    Baseline explainability generator for court records.
    """

    def explain(
        self,
        evidence_id: str,
        forensic_data: Dict[str, Any],
        ai_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        forensic_anomalies = forensic_data.get("anomalies", [])
        ai_tamper = ai_data.get("tamper_detected", False)
        ai_conf = ai_data.get("confidence_score", 0.0)
        ai_findings = ai_data.get("findings", [])

        # Categorize confidence into court-friendly tiers
        if ai_conf >= 0.80:
            category = "HIGH"
        elif ai_conf >= 0.60:
            category = "MEDIUM"
        elif ai_conf >= 0.40:
            category = "LOW"
        else:
            category = "INCONCLUSIVE"

        # Construct clear summary narrative
        factors: List[str] = []
        if forensic_anomalies:
            factors.extend(forensic_anomalies)

        if ai_tamper:
            factors.append(f"AI screening indicates potential anomalies (confidence: {ai_conf:.2f}).")
            factors.extend(ai_findings)
            summary = (
                f"Evidence '{evidence_id}' exhibits forensic or structural anomalies that warrant manual scrutiny. "
                f"Confidence level is categorized as {category}."
            )
        else:
            factors.append("No active tampering patterns flagged during automated screening.")
            summary = (
                f"Evidence '{evidence_id}' shows no obvious automated indicators of tampering. "
                f"Structural format aligns with declared specification."
            )

        limitations = (
            "Automated analysis serves as an investigative screening aid. "
            "Under Bharatiya Sakshya Adhiniyam standards, automated scores must be corroborated by "
            "an accredited forensic expert before final judicial determination."
        )

        return {
            "evidence_id": evidence_id,
            "reasoning_summary": summary,
            "confidence_category": category,
            "confidence_score": ai_conf,
            "contributing_factors": factors,
            "limitations_disclaimer": limitations
        }
