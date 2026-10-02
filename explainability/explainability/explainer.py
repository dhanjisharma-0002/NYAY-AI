"""
NYAYAI - Advanced Court Admissibility & Judicial Explainability Engine
Module Lead: Ridhi Masih (Evidence Intelligence Lead)

Transforms complex machine learning indicators, Error Level Analysis (ELA) metrics,
and forensic metadata into plain-language legal rationales admissible under:
- Bharatiya Sakshya Adhiniyam (BSA), 2023 (Section 63 & 65B Electronic Records)
- ISO/IEC 27037 Standards for Digital Evidence Handling
- Rule 13 (No Invented AI Precision) & Rule 14 (Objective Judicial Descriptions)
"""

from typing import Dict, Any, List, Optional
from .base import BaseExplainer


class BaselineCourtExplainer(BaseExplainer):
    """
    Courtroom-grade explainability engine translating multi-modal forensic findings
    and AI inference into legally defensible rationales for judges, prosecutors, and advocates.
    """

    def explain(
        self,
        evidence_id: str,
        forensic_data: Dict[str, Any],
        ai_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Translates raw forensic metadata and AI inference outputs into a structured judicial briefing.
        """
        forensic_anomalies = forensic_data.get("anomalies", [])
        ai_tamper = ai_data.get("tamper_detected", False)
        ai_conf = float(ai_data.get("confidence_score", 0.50))
        ai_findings = ai_data.get("findings", [])
        details = ai_data.get("details", {})
        tamper_flags = details.get("tamper_flags", [])
        ela_metrics = details.get("ela_metrics")
        entropy = details.get("shannon_entropy")

        # ----------------------------------------------------------------------
        # 1. Judicial Confidence & Probative Weight Tiering
        # ----------------------------------------------------------------------
        if ai_conf >= 0.80:
            category = "HIGH"
            legal_weight = "HIGH_PROBATIVE_CONCERN" if ai_tamper else "HIGH_RELIABILITY"
            admissibility_flag = "MANUAL_SCRUTINY_MANDATED" if ai_tamper else "PRESUMPTIVE_INTEGRITY"
        elif ai_conf >= 0.60:
            category = "MEDIUM"
            legal_weight = "MODERATE_EVIDENTIARY_WEIGHT"
            admissibility_flag = "CORROBORATION_RECOMMENDED"
        elif ai_conf >= 0.40:
            category = "LOW"
            legal_weight = "LOW_PROBATIVE_WEIGHT"
            admissibility_flag = "INCONCLUSIVE_RESCREEN_REQUIRED"
        else:
            category = "INCONCLUSIVE"
            legal_weight = "INSUFFICIENT_TECHNICAL_BASIS"
            admissibility_flag = "NOT_ADMISSIBLE_WITHOUT_RETEST"

        # ----------------------------------------------------------------------
        # 2. Contributing Factors Assembly (Clear Forensic Chain)
        # ----------------------------------------------------------------------
        factors: List[str] = []
        if forensic_anomalies:
            factors.extend(forensic_anomalies)

        if ai_tamper:
            factors.append(f"AI screening flagged potential manipulation (calibrated confidence: {ai_conf:.2f}).")
            factors.extend(ai_findings)
        else:
            factors.append("Automated screening identified no active manipulation patterns.")

        # ----------------------------------------------------------------------
        # 3. Plain Language Judicial Narrative
        # ----------------------------------------------------------------------
        plain_explanations: List[str] = []

        if "GENERATIVE_AI_MARKER" in tamper_flags:
            plain_explanations.append(
                "Synthetic Media Alert: Binary markers associated with generative AI synthesis models "
                "were identified in the file metadata. This suggests the image was synthesized, "
                "in-painted, or hallucinated using AI rather than captured directly from a physical sensor."
            )

        if "EDITING_SOFTWARE_METADATA" in tamper_flags:
            plain_explanations.append(
                "Digital Editing Traces: Metadata tags from photo editing suites (e.g., Adobe Photoshop, GIMP) "
                "were discovered. This indicates post-capture manipulation or re-export outside of original device custody."
            )

        if "ELA_LOCALIZED_DISPARITY" in tamper_flags and ela_metrics:
            plain_explanations.append(
                f"Error Level Analysis (ELA) Discrepancy: Localized compression variance was flagged "
                f"(max compression error: {ela_metrics.get('max_error')}, std: {ela_metrics.get('std_error')}). "
                f"In forensic physics, when an image is modified, inserted elements carry different compression "
                f"characteristics than the authentic background."
            )

        if "ANOMALOUS_LOW_ENTROPY" in tamper_flags and entropy is not None:
            plain_explanations.append(
                f"Structural Uniformity Anomaly: Shannon entropy is {entropy:.2f} bits/byte, which is abnormally low. "
                f"Authentic digital photos contain optical noise with higher entropy. Low entropy suggests "
                f"artificial flattening, blank masking, or synthesized fill."
            )

        if not plain_explanations:
            if ai_tamper:
                plain_explanations.append(
                    "Algorithmic screening identified variance from standard baseline authentic profiles."
                )
            else:
                plain_explanations.append(
                    "The digital artifact exhibits consistent structural entropy, uniform compression, and "
                    "no signatures of known generative or editing software."
                )

        # ----------------------------------------------------------------------
        # 4. Summary Formulation
        # ----------------------------------------------------------------------
        if ai_tamper:
            summary = (
                f"Evidence '{evidence_id}' exhibits forensic or structural anomalies that warrant manual scrutiny. "
                f"Confidence level is categorized as {category}. "
                f"Primary indicator: {plain_explanations[0]}"
            )
        else:
            summary = (
                f"Evidence '{evidence_id}' shows no obvious automated indicators of tampering. "
                f"Structural format aligns with declared specification."
            )

        # ----------------------------------------------------------------------
        # 5. Statutory Limitations & Defense Safeguards (Rule 14 & BSA 2023)
        # ----------------------------------------------------------------------
        limitations = (
            "Automated analysis serves as an investigative screening aid under the Bharatiya Sakshya Adhiniyam, 2023. "
            "Under Section 63/65B standards, automated scores must be corroborated by an accredited forensic expert "
            "before final judicial determination. Notice: Recompression from cloud storage or social messaging applications "
            "(e.g., WhatsApp, Telegram) can introduce benign compression anomalies without intentional tampering."
        )

        # ----------------------------------------------------------------------
        # 6. Actionable Judicial Recommendations
        # ----------------------------------------------------------------------
        judicial_recommendations: List[str] = []
        if ai_tamper:
            judicial_recommendations.append("Issue summons for original capture device under BSA Section 63(4).")
            judicial_recommendations.append("Direct Central/State Forensic Science Laboratory (FSL) inspection.")
            judicial_recommendations.append("Require production of unbroken chain-of-custody transfer logs.")
        else:
            judicial_recommendations.append("Admissible as prima facie consistent electronic record subject to Section 63 certificate.")

        return {
            "evidence_id": evidence_id,
            "reasoning_summary": summary,
            "confidence_category": category,
            "confidence_score": ai_conf,
            "legal_weight": legal_weight,
            "admissibility_flag": admissibility_flag,
            "contributing_factors": factors,
            "plain_language_explanations": plain_explanations,
            "judicial_recommendations": judicial_recommendations,
            "limitations_disclaimer": limitations
        }
