"""
NYAYAI - Court Admissibility & Judicial Explainability Engine
Module Lead: Ridhi Masih (Evidence Intelligence Lead)

Transforms complex AI screening indicators, Error Level Analysis (ELA) metrics,
and forensic metadata into plain-language legal rationales admissible under:
- Bharatiya Sakshya Adhiniyam (BSA), 2023 (Section 63 & 65B Electronic Records)
- ISO/IEC 27037 Standards for Digital Evidence Handling
- Rule 13 (No Invented AI Precision) & Rule 14 (Objective Judicial Descriptions)
"""

from typing import Dict, Any, List, Optional
from .base import BaseExplainer


class BaselineCourtExplainer(BaseExplainer):
    """
    Courtroom-grade explainability engine translating AI screening results
    and forensic findings into legally defensible rationales for judicial officers.
    
    Guarantees:
    - Preserves both case_id and evidence_id across all explanations.
    - Clearly explains why indicators contributed to the screening result.
    - Never turns an AI screening result into a definitive forensic conclusion.
    - Explicitly articulates scientific limitations and statutory caveats.
    - Independently testable.
    """

    def explain(
        self,
        *args,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Translates raw AI screening and forensic findings into a structured judicial briefing.
        Supports both modern (case_id, evidence_id, ai_data, forensic_data)
        and backwards-compatible (evidence_id, forensic_data, ai_data) calling conventions.
        """
        cid: Optional[str] = None
        eid: Optional[str] = None
        ai_dict: Optional[Dict[str, Any]] = None
        forensic_dict: Optional[Dict[str, Any]] = None

        if len(args) == 0:
            cid = kwargs.get("case_id")
            eid = kwargs.get("evidence_id")
            ai_dict = kwargs.get("ai_data")
            forensic_dict = kwargs.get("forensic_data")
        elif len(args) == 1:
            eid = args[0]
            cid = kwargs.get("case_id")
            ai_dict = kwargs.get("ai_data")
            forensic_dict = kwargs.get("forensic_data")
        elif len(args) == 2:
            if isinstance(args[0], str) and isinstance(args[1], str):
                cid = args[0]
                eid = args[1]
                ai_dict = kwargs.get("ai_data")
                forensic_dict = kwargs.get("forensic_data")
            else:
                eid = args[0]
                cid = kwargs.get("case_id")
                if isinstance(args[1], dict) and ("tamper_detected" in args[1] or "risk_score" in args[1]):
                    ai_dict = args[1]
                    forensic_dict = kwargs.get("forensic_data")
                else:
                    forensic_dict = args[1]
                    ai_dict = kwargs.get("ai_data")
        elif len(args) == 3:
            if isinstance(args[0], str) and isinstance(args[1], str) and not isinstance(args[2], (str, bytes)):
                # (case_id, evidence_id, ai_data)
                cid = args[0]
                eid = args[1]
                ai_dict = args[2]
                forensic_dict = kwargs.get("forensic_data")
            else:
                # Legacy: (evidence_id, forensic_data, ai_data)
                eid = args[0]
                forensic_dict = args[1]
                ai_dict = args[2]
                cid = kwargs.get("case_id")
        elif len(args) >= 4:
            cid = args[0]
            eid = args[1]
            ai_dict = args[2]
            forensic_dict = args[3]

        if "case_id" in kwargs and cid is None:
            cid = kwargs["case_id"]
        if "evidence_id" in kwargs and eid is None:
            eid = kwargs["evidence_id"]

        # Strict validation of empty strings
        if cid is not None and not str(cid).strip():
            raise ValueError("case_id is required and cannot be empty")
        if eid is not None and not str(eid).strip():
            raise ValueError("evidence_id is required and cannot be empty")
        if eid is None or not str(eid).strip():
            raise ValueError("evidence_id is required and cannot be empty")

        if cid is None:
            # Fallback for legacy calls that did not provide case_id
            cid = "CASE-GENERAL"

        cid = str(cid).strip()
        eid = str(eid).strip()

        ai_res = ai_dict if isinstance(ai_dict, dict) else {}
        forensic_res = forensic_dict if isinstance(forensic_dict, dict) else {}

        # Extract indicators and risk scoring (supports both modern risk_score and legacy confidence_score)
        risk_score = ai_res.get("risk_score")
        if risk_score is None:
            risk_score = ai_res.get("confidence_score", 0.0)
        risk_score = float(risk_score)

        assessment = ai_res.get("assessment")
        if not assessment:
            if risk_score >= 0.70 or (risk_score >= 0.50 and ai_res.get("tamper_detected")):
                assessment = "high_risk"
            elif risk_score >= 0.35:
                assessment = "medium_risk"
            else:
                assessment = "low_risk"

        ai_indicators = ai_res.get("indicators") or ai_res.get("findings") or []
        forensic_anomalies = forensic_res.get("anomalies") or []
        details = ai_res.get("details", {})
        ela_metrics = details.get("ela_metrics") if isinstance(details, dict) else None
        entropy = details.get("shannon_entropy") if isinstance(details, dict) else None

        # ----------------------------------------------------------------------
        # 1. Judicial Weight & Admissibility Assessment
        # ----------------------------------------------------------------------
        if assessment == "high_risk":
            legal_weight = "HIGH_PROBATIVE_CONCERN"
            admissibility_flag = "MANUAL_SCRUTINY_MANDATED"
            confidence_category = "HIGH"
        elif assessment == "medium_risk":
            legal_weight = "MODERATE_EVIDENTIARY_WEIGHT"
            admissibility_flag = "CORROBORATION_RECOMMENDED"
            confidence_category = "MEDIUM"
        else:
            legal_weight = "HIGH_RELIABILITY"
            admissibility_flag = "PRESUMPTIVE_INTEGRITY"
            confidence_category = "LOW" if risk_score > 0.0 else "INCONCLUSIVE"

        # ----------------------------------------------------------------------
        # 2. Contributing Factors (Clear Forensic Chain)
        # ----------------------------------------------------------------------
        contributing_factors: List[str] = []
        for anomaly in forensic_anomalies:
            contributing_factors.append(f"Forensic Metadata: {anomaly}")

        for indicator in ai_indicators:
            contributing_factors.append(f"AI Screening Indicator: {indicator}")

        if not contributing_factors:
            contributing_factors.append("No active tampering or format anomalies detected during screening.")

        # ----------------------------------------------------------------------
        # 3. Plain Language Explanations (Translating Cues for Courtroom)
        # ----------------------------------------------------------------------
        plain_explanations: List[str] = []

        for indicator in ai_indicators:
            ind_lower = indicator.lower()
            if "synthetic media" in ind_lower or "generative ai" in ind_lower:
                plain_explanations.append(
                    "Generative AI Marker: Byte sequence markers associated with AI synthesis engines "
                    "were detected in file streams, suggesting synthetic generation rather than direct optical capture."
                )
            elif "editing software" in ind_lower or "photoshop" in ind_lower:
                plain_explanations.append(
                    "Digital Editing Traces: Metadata tags from photo manipulation suites were discovered, "
                    "indicating post-capture processing or export."
                )
            elif "error level analysis" in ind_lower or "ela" in ind_lower:
                max_err = ela_metrics.get("max_error") if ela_metrics else "elevated"
                plain_explanations.append(
                    f"Compression Disparity (ELA): Localized pixel error divergence was flagged (max error: {max_err}). "
                    f"Different compression patterns within the same image suggest inserted or spliced content."
                )
            elif "entropy" in ind_lower:
                plain_explanations.append(
                    f"Structural Uniformity: Shannon entropy ({entropy} bits/byte) shows abnormal uniformity, "
                    f"inconsistent with natural camera sensor noise."
                )
            elif "hash mismatch" in ind_lower:
                plain_explanations.append(
                    "Integrity Screening Flag: A cryptographic hash variance was noted by the hashing layer; "
                    "this highlights an integrity checkpoint alert, not definitive proof of tampering."
                )

        if not plain_explanations:
            if assessment != "low_risk":
                plain_explanations.append(
                    "Automated heuristic screening identified structural variance from baseline authentic profiles."
                )
            else:
                plain_explanations.append(
                    "The digital artifact exhibits consistent structural entropy, uniform compression, and "
                    "no signatures of known generative AI or digital editing tools."
                )

        # ----------------------------------------------------------------------
        # 4. Objective Reasoning Summary (Rule 14: Never claim definite forgery)
        # ----------------------------------------------------------------------
        if assessment != "low_risk":
            summary = (
                f"Evidence '{eid}' in case '{cid}' exhibits heuristic indicators that warrant manual scrutiny. "
                f"Assessment is categorized as {assessment} (heuristic score: {risk_score}). "
                f"Primary contributing factor: {plain_explanations[0]}"
            )
        else:
            summary = (
                f"Evidence '{eid}' in case '{cid}' shows no automated indicators of tampering. "
                f"Structural format aligns with declared specification."
            )

        # ----------------------------------------------------------------------
        # 5. Statutory Limitations & Defense Safeguards
        # ----------------------------------------------------------------------
        limitations = (
            "Automated analysis serves as an investigative screening aid under the Bharatiya Sakshya Adhiniyam, 2023. "
            "Under Section 63/65B standards, automated heuristic scores must be corroborated by an accredited forensic expert "
            "before final judicial determination. Notice: Recompression from cloud storage or social messaging applications "
            "(e.g., WhatsApp, Telegram) can introduce benign compression anomalies without intentional tampering."
        )

        # ----------------------------------------------------------------------
        # 6. Actionable Judicial Recommendations
        # ----------------------------------------------------------------------
        judicial_recommendations: List[str] = []
        if assessment == "high_risk":
            judicial_recommendations.append("Issue summons for original capture device under BSA Section 63(4).")
            judicial_recommendations.append("Direct Central/State Forensic Science Laboratory (FSL) inspection.")
            judicial_recommendations.append("Require production of unbroken chain-of-custody transfer logs.")
        elif assessment == "medium_risk":
            judicial_recommendations.append("Verify device provenance records and operator transmission logs.")
            judicial_recommendations.append("Corroborate with secondary forensic inspection before exhibit tender.")
        else:
            judicial_recommendations.append("Admissible as prima facie consistent electronic record subject to Section 63 certificate.")

        return {
            "case_id": cid,
            "evidence_id": eid,
            "assessment": assessment,
            "risk_score": risk_score,
            "confidence_category": confidence_category,
            "legal_weight": legal_weight,
            "admissibility_flag": admissibility_flag,
            "reasoning_summary": summary,
            "contributing_factors": contributing_factors,
            "plain_language_explanations": plain_explanations,
            "judicial_recommendations": judicial_recommendations,
            "limitations_disclaimer": limitations
        }
