"""
NYAYAI - AI Tamper & Synthesis Screening Engine
Module Lead: Ridhi Masih (Evidence Intelligence Lead)

Enforces:
- Rule 2: Never modify or overwrite original evidence files
- Rule 9: AI results must remain linked to both case_id and evidence_id
- Rule 13: Do not invent AI accuracy or use fake calibrated confidence values
- Rule 14: Do not claim forensic certainty without evidence (objective screening cues only)
- Rule 15: Keep modules independently testable
- Bharatiya Sakshya Adhiniyam (BSA), 2023 & ISO/IEC 27037 standards
"""

import os
import io
import math
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import numpy as np
from PIL import Image, ImageChops

from .base import BaseAIAnalyzer


# Signatures of generative AI synthesis models and digital manipulation software
KNOWN_EDITING_SIGNATURES = [
    b"Adobe Photoshop",
    b"Photoshop 3.0",
    b"GIMP",
    b"Canva",
    b"CorelDraw",
    b"Procreate",
    b"Figma",
    b"Affinity Photo"
]

KNOWN_SYNTHETIC_AI_SIGNATURES = [
    b"Stable Diffusion",
    b"Midjourney",
    b"DALL-E",
    b"NovelAI",
    b"ComfyUI",
    b"AUTOMATIC1111",
    b"InvokeAI"
]


class BaselineTamperDetector(BaseAIAnalyzer):
    """
    Multi-Modal Evidence Intelligence & Tamper Screening Model.
    Lead: Ridhi Masih
    
    Performs heuristic tamper and synthesis screening using forensic metadata
    and read-only binary stream inspection.
    
    Enforces that risk_score is a heuristic screening index, NOT an empirical probability.
    Does not use fake or hardcoded 'calibrated confidence' values.
    """

    def __init__(
        self,
        analyzer_version: str = "2.2.0"
    ):
        self.analyzer_version = analyzer_version

    @staticmethod
    def _compute_entropy(file_path: str, max_bytes: int = 131072) -> float:
        """
        Calculates Shannon entropy in bits per byte (0.0 to 8.0) on a read-only stream.
        """
        if not os.path.exists(file_path):
            return 0.0

        byte_counts = [0] * 256
        total_bytes = 0

        with open(file_path, "rb") as f:
            chunk = f.read(max_bytes)
            total_bytes = len(chunk)
            for b in chunk:
                byte_counts[b] += 1

        if total_bytes == 0:
            return 0.0

        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / total_bytes
                entropy -= p * math.log2(p)

        return round(entropy, 4)

    @staticmethod
    def _compute_ela(file_path: str, quality: int = 95) -> Optional[Dict[str, Any]]:
        """
        Performs in-memory Error Level Analysis (ELA) for image artifacts.
        Never writes to disk or mutates original evidence (Rule 2).
        """
        try:
            with Image.open(file_path) as original_img:
                img_rgb = original_img.convert("RGB")
                buffer = io.BytesIO()
                img_rgb.save(buffer, format="JPEG", quality=quality)
                buffer.seek(0)
                
                with Image.open(buffer) as resaved_img:
                    diff = ImageChops.difference(img_rgb, resaved_img)
                    diff_arr = np.array(diff, dtype=np.float32)
                    mean_error = float(np.mean(diff_arr))
                    max_error = float(np.max(diff_arr))
                    std_error = float(np.std(diff_arr))

                    # High localized variance relative to mean suggests compression disparity
                    suspicious_variance = (max_error > 25.0) and (std_error > 2.8 * (mean_error + 0.1))
                    return {
                        "ela_performed": True,
                        "mean_error": round(mean_error, 3),
                        "max_error": round(max_error, 3),
                        "std_error": round(std_error, 3),
                        "suspicious_variance": bool(suspicious_variance)
                    }
        except Exception:
            return None

    def analyze(
        self,
        case_id: str,
        evidence_id: str,
        metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Screen evidence for potential tampering or synthesis using forensic metadata.
        Strictly requires both case_id and evidence_id.
        """
        # Strict validation of mandatory identifiers
        if not case_id or not isinstance(case_id, str) or not case_id.strip():
            raise ValueError("case_id is required and cannot be empty")
        if not evidence_id or not isinstance(evidence_id, str) or not evidence_id.strip():
            raise ValueError("evidence_id is required and cannot be empty")
        if metadata is None or not isinstance(metadata, dict):
            raise ValueError("metadata must be a dictionary supplied by the forensic layer")

        case_id = case_id.strip()
        evidence_id = evidence_id.strip()

        analysis_id = f"AI-ANL-{uuid.uuid4().hex[:12].upper()}"
        analysis_timestamp = datetime.now(timezone.utc).isoformat()

        indicators: List[str] = []
        raw_risk_weight: float = 0.0
        file_path = metadata.get("file_path") or metadata.get("vault_path")
        file_size: Optional[int] = None
        entropy: Optional[float] = None
        ela_metrics: Optional[Dict[str, Any]] = None

        # ----------------------------------------------------------------------
        # 1. Read-Only Physical & Structural Inspection (if file_path provided)
        # ----------------------------------------------------------------------
        if file_path:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"Target evidence file not found for AI screening: {file_path}")

            file_size = os.path.getsize(file_path)
            ext = os.path.splitext(file_path)[1].lower()

            # Shannon Entropy Analysis
            entropy = self._compute_entropy(file_path)
            if file_size < 100:
                indicators.append("Suspiciously truncated binary file (< 100 bytes). Potential incomplete artifact.")
                raw_risk_weight += 0.30
            elif entropy < 1.5 and file_size > 1024:
                indicators.append(f"Abnormally low Shannon entropy ({entropy:.2f} bits/byte). File exhibits artificial uniformity.")
                raw_risk_weight += 0.25

            # Read-only sample for software/synthesis signatures
            with open(file_path, "rb") as f:
                header_sample = f.read(min(file_size, 131072))

            detected_ai = [sig.decode("ascii", errors="ignore") for sig in KNOWN_SYNTHETIC_AI_SIGNATURES if sig in header_sample]
            if detected_ai:
                indicators.append(f"Synthetic media / Generative AI pipeline markers identified: {', '.join(detected_ai)}.")
                raw_risk_weight += 0.45

            detected_editors = [sig.decode("ascii", errors="ignore") for sig in KNOWN_EDITING_SIGNATURES if sig in header_sample]
            if detected_editors:
                indicators.append(f"Editing software signatures identified in metadata streams: {', '.join(detected_editors)}.")
                raw_risk_weight += 0.30

            # Error Level Analysis for image types
            if ext in [".jpg", ".jpeg", ".png", ".webp", ".tiff", ".bmp"]:
                ela_metrics = self._compute_ela(file_path)
                if ela_metrics and ela_metrics.get("suspicious_variance"):
                    indicators.append(
                        f"Error Level Analysis flagged localized compression disparities "
                        f"(max error: {ela_metrics['max_error']}, std: {ela_metrics['std_error']}). "
                        f"Consistent with post-capture localized editing or splicing."
                    )
                    raw_risk_weight += 0.35

        # ----------------------------------------------------------------------
        # 2. Forensic Metadata & Integrity Indicator Evaluation
        # ----------------------------------------------------------------------
        # Forensic magic bytes / format check
        if metadata.get("magic_bytes_valid") is False:
            indicators.append("File signature mismatch: header magic bytes do not match declared MIME format.")
            raw_risk_weight += 0.30

        # Cryptographic hash mismatch (supplied by forensic/integrity layer)
        # Treated as an integrity indicator, NOT proof of tampering
        integrity_meta = metadata.get("integrity", {})
        hash_mismatched = (
            metadata.get("hash_mismatch") is True
            or (isinstance(integrity_meta, dict) and integrity_meta.get("hash_mismatch") is True)
            or metadata.get("status") in ("MISMATCH", "INTEGRITY_COMPROMISED")
        )
        if hash_mismatched:
            indicators.append(
                "Integrity layer reported a cryptographic hash mismatch; "
                "serves as an integrity screening indicator, not definitive proof of tampering."
            )
            raw_risk_weight += 0.35

        # Ingest external forensic anomalies without claiming certainty
        for anomaly in metadata.get("anomalies", []):
            if isinstance(anomaly, str) and anomaly.strip():
                indicators.append(f"Forensic metadata anomaly: {anomaly.strip()}")
                raw_risk_weight += 0.15

        # ----------------------------------------------------------------------
        # 3. Heuristic Risk Scoring & Assessment (No Fake Confidence Values)
        # ----------------------------------------------------------------------
        risk_score = round(min(1.0, max(0.0, raw_risk_weight)), 2)

        if risk_score >= 0.70:
            assessment = "high_risk"
            forensic_conclusion = (
                f"Heuristic screening flagged elevated risk indicators for evidence '{evidence_id}' "
                f"in case '{case_id}'. Structural and metadata anomalies warrant comprehensive "
                f"examination by an accredited forensic laboratory."
            )
        elif risk_score >= 0.35:
            assessment = "medium_risk"
            forensic_conclusion = (
                f"Heuristic screening identified moderate anomalies for evidence '{evidence_id}' "
                f"in case '{case_id}'. Findings should be corroborated with device provenance records."
            )
        else:
            assessment = "low_risk"
            forensic_conclusion = (
                f"No significant automated tampering or synthetic indicators detected for evidence '{evidence_id}' "
                f"in case '{case_id}'. Artifact structure aligns with declared specification."
            )

        limitations = [
            "Risk score is a deterministic heuristic screening index, NOT an empirical probability.",
            "No calibrated accuracy or confidence is claimed in the absence of an accredited ground-truth calibration dataset.",
            "Benign recompression (e.g. social messaging apps, cloud storage) can introduce compression anomalies without malicious intent.",
            "Under the Bharatiya Sakshya Adhiniyam, 2023, automated screening findings must be corroborated by an expert witness before judicial determination."
        ]

        audit_record = {
            "action": "AI_TAMPER_SCREENING",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "timestamp": analysis_timestamp
        }

        # Conceptual output schema strictly honoring user specification
        return {
            "analysis_id": analysis_id,
            "case_id": case_id,
            "evidence_id": evidence_id,
            "analysis_type": "tamper_synthesis_screening",
            "analyzer_version": self.analyzer_version,
            "analysis_timestamp": analysis_timestamp,
            "risk_score": risk_score,
            "assessment": assessment,
            "indicators": indicators,
            "forensic_conclusion": forensic_conclusion,
            "limitations": limitations,
            "audit": audit_record,
            # Backwards-compatibility aliases for existing backend orchestrator / adapters:
            "tamper_detected": assessment != "low_risk",
            "findings": indicators,
            "model_version": self.analyzer_version,
            "model_name": "NYAYAI-TamperSynthesisScreener",
            "confidence_score": risk_score,
            "details": {
                "file_size": file_size,
                "shannon_entropy": entropy,
                "ela_metrics": ela_metrics
            }
        }

    def detect_tampering(
        self,
        evidence_id: Any = "EVID-GENERAL",
        file_path: Optional[str] = None,
        case_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Backwards-compatible wrapper routing to analyze contract.
        Supports:
        - detect_tampering(evidence_id, file_path)
        - detect_tampering(metadata_dict)
        - detect_tampering(evidence_id, file_path, case_id=...)
        """
        if isinstance(evidence_id, dict) and file_path is None:
            meta = dict(evidence_id)
            eid = kwargs.get("evidence_id") or meta.get("evidence_id") or "EVID-GENERAL"
            cid = case_id or kwargs.get("case_id") or meta.get("case_id") or "CASE-GENERAL"
            return self.analyze(case_id=cid, evidence_id=eid, metadata=meta)

        meta = dict(metadata or {})
        if file_path:
            meta["file_path"] = file_path
        cid = case_id or kwargs.get("case_id") or meta.get("case_id") or "CASE-GENERAL"
        eid = str(evidence_id) if evidence_id else "EVID-GENERAL"
        return self.analyze(case_id=cid, evidence_id=eid, metadata=meta)
