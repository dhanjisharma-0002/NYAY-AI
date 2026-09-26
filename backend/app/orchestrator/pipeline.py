"""
NYAYAI - Master Analysis Pipeline Orchestrator
Module Lead: Dhananjay Sharma (Backend & System Integration Lead)

Coordinates the multi-stage digital evidence pipeline across decoupled engines:
Evidence Vault -> Forensic Engine -> AI Engine -> Explainability -> Custody Ledger
"""

import sys
import os
from typing import Dict, Any

# Ensure sub-engines are accessible to Python interpreter
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
for engine_dir in ["forensic-engine", "ai-engine", "explainability", "correlation", "custody", "reports"]:
    path = os.path.join(ROOT_DIR, engine_dir)
    if path not in sys.path:
        sys.path.insert(0, path)

from forensic_engine import calculate_sha256, verify_sha256, ForensicMetadataExtractor
from ai_engine import BaselineTamperDetector
from explainability import BaselineCourtExplainer
from custody import CryptographicCustodyLedger, GENESIS_HASH


class EvidencePipelineOrchestrator:
    """
    Coordinates domain engine workflows while strictly preserving original evidence integrity.
    """

    def __init__(self):
        self.metadata_extractor = ForensicMetadataExtractor()
        self.ai_tamper_detector = BaselineTamperDetector()
        self.explainer = BaselineCourtExplainer()
        self.custody_ledger = CryptographicCustodyLedger()

    def run_full_analysis(
        self,
        evidence_id: str,
        vault_path: str,
        expected_sha256: str,
        declared_mime: str,
        actor_id: str,
        last_event_hash: str,
        next_seq_num: int
    ) -> Dict[str, Any]:
        """
        Executes end-to-end analysis on an evidence item.
        """
        # Step 1: Pre-Analysis Integrity Verification (Rule 2 & 7)
        is_intact, current_hash = verify_sha256(vault_path, expected_sha256)
        if not is_intact:
            raise ValueError(
                f"INTEGRITY VIOLATION: Evidence '{evidence_id}' has been tampered with or corrupted! "
                f"Expected {expected_sha256}, calculated {current_hash}."
            )

        # Step 2: Forensic Engine (Anu Sharma)
        forensic_data = self.metadata_extractor.analyze(vault_path, declared_mime=declared_mime)

        # Step 3: AI Engine (Anu Sharma)
        ai_data = self.ai_tamper_detector.detect_tampering(evidence_id, vault_path)

        # Step 4: Explainability Engine (Ridhi Mashi)
        explanation = self.explainer.explain(evidence_id, forensic_data, ai_data)

        # Step 5: Custody Ledger Audit Event (Ridhi Mashi)
        custody_event = self.custody_ledger.create_event(
            evidence_id=evidence_id,
            sequence_number=next_seq_num,
            action="ANALYSIS_PIPELINE_EXECUTED",
            actor_id=actor_id,
            details={
                "tamper_detected": ai_data.get("tamper_detected"),
                "confidence_score": ai_data.get("confidence_score"),
                "format_valid": forensic_data.get("format_valid"),
                "anomalies_count": len(forensic_data.get("anomalies", []))
            },
            previous_event_hash=last_event_hash
        )

        return {
            "evidence_id": evidence_id,
            "sha256_hash": current_hash,
            "forensic_report": forensic_data,
            "ai_analysis": ai_data,
            "explainability": explanation,
            "custody_event": custody_event
        }
