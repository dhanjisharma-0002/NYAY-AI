"""
NYAYAI - Evidence Correlation & Intelligence Engine (Phase 9)
Module Lead: Ridhi Mashi (Evidence Intelligence & Chain-of-Custody Engineer)

Implements:
1. Multi-Evidence Chronological Timeline Assembly:
   - Uses documented evidence intake and custody event timestamps
   - Does NOT invent timestamps (missing/unknown timestamps preserved as null/unknown)
   - Strict chronological ordering
2. Cross-Evidence Relationship Discovery:
   - Represents relationships between items: Evidence A -> related_to -> Evidence B
   - Stores descriptive relationship reasons
   - Discovers duplicate hashes, shared sources, temporal windows, and matching media types
3. Cross-Evidence Attribute Matching:
   - Aggregates multi-file matches across hashes, capture sources, and formats
4. Evidence-Based Red Flag Detection:
   - Timestamp inconsistencies (e.g. post-dated capture times, sequence reversions)
   - Hash mismatches (tampering detected, baseline hash discrepancies)
   - Metadata inconsistencies (magic bytes/MIME mismatch, format structural faults)
   - Duplicate evidence (unintended identical artifacts in the same docket)
   - Analysis anomalies (elevated tampering risk scores >= 0.50)
   - Strict adherence to: "Do not claim criminality" (factual, objective descriptions)
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import uuid
from .base import BaseCorrelationEngine


class BaselineCorrelationEngine(BaseCorrelationEngine):
    """
    Core implementation of Evidence Intelligence & Case Correlation.
    """

    @staticmethod
    def _parse_iso_timestamp(ts: Any) -> Optional[datetime]:
        """
        Parses an ISO timestamp string into a timezone-aware datetime.
        Returns None if missing, null, or invalid. NEVER invents timestamps.
        """
        if not ts or ts in ("unknown", "null", "None", ""):
            return None
        if isinstance(ts, datetime):
            return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        try:
            clean_str = str(ts).strip().replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_str)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None

    def correlate_case_evidence(
        self,
        case_id: str,
        evidence_items: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Builds a comprehensive case intelligence package:
        - timeline
        - relationships
        - cross_evidence_matches
        - red_flags
        """
        if not evidence_items:
            return {
                "success": True,
                "case_id": case_id,
                "total_items": 0,
                "total_evidence_count": 0,
                "total_red_flags": 0,
                "timeline": [],
                "relationships": [],
                "links": [],
                "cross_evidence_matches": [],
                "red_flags": []
            }

        # ----------------------------------------------------------------------
        # 1. Timeline Assembly
        # ----------------------------------------------------------------------
        raw_timeline_events = []

        for item in evidence_items:
            ev_id = item.get("evidence_id")
            fname = item.get("original_filename") or item.get("filename") or f"artifact_{ev_id}"
            ev_status = item.get("status") or "SECURED"

            # Check primary evidence timestamp (created_at / intake_timestamp)
            intake_ts = item.get("created_at") or item.get("intake_timestamp")
            raw_timeline_events.append({
                "event_id": f"INTAKE-{ev_id}",
                "evidence_id": ev_id,
                "filename": fname,
                "event_type": "EVIDENCE_INTAKE",
                "timestamp": intake_ts if intake_ts else None,
                "description": f"Evidence artifact '{fname}' registered in case docket",
                "status": ev_status,
                "source": "EVIDENCE_INTAKE"
            })

            # Include documented custody events if present
            for c_ev in item.get("custody_events", []):
                raw_timeline_events.append({
                    "event_id": c_ev.get("event_id") or f"EVT-{uuid.uuid4().hex[:8].upper()}",
                    "evidence_id": ev_id,
                    "filename": fname,
                    "event_type": c_ev.get("event_type") or c_ev.get("action") or "CUSTODY_EVENT",
                    "timestamp": c_ev.get("timestamp"),
                    "description": c_ev.get("description") or f"{c_ev.get('event_type')} recorded for {ev_id}",
                    "status": ev_status,
                    "source": "CUSTODY_LEDGER"
                })

            # Include documented metadata timestamps if present (e.g. camera capture time)
            meta = item.get("metadata") or {}
            ts_meta = meta.get("timestamps_metadata") or {}
            if isinstance(ts_meta, dict):
                capture_ts = ts_meta.get("capture_time") or ts_meta.get("exif_datetime") or ts_meta.get("original_capture")
                if capture_ts:
                    raw_timeline_events.append({
                        "event_id": f"CAPTURE-{ev_id}",
                        "evidence_id": ev_id,
                        "filename": fname,
                        "event_type": "METADATA_CAPTURE_RECORDED",
                        "timestamp": capture_ts,
                        "description": f"Original device capture timestamp recorded for '{fname}'",
                        "status": ev_status,
                        "source": "METADATA"
                    })

        # Sort timeline:
        # Items with valid parsed timestamps appear in chronological order (ascending)
        # Items with None / unparseable timestamps appear at the end without invented dates
        def timeline_sort_key(ev):
            dt = self._parse_iso_timestamp(ev.get("timestamp"))
            if dt is not None:
                return (0, dt.timestamp())
            return (1, 0)

        sorted_events = sorted(raw_timeline_events, key=timeline_sort_key)

        timeline = []
        for idx, ev in enumerate(sorted_events):
            timeline.append({
                "sequence_index": idx + 1,
                "event_id": ev["event_id"],
                "evidence_id": ev["evidence_id"],
                "filename": ev["filename"],
                "event_type": ev["event_type"],
                # Strictly preserve None / null if unavailable without inventing values
                "timestamp": ev["timestamp"] if ev["timestamp"] is not None else None,
                "description": ev["description"],
                "status": ev["status"],
                "source": ev["source"]
            })

        # ----------------------------------------------------------------------
        # 2. Relationships & Cross-Evidence Matches Discovery
        # ----------------------------------------------------------------------
        relationships = []
        cross_matches = []

        # Hash map for duplicate hash detection across all items
        hash_groups: Dict[str, List[Dict[str, Any]]] = {}
        for item in evidence_items:
            h = item.get("sha256_hash")
            if h and len(h) == 64:
                hash_groups.setdefault(h.lower(), []).append(item)

        # Pairwise relationship evaluation
        n = len(evidence_items)
        for i in range(n):
            for j in range(i + 1, n):
                item_a = evidence_items[i]
                item_b = evidence_items[j]
                id_a = item_a.get("evidence_id")
                id_b = item_b.get("evidence_id")
                hash_a = item_a.get("sha256_hash")
                hash_b = item_b.get("sha256_hash")
                src_a = item_a.get("source_description")
                src_b = item_b.get("source_description")
                mime_a = item_a.get("mime_type") or item_a.get("media_type")
                mime_b = item_b.get("mime_type") or item_b.get("media_type")

                # Match 1: Identical SHA-256 Hash
                if hash_a and hash_b and hash_a.lower() == hash_b.lower():
                    reason_text = (
                        f"Evidence {id_a} and Evidence {id_b} share the exact same cryptographic "
                        f"SHA-256 hash ({hash_a}), indicating identical binary content or duplicate files."
                    )
                    rel = {
                        "source_evidence_id": id_a,
                        "target_evidence_id": id_b,
                        "related_to": id_b,
                        "relationship_type": "IDENTICAL_FILE_HASH",
                        "reason": reason_text,
                        "confidence": 1.0,
                        "notes": reason_text
                    }
                    relationships.append(rel)
                    cross_matches.append({
                        "match_type": "EXACT_HASH_MATCH",
                        "evidence_ids": [id_a, id_b],
                        "matched_attribute": "sha256_hash",
                        "matched_value": hash_a,
                        "confidence": 1.0,
                        "description": f"Cryptographic identity match between {id_a} and {id_b}."
                    })

                # Match 2: Shared Acquisition Source
                elif src_a and src_b and src_a.strip().lower() == src_b.strip().lower():
                    reason_text = (
                        f"Evidence {id_a} and Evidence {id_b} were acquired from the identical origin source: '{src_a}'."
                    )
                    rel = {
                        "source_evidence_id": id_a,
                        "target_evidence_id": id_b,
                        "related_to": id_b,
                        "relationship_type": "SAME_SOURCE_DEVICE",
                        "reason": reason_text,
                        "confidence": 0.85,
                        "notes": reason_text
                    }
                    relationships.append(rel)
                    cross_matches.append({
                        "match_type": "SOURCE_MATCH",
                        "evidence_ids": [id_a, id_b],
                        "matched_attribute": "source_description",
                        "matched_value": src_a,
                        "confidence": 0.85,
                        "description": f"Shared seizure source '{src_a}' linked across {id_a} and {id_b}."
                    })

                # Match 3: Temporal Proximity (< 300 seconds between intakes)
                dt_a = self._parse_iso_timestamp(item_a.get("created_at") or item_a.get("intake_timestamp"))
                dt_b = self._parse_iso_timestamp(item_b.get("created_at") or item_b.get("intake_timestamp"))
                if dt_a and dt_b:
                    diff_seconds = abs((dt_a - dt_b).total_seconds())
                    if diff_seconds <= 300:
                        reason_text = (
                            f"Evidence {id_a} and Evidence {id_b} were ingested within "
                            f"{int(diff_seconds)} seconds of each other in the case docket."
                        )
                        rel = {
                            "source_evidence_id": id_a,
                            "target_evidence_id": id_b,
                            "related_to": id_b,
                            "relationship_type": "TEMPORAL_PROXIMITY",
                            "reason": reason_text,
                            "confidence": 0.75,
                            "notes": reason_text
                        }
                        relationships.append(rel)

                # Match 4: Shared Media Type
                if mime_a and mime_b and mime_a.lower() == mime_b.lower() and mime_a not in ("application/octet-stream", ""):
                    reason_text = f"Both evidence items share identical MIME media format '{mime_a}'."
                    rel = {
                        "source_evidence_id": id_a,
                        "target_evidence_id": id_b,
                        "related_to": id_b,
                        "relationship_type": "SAME_MEDIA_TYPE",
                        "reason": reason_text,
                        "confidence": 0.50,
                        "notes": reason_text
                    }
                    # Only append if not already linked by a stronger relationship
                    if not any(r["source_evidence_id"] == id_a and r["target_evidence_id"] == id_b for r in relationships):
                        relationships.append(rel)

        # ----------------------------------------------------------------------
        # 3. Evidence-Based Red Flag Detection (Strict: No criminality claims)
        # ----------------------------------------------------------------------
        red_flags = []

        for item in evidence_items:
            ev_id = item.get("evidence_id")
            meta = item.get("metadata") or {}
            anomalies = meta.get("anomalies") or []
            analyses = item.get("analysis_results") or []
            ev_status = item.get("status") or "SECURED"
            ts_meta = meta.get("timestamps_metadata") or {}

            # Red Flag 1: Hash Mismatch / Integrity Compromised
            if ev_status in ("INTEGRITY_COMPROMISED", "STORAGE_ERROR", "MISMATCH"):
                red_flags.append({
                    "flag_id": f"FLAG-HASH-{uuid.uuid4().hex[:8].upper()}",
                    "flag_type": "HASH_MISMATCH",
                    "evidence_id": ev_id,
                    "severity": "CRITICAL",
                    "description": (
                        f"Cryptographic hash mismatch: Vaulted artifact SHA-256 hash does not match "
                        f"the registered baseline hash for evidence {ev_id}."
                    ),
                    "evidence_reference": {
                        "evidence_id": ev_id,
                        "status": ev_status,
                        "sha256_hash": item.get("sha256_hash")
                    }
                })

            # Red Flag 2: Timestamp Inconsistency
            # Case: Post-dated capture timestamp relative to intake
            if isinstance(ts_meta, dict):
                cap_raw = ts_meta.get("capture_time") or ts_meta.get("exif_datetime")
                intake_raw = item.get("created_at") or item.get("intake_timestamp")
                dt_cap = self._parse_iso_timestamp(cap_raw)
                dt_intake = self._parse_iso_timestamp(intake_raw)
                if dt_cap and dt_intake and dt_cap > dt_intake:
                    red_flags.append({
                        "flag_id": f"FLAG-TS-{uuid.uuid4().hex[:8].upper()}",
                        "flag_type": "TIMESTAMP_INCONSISTENCY",
                        "evidence_id": ev_id,
                        "severity": "HIGH",
                        "description": (
                            f"Timestamp inconsistency: Documented capture timestamp ({cap_raw}) "
                            f"occurs after the official evidence intake timestamp ({intake_raw})."
                        ),
                        "evidence_reference": {
                            "evidence_id": ev_id,
                            "capture_timestamp": cap_raw,
                            "intake_timestamp": intake_raw
                        }
                    })

            # Red Flag 3: Metadata Inconsistency / Format Invalid
            if meta.get("format_valid") is False or anomalies:
                anomaly_desc = "; ".join(str(a) for a in anomalies) if anomalies else "Magic bytes or header structural mismatch observed."
                red_flags.append({
                    "flag_id": f"FLAG-META-{uuid.uuid4().hex[:8].upper()}",
                    "flag_type": "METADATA_INCONSISTENCY",
                    "evidence_id": ev_id,
                    "severity": "HIGH",
                    "description": (
                        f"Metadata inconsistency: Header validation detected structural or format "
                        f"anomalies in evidence {ev_id}: {anomaly_desc}"
                    ),
                    "evidence_reference": {
                        "evidence_id": ev_id,
                        "format_valid": meta.get("format_valid"),
                        "magic_bytes": meta.get("magic_bytes"),
                        "anomalies": anomalies
                    }
                })

            # Red Flag 4: Duplicate Evidence
            item_hash = item.get("sha256_hash")
            if item_hash and len(hash_groups.get(item_hash.lower(), [])) > 1:
                duplicate_ids = [other["evidence_id"] for other in hash_groups[item_hash.lower()] if other["evidence_id"] != ev_id]
                # Avoid duplicate flags for the same pair
                if not any(f["flag_type"] == "DUPLICATE_EVIDENCE" and ev_id in str(f.get("evidence_reference", {})) for f in red_flags):
                    red_flags.append({
                        "flag_id": f"FLAG-DUP-{uuid.uuid4().hex[:8].upper()}",
                        "flag_type": "DUPLICATE_EVIDENCE",
                        "evidence_id": ev_id,
                        "severity": "MEDIUM",
                        "description": (
                            f"Duplicate evidence detected: Evidence {ev_id} shares identical cryptographic "
                            f"SHA-256 hash with evidence {duplicate_ids}."
                        ),
                        "evidence_reference": {
                            "evidence_id": ev_id,
                            "duplicate_evidence_ids": duplicate_ids,
                            "sha256_hash": item_hash
                        }
                    })

            # Red Flag 5: Analysis Anomaly (elevated risk score / AI tamper indication)
            for ar in analyses:
                risk = ar.get("risk_score") or 0.0
                pred = ar.get("prediction") or ""
                findings = ar.get("findings") or []
                if (isinstance(risk, (int, float)) and risk >= 0.50) or pred in ("TAMPER_DETECTED", "SUSPICIOUS"):
                    findings_str = "; ".join(str(f) for f in findings[:2]) if findings else "Automated screening marked tamper likelihood."
                    red_flags.append({
                        "flag_id": f"FLAG-ANOMALY-{uuid.uuid4().hex[:8].upper()}",
                        "flag_type": "ANALYSIS_ANOMALY",
                        "evidence_id": ev_id,
                        "severity": "HIGH",
                        "description": (
                            f"Analysis anomaly: Automated screening flagged elevated risk score ({risk:.2f}) "
                            f"for evidence {ev_id}. Findings: {findings_str}"
                        ),
                        "evidence_reference": {
                            "evidence_id": ev_id,
                            "risk_score": risk,
                            "prediction": pred,
                            "findings": findings
                        }
                    })

        return {
            "success": True,
            "case_id": case_id,
            "total_items": len(evidence_items),
            "total_evidence_count": len(evidence_items),
            "total_red_flags": len(red_flags),
            "timeline": timeline,
            "relationships": relationships,
            "links": relationships,  # Backward compatibility alias
            "cross_evidence_matches": cross_matches,
            "red_flags": red_flags
        }
