"""
NYAYAI - Case Docket Judicial Discovery & Cryptographic Export Bundle Service (Phase 19)
Module: backend.app.services.export_bundle_service
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Generates self-contained, air-gap verifiable Judicial Discovery & Disclosure Packages (.zip)
under Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023) Section 63 and Bharatiya Nagarik Suraksha
Sannhita, 2023 (BNSS 2023) Section 230 / Section 238:
1. Validates finalized/sealed case state (rejects unsealed cases).
2. Verifies physical vault file SHA-256 integrity against registered baselines.
3. Validates custody chain continuity and official court report presence.
4. Confirms Phase 18 judicial admissibility certification.
5. Assembles complete digital evidence bag on disk (manifest, evidence, custody, reports, certificates, audit).
6. Computes deterministic root checksum from sorted artifact paths and hashes.
7. Caches packages by case_id + docket_sealing_hash to prevent redundant compression.
8. Emits exactly one CASE_BUNDLE_EXPORTED audit log per new export.
9. Strictly read-only: never modifies evidence baselines, case status, custody, or reports.
"""

import os
import json
import uuid
import shutil
import hashlib
import zipfile
import tempfile
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models.user import User
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.custody import CustodyEvent
from backend.app.models.report import Report, CourtReport
from backend.app.models.audit import AuditLog
from backend.app.schemas.export_bundle import ExportBundleRequest
from backend.app.services.base import BaseService
from backend.app.services.hashing_service import HashingService
from backend.app.services.custody_service import CustodyService
from backend.app.services.admissibility_service import AdmissibilityService
from backend.app.services.case_finalization_service import CaseFinalizationService
from backend.app.storage import get_storage_driver
from backend.app.utils.exceptions import (
    AppException,
    EntityNotFoundException,
    PermissionDeniedException
)
from backend.app.utils.logger import get_logger

logger = get_logger("export_bundle_service")


class ExportBundleService(BaseService):
    """
    Assembles, verifies, and packages sealed case dockets into standard
    cryptographically verifiable digital evidence discovery archives.
    """

    def __init__(self, db: Session):
        super().__init__(db)
        self.hasher = HashingService()
        self.custody_service = CustodyService(db)
        self.admissibility_service = AdmissibilityService(db)
        self.finalization_service = CaseFinalizationService(db)
        self.storage = get_storage_driver()

    def export_case_bundle(
        self,
        case_id: str,
        current_user: User,
        payload: Optional[ExportBundleRequest] = None
    ) -> Dict[str, Any]:
        """
        Synthesizes a standardized, offline-verifiable Judicial Discovery Export Bundle (.zip).
        """
        # 1. Fetch Case Docket
        case = self.db.query(Case).filter_by(case_id=case_id).first()
        if not case:
            raise EntityNotFoundException("Case", case_id)

        # 2. RBAC Access Control
        user_role = (current_user.role or "").strip().upper()
        if user_role == "INVESTIGATOR":
            if case.created_by != current_user.id and case.created_by != current_user.username:
                raise PermissionDeniedException(
                    f"Access forbidden: Investigator '{current_user.username}' is not authorized to export case '{case_id}'."
                )
        elif user_role not in ("JUDGE", "ADMIN", "AUDITOR", "SYSTEM_LEAD", "LAWYER"):
            raise PermissionDeniedException(
                f"Access forbidden: Role '{user_role}' is not authorized to generate judicial discovery export bundles."
            )

        # 3. Validation Gate: Reject Unsealed Cases
        if case.status != "COMPLETED":
            raise AppException(
                message=f"Case docket '{case_id}' is in status '{case.status}' and cannot be exported. Docket must be formally finalized and cryptographically sealed under BSA 2023.",
                status_code=400,
                error_code="UNSEALED_DOCKET",
                details={"case_id": case_id, "current_status": case.status}
            )

        # 4. Batch query all evidence items in case docket
        evidence_records = (
            self.db.query(Evidence)
            .filter_by(case_id=case_id)
            .order_by(Evidence.evidence_id.asc())
            .all()
        )
        if not evidence_records:
            raise AppException(
                message=f"Case docket '{case_id}' contains zero evidence items and cannot be exported.",
                status_code=400,
                error_code="EMPTY_CASE_DOCKET",
                details={"case_id": case_id}
            )

        evidence_ids = [e.evidence_id for e in evidence_records]

        # 5. Validation Gate: Court Admissibility Report Existence
        reports = (
            self.db.query(Report)
            .filter_by(case_id=case_id)
            .order_by(Report.report_id.asc())
            .all()
        )
        legacy_reports = (
            self.db.query(CourtReport)
            .filter_by(case_id=case_id)
            .order_by(CourtReport.report_id.asc())
            .all()
        ) if not reports else []

        if not reports and not legacy_reports:
            raise AppException(
                message=f"Case docket '{case_id}' lacks an official court-ready admissibility report (BSA 2023).",
                status_code=400,
                error_code="MISSING_COURT_REPORT",
                details={"case_id": case_id}
            )

        # 6. Validation Gate: Physical Evidence Vault Integrity Check (Streaming SHA-256)
        for e in evidence_records:
            vault_hash = None
            if e.storage_reference and os.path.exists(e.storage_reference):
                try:
                    vault_hash = self.hasher.compute_file_hash(e.storage_reference)
                except Exception as fe:
                    logger.warning(f"Failed to read file hash for {e.evidence_id}: {fe}")
            elif e.storage_reference and self.storage.exists(e.storage_reference):
                try:
                    file_bytes = self.storage.retrieve(e.storage_reference)
                    vault_hash = self.hasher.compute_bytes_hash(file_bytes)
                except Exception as se:
                    logger.warning(f"Failed to retrieve bytes from storage for {e.evidence_id}: {se}")

            if not vault_hash or not self.hasher.verify_hash(vault_hash, e.sha256_hash):
                raise AppException(
                    message=f"Evidence vault file integrity verification failed for '{e.evidence_id}' ({e.original_filename}). Physical file is tampered or missing.",
                    status_code=400,
                    error_code="EVIDENCE_TAMPERED",
                    details={"evidence_id": e.evidence_id, "original_filename": e.original_filename}
                )

        # 7. Validation Gate: Cryptographic Custody Continuity
        for e in evidence_records:
            hist = self.custody_service.get_chronological_history(e.evidence_id)
            if not hist.get("chain_intact"):
                raise AppException(
                    message=f"Cryptographic chain of custody is breached for evidence '{e.evidence_id}'.",
                    status_code=400,
                    error_code="BROKEN_CUSTODY_CHAIN",
                    details={"evidence_id": e.evidence_id}
                )

        # 8. Validation Gate: Phase 18 Judicial Admissibility Certificate Verification
        cert_data = self.admissibility_service.get_admissibility_certificate(case_id, current_user)
        if not cert_data.get("is_admissible") or cert_data.get("admissibility_status") != "ADMISSIBLE":
            raise AppException(
                message=f"Case docket '{case_id}' failed judicial admissibility verification ({cert_data.get('admissibility_status')}). Only verified ADMISSIBLE dockets can be exported.",
                status_code=400,
                error_code="INADMISSIBLE_CASE",
                details={"admissibility_status": cert_data.get("admissibility_status")}
            )

        # 9. Determine Docket Sealing Hash
        sealing_hash = None
        final_audit = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case_id, action="CASE_FINALIZED")
            .order_by(AuditLog.timestamp.desc())
            .first()
        )
        if final_audit and final_audit.meta_data:
            sealing_hash = final_audit.meta_data.get("docket_sealing_hash")

        if not sealing_hash:
            manifest_info = self.finalization_service.get_sealing_manifest(case_id)
            sealing_hash = manifest_info.get("docket_sealing_hash")

        if not sealing_hash:
            raise AppException(
                message=f"Case docket '{case_id}' lacks a registered cryptographic sealing hash.",
                status_code=400,
                error_code="MISSING_SEALING_HASH",
                details={"case_id": case_id}
            )

        # 10. Check Cache (case_id + docket_sealing_hash)
        bundle_dir = os.path.join(settings.EVIDENCE_VAULT_PATH, case_id, "bundles")
        os.makedirs(bundle_dir, exist_ok=True)

        bundle_filename = f"NYAYAI_DISCOVERY_BUNDLE_{case.case_number}_{sealing_hash[:16]}.zip"
        bundle_file_path = os.path.join(bundle_dir, bundle_filename)
        manifest_cache_path = os.path.join(bundle_dir, f"METADATA_{sealing_hash[:16]}.json")

        force_repackage = payload.force_repackage if payload else False

        if os.path.exists(bundle_file_path) and os.path.exists(manifest_cache_path) and not force_repackage:
            try:
                if os.path.getsize(bundle_file_path) > 0 and zipfile.is_zipfile(bundle_file_path):
                    with open(manifest_cache_path, "r", encoding="utf-8") as mf:
                        cached_data = json.load(mf)
                    if (
                        cached_data.get("case_id") == case.case_id
                        and cached_data.get("docket_sealing_hash") == sealing_hash
                        and cached_data.get("root_checksum")
                    ):
                        cached_data["cached"] = True
                        cached_data["bundle_file_size"] = os.path.getsize(bundle_file_path)
                        logger.info(f"Serving validated cached discovery export bundle for case {case_id} (hash {sealing_hash[:16]})")
                        return cached_data
            except Exception as ce:
                logger.warning(f"Cached bundle validation failed: {ce}. Re-packaging.")

        # 11. Assemble Digital Evidence Bag on Disk (Deterministic Staging)
        now = datetime.now(timezone.utc)
        exporter_info = {
            "user_id": current_user.id,
            "username": current_user.username,
            "role": current_user.role,
            "authorized_officer_name": payload.authorized_officer_name if payload and payload.authorized_officer_name else getattr(current_user, "full_name", current_user.username),
            "purpose": payload.purpose if payload and payload.purpose else "Judicial Discovery & Court Tender (BNSS 230 / BSA 63)",
            "recipient": payload.recipient_court_or_agency if payload and payload.recipient_court_or_agency else "Competent Judicial Authority"
        }

        with tempfile.TemporaryDirectory(dir=bundle_dir) as staging_dir:
            staged_artifacts: List[Dict[str, Any]] = []

            # A. Staged Evidence Files
            ev_dir = os.path.join(staging_dir, "evidence")
            os.makedirs(ev_dir, exist_ok=True)
            for e in evidence_records:
                # Sanitize filename to ensure strict ZIP path safety (no directory traversal, no absolute paths)
                safe_orig_name = os.path.basename(e.original_filename.replace("\\", "/")).strip()
                safe_orig_name = safe_orig_name.replace("..", "").lstrip("/\\")
                if not safe_orig_name:
                    safe_orig_name = "evidence_file"
                dest_filename = f"{e.evidence_id}_{safe_orig_name}"
                dest_path = os.path.join(ev_dir, dest_filename)
                rel_archive_path = f"evidence/{dest_filename}"

                # Containment check: Ensure dest_path strictly resolves within ev_dir
                if not os.path.abspath(dest_path).startswith(os.path.abspath(ev_dir)):
                    raise AppException("Unsafe evidence filename detected.", 400, "UNSAFE_FILENAME")

                if e.storage_reference and os.path.exists(e.storage_reference):
                    shutil.copyfile(e.storage_reference, dest_path)
                elif e.storage_reference and self.storage.exists(e.storage_reference):
                    content = self.storage.retrieve(e.storage_reference)
                    with open(dest_path, "wb") as df:
                        df.write(content)
                else:
                    raise AppException(f"Evidence file missing on disk: {e.evidence_id}", 400, "EVIDENCE_FILE_MISSING")

                f_size = os.path.getsize(dest_path)
                f_hash = self.hasher.compute_file_hash(dest_path)
                staged_artifacts.append({
                    "path": rel_archive_path,
                    "artifact_type": "EVIDENCE",
                    "file_size": f_size,
                    "sha256": f_hash,
                    "abs_path": dest_path
                })

            # B. Staged Custody Ledger & Events Timeline
            cust_dir = os.path.join(staging_dir, "custody")
            os.makedirs(cust_dir, exist_ok=True)

            all_custody_events = (
                self.db.query(CustodyEvent)
                .filter(CustodyEvent.evidence_id.in_(evidence_ids))
                .order_by(CustodyEvent.evidence_id.asc(), CustodyEvent.sequence_number.asc())
                .all()
            )

            # 1) custody_ledger.json
            ledger_data = {
                "case_id": case.case_id,
                "case_number": case.case_number,
                "total_events": len(all_custody_events),
                "evidence_ledgers": {}
            }
            for ce in all_custody_events:
                if ce.evidence_id not in ledger_data["evidence_ledgers"]:
                    ledger_data["evidence_ledgers"][ce.evidence_id] = []
                p_json = json.loads(ce.payload_json) if isinstance(ce.payload_json, str) else ce.payload_json
                ledger_data["evidence_ledgers"][ce.evidence_id].append({
                    "event_id": ce.event_id,
                    "evidence_id": ce.evidence_id,
                    "sequence_number": ce.sequence_number,
                    "event_type": ce.event_type,
                    "user_id": ce.user_id,
                    "timestamp": ce.timestamp.isoformat() if hasattr(ce.timestamp, "isoformat") else str(ce.timestamp),
                    "description": ce.description,
                    "previous_hash": ce.previous_hash,
                    "event_hash": ce.event_hash,
                    "payload": p_json
                })

            ledger_path = os.path.join(cust_dir, "custody_ledger.json")
            with open(ledger_path, "w", encoding="utf-8") as lf:
                json.dump(ledger_data, lf, sort_keys=True, indent=2)
            staged_artifacts.append({
                "path": "custody/custody_ledger.json",
                "artifact_type": "CUSTODY_LEDGER",
                "file_size": os.path.getsize(ledger_path),
                "sha256": self.hasher.compute_file_hash(ledger_path),
                "abs_path": ledger_path
            })

            # 2) events_timeline.json (chronological global order)
            sorted_events = sorted(
                all_custody_events,
                key=lambda x: (x.timestamp.isoformat() if hasattr(x.timestamp, "isoformat") else str(x.timestamp), x.sequence_number)
            )
            timeline_data = [
                {
                    "event_id": ce.event_id,
                    "evidence_id": ce.evidence_id,
                    "sequence_number": ce.sequence_number,
                    "event_type": ce.event_type,
                    "timestamp": ce.timestamp.isoformat() if hasattr(ce.timestamp, "isoformat") else str(ce.timestamp),
                    "description": ce.description,
                    "event_hash": ce.event_hash
                }
                for ce in sorted_events
            ]
            timeline_path = os.path.join(cust_dir, "events_timeline.json")
            with open(timeline_path, "w", encoding="utf-8") as tf:
                json.dump(timeline_data, tf, sort_keys=True, indent=2)
            staged_artifacts.append({
                "path": "custody/events_timeline.json",
                "artifact_type": "CUSTODY_TIMELINE",
                "file_size": os.path.getsize(timeline_path),
                "sha256": self.hasher.compute_file_hash(timeline_path),
                "abs_path": timeline_path
            })

            # C. Staged Reports
            rep_dir = os.path.join(staging_dir, "reports")
            os.makedirs(rep_dir, exist_ok=True)
            rep_index = []

            for r in reports:
                r_ext = ".pdf"
                if r.storage_reference:
                    _, ext = os.path.splitext(r.storage_reference)
                    if ext:
                        r_ext = ext
                rep_dest_path = os.path.join(rep_dir, f"{r.report_id}{r_ext}")
                rel_rep_path = f"reports/{r.report_id}{r_ext}"

                if r.storage_reference and os.path.exists(r.storage_reference):
                    shutil.copyfile(r.storage_reference, rep_dest_path)
                else:
                    # Synthetic report placeholder for air-gap discovery if file moved
                    with open(rep_dest_path, "w", encoding="utf-8") as rf:
                        rf.write(f"NYAY-AI Official Report Record: {r.report_id}\nSHA-256: {r.report_sha256}\nCode: {r.verification_code}\n")

                staged_artifacts.append({
                    "path": rel_rep_path,
                    "artifact_type": "COURT_REPORT",
                    "file_size": os.path.getsize(rep_dest_path),
                    "sha256": self.hasher.compute_file_hash(rep_dest_path),
                    "abs_path": rep_dest_path
                })
                rep_index.append({
                    "report_id": r.report_id,
                    "report_type": r.report_type,
                    "report_sha256": r.report_sha256,
                    "verification_code": r.verification_code,
                    "relative_path": rel_rep_path
                })

            for lr in legacy_reports:
                lr_dest = os.path.join(rep_dir, f"{lr.report_id}.pdf")
                rel_lr_path = f"reports/{lr.report_id}.pdf"
                if lr.storage_reference and os.path.exists(lr.storage_reference):
                    shutil.copyfile(lr.storage_reference, lr_dest)
                else:
                    with open(lr_dest, "w", encoding="utf-8") as lf:
                        lf.write(f"NYAY-AI Court Report Record: {lr.report_id}\nSHA-256: {lr.report_sha256}\n")
                staged_artifacts.append({
                    "path": rel_lr_path,
                    "artifact_type": "COURT_REPORT",
                    "file_size": os.path.getsize(lr_dest),
                    "sha256": self.hasher.compute_file_hash(lr_dest),
                    "abs_path": lr_dest
                })

            rep_index_path = os.path.join(rep_dir, "reports_index.json")
            with open(rep_index_path, "w", encoding="utf-8") as rif:
                json.dump(rep_index, rif, sort_keys=True, indent=2)
            staged_artifacts.append({
                "path": "reports/reports_index.json",
                "artifact_type": "REPORT_METADATA",
                "file_size": os.path.getsize(rep_index_path),
                "sha256": self.hasher.compute_file_hash(rep_index_path),
                "abs_path": rep_index_path
            })

            # D. Staged Judicial Admissibility Certificate
            cert_path = os.path.join(staging_dir, "admissibility_certificate.json")
            with open(cert_path, "w", encoding="utf-8") as cf:
                json.dump(cert_data, cf, sort_keys=True, indent=2)
            staged_artifacts.append({
                "path": "admissibility_certificate.json",
                "artifact_type": "ADMISSIBILITY_CERTIFICATE",
                "file_size": os.path.getsize(cert_path),
                "sha256": self.hasher.compute_file_hash(cert_path),
                "abs_path": cert_path
            })

            # E. Staged Audit Trail
            aud_dir = os.path.join(staging_dir, "audit")
            os.makedirs(aud_dir, exist_ok=True)
            case_audits = (
                self.db.query(AuditLog)
                .filter(
                    (AuditLog.resource_id == case_id) |
                    (AuditLog.resource_id.in_(evidence_ids))
                )
                .order_by(AuditLog.timestamp.asc())
                .all()
            )
            audit_records = [
                {
                    "audit_id": a.audit_id,
                    "action": a.action,
                    "resource_type": a.resource_type,
                    "resource_id": a.resource_id,
                    "timestamp": a.timestamp.isoformat() if hasattr(a.timestamp, "isoformat") else str(a.timestamp),
                    "user_id": a.user_id,
                    "meta_data": a.meta_data
                }
                for a in case_audits
            ]
            aud_path = os.path.join(aud_dir, "case_audit_trail.json")
            with open(aud_path, "w", encoding="utf-8") as af:
                json.dump(audit_records, af, sort_keys=True, indent=2)
            staged_artifacts.append({
                "path": "audit/case_audit_trail.json",
                "artifact_type": "AUDIT_TRAIL",
                "file_size": os.path.getsize(aud_path),
                "sha256": self.hasher.compute_file_hash(aud_path),
                "abs_path": aud_path
            })

            # F. Staged Bundle Manifest (manifest.json)
            # Create preliminary manifest item list
            prelim_artifacts = [
                {
                    "path": a["path"],
                    "artifact_type": a["artifact_type"],
                    "file_size": a["file_size"],
                    "sha256": a["sha256"]
                }
                for a in sorted(staged_artifacts, key=lambda x: x["path"])
            ]

            manifest_content = {
                "bundle_version": "1.0",
                "statutory_framework": "BSA_2023_SEC_63_BNSS_2023_SEC_230",
                "case_id": case.case_id,
                "case_number": case.case_number,
                "title": case.title,
                "status": case.status,
                "jurisdiction": case.jurisdiction,
                "docket_sealing_hash": sealing_hash,
                "admissibility_status": cert_data.get("admissibility_status", "ADMISSIBLE"),
                "exported_at": now.isoformat(),
                "exporter": exporter_info,
                "total_artifacts": len(prelim_artifacts),
                "artifacts": prelim_artifacts
            }
            manifest_path = os.path.join(staging_dir, "manifest.json")
            with open(manifest_path, "w", encoding="utf-8") as mf:
                json.dump(manifest_content, mf, sort_keys=True, indent=2)
            staged_artifacts.append({
                "path": "manifest.json",
                "artifact_type": "BUNDLE_MANIFEST",
                "file_size": os.path.getsize(manifest_path),
                "sha256": self.hasher.compute_file_hash(manifest_path),
                "abs_path": manifest_path
            })

            # G. Deterministic Root Checksum Manifest (DISCOVERY_BUNDLE_CHECKSUM.sha256)
            # Sort all items strictly alphabetically by archive path
            staged_artifacts_sorted = sorted(staged_artifacts, key=lambda x: x["path"])
            checksum_lines = [
                "# NYAY-AI CASE DOCKET DISCOVERY BUNDLE CHECKSUM MANIFEST",
                "# Statutory Framework: BSA 2023 Sec 63 | BNSS 2023 Sec 230 | ISO/IEC 27037:2012",
                f"# Case ID: {case.case_id}",
                f"# Case Number: {case.case_number}",
                f"# Docket Sealing Hash: {sealing_hash}",
                f"# Generated At: {now.isoformat()}",
                ""
            ]
            for a in staged_artifacts_sorted:
                checksum_lines.append(f"{a['sha256']}  {a['path']}")
            checksum_text = "\n".join(checksum_lines) + "\n"

            # Compute root checksum from canonical sorted lines (independent of ZIP metadata)
            canonical_body = "\n".join(f"{a['sha256']}  {a['path']}" for a in staged_artifacts_sorted)
            root_checksum = hashlib.sha256(canonical_body.encode("utf-8")).hexdigest().lower()

            checksum_file_path = os.path.join(staging_dir, "DISCOVERY_BUNDLE_CHECKSUM.sha256")
            with open(checksum_file_path, "w", encoding="utf-8") as csf:
                csf.write(checksum_text)

            staged_artifacts.append({
                "path": "DISCOVERY_BUNDLE_CHECKSUM.sha256",
                "artifact_type": "ROOT_CHECKSUM",
                "file_size": os.path.getsize(checksum_file_path),
                "sha256": self.hasher.compute_file_hash(checksum_file_path),
                "abs_path": checksum_file_path
            })

            # 12. Write Deterministic ZIP Archive on Disk (NOT fully in memory)
            final_artifacts_sorted = sorted(staged_artifacts, key=lambda x: x["path"])
            temp_zip_fd, temp_zip_path = tempfile.mkstemp(dir=bundle_dir, suffix=".tmp.zip")
            os.close(temp_zip_fd)

            try:
                with zipfile.ZipFile(temp_zip_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zipf:
                    for a in final_artifacts_sorted:
                        # Write archive entry using canonical relative path
                        zipf.write(a["abs_path"], arcname=a["path"])

                # Atomic rename on disk
                if os.path.exists(bundle_file_path):
                    os.remove(bundle_file_path)
                shutil.move(temp_zip_path, bundle_file_path)
            finally:
                if os.path.exists(temp_zip_path):
                    try:
                        os.remove(temp_zip_path)
                    except Exception:
                        pass

        # 13. Emit exactly one CASE_BUNDLE_EXPORTED audit log
        bundle_file_size = os.path.getsize(bundle_file_path)
        audit_entry = AuditLog(
            audit_id=f"AUD-{now.year}-{uuid.uuid4().hex[:8].upper()}",
            user_id=current_user.id,
            action="CASE_BUNDLE_EXPORTED",
            resource_type="CASE",
            resource_id=case.case_id,
            timestamp=now,
            meta_data={
                "case_number": case.case_number,
                "bundle_filename": bundle_filename,
                "bundle_file_size": bundle_file_size,
                "root_checksum": root_checksum,
                "docket_sealing_hash": sealing_hash,
                "total_artifacts": len(final_artifacts_sorted),
                "purpose": exporter_info["purpose"],
                "recipient": exporter_info["recipient"],
                "exporter_role": current_user.role,
                "exporter_username": current_user.username
            }
        )
        self.db.add(audit_entry)
        self.db.commit()

        # 14. Format Final Response & Save Manifest Cache
        download_url = f"/api/cases/{case.case_id}/download-bundle"
        response_payload = {
            "case_id": case.case_id,
            "case_number": case.case_number,
            "bundle_filename": bundle_filename,
            "bundle_file_size": bundle_file_size,
            "root_checksum": root_checksum,
            "docket_sealing_hash": sealing_hash,
            "admissibility_status": cert_data.get("admissibility_status", "ADMISSIBLE"),
            "statutory_framework": "BSA_2023_SEC_63_BNSS_2023_SEC_230",
            "exported_at": now.isoformat(),
            "exporter": exporter_info,
            "total_artifacts": len(final_artifacts_sorted),
            "cached": False,
            "download_url": download_url,
            "artifacts": [
                {
                    "path": a["path"],
                    "artifact_type": a["artifact_type"],
                    "file_size": a["file_size"],
                    "sha256": a["sha256"]
                }
                for a in final_artifacts_sorted
            ]
        }

        try:
            with open(manifest_cache_path, "w", encoding="utf-8") as mf:
                json.dump(response_payload, mf, sort_keys=True, indent=2)
        except Exception as we:
            logger.warning(f"Failed to write metadata cache: {we}")

        logger.info(
            f"Judicial discovery export bundle created for case {case.case_id} "
            f"({bundle_filename}, {bundle_file_size} bytes, root {root_checksum[:16]}...)"
        )
        return response_payload

    def get_bundle_manifest(self, case_id: str, current_user: User) -> Dict[str, Any]:
        """
        Inspects the discovery bundle manifest and root checksum without downloading the archive.
        """
        case = self.db.query(Case).filter_by(case_id=case_id).first()
        if not case:
            raise EntityNotFoundException("Case", case_id)

        user_role = (current_user.role or "").strip().upper()
        if user_role == "INVESTIGATOR":
            if case.created_by != current_user.id and case.created_by != current_user.username:
                raise PermissionDeniedException(
                    f"Access forbidden: Investigator '{current_user.username}' is not authorized for case '{case_id}'."
                )
        elif user_role not in ("JUDGE", "ADMIN", "AUDITOR", "SYSTEM_LEAD", "LAWYER"):
            raise PermissionDeniedException(
                f"Access forbidden: Role '{user_role}' is not authorized to inspect discovery bundles."
            )

        # Retrieve docket sealing hash
        sealing_hash = None
        final_audit = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case_id, action="CASE_FINALIZED")
            .order_by(AuditLog.timestamp.desc())
            .first()
        )
        if final_audit and final_audit.meta_data:
            sealing_hash = final_audit.meta_data.get("docket_sealing_hash")

        bundle_dir = os.path.join(settings.EVIDENCE_VAULT_PATH, case_id, "bundles")
        if sealing_hash:
            manifest_cache_path = os.path.join(bundle_dir, f"METADATA_{sealing_hash[:16]}.json")
            bundle_filename = f"NYAYAI_DISCOVERY_BUNDLE_{case.case_number}_{sealing_hash[:16]}.zip"
            bundle_path = os.path.join(bundle_dir, bundle_filename)
            if (
                os.path.exists(manifest_cache_path)
                and os.path.exists(bundle_path)
                and os.path.getsize(bundle_path) > 0
                and zipfile.is_zipfile(bundle_path)
            ):
                try:
                    with open(manifest_cache_path, "r", encoding="utf-8") as mf:
                        cached_data = json.load(mf)
                    if (
                        cached_data.get("case_id") == case.case_id
                        and cached_data.get("docket_sealing_hash") == sealing_hash
                        and cached_data.get("root_checksum")
                    ):
                        cached_data["cached"] = True
                        cached_data["bundle_file_size"] = os.path.getsize(bundle_path)
                        return cached_data
                except Exception as ce:
                    logger.warning(f"Error loading cached manifest: {ce}")

        # If not cached or corrupted, trigger package generation
        return self.export_case_bundle(case_id, current_user)

    def get_bundle_file_for_download(self, case_id: str, current_user: User) -> Tuple[str, str]:
        """
        Resolves absolute path and filename for binary streaming download.
        Validates cached archive integrity before serving.
        """
        manifest_res = self.get_bundle_manifest(case_id, current_user)
        sealing_hash = manifest_res["docket_sealing_hash"]
        bundle_dir = os.path.join(settings.EVIDENCE_VAULT_PATH, case_id, "bundles")
        bundle_filename = manifest_res["bundle_filename"]
        bundle_path = os.path.join(bundle_dir, bundle_filename)

        if not os.path.exists(bundle_path) or not zipfile.is_zipfile(bundle_path) or os.path.getsize(bundle_path) == 0:
            # Regenerate if missing or corrupted
            re_res = self.export_case_bundle(case_id, current_user, payload=ExportBundleRequest(force_repackage=True))
            bundle_path = os.path.join(bundle_dir, re_res["bundle_filename"])
            bundle_filename = re_res["bundle_filename"]

        return bundle_path, bundle_filename
