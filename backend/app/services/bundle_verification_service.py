"""
NYAYAI - Judicial Discovery Bundle Verification Service (Phase 20)
Module: backend.app.services.bundle_verification_service
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Provides cryptographic authenticity and tamper audit verification for exported Judicial
Discovery Bundles (.zip) under Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023) Section 63:
1. Safe ZIP parsing: Blocks path-traversal (Zip-Slip), absolute paths, and oversized archives.
2. Streaming SHA-256 verification of all enclosed artifacts against manifest.json.
3. Reconstructs deterministic root checksum from canonical sorted entry list.
4. Verifies DISCOVERY_BUNDLE_CHECKSUM.sha256 independent of ZIP timestamps/metadata.
5. Authoritative docket cross-check against Phase 17 registered sealing manifest hash.
6. Cross-checks Phase 18 Section 63 judicial admissibility certificate.
7. Evaluates technical verification outcomes:
   - BUNDLE_VERIFIED_AUTHENTIC
   - BUNDLE_TAMPERED
   - ROOT_CHECKSUM_MISMATCH
   - UNREGISTERED_SEALING_HASH
   - CORRUPTED_ARCHIVE
8. Emits exactly one CASE_BUNDLE_VERIFIED audit event per run.
9. Strictly read-only: never modifies evidence baselines, case status, custody, or reports.
"""

import os
import io
import json
import uuid
import hashlib
import zipfile
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, BinaryIO

from sqlalchemy.orm import Session

from backend.app.models.user import User
from backend.app.models.case import Case
from backend.app.models.audit import AuditLog
from backend.app.schemas.bundle_verification import (
    BundleVerificationStatusEnum,
    BundleManifestVerificationRequest
)
from backend.app.services.base import BaseService
from backend.app.services.hashing_service import HashingService
from backend.app.services.case_finalization_service import CaseFinalizationService
from backend.app.utils.exceptions import (
    EntityNotFoundException,
    PermissionDeniedException
)
from backend.app.utils.logger import get_logger

logger = get_logger("bundle_verification_service")


class BundleVerificationService(BaseService):
    """
    Cryptographic verification engine for Judicial Discovery Bundles (.zip).
    """

    # Safety limits for decompression and entry inspection
    MAX_ENTRY_UNCOMPRESSED_SIZE = 250 * 1024 * 1024     # 250 MB per entry
    MAX_TOTAL_UNCOMPRESSED_SIZE = 1024 * 1024 * 1024    # 1 GB total uncompressed

    def __init__(self, db: Session):
        super().__init__(db)
        self.hasher = HashingService()
        self.finalization_service = CaseFinalizationService(db)

    def _check_case_rbac(self, case: Case, current_user: User) -> None:
        """Enforces established role and scoped ownership authorization."""
        user_role = (current_user.role or "").strip().upper()
        if user_role == "INVESTIGATOR":
            if case.created_by != current_user.id and case.created_by != current_user.username:
                raise PermissionDeniedException(
                    f"Access forbidden: Investigator '{current_user.username}' is not authorized to verify discovery bundle for case '{case.case_id}'."
                )
        elif user_role not in ("JUDGE", "ADMIN", "AUDITOR", "SYSTEM_LEAD", "LAWYER"):
            raise PermissionDeniedException(
                f"Access forbidden: Role '{user_role}' is not authorized to verify discovery bundles."
            )

    def verify_uploaded_bundle(
        self,
        case_id: str,
        zip_file: Any,
        current_user: User,
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Safely inspects and cryptographically audits an uploaded discovery .zip archive.
        """
        # 1. Fetch Case Docket
        case = self.db.query(Case).filter_by(case_id=case_id).first()
        if not case:
            raise EntityNotFoundException("Case", case_id)

        # 2. RBAC Enforcement
        self._check_case_rbac(case, current_user)

        now = datetime.now(timezone.utc)
        verifier_info = {
            "user_id": current_user.id,
            "username": current_user.username,
            "role": current_user.role,
            "notes": notes
        }

        # Retrieve authoritative docket sealing hash from system audit log / finalization service
        final_audit = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case_id, action="CASE_FINALIZED")
            .order_by(AuditLog.timestamp.desc())
            .first()
        )
        expected_sealing_hash = final_audit.meta_data.get("docket_sealing_hash") if final_audit and final_audit.meta_data else None
        if not expected_sealing_hash:
            try:
                manifest_meta = self.finalization_service.get_sealing_manifest(case_id)
                expected_sealing_hash = manifest_meta.get("docket_sealing_hash")
            except Exception:
                expected_sealing_hash = None

        # 3. Safe ZIP Opening & Structural Security Audit
        try:
            # Support both SpooledTemporaryFile, BytesIO, or file-like objects
            if hasattr(zip_file, "file"):
                zf = zipfile.ZipFile(zip_file.file, mode="r")
            elif isinstance(zip_file, (bytes, bytearray)):
                zf = zipfile.ZipFile(io.BytesIO(zip_file), mode="r")
            else:
                zf = zipfile.ZipFile(zip_file, mode="r")
        except (zipfile.BadZipFile, Exception) as ze:
            logger.warning(f"Failed to open uploaded ZIP for case {case_id}: {ze}")
            return self._finalize_and_log(
                case=case,
                current_user=current_user,
                verifier_info=verifier_info,
                verification_status=BundleVerificationStatusEnum.CORRUPTED_ARCHIVE.value,
                is_authentic=False,
                summary=f"Uploaded discovery package is not a valid ZIP archive or corrupted ({str(ze)}).",
                archive_valid=False,
                manifest_present=False,
                all_artifacts_intact=False,
                root_checksum_verified=False,
                sealing_hash_registered=False,
                admissibility_certified=False,
                expected_sealing_hash=expected_sealing_hash,
                bundle_sealing_hash=None,
                expected_root_checksum=None,
                computed_root_checksum=None,
                artifacts=[],
                tampered_paths=[],
                now=now
            )

        # 4. Enforce Safety Checks (Zip-Slip, Absolute Paths, Max Decompression Sizes)
        total_uncompressed_size = 0
        infolist = zf.infolist()
        namelist = [info.filename for info in infolist]

        for info in infolist:
            fname = info.filename
            norm_name = os.path.normpath(fname).replace("\\", "/")

            # Path Traversal and Absolute Path Detection
            if (
                ".." in fname
                or fname.startswith("/")
                or fname.startswith("\\")
                or (len(fname) > 1 and fname[1] == ":")
                or norm_name.startswith("../")
                or norm_name.startswith("..\\")
            ):
                return self._finalize_and_log(
                    case=case,
                    current_user=current_user,
                    verifier_info=verifier_info,
                    verification_status=BundleVerificationStatusEnum.CORRUPTED_ARCHIVE.value,
                    is_authentic=False,
                    summary=f"Security rejection: Zip-slip path traversal or unsafe absolute entry detected ({fname}).",
                    archive_valid=False,
                    manifest_present=False,
                    all_artifacts_intact=False,
                    root_checksum_verified=False,
                    sealing_hash_registered=False,
                    admissibility_certified=False,
                    expected_sealing_hash=expected_sealing_hash,
                    bundle_sealing_hash=None,
                    expected_root_checksum=None,
                    computed_root_checksum=None,
                    artifacts=[],
                    tampered_paths=[fname],
                    now=now
                )

            # Per-entry size check
            if info.file_size > self.MAX_ENTRY_UNCOMPRESSED_SIZE:
                return self._finalize_and_log(
                    case=case,
                    current_user=current_user,
                    verifier_info=verifier_info,
                    verification_status=BundleVerificationStatusEnum.CORRUPTED_ARCHIVE.value,
                    is_authentic=False,
                    summary=f"Security rejection: Entry '{fname}' exceeds maximum allowed uncompressed size limit.",
                    archive_valid=False,
                    manifest_present=False,
                    all_artifacts_intact=False,
                    root_checksum_verified=False,
                    sealing_hash_registered=False,
                    admissibility_certified=False,
                    expected_sealing_hash=expected_sealing_hash,
                    bundle_sealing_hash=None,
                    expected_root_checksum=None,
                    computed_root_checksum=None,
                    artifacts=[],
                    tampered_paths=[fname],
                    now=now
                )

            total_uncompressed_size += info.file_size
            if total_uncompressed_size > self.MAX_TOTAL_UNCOMPRESSED_SIZE:
                return self._finalize_and_log(
                    case=case,
                    current_user=current_user,
                    verifier_info=verifier_info,
                    verification_status=BundleVerificationStatusEnum.CORRUPTED_ARCHIVE.value,
                    is_authentic=False,
                    summary="Security rejection: Total uncompressed archive size exceeds maximum safety limit (Zip bomb protection).",
                    archive_valid=False,
                    manifest_present=False,
                    all_artifacts_intact=False,
                    root_checksum_verified=False,
                    sealing_hash_registered=False,
                    admissibility_certified=False,
                    expected_sealing_hash=expected_sealing_hash,
                    bundle_sealing_hash=None,
                    expected_root_checksum=None,
                    computed_root_checksum=None,
                    artifacts=[],
                    tampered_paths=["TOTAL_ARCHIVE_SIZE"],
                    now=now
                )

        # 5. Verify Presence of Mandatory Metadata Files and Artifact Groups (Requirement 5)
        manifest_present = "manifest.json" in namelist
        checksum_file_present = "DISCOVERY_BUNDLE_CHECKSUM.sha256" in namelist
        cert_present = "admissibility_certificate.json" in namelist
        has_evidence = any(n.startswith("evidence/") and len(n) > 9 for n in namelist)
        has_custody = any(n.startswith("custody/") and len(n) > 8 for n in namelist)
        has_reports = any(n.startswith("reports/") and len(n) > 8 for n in namelist)
        has_audit = any(n.startswith("audit/") and len(n) > 6 for n in namelist)

        missing_items = []
        if not manifest_present:
            missing_items.append("manifest.json")
        if not checksum_file_present:
            missing_items.append("DISCOVERY_BUNDLE_CHECKSUM.sha256")
        if not cert_present:
            missing_items.append("admissibility_certificate.json")
        if not has_evidence:
            missing_items.append("evidence/*")
        if not has_custody:
            missing_items.append("custody/*")
        if not has_reports:
            missing_items.append("reports/*")
        if not has_audit:
            missing_items.append("audit/*")

        if missing_items:
            return self._finalize_and_log(
                case=case,
                current_user=current_user,
                verifier_info=verifier_info,
                verification_status=BundleVerificationStatusEnum.BUNDLE_TAMPERED.value,
                is_authentic=False,
                summary=f"Mandatory discovery archive constituents missing: {', '.join(missing_items)}.",
                archive_valid=True,
                manifest_present=manifest_present,
                all_artifacts_intact=False,
                root_checksum_verified=False,
                sealing_hash_registered=False,
                admissibility_certified=False,
                expected_sealing_hash=expected_sealing_hash,
                bundle_sealing_hash=None,
                expected_root_checksum=None,
                computed_root_checksum=None,
                artifacts=[],
                tampered_paths=missing_items,
                now=now
            )

        # 6. Parse and Cross-Check manifest.json
        try:
            with zf.open("manifest.json", "r") as mf:
                manifest_data = json.loads(mf.read().decode("utf-8"))
        except Exception as me:
            return self._finalize_and_log(
                case=case,
                current_user=current_user,
                verifier_info=verifier_info,
                verification_status=BundleVerificationStatusEnum.BUNDLE_TAMPERED.value,
                is_authentic=False,
                summary=f"Malformed manifest.json in discovery bundle: {str(me)}.",
                archive_valid=True,
                manifest_present=True,
                all_artifacts_intact=False,
                root_checksum_verified=False,
                sealing_hash_registered=False,
                admissibility_certified=False,
                expected_sealing_hash=expected_sealing_hash,
                bundle_sealing_hash=None,
                expected_root_checksum=None,
                computed_root_checksum=None,
                artifacts=[],
                tampered_paths=["manifest.json"],
                now=now
            )

        bundle_case_id = manifest_data.get("case_id")
        bundle_sealing_hash = manifest_data.get("docket_sealing_hash")
        expected_root_checksum = manifest_data.get("root_checksum")

        # Parse DISCOVERY_BUNDLE_CHECKSUM.sha256 file
        checksum_map_from_file: Dict[str, str] = {}
        raw_cs_lines: List[str] = []
        try:
            with zf.open("DISCOVERY_BUNDLE_CHECKSUM.sha256", "r") as csf:
                for line in csf.read().decode("utf-8").splitlines():
                    sline = line.strip()
                    if sline and not sline.startswith("#"):
                        raw_cs_lines.append(sline)
                        parts = sline.split("  ", 1)
                        if len(parts) == 2:
                            checksum_map_from_file[parts[1]] = parts[0].lower()
        except Exception:
            checksum_map_from_file = {}

        # 7. Authoritative Sealing Hash Cross-Check (Requirement 6)
        sealing_hash_registered = bool(
            expected_sealing_hash
            and bundle_sealing_hash
            and bundle_sealing_hash.lower() == expected_sealing_hash.lower()
        )

        # 8. Parse and Cross-Check admissibility_certificate.json (Requirement 7)
        admissibility_certified = False
        try:
            with zf.open("admissibility_certificate.json", "r") as cf:
                cert_data = json.loads(cf.read().decode("utf-8"))
            if (
                cert_data.get("case_id") == case.case_id
                and cert_data.get("is_admissible") is True
                and cert_data.get("admissibility_status") == "ADMISSIBLE"
            ):
                admissibility_certified = True
        except Exception:
            admissibility_certified = False

        # 9. Streaming SHA-256 Verification for Every Enclosed Artifact (Requirement 3)
        manifest_artifacts = manifest_data.get("artifacts", [])
        artifact_audit_items: List[Dict[str, Any]] = []
        tampered_artifact_paths: List[str] = []
        computed_hash_map: Dict[str, str] = {}

        for item in manifest_artifacts:
            arc_path = item.get("path")
            expected_hash = item.get("sha256", "").lower()
            art_type = item.get("artifact_type", "UNKNOWN")

            if arc_path not in namelist:
                tampered_artifact_paths.append(arc_path)
                artifact_audit_items.append({
                    "path": arc_path,
                    "artifact_type": art_type,
                    "expected_sha256": expected_hash,
                    "computed_sha256": None,
                    "matches": False,
                    "file_size": 0
                })
                continue

            # Stream entry chunk-by-chunk using ZipFile.open() without writing to disk
            hasher = hashlib.sha256()
            entry_bytes_read = 0
            with zf.open(arc_path, "r") as ef:
                while True:
                    chunk = ef.read(64 * 1024)
                    if not chunk:
                        break
                    entry_bytes_read += len(chunk)
                    hasher.update(chunk)

            computed_sha = hasher.hexdigest().lower()
            computed_hash_map[arc_path] = computed_sha
            matches = (computed_sha == expected_hash)

            # Also check against DISCOVERY_BUNDLE_CHECKSUM.sha256 if present
            if arc_path in checksum_map_from_file:
                if computed_sha != checksum_map_from_file[arc_path]:
                    matches = False

            if not matches:
                tampered_artifact_paths.append(arc_path)

            artifact_audit_items.append({
                "path": arc_path,
                "artifact_type": art_type,
                "expected_sha256": expected_hash,
                "computed_sha256": computed_sha,
                "matches": matches,
                "file_size": entry_bytes_read
            })

        # Also verify manifest.json itself against DISCOVERY_BUNDLE_CHECKSUM.sha256
        if "manifest.json" in namelist:
            hasher = hashlib.sha256()
            m_bytes = 0
            with zf.open("manifest.json", "r") as mf:
                while True:
                    chunk = mf.read(64 * 1024)
                    if not chunk:
                        break
                    m_bytes += len(chunk)
                    hasher.update(chunk)
            computed_m_sha = hasher.hexdigest().lower()
            computed_hash_map["manifest.json"] = computed_m_sha
            exp_m_sha = checksum_map_from_file.get("manifest.json", computed_m_sha)
            m_matches = (computed_m_sha == exp_m_sha)
            if not m_matches:
                tampered_artifact_paths.append("manifest.json")
            artifact_audit_items.append({
                "path": "manifest.json",
                "artifact_type": "BUNDLE_MANIFEST",
                "expected_sha256": exp_m_sha,
                "computed_sha256": computed_m_sha,
                "matches": m_matches,
                "file_size": m_bytes
            })

        all_artifacts_intact = (len(tampered_artifact_paths) == 0 and len(artifact_audit_items) > 0)

        # 10. Reconstruct Canonical Sorted Root Checksum (Requirement 4)
        non_checksum_entries = [
            (path, sha)
            for path, sha in computed_hash_map.items()
            if path != "DISCOVERY_BUNDLE_CHECKSUM.sha256" and sha
        ]
        sorted_entries = sorted(non_checksum_entries, key=lambda x: x[0])
        canonical_body = "\n".join(f"{sha}  {path}" for path, sha in sorted_entries)
        computed_root_checksum = hashlib.sha256(canonical_body.encode("utf-8")).hexdigest().lower() if sorted_entries else None

        # Verify against DISCOVERY_BUNDLE_CHECKSUM.sha256 file contents
        file_root_checksum = hashlib.sha256("\n".join(raw_cs_lines).encode("utf-8")).hexdigest().lower() if raw_cs_lines else None

        # Check against authoritative CASE_BUNDLE_EXPORTED audit record
        export_audit = (
            self.db.query(AuditLog)
            .filter_by(resource_id=case_id, action="CASE_BUNDLE_EXPORTED")
            .order_by(AuditLog.timestamp.desc())
            .first()
        )
        recorded_export_root = export_audit.meta_data.get("root_checksum", "").lower() if export_audit and export_audit.meta_data else None

        root_checksum_matches = (
            computed_root_checksum is not None
            and file_root_checksum is not None
            and computed_root_checksum == file_root_checksum
            and (recorded_export_root is None or computed_root_checksum == recorded_export_root)
            and (expected_root_checksum is None or computed_root_checksum == expected_root_checksum.lower())
        )

        # 11. Determine Technical Verification Status (Requirement 8)
        if not sealing_hash_registered:
            status_outcome = BundleVerificationStatusEnum.UNREGISTERED_SEALING_HASH.value
            is_authentic = False
            summary = (
                f"Authoritative sealing mismatch: The discovery bundle sealing hash "
                f"('{str(bundle_sealing_hash)[:16]}...') does not match the registered "
                f"sealing manifest hash ('{str(expected_sealing_hash)[:16]}...') for case '{case_id}'."
            )
        elif not all_artifacts_intact or not admissibility_certified:
            status_outcome = BundleVerificationStatusEnum.BUNDLE_TAMPERED.value
            is_authentic = False
            reasons = []
            if tampered_artifact_paths:
                reasons.append(f"{len(tampered_artifact_paths)} constituent artifact(s) failed hash verification")
            if not admissibility_certified:
                reasons.append("enclosed Section 63 admissibility certificate is invalid or does not match case")
            summary = f"Discovery bundle tamper detected: {'; '.join(reasons)}."
        elif not root_checksum_matches:
            status_outcome = BundleVerificationStatusEnum.ROOT_CHECKSUM_MISMATCH.value
            is_authentic = False
            summary = (
                f"Root checksum divergence: Recomputed bundle root hash ({computed_root_checksum[:16] if computed_root_checksum else 'None'}...) "
                f"does not match DISCOVERY_BUNDLE_CHECKSUM.sha256."
            )
        else:
            status_outcome = BundleVerificationStatusEnum.BUNDLE_VERIFIED_AUTHENTIC.value
            is_authentic = True
            summary = (
                f"Judicial Discovery Package verified authentic under Section 63 of Bharatiya Sakshya Adhiniyam, 2023. "
                f"All {len(artifact_audit_items)} artifacts, custody ledgers, reports, and root checksum ({computed_root_checksum[:16]}...) match authoritative sealed records."
            )

        # 12. Finalize Response and Emit Single CASE_BUNDLE_VERIFIED Audit Log (Requirement 9)
        return self._finalize_and_log(
            case=case,
            current_user=current_user,
            verifier_info=verifier_info,
            verification_status=status_outcome,
            is_authentic=is_authentic,
            summary=summary,
            archive_valid=True,
            manifest_present=True,
            all_artifacts_intact=all_artifacts_intact,
            root_checksum_verified=root_checksum_matches,
            sealing_hash_registered=sealing_hash_registered,
            admissibility_certified=admissibility_certified,
            expected_sealing_hash=expected_sealing_hash,
            bundle_sealing_hash=bundle_sealing_hash,
            expected_root_checksum=recorded_export_root or expected_root_checksum,
            computed_root_checksum=computed_root_checksum,
            artifacts=artifact_audit_items,
            tampered_paths=tampered_artifact_paths,
            now=now
        )

    def verify_bundle_manifest(
        self,
        payload: BundleManifestVerificationRequest,
        current_user: Optional[User] = None
    ) -> Dict[str, Any]:
        """
        Lightweight / air-gap manifest verification without uploading large media files.
        """
        case = self.db.query(Case).filter_by(case_id=payload.case_id).first()
        if not case:
            raise EntityNotFoundException("Case", payload.case_id)

        if current_user:
            self._check_case_rbac(case, current_user)
            verifier_dict = {
                "user_id": current_user.id,
                "username": current_user.username,
                "role": current_user.role,
                "notes": payload.notes
            }
        else:
            verifier_dict = {
                "user_id": None,
                "username": "PUBLIC_AUDITOR",
                "role": "PUBLIC_VERIFIER",
                "notes": payload.notes
            }

        now = datetime.now(timezone.utc)

        # Authoritative Sealing Hash Cross-Check
        final_audit = (
            self.db.query(AuditLog)
            .filter_by(resource_id=payload.case_id, action="CASE_FINALIZED")
            .order_by(AuditLog.timestamp.desc())
            .first()
        )
        expected_sealing_hash = final_audit.meta_data.get("docket_sealing_hash") if final_audit and final_audit.meta_data else None
        if not expected_sealing_hash:
            try:
                manifest_meta = self.finalization_service.get_sealing_manifest(payload.case_id)
                expected_sealing_hash = manifest_meta.get("docket_sealing_hash")
            except Exception:
                expected_sealing_hash = None

        sealing_hash_matches = bool(
            expected_sealing_hash
            and payload.docket_sealing_hash
            and payload.docket_sealing_hash.lower() == expected_sealing_hash.lower()
        )

        # Verify Root Checksum (against manifest text or recorded export audit)
        root_checksum_matches = False
        if payload.checksum_manifest_text:
            cs_lines = [
                line.strip()
                for line in payload.checksum_manifest_text.splitlines()
                if line.strip() and not line.startswith("#")
            ]
            recomputed = hashlib.sha256("\n".join(cs_lines).encode("utf-8")).hexdigest().lower()
            root_checksum_matches = (recomputed == payload.root_checksum.lower())
        else:
            export_audit = (
                self.db.query(AuditLog)
                .filter_by(resource_id=payload.case_id, action="CASE_BUNDLE_EXPORTED")
                .order_by(AuditLog.timestamp.desc())
                .first()
            )
            if export_audit and export_audit.meta_data:
                rec_checksum = export_audit.meta_data.get("root_checksum", "").lower()
                root_checksum_matches = (rec_checksum == payload.root_checksum.lower())

        # Check Latest Admissibility State
        admissibility_audit = (
            self.db.query(AuditLog)
            .filter_by(resource_id=payload.case_id, action="CASE_ADMISSIBILITY_VERIFIED")
            .order_by(AuditLog.timestamp.desc())
            .first()
        )
        admissibility_status = "UNKNOWN"
        if admissibility_audit and admissibility_audit.meta_data:
            admissibility_status = admissibility_audit.meta_data.get("admissibility_status", "UNKNOWN")

        # Resolve Status
        if not sealing_hash_matches:
            status_outcome = BundleVerificationStatusEnum.UNREGISTERED_SEALING_HASH.value
            is_authentic = False
            summary = "Supplied docket sealing hash does not match registered case finalization manifest."
        elif not root_checksum_matches:
            status_outcome = BundleVerificationStatusEnum.ROOT_CHECKSUM_MISMATCH.value
            is_authentic = False
            summary = "Supplied root checksum does not match discovery bundle checksum manifest records."
        else:
            status_outcome = BundleVerificationStatusEnum.BUNDLE_VERIFIED_AUTHENTIC.value
            is_authentic = True
            summary = "Discovery bundle manifest and root checksum verified authentic against court docket records."

        # Emit exactly one CASE_BUNDLE_VERIFIED audit log
        audit_entry = AuditLog(
            audit_id=f"AUD-{now.year}-{uuid.uuid4().hex[:8].upper()}",
            user_id=verifier_dict.get("user_id"),
            action="CASE_BUNDLE_VERIFIED",
            resource_type="CASE",
            resource_id=case.case_id,
            timestamp=now,
            meta_data={
                "case_number": case.case_number,
                "verification_method": "AIRGAP_MANIFEST",
                "verification_status": status_outcome,
                "is_authentic": is_authentic,
                "docket_sealing_hash": expected_sealing_hash,
                "supplied_sealing_hash": payload.docket_sealing_hash,
                "root_checksum": payload.root_checksum,
                "verifier_role": verifier_dict.get("role"),
                "verifier_username": verifier_dict.get("username")
            }
        )
        self.db.add(audit_entry)
        self.db.commit()

        return {
            "case_id": case.case_id,
            "case_number": case.case_number,
            "verification_status": status_outcome,
            "is_authentic": is_authentic,
            "statutory_framework": "BSA_2023_SEC_63_BNSS_2023_SEC_230",
            "verified_at": now.isoformat(),
            "verifier": verifier_dict,
            "docket_sealing_hash_matches": sealing_hash_matches,
            "root_checksum_matches": root_checksum_matches,
            "admissibility_status": admissibility_status,
            "verification_summary": summary
        }

    def _finalize_and_log(
        self,
        case: Case,
        current_user: User,
        verifier_info: Dict[str, Any],
        verification_status: str,
        is_authentic: bool,
        summary: str,
        archive_valid: bool,
        manifest_present: bool,
        all_artifacts_intact: bool,
        root_checksum_verified: bool,
        sealing_hash_registered: bool,
        admissibility_certified: bool,
        expected_sealing_hash: Optional[str],
        bundle_sealing_hash: Optional[str],
        expected_root_checksum: Optional[str],
        computed_root_checksum: Optional[str],
        artifacts: List[Dict[str, Any]],
        tampered_paths: List[str],
        now: datetime
    ) -> Dict[str, Any]:
        """
        Emits single CASE_BUNDLE_VERIFIED audit log and builds standardized verification receipt.
        """
        # Exactly one CASE_BUNDLE_VERIFIED audit log
        audit_entry = AuditLog(
            audit_id=f"AUD-{now.year}-{uuid.uuid4().hex[:8].upper()}",
            user_id=current_user.id,
            action="CASE_BUNDLE_VERIFIED",
            resource_type="CASE",
            resource_id=case.case_id,
            timestamp=now,
            meta_data={
                "case_number": case.case_number,
                "verification_status": verification_status,
                "is_authentic": is_authentic,
                "expected_sealing_hash": expected_sealing_hash,
                "bundle_sealing_hash": bundle_sealing_hash,
                "expected_root_checksum": expected_root_checksum,
                "computed_root_checksum": computed_root_checksum,
                "total_artifacts_checked": len(artifacts),
                "tampered_artifacts_count": len(tampered_paths),
                "tampered_artifact_paths": tampered_paths,
                "verifier_role": current_user.role,
                "verifier_username": current_user.username
            }
        )
        self.db.add(audit_entry)
        self.db.commit()

        logger.info(
            f"Judicial discovery bundle verified for case {case.case_id}: "
            f"status={verification_status}, is_authentic={is_authentic} by {current_user.username}"
        )

        return {
            "case_id": case.case_id,
            "case_number": case.case_number,
            "verification_status": verification_status,
            "is_authentic": is_authentic,
            "statutory_framework": "BSA_2023_SEC_63_BNSS_2023_SEC_230",
            "verified_at": now.isoformat(),
            "verifier": verifier_info,
            "checks": {
                "archive_structure_valid": archive_valid,
                "manifest_present": manifest_present,
                "all_artifacts_intact": all_artifacts_intact,
                "root_checksum_verified": root_checksum_verified,
                "sealing_hash_registered": sealing_hash_registered,
                "admissibility_certified": admissibility_certified,
                "total_artifacts_checked": len(artifacts),
                "tampered_artifacts_count": len(tampered_paths),
                "tampered_artifact_paths": tampered_paths
            },
            "expected_sealing_hash": expected_sealing_hash,
            "bundle_sealing_hash": bundle_sealing_hash,
            "expected_root_checksum": expected_root_checksum,
            "computed_root_checksum": computed_root_checksum,
            "verification_summary": summary,
            "artifacts": artifacts
        }
