"""
NYAYAI - Judicial Discovery Bundle Verification Schemas (Phase 20)
Module: backend.app.schemas.bundle_verification
Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class BundleVerificationStatusEnum(str, Enum):
    """Technical evidentiary discovery bundle verification outcomes under BSA 2023."""
    BUNDLE_VERIFIED_AUTHENTIC = "BUNDLE_VERIFIED_AUTHENTIC"
    BUNDLE_TAMPERED = "BUNDLE_TAMPERED"
    ROOT_CHECKSUM_MISMATCH = "ROOT_CHECKSUM_MISMATCH"
    UNREGISTERED_SEALING_HASH = "UNREGISTERED_SEALING_HASH"
    CORRUPTED_ARCHIVE = "CORRUPTED_ARCHIVE"


class ArtifactVerificationItem(BaseModel):
    """Verification details for an individual artifact enclosed in the bundle."""
    path: str
    artifact_type: str
    expected_sha256: str
    computed_sha256: Optional[str] = None
    matches: bool
    file_size: int


class BundleVerificationChecks(BaseModel):
    """Granular technical checks executed on the discovery bundle."""
    archive_structure_valid: bool
    manifest_present: bool
    all_artifacts_intact: bool
    root_checksum_verified: bool
    sealing_hash_registered: bool
    admissibility_certified: bool
    total_artifacts_checked: int
    tampered_artifacts_count: int
    tampered_artifact_paths: List[str] = Field(default_factory=list)


class BundleVerificationResponse(BaseModel):
    """Detailed judicial discovery bundle verification assessment and receipt."""
    case_id: str
    case_number: str
    verification_status: str
    is_authentic: bool
    statutory_framework: str = "BSA_2023_SEC_63_BNSS_2023_SEC_230"
    verified_at: str
    verifier: Dict[str, Any]
    checks: BundleVerificationChecks
    expected_sealing_hash: Optional[str] = None
    bundle_sealing_hash: Optional[str] = None
    expected_root_checksum: Optional[str] = None
    computed_root_checksum: Optional[str] = None
    verification_summary: str
    artifacts: List[ArtifactVerificationItem] = Field(default_factory=list)


class BundleManifestVerificationRequest(BaseModel):
    """Payload for air-gapped / lightweight discovery bundle manifest verification."""
    case_id: str = Field(..., description="Unique case identifier")
    root_checksum: str = Field(..., description="Root SHA-256 checksum from DISCOVERY_BUNDLE_CHECKSUM.sha256")
    docket_sealing_hash: str = Field(..., description="Phase 17 docket sealing manifest hash")
    checksum_manifest_text: Optional[str] = Field(
        None,
        description="Full text contents of DISCOVERY_BUNDLE_CHECKSUM.sha256 for canonical parsing"
    )
    notes: Optional[str] = Field(None, description="Auditor verification notes")


class BundleManifestVerificationResponse(BaseModel):
    """Receipt for air-gapped / lightweight discovery bundle manifest verification."""
    case_id: str
    case_number: str
    verification_status: str
    is_authentic: bool
    statutory_framework: str = "BSA_2023_SEC_63_BNSS_2023_SEC_230"
    verified_at: str
    verifier: Dict[str, Any]
    docket_sealing_hash_matches: bool
    root_checksum_matches: bool
    admissibility_status: str
    verification_summary: str
