"""
NYAYAI - Case Docket Judicial Discovery & Cryptographic Export Bundle Schemas (Phase 19)
Module: backend.app.schemas.export_bundle
Lead: Dhananjay Sharma (Backend & System Integration Lead)
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class ExportBundleRequest(BaseModel):
    """Payload for initiating judicial discovery bundle generation."""
    purpose: Optional[str] = Field(
        None,
        description="Reason or legal proceeding for discovery export (e.g. 'Court Evidence Tender', 'Defense Disclosure under BNSS 230')"
    )
    recipient_court_or_agency: Optional[str] = Field(
        None,
        description="Destination court, bench, or forensic laboratory (e.g. 'Sessions Court Delhi', 'CFSL New Delhi')"
    )
    authorized_officer_name: Optional[str] = Field(
        None,
        description="Name of presiding judge, public prosecutor, or forensic custodian"
    )
    notes: Optional[str] = Field(
        None,
        description="Additional disclosure or custody transfer remarks"
    )
    force_repackage: Optional[bool] = Field(
        False,
        description="If true, bypasses existing cached archive and regenerates fresh bundle"
    )


class BundleArtifactItem(BaseModel):
    """Metadata for an individual file enclosed within the discovery bundle."""
    path: str
    artifact_type: str
    file_size: int
    sha256: str


class ExportBundleResponse(BaseModel):
    """Detailed summary of the generated judicial discovery export package."""
    case_id: str
    case_number: str
    bundle_filename: str
    bundle_file_size: int
    root_checksum: str
    docket_sealing_hash: str
    admissibility_status: str
    statutory_framework: str = "BSA_2023_SEC_63_BNSS_2023_SEC_230"
    exported_at: str
    exporter: Dict[str, Any]
    total_artifacts: int
    cached: bool
    download_url: str
    artifacts: List[BundleArtifactItem] = Field(default_factory=list)


class BundleManifestResponse(BaseModel):
    """Manifest view for pre-download inspection of a judicial discovery bundle."""
    case_id: str
    case_number: str
    bundle_filename: str
    bundle_file_size: int
    root_checksum: str
    docket_sealing_hash: str
    admissibility_status: str
    statutory_framework: str = "BSA_2023_SEC_63_BNSS_2023_SEC_230"
    exported_at: str
    exporter: Dict[str, Any]
    total_artifacts: int
    cached: bool
    download_url: str
    artifacts: List[BundleArtifactItem] = Field(default_factory=list)
