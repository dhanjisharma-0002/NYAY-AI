"""
NYAYAI - Role-Based Access Control (RBAC) Specification
Module: backend.app.core.roles
Defines supported platform roles, capability scopes, and permission hierarchies.
"""

from enum import Enum
from typing import Dict, List, Set, Optional


class RoleEnum(str, Enum):
    """
    Standard platform roles supported in NYAYAI.
    """
    ADMIN = "ADMIN"
    INVESTIGATOR = "INVESTIGATOR"
    LAWYER = "LAWYER"
    JUDGE = "JUDGE"

    # Backward compatibility roles from Phase 0-2
    SYSTEM_LEAD = "SYSTEM_LEAD"
    FORENSIC_EXPERT = "FORENSIC_EXPERT"
    AUDITOR = "AUDITOR"


# Permission scopes defining granular capabilities per role
ROLE_PERMISSIONS: Dict[str, List[str]] = {
    RoleEnum.ADMIN.value: [
        "user:management",
        "system:administration",
        "case:create",
        "case:read",
        "case:update",
        "case:delete",
        "evidence:upload",
        "evidence:read",
        "evidence:analyze",
        "reports:view",
        "reports:generate",
        "reports:verify",
        "audit:read"
    ],
    RoleEnum.INVESTIGATOR.value: [
        "case:create",
        "case:read",
        "case:update",
        "evidence:upload",
        "evidence:read_assigned",
        "evidence:read",
        "analysis:initiate"
    ],
    RoleEnum.LAWYER.value: [
        "case:view_permitted",
        "reports:view"
    ],
    RoleEnum.JUDGE.value: [
        "case:read",
        "reports:view",
        "reports:verify_authenticity",
        "custody:verify"
    ],
    # Legacy roles mapped to equivalent capability sets
    RoleEnum.SYSTEM_LEAD.value: [
        "*"
    ],
    RoleEnum.FORENSIC_EXPERT.value: [
        "evidence:read",
        "evidence:analyze",
        "forensics:inspect",
        "reports:generate"
    ],
    RoleEnum.AUDITOR.value: [
        "audit:read",
        "custody:verify",
        "reports:view"
    ]
}


def normalize_role(role_name: str) -> str:
    """Normalizes role strings to uppercase and validates against known roles."""
    cleaned = role_name.strip().upper()
    valid_roles = {r.value for r in RoleEnum}
    if cleaned not in valid_roles:
        raise ValueError(f"Invalid role '{role_name}'. Supported roles: {[r.value for r in RoleEnum if r in [RoleEnum.ADMIN, RoleEnum.INVESTIGATOR, RoleEnum.LAWYER, RoleEnum.JUDGE]]}")
    return cleaned


def has_permission(role: str, permission: str) -> bool:
    """
    Evaluates whether a role possesses a specific capability permission.
    Adheres to the principle of least privilege ('Do not assume unrestricted access').
    """
    normalized = role.upper()
    perms = ROLE_PERMISSIONS.get(normalized, [])
    if "*" in perms:
        return True
    return permission in perms
