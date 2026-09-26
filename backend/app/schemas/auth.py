"""
NYAYAI - Authentication and RBAC Schemas
Module: backend.app.schemas.auth
Defines contract interfaces for user registration, credential verification,
and token issuance. Never leaks password hashes or secrets.
"""

from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    """Payload for user registration."""
    username: str = Field(..., min_length=3, max_length=64, description="Unique login identifier")
    email: EmailStr = Field(..., description="Official government or institutional email")
    password: str = Field(..., min_length=8, description="Secure plaintext password (min 8 characters)")
    full_name: str = Field(..., min_length=2, max_length=128, description="Real name of officer or practitioner")
    role: str = Field(default="INVESTIGATOR", description="Requested role: ADMIN, INVESTIGATOR, LAWYER, JUDGE")
    badge_number: Optional[str] = Field(None, description="Departmental identification or bar council registration number")


class LoginRequest(BaseModel):
    """Payload for user login."""
    username: str = Field(..., description="Registered username")
    password: str = Field(..., description="Plaintext account password")


class UserResponse(BaseModel):
    """
    Safe public user representation.
    CRITICAL: Strictly excludes password, password hash, and internal secrets.
    """
    user_id: str
    username: str
    email: str
    full_name: str
    badge_number: Optional[str] = None
    role: str
    is_active: bool
    created_at: Optional[str] = None

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    """JWT Bearer token and expiration metadata."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse
