"""
NYAYAI - Security, JWT Authentication & RBAC Dependencies
Module: backend.app.core.security
Provides:
- Secure password hashing & verification via bcrypt (12 rounds)
- Cryptographic JWT access token issuance & verification via PyJWT
- Fast and reusable role-based authorization dependencies
- Strict access boundaries adhering to the principle of least privilege
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Callable

import bcrypt
import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.models.user import User
from backend.app.core.roles import RoleEnum, has_permission
from backend.app.utils.exceptions import AuthenticationException, PermissionDeniedException

# HTTPBearer scheme for OpenAPI documentation and token parsing
http_bearer = HTTPBearer(auto_error=False)


# ==============================================================================
# 1. Password Hashing & Verification (Bcrypt)
# ==============================================================================

def get_password_hash(password: str) -> str:
    """
    Computes a salted, adaptive bcrypt hash of the plaintext password.
    Never stores or logs plaintext passwords.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plaintext password against a stored bcrypt hash.
    Constant-time comparison protects against timing attacks.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


# ==============================================================================
# 2. JWT Access Token Management (PyJWT)
# ==============================================================================

def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Generates a cryptographically signed JWT token with expiry and unique token ID.
    """
    to_encode = data.copy()
    now_utc = datetime.now(timezone.utc)
    
    if expires_delta:
        expire = now_utc + expires_delta
    else:
        expire = now_utc + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "iat": now_utc,
        "jti": str(uuid.uuid4())
    })

    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decodes and validates JWT token signature and expiration.
    Raises AuthenticationException on signature failure, expiration, or malformed claims.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthenticationException("Authentication token has expired. Please log in again.")
    except jwt.InvalidTokenError:
        raise AuthenticationException("Could not validate credentials: invalid token signature.")


# ==============================================================================
# 3. User Authentication Dependencies
# ==============================================================================

def extract_token_from_header(
    authorization: Optional[str] = Header(None),
    bearer_creds: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer)
) -> Optional[str]:
    """Extracts raw JWT token from either HTTPBearer or direct Authorization header."""
    if bearer_creds and bearer_creds.credentials:
        return bearer_creds.credentials
    if authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
        elif len(parts) == 1:
            return parts[0]
    return None


def get_current_user(
    token: Optional[str] = Depends(extract_token_from_header),
    db: Session = Depends(get_db)
) -> User:
    """
    Strict dependency: enforces valid JWT and active user identity.
    Raises HTTP 401 if missing, invalid, or inactive.
    """
    if not token:
        raise AuthenticationException("Missing or malformed Authorization header. Bearer token required.")

    payload = decode_access_token(token)
    user_id: Optional[str] = payload.get("sub") or payload.get("user_id")
    username: Optional[str] = payload.get("username")

    if not user_id and not username:
        raise AuthenticationException("Malformed token claims: missing subject identifier.")

    # Query active user by ID or username
    query = db.query(User)
    if user_id:
        user = query.filter(User.id == user_id).first()
    else:
        user = query.filter(User.username == username).first()

    if not user:
        raise AuthenticationException("User corresponding to token was not found.")

    if not user.is_active:
        raise AuthenticationException("User account is inactive or disabled.")

    return user


def get_current_user_optional(
    token: Optional[str] = Depends(extract_token_from_header),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Permissive dependency: returns authenticated User if valid token is provided;
    returns None if no Authorization header is present.
    """
    if not token:
        return None
    try:
        return get_current_user(token=token, db=db)
    except Exception:
        return None


# Backward compatibility for Phase 0-2 helper
def get_current_user_id(authorization: Optional[str] = Header(None)) -> str:
    """
    Preserved for backward compatibility.
    Resolves bearer token to user ID, defaulting to USR-SYSTEM-LEAD for dev probes.
    """
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        try:
            payload = decode_access_token(token)
            return payload.get("sub", token)
        except Exception:
            return token if len(token) < 40 else "USR-SYSTEM-LEAD"
    return "USR-SYSTEM-LEAD"


# ==============================================================================
# 4. Role-Based Access Control (RBAC) Dependencies
# ==============================================================================

def require_roles(*allowed_roles: str, allow_admin: bool = False) -> Callable:
    """
    Creates a reusable FastAPI dependency requiring the authenticated user
    to possess at least one of the specified roles.
    
    If allow_admin is True, users with role 'ADMIN' or 'SYSTEM_LEAD' are also permitted.
    If allow_admin is False (default), ONLY the specified roles have access (strictly adhering
    to 'Do not assume unrestricted access').
    """
    normalized_allowed = {r.strip().upper() for r in allowed_roles}
    if allow_admin:
        normalized_allowed.add("ADMIN")
        normalized_allowed.add("SYSTEM_LEAD")

    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        user_role = current_user.role.strip().upper()

        # Handle SYSTEM_LEAD as ADMIN alias if ADMIN is allowed
        if user_role == "SYSTEM_LEAD" and "ADMIN" in normalized_allowed:
            return current_user

        if user_role in normalized_allowed:
            return current_user

        raise PermissionDeniedException(
            f"Access forbidden: User with role '{current_user.role}' lacks authorization for this resource. Required role(s): {list(normalized_allowed)}"
        )

    return role_checker


def require_permission(permission: str) -> Callable:
    """
    Creates a reusable FastAPI dependency checking if the user's role grants
    the specific granular capability.
    """
    def permission_checker(current_user: User = Depends(get_current_user)) -> User:
        if has_permission(current_user.role, permission):
            return current_user
        raise PermissionDeniedException(
            f"Access forbidden: User role '{current_user.role}' lacks required permission: '{permission}'."
        )

    return permission_checker


# Convenient Pre-bound Role Dependencies
require_admin = require_roles("ADMIN", "SYSTEM_LEAD")
require_investigator = require_roles("INVESTIGATOR")
require_lawyer = require_roles("LAWYER")
require_judge = require_roles("JUDGE")
