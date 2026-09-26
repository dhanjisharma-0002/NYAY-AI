"""
NYAYAI - Authentication API Router
Module: backend.app.api.auth
Endpoints:
- POST /api/auth/register : User registration with secure bcrypt hashing
- POST /api/auth/login    : Credential validation and JWT token issuance
- GET  /api/auth/me       : Profile retrieval for authenticated identity
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.user import User
from backend.app.core.security import get_current_user
from backend.app.schemas.auth import RegisterRequest, LoginRequest, TokenResponse, UserResponse
from backend.app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new platform user"
)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    """
    Registers a new officer or judicial actor.
    - Password is salted and hashed via bcrypt (12 rounds).
    - Plaintext password is never stored or logged.
    - Rejects duplicate username or email with HTTP 400.
    """
    service = AuthService(db)
    return service.register_user(payload)


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate and receive JWT token"
)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """
    Authenticates user against stored bcrypt hash.
    Returns signed JWT access token with expiration metadata.
    """
    service = AuthService(db)
    return service.authenticate_user(payload)


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve current user profile"
)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """
    Retrieves profile information for the verified JWT bearer.
    Excludes password, password hash, and internal secrets.
    """
    return UserResponse(
        user_id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        badge_number=current_user.badge_number,
        role=current_user.role,
        is_active=current_user.is_active,
        created_at=current_user.created_at.isoformat() if current_user.created_at else None
    )
