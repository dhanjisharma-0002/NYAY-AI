"""
NYAYAI - Authentication and User Management Service
Module: backend.app.services.auth_service
Handles registration, credential validation, and JWT token issuance.
Ensures zero plaintext password storage and zero secret leakage.
"""

import uuid
from typing import Optional
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models.user import User
from backend.app.models.role import Role
from backend.app.core.roles import normalize_role, RoleEnum
from backend.app.core.security import get_password_hash, verify_password, create_access_token
from backend.app.schemas.auth import RegisterRequest, LoginRequest, TokenResponse, UserResponse
from backend.app.services.base import BaseService
from backend.app.utils.exceptions import AppException, AuthenticationException, ValidationException


class AuthService(BaseService):
    """Encapsulates authentication, registration, and user access validation."""

    def register_user(self, payload: RegisterRequest) -> UserResponse:
        """
        Registers a new user with securely hashed credentials.
        Validates unique constraints (username, email) and assigns appropriate role.
        """
        # 1. Validate and normalize role
        try:
            canonical_role = normalize_role(payload.role)
        except ValueError as err:
            raise ValidationException(str(err))

        # 2. Check for duplicate username
        existing_username = self.db.query(User).filter_by(username=payload.username).first()
        if existing_username:
            raise AppException(
                message=f"Username '{payload.username}' is already in use.",
                status_code=400,
                error_code="DUPLICATE_USERNAME"
            )

        # 3. Check for duplicate email
        existing_email = self.db.query(User).filter_by(email=payload.email).first()
        if existing_email:
            raise AppException(
                message=f"Email '{payload.email}' is already registered.",
                status_code=400,
                error_code="DUPLICATE_EMAIL"
            )

        # 4. Resolve Role entity in database (if seeded)
        role_record = self.db.query(Role).filter_by(name=canonical_role).first()
        role_id = role_record.id if role_record else None

        # 5. Hash password with bcrypt (salt rounds = 12)
        hashed_pw = get_password_hash(payload.password)

        # 6. Instantiate and commit user
        new_user = User(
            id=str(uuid.uuid4()),
            username=payload.username,
            email=payload.email,
            hashed_password=hashed_pw,
            full_name=payload.full_name,
            badge_number=payload.badge_number,
            role_id=role_id,
            role=canonical_role,
            is_active=True
        )
        self.db.add(new_user)
        self.db.commit()
        self.db.refresh(new_user)

        return UserResponse(
            user_id=new_user.id,
            username=new_user.username,
            email=new_user.email,
            full_name=new_user.full_name,
            badge_number=new_user.badge_number,
            role=new_user.role,
            is_active=new_user.is_active,
            created_at=new_user.created_at.isoformat() if new_user.created_at else None
        )

    def authenticate_user(self, payload: LoginRequest) -> TokenResponse:
        """
        Validates user credentials against stored bcrypt hash and generates JWT.
        Returns HTTP 401 on missing user, invalid password, or inactive account.
        """
        user = self.db.query(User).filter_by(username=payload.username).first()
        if not user:
            raise AuthenticationException("Invalid username or password.")

        if not verify_password(payload.password, user.hashed_password):
            raise AuthenticationException("Invalid username or password.")

        if not user.is_active:
            raise AuthenticationException("User account is inactive or disabled.")

        # Issue cryptographically signed JWT token
        token_claims = {
            "sub": user.id,
            "username": user.username,
            "role": user.role
        }
        access_token = create_access_token(token_claims)
        expires_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

        user_response = UserResponse(
            user_id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            badge_number=user.badge_number,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at.isoformat() if user.created_at else None
        )

        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=expires_seconds,
            user=user_response
        )
