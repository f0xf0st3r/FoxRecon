"""Authentication module - JWT auth, RBAC middleware, dependencies."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from internal.config import get_settings

settings = get_settings()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# HTTP Bearer token scheme
security = HTTPBearer()


# ------------------------------------------------------------------ #
# Token models
# ------------------------------------------------------------------ #
class TokenPayload(BaseModel):
    sub: str  # user ID
    email: str
    role: str
    exp: datetime
    type: str = "access"


# ------------------------------------------------------------------ #
# Password utilities
# ------------------------------------------------------------------ #
def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


# ------------------------------------------------------------------ #
# JWT utilities
# ------------------------------------------------------------------ #
def create_access_token(
    user_id: str,
    email: str,
    role: str,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a JWT access token."""
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.jwt_access_token_expire_minutes)

    expire = datetime.now(timezone.utc) + expires_delta

    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": expire,
        "type": "access",
        "iat": datetime.now(timezone.utc),
    }

    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(
    user_id: str,
    email: str,
    role: str,
) -> str:
    """Create a JWT refresh token."""
    expires_delta = timedelta(days=settings.jwt_refresh_token_expire_days)
    expire = datetime.now(timezone.utc) + expires_delta

    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": expire,
        "type": "refresh",
        "iat": datetime.now(timezone.utc),
    }

    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any]:
    """Decode and verify a JWT token."""
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ------------------------------------------------------------------ #
# Dependencies
# ------------------------------------------------------------------ #
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict[str, Any]:
    """Get current authenticated user from JWT token."""
    payload = decode_token(credentials.credentials)

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )

    return {
        "id": uuid.UUID(payload["sub"]),
        "email": payload["email"],
        "role": payload["role"],
    }


async def get_current_active_user(
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """Get current user and verify active status."""
    # In production, check against database
    return current_user


def require_role(required_roles: list[str]):
    """Dependency factory for role-based access control.

    Usage:
        @router.get("/admin", dependencies=[Depends(require_role(["admin"]))])
    """
    async def role_checker(current_user: dict[str, Any] = Depends(get_current_user)):
        if current_user["role"] not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    return role_checker


async def get_api_key_user(
    api_key: str,
) -> dict[str, Any] | None:
    """Validate an API key and return user info.

    In production, compare against hashed API keys in database.
    """
    # Placeholder - implement actual API key validation
    return None
