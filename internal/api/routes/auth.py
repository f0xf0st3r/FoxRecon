"""Authentication routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from internal.auth.jwt import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
    get_current_active_user,
)
from internal.api.schemas import Token, UserCreate, UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=8, max_length=128)


class TokenRefresh(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


@router.post(
    "/register",
    response_model=Token,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
async def register(payload: RegisterRequest):
    """Register a new user and return JWT tokens."""
    from internal.database.base import get_db
    from internal.database.models import User
    from sqlalchemy import select
    from fastapi import Depends as FastapiDepends
    from sqlalchemy.ext.asyncio import AsyncSession

    db: AsyncSession = FastapiDepends(get_db)

    # Check if user exists
    result = await db.execute(
        select(User).where((User.email == payload.email) | (User.username == payload.username))
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email or username already exists",
        )

    # Create user
    user = User(
        email=payload.email,
        username=payload.username,
        hashed_password=hash_password(payload.password),
        role="analyst",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    # Generate tokens
    access_token = create_access_token(
        user_id=str(user.id),
        email=user.email,
        role=user.role,
    )
    refresh_token = create_refresh_token(
        user_id=str(user.id),
        email=user.email,
        role=user.role,
    )

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post(
    "/login",
    response_model=Token,
    summary="Authenticate and get tokens",
)
async def login(payload: LoginRequest):
    """Authenticate with email/password and receive JWT tokens."""
    from internal.database.base import get_db
    from internal.database.models import User
    from sqlalchemy import select
    from fastapi import Depends as FastapiDepends
    from sqlalchemy.ext.asyncio import AsyncSession

    db: AsyncSession = FastapiDepends(get_db)

    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )

    # Update last login
    from datetime import datetime, timezone
    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    access_token = create_access_token(
        user_id=str(user.id),
        email=user.email,
        role=user.role,
    )
    refresh_token = create_refresh_token(
        user_id=str(user.id),
        email=user.email,
        role=user.role,
    )

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post(
    "/refresh",
    response_model=Token,
    summary="Refresh access token",
)
async def refresh_token(payload: TokenRefresh):
    """Use a refresh token to get a new access token."""
    from internal.auth.jwt import decode_token

    token_data = decode_token(payload.refresh_token)

    if token_data.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )

    access_token = create_access_token(
        user_id=token_data["sub"],
        email=token_data["email"],
        role=token_data["role"],
    )

    return Token(
        access_token=access_token,
        refresh_token=payload.refresh_token,
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
)
async def get_me(current_user: dict = Depends(get_current_active_user)):
    """Get the authenticated user's profile."""
    from internal.database.base import get_db
    from internal.database.models import User
    from sqlalchemy import select
    from fastapi import Depends as FastapiDepends
    from sqlalchemy.ext.asyncio import AsyncSession

    db: AsyncSession = FastapiDepends(get_db)

    result = await db.execute(select(User).where(User.id == current_user["id"]))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return user


@router.post(
    "/change-password",
    status_code=status.HTTP_200_OK,
    summary="Change current password",
)
async def change_password(
    payload: ChangePasswordRequest,
    current_user: dict = Depends(get_current_active_user),
):
    """Change the authenticated user's password."""
    from internal.database.base import get_db
    from internal.database.models import User
    from sqlalchemy import select
    from fastapi import Depends as FastapiDepends
    from sqlalchemy.ext.asyncio import AsyncSession

    db: AsyncSession = FastapiDepends(get_db)

    result = await db.execute(select(User).where(User.id == current_user["id"]))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    user.hashed_password = hash_password(payload.new_password)
    await db.commit()

    return {"message": "Password changed successfully"}
