"""User and organization models."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from internal.database.base import Base


class User(Base):
    """System users with RBAC support."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    api_key_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Relationships
    organizations: Mapped[list["Organization"]] = relationship(
        "Organization", secondary="user_organizations", back_populates="users"
    )
    scan_jobs: Mapped[list["ScanJob"]] = relationship("ScanJob", back_populates="user")
    reports: Mapped[list["Report"]] = relationship("Report", back_populates="user")
    activity_logs: Mapped[list["ActivityLog"]] = relationship("ActivityLog", back_populates="user")

    __table_args__ = (
        UniqueConstraint("email", name="uq_users_email"),
        UniqueConstraint("username", name="uq_users_username"),
    )


class Organization(Base):
    """Organizations for multi-tenant support."""

    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    settings: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    users: Mapped[list["User"]] = relationship(
        "User", secondary="user_organizations", back_populates="organizations"
    )
    targets: Mapped[list["Target"]] = relationship("Target", back_populates="organization")


class UserOrganization(Base):
    """Many-to-many link between users and organizations with role."""

    __tablename__ = "user_organizations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(50), default="member", nullable=False)

    __table_args__ = (
        UniqueConstraint("user_id", "organization_id", name="uq_user_org"),
    )
