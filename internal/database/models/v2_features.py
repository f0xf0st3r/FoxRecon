"""V2 models for extended reconnaissance features."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from internal.database.base import Base


class JSEndpoint(Base):
    """Endpoints discovered from JavaScript analysis."""

    __tablename__ = "js_endpoints"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=True
    )
    source_file: Mapped[str] = mapped_column(String(750), nullable=False)
    url: Mapped[str] = mapped_column(String(750), nullable=False)
    endpoint_type: Mapped[str] = mapped_column(String(50), nullable=False)
    method: Mapped[str] = mapped_column(String(10), default="GET", nullable=False)
    full_url: Mapped[str] = mapped_column(String(750), nullable=False)

    __table_args__ = (
        Index("ix_js_endpoints_target", "target_id"),
        Index("ix_js_endpoints_source", "source_file"),
    )


class JSSecret(Base):
    """Secrets discovered in JavaScript files."""

    __tablename__ = "js_secrets"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=True
    )
    secret_type: Mapped[str] = mapped_column(String(100), nullable=False)
    masked_value: Mapped[str] = mapped_column(String(200), nullable=False)
    source_file: Mapped[str] = mapped_column(String(750), nullable=False)
    line_number: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    __table_args__ = (
        Index("ix_js_secrets_target", "target_id"),
        Index("ix_js_secrets_type", "secret_type"),
    )


class DNSRecord(Base):
    """DNS records discovered during intelligence gathering."""

    __tablename__ = "dns_records"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=True
    )
    record_name: Mapped[str] = mapped_column(String(255), nullable=False)
    record_type: Mapped[str] = mapped_column(String(10), nullable=False)
    record_value: Mapped[str] = mapped_column(String(500), nullable=False)
    ttl: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    __table_args__ = (
        Index("ix_dns_records_target_type", "target_id", "record_type"),
        Index("ix_dns_records_value", "record_value"),
    )


class APIDiscovery(Base):
    """Discovered API endpoints (Swagger, GraphQL, REST)."""

    __tablename__ = "api_discoveries"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=True
    )
    discovery_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # swagger, graphql, api_base, actuator, openid
    url: Mapped[str] = mapped_column(String(750), nullable=False)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    is_public: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    discovery_metadata: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)

    __table_args__ = (
        Index("ix_api_discovery_target_type", "target_id", "discovery_type"),
        Index("ix_api_discovery_url", "url"),
    )


class CloudExposure(Base):
    """Exposed cloud storage buckets/containers."""

    __tablename__ = "cloud_exposures"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=True
    )
    cloud_provider: Mapped[str] = mapped_column(String(20), nullable=False)
    # aws, azure, gcp
    bucket_name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(String(750), nullable=False)
    is_public: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_listable: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)

    __table_args__ = (
        Index("ix_cloud_exposure_target", "target_id"),
        Index("ix_cloud_exposure_provider", "cloud_provider"),
        Index("ix_cloud_exposure_public", "is_public"),
    )
