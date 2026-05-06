"""Target, domain, and asset models."""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from internal.database.base import Base


class Target(Base):
    """Scan targets (root domains, IP ranges, URLs)."""

    __tablename__ = "targets"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # domain, ip, cidr, url
    value: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(20), default="in_scope", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="targets")
    subdomains: Mapped[list["Subdomain"]] = relationship(
        "Subdomain", back_populates="target", cascade="all, delete-orphan"
    )
    scan_jobs: Mapped[list["ScanJob"]] = relationship("ScanJob", back_populates="target")
    live_hosts: Mapped[list["LiveHost"]] = relationship(
        "LiveHost", back_populates="target", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "value", name="uq_org_target"),
        Index("ix_targets_org_type", "organization_id", "target_type"),
    )


class Subdomain(Base):
    """Discovered subdomains from recon engines."""

    __tablename__ = "subdomains"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    is_apex: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    source: Mapped[str | None] = mapped_column(String(100), nullable=True)
    resolved_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    first_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=True
    )
    last_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=True
    )

    # Relationships
    target: Mapped["Target"] = relationship("Target", back_populates="subdomains")
    live_host: Mapped["LiveHost | None"] = relationship(
        "LiveHost",
        primaryjoin="and_(Subdomain.domain==foreign(LiveHost.hostname))",
        viewonly=True,
    )

    __table_args__ = (
        UniqueConstraint("target_id", "domain", name="uq_target_subdomain"),
        Index("ix_subdomains_domain", "domain"),
    )


class LiveHost(Base):
    """Hosts with live HTTP services detected by httpx."""

    __tablename__ = "live_hosts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    url: Mapped[str] = mapped_column(String(750), nullable=False)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    port: Mapped[int] = mapped_column(Integer, default=443, nullable=False)
    scheme: Mapped[str] = mapped_column(String(5), default="https", nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str | None] = mapped_column(String(500), nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(200), nullable=True)
    content_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tech_stack: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    webserver: Mapped[str | None] = mapped_column(String(200), nullable=True)
    hash: Mapped[str | None] = mapped_column(String(64), nullable=True)  # body hash for dedup
    last_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=True
    )

    # Relationships
    target: Mapped["Target"] = relationship("Target", back_populates="live_hosts")
    ports: Mapped[list["Port"]] = relationship(
        "Port", back_populates="live_host", cascade="all, delete-orphan"
    )
    screenshots: Mapped[list["Screenshot"]] = relationship(
        "Screenshot", back_populates="live_host", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("target_id", "hostname", "port", name="uq_target_host_port"),
        Index("ix_live_hosts_url", "url"),
        Index("ix_live_hosts_status", "status_code"),
    )


class Port(Base):
    """Open ports discovered by naabu/nmap."""

    __tablename__ = "ports"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    live_host_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("live_hosts.id", ondelete="CASCADE"), nullable=True
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    port_number: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp", nullable=False)
    state: Mapped[str] = mapped_column(String(20), default="open", nullable=False)
    service_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    service_version: Mapped[str | None] = mapped_column(String(200), nullable=True)
    product: Mapped[str | None] = mapped_column(String(200), nullable=True)
    extra_info: Mapped[str | None] = mapped_column(Text, nullable=True)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=True
    )

    # Relationships
    live_host: Mapped["LiveHost | None"] = relationship("LiveHost", back_populates="ports")

    __table_args__ = (
        UniqueConstraint("target_id", "host", "port_number", "protocol", name="uq_port"),
        Index("ix_ports_host_port", "host", "port_number"),
        Index("ix_ports_service", "service_name"),
    )


class Technology(Base):
    """Detected technologies on hosts."""

    __tablename__ = "technologies"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    live_host_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("live_hosts.id", ondelete="CASCADE"), nullable=True
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    confidence: Mapped[float | None] = mapped_column(nullable=True)

    __table_args__ = (
        UniqueConstraint("target_id", "name", "version", name="uq_technology"),
        Index("ix_technologies_name", "name"),
    )


class Screenshot(Base):
    """Screenshots captured by gowitness/playwright."""

    __tablename__ = "screenshots"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    live_host_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("live_hosts.id", ondelete="CASCADE"), nullable=False
    )
    url: Mapped[str] = mapped_column(String(750), nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    height: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str | None] = mapped_column(String(500), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=True
    )

    # Relationships
    live_host: Mapped["LiveHost"] = relationship("LiveHost", back_populates="screenshots")
