"""Scan job and result models."""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from internal.database.base import Base


class ScanJob(Base):
    """Top-level scan job orchestrating the full pipeline."""

    __tablename__ = "scan_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)  # full, recon, port, vuln
    status: Mapped[str] = mapped_column(
        String(20), default="pending", nullable=False, index=True
    )
    # pending, queued, running, completed, failed, cancelled
    priority: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    configuration: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    started_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Celery task tracking
    celery_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Results summary (updated as stages complete)
    subdomains_found: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    live_hosts_found: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ports_found: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    target: Mapped["Target"] = relationship("Target", back_populates="scan_jobs")
    user: Mapped["User"] = relationship("User", back_populates="scan_jobs")
    scan_results: Mapped[list["ScanResult"]] = relationship(
        "ScanResult", back_populates="scan_job", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="scan_job", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_scan_jobs_status", "status"),
        Index("ix_scan_jobs_target_status", "target_id", "status"),
    )


class ScanResult(Base):
    """Individual stage results within a scan job."""

    __tablename__ = "scan_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    stage: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    # recon, live_hosts, port_scan, content_discovery, vuln_scan, js_analysis, screenshot
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    tool_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    tool_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    input_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    output_summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    raw_output_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(nullable=True)
    item_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    scan_job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="scan_results")

    __table_args__ = (
        Index("ix_scan_results_job_stage", "scan_job_id", "stage"),
    )


class Finding(Base):
    """Normalized findings from all scan stages."""

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    finding_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    # subdomain, open_port, service, tech_detection, vulnerability,
    # secret_leak, misconfiguration, content_discovery, js_endpoint
    severity: Mapped[str] = mapped_column(
        String(20), default="info", nullable=False, index=True
    )
    # critical, high, medium, low, info
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    url: Mapped[str | None] = mapped_column(String(750), nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    tags: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    tool_source: Mapped[str | None] = mapped_column(String(100), nullable=True)
    raw_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    is_duplicate: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    duplicate_of: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id"), nullable=True
    )
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cve_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    scan_job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="findings")
    duplicates: Mapped[list["Finding"]] = relationship(
        "Finding",
        backref="original",
        remote_side=[id],
        primaryjoin="Finding.duplicate_of==Finding.id",
    )

    __table_args__ = (
        Index("ix_findings_severity_type", "severity", "finding_type"),
        Index("ix_findings_host", "host"),
        Index("ix_findings_target_severity", "target_id", "severity"),
    )


class Vulnerability(Base):
    """Structured vulnerability records from nuclei scans."""

    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=True
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    template_id: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    template_name: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    matched_url: Mapped[str | None] = mapped_column(String(750), nullable=True)
    matched_at: Mapped[str | None] = mapped_column(String(750), nullable=True)
    extracted_results: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    cve_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    cwe_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    cvss_metrics: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    curl_command: Mapped[str | None] = mapped_column(Text, nullable=True)
    request: Mapped[str | None] = mapped_column(Text, nullable=True)
    response: Mapped[str | None] = mapped_column(Text, nullable=True)
    info: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    first_seen: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_vulns_template_severity", "template_id", "severity"),
        Index("ix_vulns_host", "host"),
    )
