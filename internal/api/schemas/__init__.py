"""Pydantic schemas for API request/response validation."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, EmailStr, Field, field_validator


# ------------------------------------------------------------------ #
# Enums
# ------------------------------------------------------------------ #
class TargetType(str, Enum):
    domain = "domain"
    ip = "ip"
    cidr = "cidr"
    url = "url"


class ScanType(str, Enum):
    full = "full"
    recon = "recon"
    port = "port"
    vuln = "vuln"


class ScanStatus(str, Enum):
    pending = "pending"
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


# ------------------------------------------------------------------ #
# User schemas
# ------------------------------------------------------------------ #
class UserCreate(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(default="analyst")


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    username: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# ------------------------------------------------------------------ #
# Target schemas
# ------------------------------------------------------------------ #
class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    target_type: TargetType
    value: str = Field(min_length=1, max_length=500)
    scope: str = Field(default="in_scope")
    notes: str | None = None

    @field_validator("value")
    @classmethod
    def validate_target_value(cls, v: str) -> str:
        from internal.utils.security import validate_target
        _, sanitized = validate_target(v)
        return sanitized


class TargetResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    target_type: str
    value: str
    scope: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class TargetListResponse(BaseModel):
    targets: list[TargetResponse]
    total: int


# ------------------------------------------------------------------ #
# Scan schemas
# ------------------------------------------------------------------ #
class ScanCreate(BaseModel):
    target_id: uuid.UUID
    scan_type: ScanType = ScanType.full
    priority: int = Field(default=5, ge=1, le=10)
    # Pipeline configuration
    run_recon: bool = True
    run_httpx: bool = True
    run_naabu: bool = True
    run_nuclei: bool = True
    naabu_top_ports: int = Field(default=100, ge=1, le=1000)
    nuclei_rate_limit: int = 50
    nuclei_concurrency: int = 25
    nuclei_severities: list[str] | None = None
    timeout: int = Field(default=3600, ge=60, le=7200)


class ScanResponse(BaseModel):
    id: uuid.UUID
    target_id: uuid.UUID
    scan_type: str
    status: str
    priority: int
    subdomains_found: int
    live_hosts_found: int
    ports_found: int
    findings_count: int
    celery_task_id: str | None
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanStageResponse(BaseModel):
    id: uuid.UUID
    stage: str
    status: str
    tool_name: str | None
    item_count: int
    duration_seconds: float | None
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None

    model_config = {"from_attributes": True}


class ScanDetailResponse(ScanResponse):
    stages: list[ScanStageResponse] = []


# ------------------------------------------------------------------ #
# Finding schemas
# ------------------------------------------------------------------ #
class FindingResponse(BaseModel):
    id: uuid.UUID
    scan_job_id: uuid.UUID
    target_id: uuid.UUID
    finding_type: str
    severity: str
    title: str
    description: str | None
    host: str | None
    port: int | None
    url: str | None
    evidence: str | None
    tags: list | None
    tool_source: str | None
    is_duplicate: bool
    is_verified: bool
    false_positive: bool
    cvss_score: float | None
    cve_ids: list | None
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingListResponse(BaseModel):
    findings: list[FindingResponse]
    total: int
    severity_counts: dict[str, int]


# ------------------------------------------------------------------ #
# Vulnerability schemas
# ------------------------------------------------------------------ #
class VulnerabilityResponse(BaseModel):
    id: uuid.UUID
    target_id: uuid.UUID
    template_id: str
    template_name: str
    severity: str
    host: str
    matched_url: str | None
    cve_ids: list | None
    cwe_ids: list | None
    cvss_metrics: dict | None
    first_seen: datetime | None
    last_seen: datetime | None

    model_config = {"from_attributes": True}


# ------------------------------------------------------------------ #
# Live host schemas
# ------------------------------------------------------------------ #
class LiveHostResponse(BaseModel):
    id: uuid.UUID
    hostname: str
    url: str
    ip: str | None
    port: int
    scheme: str
    status_code: int | None
    title: str | None
    content_type: str | None
    tech_stack: list | None
    webserver: str | None
    response_time_ms: int | None

    model_config = {"from_attributes": True}


# ------------------------------------------------------------------ #
# Port schemas
# ------------------------------------------------------------------ #
class PortResponse(BaseModel):
    id: uuid.UUID
    host: str
    ip: str | None
    port_number: int
    protocol: str
    state: str
    service_name: str | None
    service_version: str | None
    product: str | None

    model_config = {"from_attributes": True}


# ------------------------------------------------------------------ #
# Report schemas
# ------------------------------------------------------------------ #
class ReportCreate(BaseModel):
    target_id: uuid.UUID | None = None
    title: str = Field(min_length=1, max_length=500)
    report_type: str = "full"
    format: str = "markdown"
    scan_job_ids: list[uuid.UUID] | None = None


class ReportResponse(BaseModel):
    id: uuid.UUID
    title: str
    report_type: str
    format: str
    status: str
    file_path: str | None
    generated_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


# ------------------------------------------------------------------ #
# Organization schemas
# ------------------------------------------------------------------ #
class OrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(min_length=1, max_length=100)
    description: str | None = None


class OrganizationResponse(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    description: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


# ------------------------------------------------------------------ #
# Dashboard schemas
# ------------------------------------------------------------------ #
class DashboardSummary(BaseModel):
    total_targets: int
    total_scans: int
    active_scans: int
    total_subdomains: int
    total_live_hosts: int
    total_open_ports: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    recent_scans: list[ScanResponse]
