"""Findings and vulnerability routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from internal.database.base import get_db
from internal.database.models import Finding, Vulnerability, LiveHost, Port
from internal.api.schemas import (
    FindingResponse,
    FindingListResponse,
    VulnerabilityResponse,
    LiveHostResponse,
    PortResponse,
    Severity,
)

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get(
    "/",
    response_model=FindingListResponse,
    summary="List all findings",
)
async def list_findings(
    target_id: uuid.UUID | None = Query(None),
    scan_job_id: uuid.UUID | None = Query(None),
    severity: Severity | None = Query(None),
    finding_type: str | None = Query(None),
    is_duplicate: bool | None = Query(None),
    false_positive: bool | None = Query(None),
    search: str | None = Query(None, max_length=200),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """List findings with filtering and severity counts."""
    query = select(Finding).where(Finding.is_duplicate == False)

    if target_id:
        query = query.where(Finding.target_id == target_id)
    if scan_job_id:
        query = query.where(Finding.scan_job_id == scan_job_id)
    if severity:
        query = query.where(Finding.severity == severity.value)
    if finding_type:
        query = query.where(Finding.finding_type == finding_type)
    if is_duplicate is not None:
        query = query.where(Finding.is_duplicate == is_duplicate)
    if false_positive is not None:
        query = query.where(Finding.false_positive == false_positive)
    if search:
        query = query.where(
            Finding.title.ilike(f"%{search}%")
            | Finding.description.ilike(f"%{search}%")
            | Finding.host.ilike(f"%{search}%")
        )

    # Get total count
    count_stmt = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    # Get severity distribution
    severity_stmt = (
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.is_duplicate == False)
    )
    if target_id:
        severity_stmt = severity_stmt.where(Finding.target_id == target_id)
    severity_stmt = severity_stmt.group_by(Finding.severity)
    severity_result = await db.execute(severity_stmt)
    severity_counts = dict(severity_result.all())

    query = query.order_by(
        func.case(
            (Finding.severity == "critical", 0),
            (Finding.severity == "high", 1),
            (Finding.severity == "medium", 2),
            (Finding.severity == "low", 3),
            else_=4,
        ),
        Finding.created_at.desc(),
    ).offset(offset).limit(limit)

    result = await db.execute(query)
    findings = result.scalars().all()

    return FindingListResponse(
        findings=[FindingResponse.model_validate(f) for f in findings],
        total=total,
        severity_counts=severity_counts,
    )


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Get finding details",
)
async def get_finding(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get details for a specific finding."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding {finding_id} not found",
        )
    return finding


@router.patch(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Update finding status",
)
async def update_finding(
    finding_id: uuid.UUID,
    is_verified: bool | None = None,
    false_positive: bool | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Update finding verification status."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding {finding_id} not found",
        )

    if is_verified is not None:
        finding.is_verified = is_verified
    if false_positive is not None:
        finding.false_positive = false_positive

    await db.commit()
    await db.refresh(finding)
    return finding


# ------------------------------------------------------------------ #
# Vulnerabilities sub-router
# ------------------------------------------------------------------ #
@router.get(
    "/vulnerabilities",
    response_model=list[VulnerabilityResponse],
    summary="List vulnerability scan results",
)
async def list_vulnerabilities(
    target_id: uuid.UUID | None = Query(None),
    severity: Severity | None = Query(None),
    template_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """List structured vulnerability results from nuclei scans."""
    query = select(Vulnerability)

    if target_id:
        query = query.where(Vulnerability.target_id == target_id)
    if severity:
        query = query.where(Vulnerability.severity == severity.value)
    if template_id:
        query = query.where(Vulnerability.template_id == template_id)

    query = query.order_by(
        func.case(
            (Vulnerability.severity == "critical", 0),
            (Vulnerability.severity == "high", 1),
            (Vulnerability.severity == "medium", 2),
            (Vulnerability.severity == "low", 3),
            else_=4,
        ),
        Vulnerability.created_at.desc(),
    ).limit(limit)

    result = await db.execute(query)
    return result.scalars().all()


# ------------------------------------------------------------------ #
# Live hosts sub-router
# ------------------------------------------------------------------ #
@router.get(
    "/live-hosts",
    response_model=list[LiveHostResponse],
    summary="List live HTTP hosts",
)
async def list_live_hosts(
    target_id: uuid.UUID | None = Query(None),
    status_code: int | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    """List detected live HTTP/HTTPS hosts."""
    query = select(LiveHost)

    if target_id:
        query = query.where(LiveHost.target_id == target_id)
    if status_code:
        query = query.where(LiveHost.status_code == status_code)

    query = query.order_by(LiveHost.hostname).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


# ------------------------------------------------------------------ #
# Ports sub-router
# ------------------------------------------------------------------ #
@router.get(
    "/ports",
    response_model=list[PortResponse],
    summary="List open ports",
)
async def list_ports(
    target_id: uuid.UUID | None = Query(None),
    service: str | None = Query(None),
    limit: int = Query(200, ge=1, le=2000),
    db: AsyncSession = Depends(get_db),
):
    """List discovered open ports and services."""
    query = select(Port).where(Port.state == "open")

    if target_id:
        query = query.where(Port.target_id == target_id)
    if service:
        query = query.where(Port.service_name.ilike(f"%{service}%"))

    query = query.order_by(Port.port_number).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()
