"""Dashboard and statistics routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from internal.database.base import get_db
from internal.database.models import (
    ScanJob,
    Target,
    Subdomain,
    LiveHost,
    Port,
    Finding,
)
from internal.api.schemas import DashboardSummary, ScanResponse

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get(
    "/",
    response_model=DashboardSummary,
    summary="Get dashboard summary statistics",
)
async def get_dashboard(
    organization_id: uuid.UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Get aggregated statistics for the dashboard."""
    # Build base filters
    target_filter = []
    if organization_id:
        target_filter.append(Target.organization_id == organization_id)

    # Count targets
    target_query = select(func.count(Target.id))
    if target_filter:
        target_query = target_query.where(*target_filter)
    total_targets = (await db.execute(target_query)).scalar() or 0

    # Count scans
    total_scans = (await db.execute(select(func.count(ScanJob.id)))).scalar() or 0
    active_scans = (
        await db.execute(
            select(func.count(ScanJob.id)).where(ScanJob.status.in_(["running", "queued"]))
        )
    ).scalar() or 0

    # Count assets
    subdomain_query = select(func.count(Subdomain.id))
    if target_filter:
        subdomain_query = subdomain_query.join(Target).where(*target_filter)
    total_subdomains = (await db.execute(subdomain_query)).scalar() or 0

    live_host_query = select(func.count(LiveHost.id))
    if target_filter:
        live_host_query = live_host_query.join(Target).where(*target_filter)
    total_live_hosts = (await db.execute(live_host_query)).scalar() or 0

    port_query = select(func.count(Port.id)).where(Port.state == "open")
    if target_filter:
        port_query = port_query.join(Target).where(*target_filter)
    total_open_ports = (await db.execute(port_query)).scalar() or 0

    # Count findings (non-duplicate)
    finding_query = select(func.count(Finding.id)).where(Finding.is_duplicate == False)
    if target_filter:
        finding_query = finding_query.join(Target).where(*target_filter)
    total_findings = (await db.execute(finding_query)).scalar() or 0

    # Severity counts
    async def _count_severity(sev: str) -> int:
        q = (
            select(func.count(Finding.id))
            .where(Finding.severity == sev, Finding.is_duplicate == False)
        )
        if target_filter:
            q = q.join(Target).where(*target_filter)
        return (await db.execute(q)).scalar() or 0

    critical_findings = await _count_severity("critical")
    high_findings = await _count_severity("high")
    medium_findings = await _count_severity("medium")
    low_findings = await _count_severity("low")

    # Recent scans
    recent_stmt = (
        select(ScanJob)
        .order_by(ScanJob.created_at.desc())
        .limit(10)
    )
    recent_scans = (await db.execute(recent_stmt)).scalars().all()

    return DashboardSummary(
        total_targets=total_targets,
        total_scans=total_scans,
        active_scans=active_scans,
        total_subdomains=total_subdomains,
        total_live_hosts=total_live_hosts,
        total_open_ports=total_open_ports,
        total_findings=total_findings,
        critical_findings=critical_findings,
        high_findings=high_findings,
        medium_findings=medium_findings,
        low_findings=low_findings,
        recent_scans=[ScanResponse.model_validate(s) for s in recent_scans],
    )
