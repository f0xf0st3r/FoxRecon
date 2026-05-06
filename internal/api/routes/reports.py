"""Report generation routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from internal.database.base import get_db
from internal.database.models import Report, ScanJob, Finding, Target
from internal.api.schemas import ReportCreate, ReportResponse

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post(
    "/",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a new report",
)
async def create_report(
    payload: ReportCreate,
    db: AsyncSession = Depends(get_db),
):
    """Generate a report from scan data.

    Supports markdown, JSON, and PDF export formats.
    """
    report = Report(
        target_id=payload.target_id,
        title=payload.title,
        report_type=payload.report_type,
        format=payload.format,
        scan_job_ids=[str(j) for j in payload.scan_job_ids] if payload.scan_job_ids else [],
        status="pending",
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    # Generate report content asynchronously
    try:
        from internal.reporting.generator import ReportGenerator
        generator = ReportGenerator(db)
        content, file_path = await generator.generate(report)

        report.content = content
        report.file_path = file_path
        report.status = "completed"
        report.generated_at = func.now()
    except Exception as e:
        report.status = "failed"
        report.content = f"Report generation failed: {e}"

    await db.commit()
    await db.refresh(report)

    return report


@router.get(
    "/",
    response_model=list[ReportResponse],
    summary="List all reports",
)
async def list_reports(
    target_id: uuid.UUID | None = Query(None),
    format_filter: str | None = Query(None, alias="format"),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """List generated reports."""
    query = select(Report).order_by(Report.created_at.desc())

    if target_id:
        query = query.where(Report.target_id == target_id)
    if format_filter:
        query = query.where(Report.format == format_filter)

    query = query.limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get(
    "/{report_id}",
    response_model=ReportResponse,
    summary="Get report content",
)
async def get_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific report with its content."""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report {report_id} not found",
        )
    return report
