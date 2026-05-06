"""Scan management routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from internal.database.base import get_db
from internal.database.models import ScanJob, ScanResult, Target
from internal.api.schemas import (
    ScanCreate,
    ScanDetailResponse,
    ScanResponse,
    ScanStageResponse,
    ScanStatus,
)

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post(
    "/",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create and queue a new scan",
)
async def create_scan(
    payload: ScanCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a new scan job and queue it for execution.

    The scan pipeline runs: subfinder → httpx → naabu → nuclei
    Results are stored in PostgreSQL as each stage completes.
    """
    # Verify target exists
    result = await db.execute(
        select(Target).where(Target.id == payload.target_id, Target.is_active == True)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target {payload.target_id} not found or inactive",
        )

    # Create scan job
    scan_job = ScanJob(
        target_id=payload.target_id,
        scan_type=payload.scan_type.value,
        status="pending",
        priority=payload.priority,
        configuration={
            "run_recon": payload.run_recon,
            "run_httpx": payload.run_httpx,
            "run_naabu": payload.run_naabu,
            "run_nuclei": payload.run_nuclei,
            "naabu_top_ports": payload.naabu_top_ports,
            "nuclei_rate_limit": payload.nuclei_rate_limit,
            "nuclei_concurrency": payload.nuclei_concurrency,
            "timeout": payload.timeout,
        },
    )
    db.add(scan_job)
    await db.flush()

    # Queue Celery task
    try:
        from internal.workers.tasks import execute_scan_task

        pipeline_config = {
            "run_recon": payload.run_recon,
            "run_httpx": payload.run_httpx,
            "run_naabu": payload.run_naabu,
            "run_nuclei": payload.run_nuclei,
            "naabu_top_ports": payload.naabu_top_ports,
            "nuclei_rate_limit": payload.nuclei_rate_limit,
            "nuclei_concurrency": payload.nuclei_concurrency,
            "timeout": payload.timeout,
        }

        task = execute_scan_task.apply_async(
            kwargs={
                "scan_job_id": str(scan_job.id),
                "target_value": target.value,
                "target_id": str(target.id),
                "pipeline_config": pipeline_config,
            },
            queue="scans",
        )
        scan_job.celery_task_id = task.id
        scan_job.status = "queued"
    except Exception as e:
        scan_job.status = "failed"
        scan_job.error_message = f"Failed to queue task: {e}"

    await db.commit()
    await db.refresh(scan_job)

    return scan_job


@router.get(
    "/",
    response_model=list[ScanResponse],
    summary="List all scans",
)
async def list_scans(
    status_filter: ScanStatus | None = Query(None, alias="status"),
    target_id: uuid.UUID | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """List scan jobs with optional filtering."""
    query = select(ScanJob).order_by(ScanJob.created_at.desc())

    if status_filter:
        query = query.where(ScanJob.status == status_filter.value)
    if target_id:
        query = query.where(ScanJob.target_id == target_id)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get(
    "/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Get scan details with stages",
)
async def get_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get detailed information about a specific scan including all stages."""
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan_job = result.scalar_one_or_none()
    if not scan_job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    # Get stages
    stages_result = await db.execute(
        select(ScanResult)
        .where(ScanResult.scan_job_id == scan_id)
        .order_by(ScanResult.started_at)
    )
    stages = stages_result.scalars().all()

    response = ScanDetailResponse.model_validate(scan_job)
    response.stages = [ScanStageResponse.model_validate(s) for s in stages]
    return response


@router.post(
    "/{scan_id}/cancel",
    response_model=ScanResponse,
    summary="Cancel a running scan",
)
async def cancel_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Cancel a queued or running scan."""
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan_job = result.scalar_one_or_none()
    if not scan_job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    if scan_job.status not in ("pending", "queued", "running"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel scan in {scan_job.status} state",
        )

    # Revoke Celery task if running
    if scan_job.celery_task_id:
        try:
            from internal.workers.celery_app import celery_app
            celery_app.control.revoke(scan_job.celery_task_id, terminate=True)
        except Exception:
            pass

    scan_job.status = "cancelled"
    scan_job.completed_at = func.now()
    await db.commit()
    await db.refresh(scan_job)

    return scan_job
