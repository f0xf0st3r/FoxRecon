"""Schedule management routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from internal.database.base import get_db
from internal.api.schemas import ScanType
from internal.workers.scheduler import ScheduleCreate, ScheduleResponse, validate_cron

router = APIRouter(prefix="/schedules", tags=["schedules"])


@router.post(
    "/",
    response_model=ScheduleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a recurring scan schedule",
)
async def create_schedule(
    payload: ScheduleCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a new recurring scan schedule using Celery beat."""
    from internal.database.models import ScanSchedule

    if not validate_cron(payload.cron_expression):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cron expression",
        )

    schedule = ScanSchedule(
        target_id=payload.target_id,
        scan_type=payload.scan_type.value,
        cron_expression=payload.cron_expression,
        timezone=payload.timezone,
        enabled=payload.enabled,
        notification_email=payload.notification_email,
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)

    # Register with Celery beat
    try:
        from internal.workers.scheduler import cron_to_kwargs
        from internal.workers.tasks import execute_scan_task

        kwargs = cron_to_kwargs(payload.cron_expression)

        # Add to Celery beat schedule
        from internal.workers.celery_app import celery_app
        from celery.schedules import crontab

        celery_app.conf.beat_schedule[f"schedule_{schedule.id}"] = {
            "task": "foxrecon.execute_scan",
            "schedule": crontab(
                minute=kwargs["minute"],
                hour=kwargs["hour"],
                day_of_month=kwargs["day_of_month"],
                month_of_year=kwargs["month_of_year"],
                day_of_week=kwargs["day_of_week"],
            ),
            "args": (),
            "kwargs": {
                "scan_job_id": "",  # Will be created at runtime
                "target_value": "",  # Resolved at runtime
                "target_id": str(payload.target_id),
            },
        }
    except Exception as e:
        # Schedule created but celery registration failed
        pass

    return schedule


@router.get(
    "/",
    response_model=list[ScheduleResponse],
    summary="List all schedules",
)
async def list_schedules(
    target_id: uuid.UUID | None = Query(None),
    enabled_only: bool = Query(True),
    db: AsyncSession = Depends(get_db),
):
    """List scan schedules."""
    from internal.database.models import ScanSchedule

    query = select(ScanSchedule).order_by(ScanSchedule.created_at.desc())

    if target_id:
        query = query.where(ScanSchedule.target_id == target_id)
    if enabled_only:
        query = query.where(ScanSchedule.enabled == True)

    result = await db.execute(query)
    return result.scalars().all()


@router.get(
    "/{schedule_id}",
    response_model=ScheduleResponse,
    summary="Get schedule details",
)
async def get_schedule(
    schedule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get details for a specific schedule."""
    from internal.database.models import ScanSchedule

    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Schedule {schedule_id} not found",
        )
    return schedule


@router.patch(
    "/{schedule_id}/toggle",
    response_model=ScheduleResponse,
    summary="Enable or disable a schedule",
)
async def toggle_schedule(
    schedule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Toggle a schedule's enabled status."""
    from internal.database.models import ScanSchedule

    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Schedule {schedule_id} not found",
        )

    schedule.enabled = not schedule.enabled
    await db.commit()
    await db.refresh(schedule)

    return schedule


@router.delete(
    "/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a schedule",
)
async def delete_schedule(
    schedule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Delete a schedule."""
    from internal.database.models import ScanSchedule

    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Schedule {schedule_id} not found",
        )

    await db.delete(schedule)
    await db.commit()
