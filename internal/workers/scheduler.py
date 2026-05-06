"""Scan scheduling module for recurring scans."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from internal.api.schemas import ScanType


class ScheduleCreate(BaseModel):
    """Create a recurring scan schedule."""

    target_id: uuid.UUID
    scan_type: ScanType = ScanType.full
    cron_expression: str = Field(
        default="0 2 * * 0",  # Every Sunday at 2 AM
        description="Cron expression (minute hour day month weekday)",
    )
    enabled: bool = True
    timezone: str = "UTC"
    notification_email: str | None = None


class ScheduleResponse(BaseModel):
    id: uuid.UUID
    target_id: uuid.UUID
    scan_type: str
    cron_expression: str
    enabled: bool
    timezone: str
    last_run: datetime | None
    next_run: datetime | None
    total_runs: int
    created_at: datetime

    model_config = {"from_attributes": True}


def cron_to_kwargs(cron: str) -> dict:
    """Convert cron expression to Celery beat kwargs.

    Format: minute hour day month weekday
    """
    parts = cron.strip().split()
    if len(parts) != 5:
        raise ValueError("Invalid cron expression. Expected 5 fields: minute hour day month weekday")

    return {
        "minute": parts[0],
        "hour": parts[1],
        "day_of_month": parts[2],
        "month_of_year": parts[3],
        "day_of_week": parts[4],
    }


def validate_cron(cron: str) -> bool:
    """Validate a cron expression."""
    try:
        cron_to_kwargs(cron)
        return True
    except ValueError:
        return False
