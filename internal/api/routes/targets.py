"""Target management routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from internal.database.base import get_db
from internal.database.models import Target, Subdomain
from internal.api.schemas import (
    TargetCreate,
    TargetResponse,
    TargetListResponse,
)

router = APIRouter(prefix="/targets", tags=["targets"])


@router.post(
    "/",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a new scan target",
)
async def create_target(
    payload: TargetCreate,
    organization_id: uuid.UUID = Query(...),
    db: AsyncSession = Depends(get_db),
):
    """Register a new target for scanning."""
    # Check for duplicate
    existing = await db.execute(
        select(Target).where(
            Target.organization_id == organization_id,
            Target.value == payload.value,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target already exists for this organization",
        )

    target = Target(
        organization_id=organization_id,
        name=payload.name,
        target_type=payload.target_type.value,
        value=payload.value,
        scope=payload.scope,
        notes=payload.notes,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    return target


@router.get(
    "/",
    response_model=TargetListResponse,
    summary="List all targets",
)
async def list_targets(
    organization_id: uuid.UUID = Query(...),
    scope: str | None = Query(None),
    is_active: bool | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """List targets for an organization."""
    query = select(Target).where(Target.organization_id == organization_id)

    if scope:
        query = query.where(Target.scope == scope)
    if is_active is not None:
        query = query.where(Target.is_active == is_active)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar()

    query = query.order_by(Target.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    targets = result.scalars().all()

    return TargetListResponse(
        targets=[TargetResponse.model_validate(t) for t in targets],
        total=total or 0,
    )


@router.get(
    "/{target_id}",
    response_model=TargetResponse,
    summary="Get target details",
)
async def get_target(
    target_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get details for a specific target."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target {target_id} not found",
        )
    return target


@router.get(
    "/{target_id}/subdomains",
    summary="Get subdomains for a target",
)
async def get_subdomains(
    target_id: uuid.UUID,
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """Get all discovered subdomains for a target."""
    stmt = (
        select(Subdomain)
        .where(Subdomain.target_id == target_id)
        .order_by(Subdomain.domain)
        .offset(offset)
        .limit(limit)
    )
    result = await db.execute(stmt)
    subdomains = result.scalars().all()

    return {
        "subdomains": [
            {
                "id": str(s.id),
                "domain": s.domain,
                "is_apex": s.is_apex,
                "source": s.source,
                "resolved_ip": s.resolved_ip,
                "created_at": s.created_at,
            }
            for s in subdomains
        ],
        "total": len(subdomains),
    }
