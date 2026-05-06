"""Celery tasks for scan execution."""

from __future__ import annotations

import uuid

from internal.workers.celery_app import celery_app
from internal.utils.logging import get_logger

logger = get_logger(module="celery_tasks")


@celery_app.task(
    bind=True,
    name="foxrecon.execute_scan",
    queue="scans",
    max_retries=2,
    default_retry_delay=60,
    acks_late=True,
)
def execute_scan_task(
    self,
    scan_job_id: str,
    target_value: str,
    target_id: str,
    pipeline_config: dict | None = None,
) -> dict:
    """Execute a full scan pipeline asynchronously.

    Args:
        scan_job_id: UUID of the ScanJob record
        target_value: The domain/URL/IP to scan
        target_id: UUID of the Target record
        pipeline_config: Optional pipeline configuration dict

    Returns:
        Dict with scan results summary
    """
    import asyncio
    from internal.config import get_settings
    from internal.database.base import init_engine, get_session_factory
    from internal.database.models import ScanJob
    from internal.recon.engine import ReconEngine, ScanPipelineConfig
    from sqlalchemy import select

    settings = get_settings()
    init_engine(settings)

    async def _run() -> dict:
        factory = get_session_factory()
        async with factory() as db:
            # Fetch scan job
            result = await db.execute(
                select(ScanJob).where(ScanJob.id == uuid.UUID(scan_job_id))
            )
            scan_job = result.scalar_one_or_none()
            if not scan_job:
                return {"error": f"ScanJob {scan_job_id} not found"}

            engine = ReconEngine(settings)

            # Convert config dict to object
            config = None
            if pipeline_config:
                config = ScanPipelineConfig(**pipeline_config)

            pipeline_result = await engine.run_pipeline(
                db=db,
                scan_job=scan_job,
                target_value=target_value,
                config=config,
            )

            return {
                "scan_job_id": str(pipeline_result.scan_job_id),
                "success": pipeline_result.success,
                "stages_completed": pipeline_result.stages_completed,
                "subdomains_found": pipeline_result.subdomains_found,
                "live_hosts_found": pipeline_result.live_hosts_found,
                "ports_found": pipeline_result.ports_found,
                "findings_found": pipeline_result.findings_found,
                "errors": pipeline_result.errors,
                "duration_seconds": pipeline_result.duration_seconds,
            }

    try:
        return asyncio.run(_run())
    except Exception as e:
        logger.exception("scan_task_failed", scan_job_id=scan_job_id)
        self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@celery_app.task(
    bind=True,
    name="foxrecon.execute_recon_only",
    queue="scans",
    max_retries=1,
)
def execute_recon_task(
    self,
    scan_job_id: str,
    target_value: str,
    target_id: str,
) -> dict:
    """Execute only the subdomain enumeration stage."""
    import asyncio
    from internal.config import get_settings
    from internal.database.base import init_engine, get_session_factory
    from internal.database.models import ScanJob
    from internal.recon.engine import ReconEngine, ScanPipelineConfig
    from sqlalchemy import select

    settings = get_settings()
    init_engine(settings)

    async def _run() -> dict:
        factory = get_session_factory()
        async with factory() as db:
            result = await db.execute(
                select(ScanJob).where(ScanJob.id == uuid.UUID(scan_job_id))
            )
            scan_job = result.scalar_one_or_none()
            if not scan_job:
                return {"error": f"ScanJob {scan_job_id} not found"}

            engine = ReconEngine(settings)
            config = ScanPipelineConfig(
                run_recon=True,
                run_httpx=False,
                run_naabu=False,
                run_nuclei=False,
            )

            pipeline_result = await engine.run_pipeline(
                db=db,
                scan_job=scan_job,
                target_value=target_value,
                config=config,
            )

            return {
                "scan_job_id": str(pipeline_result.scan_job_id),
                "success": pipeline_result.success,
                "subdomains_found": pipeline_result.subdomains_found,
                "duration_seconds": pipeline_result.duration_seconds,
            }

    try:
        return asyncio.run(_run())
    except Exception as e:
        logger.exception("recon_task_failed", scan_job_id=scan_job_id)
        self.retry(exc=e)
