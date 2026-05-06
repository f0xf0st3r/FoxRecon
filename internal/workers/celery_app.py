"""Celery application configuration."""

from __future__ import annotations

from celery import Celery

from internal.config import get_settings


def create_celery_app() -> Celery:
    """Create and configure the Celery application."""
    settings = get_settings()

    app = Celery(
        "foxrecon",
        broker=settings.celery_broker_url,
        backend=settings.celery_result_backend,
    )

    app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,

        # Task routing
        task_default_queue="default",
        task_default_exchange="default",
        task_default_routing_key="default",

        # Queue definitions for different task types
        task_queues={
            "default": {
                "exchange": "default",
                "routing_key": "default",
            },
            "scans": {
                "exchange": "scans",
                "routing_key": "scans",
            },
            "reports": {
                "exchange": "reports",
                "routing_key": "reports",
            },
        },

        # Retry policy
        task_acks_late=True,
        task_reject_on_worker_lost=True,

        # Rate limiting
        worker_prefetch_multiplier=1,

        # Timeouts
        task_soft_time_limit=3600,
        task_time_limit=7200,

        # Logging
        worker_hijack_root_logger=False,

        # Result settings
        result_expires=86400,  # 24 hours
        result_backend_thread_safe=True,
    )

    # Auto-discover tasks
    app.autodiscover_tasks(["internal.workers.tasks"])

    return app


celery_app = create_celery_app()
