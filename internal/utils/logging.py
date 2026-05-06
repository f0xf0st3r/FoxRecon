"""Structured logging configuration using structlog."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import structlog
from structlog.contextvars import clear_contextvars, merge_contextvars

from internal.config import Settings


def setup_logging(settings: Settings | None = None) -> None:
    """Configure structured logging for the application.

    In development: human-readable console output with colors.
    In production: JSON-formatted output for log aggregation systems.
    """
    if settings is None:
        from internal.config import get_settings
        settings = get_settings()

    is_prod = settings.app_env == "production"

    # Shared processors
    shared_processors: list = [
        merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if is_prod:
        # Production: JSON output
        processors = shared_processors + [
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Development: Console output with colors
        processors = shared_processors + [
            structlog.dev.ConsoleRenderer(colors=True),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.DEBUG if settings.debug else logging.INFO
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Also configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=logging.DEBUG if settings.debug else logging.INFO,
    )


def get_logger(**initial_values: object) -> structlog.stdlib.BoundLogger:
    """Get a structured logger instance with optional initial context."""
    return structlog.get_logger(**initial_values)


def bind_context(**kwargs: object) -> None:
    """Bind key-value pairs to the current logging context."""
    structlog.contextvars.bind_contextvars(**kwargs)


def clear_context() -> None:
    """Clear the current logging context."""
    clear_contextvars()


# Audit logger for security-relevant events
def get_audit_logger() -> structlog.stdlib.BoundLogger:
    """Get a dedicated audit logger."""
    return structlog.get_logger(audit=True)
