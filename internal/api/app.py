"""Main FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from internal.config import get_settings
from internal.database.base import init_engine, close_engine
from internal.utils.logging import setup_logging


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management."""
    settings = get_settings()

    # Setup
    setup_logging(settings)
    init_engine(settings)

    yield

    # Teardown
    await close_engine()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        description="Offensive Reconnaissance & Attack Surface Management Platform",
        version="2.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Trusted host
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"] if settings.debug else ["localhost", "127.0.0.1"],
    )

    # Register V1 routes
    from internal.api.routes import scans, targets, findings, reports, dashboard

    api_prefix = settings.api_prefix
    app.include_router(scans.router, prefix=api_prefix)
    app.include_router(targets.router, prefix=api_prefix)
    app.include_router(findings.router, prefix=api_prefix)
    app.include_router(reports.router, prefix=api_prefix)
    app.include_router(dashboard.router, prefix=api_prefix)

    # Register V2 routes
    from internal.api.routes import auth, websocket, schedules

    app.include_router(auth.router, prefix=api_prefix)
    app.include_router(websocket.router, prefix=api_prefix)
    app.include_router(schedules.router, prefix=api_prefix)

    # V2 Intelligence routes (inline for now)
    from internal.api.routes.intelligence import router as intelligence_router
    app.include_router(intelligence_router, prefix=api_prefix)

    # Health check
    @app.get("/health", tags=["system"])
    async def health_check():
        return {
            "status": "healthy",
            "service": settings.app_name,
            "version": "2.0.0",
        }

    @app.get("/", tags=["system"])
    async def root():
        return {
            "service": settings.app_name,
            "version": "2.0.0",
            "docs": "/docs",
            "health": "/health",
        }

    return app
