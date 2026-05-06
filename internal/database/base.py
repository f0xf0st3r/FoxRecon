"""SQLAlchemy base model and session management."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, func
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from internal.config import Settings


class Base(DeclarativeBase):
    """Base class for all ORM models."""

    # Generate table names automatically from class name
    __tablename__: str

    # All models have these timestamp columns
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


# Engine and session factory - initialized at startup
_engine = None
_session_factory = None


def init_engine(settings: Settings) -> Any:
    """Initialize the async engine and session factory."""
    global _engine, _session_factory

    _engine = create_async_engine(
        settings.database_url,
        echo=settings.debug,
        pool_size=settings.postgres_pool_size,
        max_overflow=settings.postgres_max_overflow,
        pool_pre_ping=True,
        pool_recycle=3600,
    )

    _session_factory = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Get the session factory (must call init_engine first)."""
    if _session_factory is None:
        raise RuntimeError("Database engine not initialized")
    return _session_factory


async def get_db() -> AsyncSession:
    """FastAPI dependency for getting a database session."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def close_engine() -> None:
    """Dispose of the engine on shutdown."""
    global _engine
    if _engine:
        await _engine.dispose()
