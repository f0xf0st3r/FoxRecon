#!/usr/bin/env python3
"""Database management CLI for FoxRecon."""

import asyncio
import sys

import click

from internal.config import get_settings
from internal.database.base import init_engine, get_session_factory, Base


@click.group()
def cli():
    """FoxRecon database management."""
    pass


@cli.command()
def init():
    """Initialize the database schema (development only)."""
    settings = get_settings()
    engine = init_engine(settings)

    async def _create_tables():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await engine.dispose()

    asyncio.run(_create_tables())
    click.echo("Database schema created successfully.")


@cli.command()
def drop():
    """Drop all tables (WARNING: destructive!)."""
    if click.confirm("This will delete ALL data. Continue?"):
        settings = get_settings()
        engine = init_engine(settings)

        async def _drop_tables():
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)
            await engine.dispose()

        asyncio.run(_drop_tables())
        click.echo("All tables dropped.")


@cli.command()
def migrate():
    """Run Alembic migrations."""
    click.echo("Run: alembic upgrade head")
    click.echo("Or use: docker compose run --rm api alembic upgrade head")


@cli.command()
@click.argument("migration_name")
def new_migration(migration_name):
    """Create a new Alembic migration."""
    click.echo(f"Run: alembic revision --autogenerate -m \"{migration_name}\"")


@cli.command()
def shell():
    """Open an interactive database shell."""
    from sqlalchemy import select
    from internal.database.models import *  # noqa: F401

    settings = get_settings()
    engine = init_engine(settings)

    async def _shell():
        factory = get_session_factory()
        async with factory() as session:
            print("FoxRecon Database Shell")
            print("Available: session, select, and all models")
            print("Type 'exit' to quit")
            while True:
                try:
                    cmd = input("foxrecon> ")
                    if cmd.strip().lower() in ("exit", "quit"):
                        break
                    if cmd.strip():
                        # Safe eval for simple queries
                        print(eval(cmd, {"session": session, "select": select}))
                except (EOFError, KeyboardInterrupt):
                    break
                except Exception as e:
                    print(f"Error: {e}")

        await engine.dispose()

    asyncio.run(_shell())


if __name__ == "__main__":
    cli()
