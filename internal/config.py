"""Application configuration management using Pydantic Settings."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized application configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------ #
    # Application
    # ------------------------------------------------------------------ #
    app_name: str = "FoxRecon"
    app_env: str = "production"
    debug: bool = False
    secret_key: str = "CHANGE-ME-IN-PRODUCTION"
    api_prefix: str = "/api/v1"

    # ------------------------------------------------------------------ #
    # Server
    # ------------------------------------------------------------------ #
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    allowed_origins: list[str] = Field(default_factory=lambda: ["*"])

    # ------------------------------------------------------------------ #
    # PostgreSQL
    # ------------------------------------------------------------------ #
    postgres_user: str = "foxrecon"
    postgres_password: str = "foxrecon_secret"
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "foxrecon"
    postgres_pool_size: int = 20
    postgres_max_overflow: int = 10

    @property
    def database_url(self) -> str:
        """Build async SQLAlchemy URL."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def database_url_sync(self) -> str:
        """Build sync SQLAlchemy URL (for Alembic)."""
        return (
            f"postgresql+psycopg2://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # ------------------------------------------------------------------ #
    # Redis
    # ------------------------------------------------------------------ #
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str = ""

    @property
    def redis_url(self) -> str:
        if self.redis_password:
            return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    # ------------------------------------------------------------------ #
    # Celery
    # ------------------------------------------------------------------ #
    celery_broker_url: str = ""
    celery_result_backend: str = ""

    @field_validator("celery_broker_url", mode="before")
    @classmethod
    def set_celery_broker(cls, v: str | None, info) -> str:
        if v:
            return v
        settings = info.data
        pwd = settings.get("redis_password", "")
        host = settings.get("redis_host", "localhost")
        port = settings.get("redis_port", 6379)
        db = settings.get("redis_db", 1)
        if pwd:
            return f"redis://:{pwd}@{host}:{port}/{db}"
        return f"redis://{host}:{port}/{db}"

    @field_validator("celery_result_backend", mode="before")
    @classmethod
    def set_celery_backend(cls, v: str | None, info) -> str:
        if v:
            return v
        settings = info.data
        pwd = settings.get("redis_password", "")
        host = settings.get("redis_host", "localhost")
        port = settings.get("redis_port", 6379)
        db = settings.get("redis_db", 2)
        if pwd:
            return f"redis://:{pwd}@{host}:{port}/{db}"
        return f"redis://{host}:{port}/{db}"

    # ------------------------------------------------------------------ #
    # JWT Auth
    # ------------------------------------------------------------------ #
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60
    jwt_refresh_token_expire_days: int = 30

    # ------------------------------------------------------------------ #
    # Rate Limiting
    # ------------------------------------------------------------------ #
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60

    # ------------------------------------------------------------------ #
    # Scan Engine
    # ------------------------------------------------------------------ #
    scan_timeout_seconds: int = 3600
    max_concurrent_scans: int = 10
    scan_rate_limit_per_minute: int = 50

    # Tool binary paths (defaults assume PATH resolution)
    subfinder_path: str = "subfinder"
    httpx_path: str = "httpx"
    naabu_path: str = "naabu"
    nuclei_path: str = "nuclei"
    nmap_path: str = "nmap"
    ffuf_path: str = "ffuf"
    gowitness_path: str = "gowitness"

    # Wordlists
    default_wordlist_path: str = "/usr/share/seclists/Discovery/Web-Content/common.txt"

    # Nuclei
    nuclei_templates_path: str = ""
    nuclei_severity_filter: str = "low,medium,high,critical"
    nuclei_rate_limit: int = 50
    nuclei_concurrency: int = 25

    # ------------------------------------------------------------------ #
    # Storage
    # ------------------------------------------------------------------ #
    data_dir: str = "/tmp/foxrecon_data"
    screenshots_dir: str = ""
    scan_results_dir: str = ""
    reports_dir: str = ""

    def model_post_init(self, __context: object) -> None:
        """Derive sub-paths after initialization."""
        base = Path(self.data_dir)
        if not self.screenshots_dir:
            self.screenshots_dir = str(base / "screenshots")
        if not self.scan_results_dir:
            self.scan_results_dir = str(base / "scan_results")
        if not self.reports_dir:
            self.reports_dir = str(base / "reports")

        # Ensure directories exist
        for d in [self.data_dir, self.screenshots_dir,
                   self.scan_results_dir, self.reports_dir]:
            Path(d).mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance (singleton pattern)."""
    return Settings()
