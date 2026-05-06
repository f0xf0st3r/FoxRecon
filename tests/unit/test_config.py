"""Unit tests for configuration."""

import pytest

from internal.config import Settings


class TestSettings:
    def test_default_values(self):
        settings = Settings()
        assert settings.app_name == "FoxRecon"
        assert settings.postgres_port == 5432
        assert settings.redis_port == 6379

    def test_database_url(self):
        settings = Settings(
            postgres_user="testuser",
            postgres_password="testpass",
            postgres_host="db.example.com",
            postgres_port=5433,
            postgres_db="testdb",
        )
        assert "testuser" in settings.database_url
        assert "db.example.com:5433" in settings.database_url
        assert "asyncpg" in settings.database_url

    def test_database_url_sync(self):
        settings = Settings()
        assert "psycopg2" in settings.database_url_sync

    def test_redis_url(self):
        settings = Settings(redis_host="redis.example.com", redis_port=6380)
        assert "redis://redis.example.com:6380" in settings.redis_url

    def test_redis_url_with_password(self):
        settings = Settings(
            redis_host="redis.example.com",
            redis_password="secret",
        )
        assert "redis://:secret@redis.example.com" in settings.redis_url

    def test_celery_broker_auto(self):
        settings = Settings(
            redis_host="redis.example.com",
            redis_port=6380,
            redis_db=1,
        )
        assert "redis://redis.example.com:6380/1" in settings.celery_broker_url

    def test_celery_backend_auto(self):
        settings = Settings(
            redis_host="redis.example.com",
            redis_port=6380,
            redis_db=2,
        )
        assert "redis://redis.example.com:6380/2" in settings.celery_result_backend

    def test_data_dirs_created(self, tmp_path, monkeypatch):
        data_dir = str(tmp_path / "test_data")
        settings = Settings(data_dir=data_dir)
        assert settings.screenshots_dir is not None
        assert settings.scan_results_dir is not None
        assert settings.reports_dir is not None
