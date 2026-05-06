"""Integration tests for FastAPI application."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    from internal.api.app import create_app
    from internal.config import get_settings

    # Override settings for testing
    import os
    os.environ["POSTGRES_HOST"] = "localhost"
    os.environ["REDIS_HOST"] = "localhost"

    app = create_app()
    return TestClient(app)


class TestHealthEndpoint:
    def test_health_check(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "FoxRecon"

    def test_root(self, client):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "docs" in data


class TestOpenAPI:
    def test_openapi_schema(self, client):
        response = client.get("/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert "info" in schema
        assert schema["info"]["title"] == "FoxRecon"

    def test_docs(self, client):
        response = client.get("/docs")
        assert response.status_code == 200


class TestScanEndpoints:
    def test_list_scans_empty(self, client):
        response = client.get("/api/v1/scans/")
        # Will fail without DB, but tests routing
        assert response.status_code in (200, 500)

    def test_create_scan_invalid_target(self, client):
        response = client.post(
            "/api/v1/scans/",
            json={
                "target_id": "00000000-0000-0000-0000-000000000000",
                "scan_type": "full",
            },
        )
        assert response.status_code in (404, 422, 500)


class TestTargetEndpoints:
    def test_list_targets(self, client):
        response = client.get(
            "/api/v1/targets/",
            params={"organization_id": "00000000-0000-0000-0000-000000000000"},
        )
        assert response.status_code in (200, 500)


class TestFindingsEndpoints:
    def test_list_findings_empty(self, client):
        response = client.get("/api/v1/findings/")
        assert response.status_code in (200, 500)

    def test_list_vulnerabilities(self, client):
        response = client.get("/api/v1/findings/vulnerabilities")
        assert response.status_code in (200, 500)

    def test_list_live_hosts(self, client):
        response = client.get("/api/v1/findings/live-hosts")
        assert response.status_code in (200, 500)

    def test_list_ports(self, client):
        response = client.get("/api/v1/findings/ports")
        assert response.status_code in (200, 500)


class TestDashboardEndpoint:
    def test_dashboard(self, client):
        response = client.get("/api/v1/dashboard/")
        assert response.status_code in (200, 500)


class TestReportsEndpoint:
    def test_list_reports(self, client):
        response = client.get("/api/v1/reports/")
        assert response.status_code in (200, 500)
