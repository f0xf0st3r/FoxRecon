"""API discovery module for Swagger, GraphQL, and endpoint detection."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from internal.utils.logging import get_logger
from internal.utils.security import validate_domain

logger = get_logger(module="api_discovery")

# Common API documentation paths
SWAGGER_PATHS = [
    "/swagger.json",
    "/swagger.yaml",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/api/docs",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/api/openapi.json",
    "/api/v1/openapi.json",
    "/api-docs",
    "/api-docs.json",
    "/api/v1/api-docs",
    "/api/v2/api-docs",
    "/swagger/resources",
]

GRAPHQL_PATHS = [
    "/graphql",
    "/graphql/console",
    "/graphiql",
    "/api/graphql",
    "/api/v1/graphql",
    "/v1/graphql",
    "/playground",
    "/api/playground",
    "/_graphql",
    "/query",
    "/api/query",
    "/altair",
    "/graphiql.php",
    "/graphql.php",
]

API_BASE_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/v1",
    "/v2",
    "/v3",
    "/rest",
    "/rest/v1",
    "/rest/api",
    "/wp-json",
    "/wp-json/wp/v2",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/configprops",
    "/actuator/beans",
    "/.well-known/openid-configuration",
]


@dataclass
class SwaggerEndpoint:
    """Discovered Swagger/OpenAPI endpoint."""

    url: str
    swagger_type: str  # json, yaml, ui
    version: str = ""
    title: str = ""
    paths_count: int = 0


@dataclass
class GraphQLEndpoint:
    """Discovered GraphQL endpoint."""

    url: str
    has_introspection: bool = False
    has_playground: bool = False
    schema_fields: list[str] = field(default_factory=list)


@dataclass
class APIEndpoint:
    """Discovered API base endpoint."""

    url: str
    endpoint_type: str  # rest, actuator, openid, wp_json
    status_code: int = 0
    content_type: str = ""
    response_preview: str = ""


@dataclass
class APIDiscoveryResult:
    """Complete API discovery results."""

    base_url: str
    swagger_endpoints: list[SwaggerEndpoint] = field(default_factory=list)
    graphql_endpoints: list[GraphQLEndpoint] = field(default_factory=list)
    api_endpoints: list[APIEndpoint] = field(default_factory=list)
    total_found: int = 0
    errors: list[str] = field(default_factory=list)


class APIDiscovery:
    """Discovers API endpoints, Swagger docs, and GraphQL interfaces."""

    def __init__(self, timeout: int = 10, user_agent: str = "Mozilla/5.0") -> None:
        self.timeout = timeout
        self.user_agent = user_agent

    async def discover(self, url: str) -> APIDiscoveryResult:
        """Discover all API-related endpoints for a target."""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        result = APIDiscoveryResult(base_url=url)

        # Parallel discovery of all endpoint types
        await self._discover_swagger(base, result)
        await self._discover_graphql(base, result)
        await self._discover_api_endpoints(base, result)

        result.total_found = (
            len(result.swagger_endpoints)
            + len(result.graphql_endpoints)
            + len(result.api_endpoints)
        )

        return result

    async def _discover_swagger(self, base: str, result: APIDiscoveryResult) -> None:
        """Discover Swagger/OpenAPI documentation endpoints."""
        headers = {"User-Agent": self.user_agent}

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers=headers,
        ) as client:
            for path in SWAGGER_PATHS:
                try:
                    url = urljoin(base, path)
                    response = await client.get(url)

                    if response.status_code in (200, 301, 302):
                        if path.endswith(".json") or "openapi" in response.text.lower():
                            # Parse Swagger/OpenAPI spec
                            try:
                                spec = response.json()
                                swagger = SwaggerEndpoint(
                                    url=url,
                                    swagger_type="json",
                                    version=spec.get("openapi", spec.get("swagger", "unknown")),
                                    title=spec.get("info", {}).get("title", ""),
                                    paths_count=len(spec.get("paths", {})),
                                )
                            except json.JSONDecodeError:
                                swagger = SwaggerEndpoint(
                                    url=url,
                                    swagger_type="unknown",
                                )
                        elif path.endswith(".yaml") or path.endswith(".yml"):
                            swagger = SwaggerEndpoint(
                                url=url,
                                swagger_type="yaml",
                            )
                        else:
                            swagger = SwaggerEndpoint(
                                url=url,
                                swagger_type="ui",
                            )

                        result.swagger_endpoints.append(swagger)

                except Exception as e:
                    result.errors.append(f"Swagger check failed {path}: {e}")

    async def _discover_graphql(self, base: str, result: APIDiscoveryResult) -> None:
        """Discover GraphQL endpoints."""
        headers = {
            "User-Agent": self.user_agent,
            "Content-Type": "application/json",
        }

        introspection_query = json.dumps({
            "query": """
            query IntrospectionQuery {
                __schema {
                    types {
                        name
                        kind
                        fields { name }
                    }
                }
            }
            """
        })

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers=headers,
        ) as client:
            for path in GRAPHQL_PATHS:
                try:
                    url = urljoin(base, path)
                    response = await client.post(url, content=introspection_query)

                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if "data" in data and "__schema" in data.get("data", {}):
                                schema = data["data"]["__schema"]
                                graphql = GraphQLEndpoint(
                                    url=url,
                                    has_introspection=True,
                                    schema_fields=[
                                        t.get("name", "")
                                        for t in schema.get("types", [])[:50]
                                    ],
                                )
                                result.graphql_endpoints.append(graphql)
                        except json.JSONDecodeError:
                            # GraphQL endpoint exists but returned non-JSON
                            graphql = GraphQLEndpoint(url=url)
                            result.graphql_endpoints.append(graphql)

                    # Also check for playground/GraphiQL
                    if "playground" in path or "graphiql" in path:
                        get_response = await client.get(url)
                        if get_response.status_code == 200:
                            if "GraphiQL" in get_response.text or "Playground" in get_response.text:
                                graphql = GraphQLEndpoint(
                                    url=url,
                                    has_playground=True,
                                )
                                # Avoid duplicates
                                if not any(g.url == url for g in result.graphql_endpoints):
                                    result.graphql_endpoints.append(graphql)

                except Exception as e:
                    result.errors.append(f"GraphQL check failed {path}: {e}")

    async def _discover_api_endpoints(self, base: str, result: APIDiscoveryResult) -> None:
        """Discover common API base paths."""
        headers = {"User-Agent": self.user_agent}

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers=headers,
        ) as client:
            for path in API_BASE_PATHS:
                try:
                    url = urljoin(base, path)
                    response = await client.get(url)

                    if response.status_code != 404:
                        # Determine endpoint type
                        if "actuator" in path:
                            etype = "actuator"
                        elif "openid" in path:
                            etype = "openid"
                        elif "wp-json" in path:
                            etype = "wp_json"
                        else:
                            etype = "rest"

                        api_endpoint = APIEndpoint(
                            url=url,
                            endpoint_type=etype,
                            status_code=response.status_code,
                            content_type=response.headers.get("content-type", ""),
                            response_preview=response.text[:200],
                        )
                        result.api_endpoints.append(api_endpoint)

                except Exception as e:
                    result.errors.append(f"API endpoint check failed {path}: {e}")
