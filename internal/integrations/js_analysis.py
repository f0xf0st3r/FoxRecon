"""JavaScript analysis module for endpoint and secret extraction."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from internal.utils.logging import get_logger
from internal.utils.security import validate_domain

logger = get_logger(module="js_analysis")

# ------------------------------------------------------------------ #
# Pattern definitions
# ------------------------------------------------------------------ #

# API endpoints in JS
_API_ENDPOINT_PATTERNS = [
    r'["\'](/[a-zA-Z0-9_/{}.-]+)["\']',
    r'(?:"|\'|`)(https?://[^"\'>\s]+)',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
    r'\.get\(["\']([^"\']+)["\']',
    r'\.post\(["\']([^"\']+)["\']',
    r'url:\s*["\']([^"\']+)["\']',
    r'action=["\']([^"\']+)["\']',
    r'href=["\']([^"\']+)["\']',
    r'src=["\']([^"\']+)["\']',
]

# Secret patterns
_SECRET_PATTERNS = {
    "aws_access_key": r'AKIA[0-9A-Z]{16}',
    "aws_secret_key": r'(?:aws_secret_access_key|aws_secret_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
    "private_key": r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
    "jwt_token": r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    "generic_api_key": r'(?:api_key|apikey|api-key)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
    "generic_secret": r'(?:secret|secret_key|secret-key)\s*[=:]\s*["\']?([A-Za-z0-9_\-+/=]{20,})["\']?',
    "github_token": r'ghp_[A-Za-z0-9_]{36}',
    "google_api_key": r'AIza[0-9A-Za-z\-_]{35}',
    "slack_token": r'xox[bprs]-[0-9A-Za-z\-]+',
    "slack_webhook": r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
    "sendgrid_key": r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
    "twilio_key": r'SK[0-9a-fA-F]{32}',
    "firebase_url": r'https://[a-z0-9-]+\.firebaseio\.com',
    "heroku_api_key": r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    "password_assignment": r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^\s"\']{4,})["\']',
    "bearer_token": r'Bearer\s+[A-Za-z0-9\-._~+/]+=*',
    "basic_auth": r'Basic\s+[A-Za-z0-9+/=]+',
    "connection_string": r'(?:mongodb|postgres|mysql|redis):\/\/[^\s"\'>]+',
}

# Common JS file extensions and paths
_JS_EXTENSIONS = [".js", ".mjs", ".bundle.js", ".min.js"]
_JS_PATHS = [
    "/app.js", "/main.js", "/index.js", "/bundle.js",
    "/static/js/", "/assets/js/", "/js/",
    "/app.min.js", "/main.min.js", "/bundle.min.js",
    "/runtime.js", "/vendors.js", "/chunk.js",
]


@dataclass
class JSEndpoint:
    """Discovered endpoint from JavaScript analysis."""

    url: str
    source_file: str
    endpoint_type: str  # api, redirect, action, resource
    method: str = "GET"
    full_url: str = ""


@dataclass
class JSSecret:
    """Discovered secret in JavaScript."""

    secret_type: str
    value: str  # Masked in production output
    source_file: str
    line_number: int = 0
    confidence: float = 1.0


@dataclass
class JSAnalysisResult:
    """Complete result from JS file analysis."""

    source_url: str
    endpoints: list[JSEndpoint] = field(default_factory=list)
    secrets: list[JSSecret] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0


class JSAnalyzer:
    """Analyzes JavaScript files for endpoints, secrets, and intelligence."""

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout
        self._endpoint_patterns = [
            re.compile(p, re.MULTILINE) for p in _API_ENDPOINT_PATTERNS
        ]
        self._secret_patterns = {
            name: re.compile(pattern, re.MULTILINE)
            for name, pattern in _SECRET_PATTERNS.items()
        }

    async def analyze_url(self, base_url: str) -> JSAnalysisResult:
        """Analyze a web application's JavaScript files.

        Workflow:
        1. Fetch the main page and extract <script> tags
        2. Download all JS files
        3. Analyze each file for endpoints, secrets, subdomains
        """
        import time
        start = time.monotonic()
        result = JSAnalysisResult(source_url=base_url)

        try:
            # Step 1: Fetch page and find JS references
            js_urls = await self._find_js_files(base_url)

            # Step 2: Analyze each JS file
            for js_url in js_urls[:20]:  # Limit to prevent overload
                try:
                    analysis = await self._analyze_js_file(js_url)
                    result.endpoints.extend(analysis.endpoints)
                    result.secrets.extend(analysis.secrets)
                    result.imports.extend(analysis.imports)
                    result.subdomains.extend(analysis.subdomains)
                except Exception as e:
                    result.errors.append(f"Failed to analyze {js_url}: {e}")

        except Exception as e:
            result.errors.append(f"Failed to analyze {base_url}: {e}")

        result.duration_seconds = round(time.monotonic() - start, 2)
        return result

    async def _find_js_files(self, url: str) -> list[str]:
        """Find JavaScript file references in a page."""
        js_urls: set[str] = set()
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Add known common paths
        for path in _JS_PATHS:
            js_urls.add(urljoin(base, path))

        # Try to fetch page and extract script tags
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True
            ) as client:
                response = await client.get(url)
                html = response.text

                # Extract script src URLs
                script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']')
                for match in script_pattern.finditer(html):
                    src = match.group(1)
                    if src.endswith(tuple(_JS_EXTENSIONS)):
                        js_urls.add(urljoin(url, src))

                    # Check for inline JS with src patterns
                    src_matches = re.findall(r'src=["\']([^"\']\.js[^"\']*)["\']', html)
                    for s in src_matches:
                        js_urls.add(urljoin(url, s))

        except Exception as e:
            logger.warning("failed_to_fetch_page", url=url, error=str(e))

        return list(js_urls)

    async def _analyze_js_file(self, url: str) -> JSAnalysisResult:
        """Analyze a single JavaScript file."""
        import time
        start = time.monotonic()
        result = JSAnalysisResult(source_url=url)

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(url)
            content = response.text

        # Extract endpoints
        result.endpoints = self._extract_endpoints(content, url)

        # Extract secrets
        result.secrets = self._extract_secrets(content, url)

        # Extract subdomains
        result.subdomains = self._extract_subdomains(content)

        # Extract imports
        result.imports = self._extract_imports(content)

        result.duration_seconds = round(time.monotonic() - start, 2)
        return result

    def _extract_endpoints(self, content: str, source: str) -> list[JSEndpoint]:
        """Extract API endpoints from JavaScript content."""
        endpoints: list[JSEndpoint] = []
        parsed = urlparse(source)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for i, pattern in enumerate(self._endpoint_patterns):
            for match in pattern.finditer(content):
                raw_url = match.group(1)
                if not raw_url or len(raw_url) < 3:
                    continue

                # Skip common non-endpoint strings
                if any(skip in raw_url.lower() for skip in [
                    ".js", ".css", ".png", ".jpg", ".svg", ".ico",
                    "placeholder", "lorem", "example.com",
                ]):
                    continue

                # Determine endpoint type
                if i == 0:
                    etype = "api"
                elif i == 1:
                    etype = "redirect" if "http" in raw_url else "api"
                else:
                    etype = "api"

                full_url = raw_url if raw_url.startswith("http") else urljoin(base, raw_url)

                endpoints.append(JSEndpoint(
                    url=raw_url,
                    source_file=source,
                    endpoint_type=etype,
                    full_url=full_url,
                ))

        # Deduplicate by URL
        seen = set()
        unique = []
        for ep in endpoints:
            if ep.url not in seen:
                seen.add(ep.url)
                unique.append(ep)

        return unique

    def _extract_secrets(self, content: str, source: str) -> list[JSSecret]:
        """Extract potential secrets from JavaScript content."""
        secrets: list[JSSecret] = []

        for name, pattern in self._secret_patterns.items():
            for match in pattern.finditer(content):
                value = match.group(0)
                # Calculate line number
                line_num = content[:match.start()].count("\n") + 1

                # Mask sensitive value for safe logging
                if len(value) > 10:
                    masked = value[:4] + "..." + value[-4:]
                else:
                    masked = "***"

                secrets.append(JSSecret(
                    secret_type=name,
                    value=masked,
                    source_file=source,
                    line_number=line_num,
                    confidence=0.8 if name.startswith("generic") else 1.0,
                ))

        return secrets

    def _extract_subdomains(self, content: str) -> list[str]:
        """Extract subdomain references from JavaScript."""
        subdomains: set[str] = set()

        # Match domain-like patterns
        domain_pattern = re.compile(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+')

        for match in domain_pattern.finditer(content):
            domain = match.group(0).lower()
            # Filter common TLDs and non-domain patterns
            if "." in domain and not any(skip in domain for skip in [
                ".js", ".css", ".png", ".jpg", ".svg",
                "example.com", "example.org",
            ]):
                try:
                    validate_domain(domain)
                    subdomains.add(domain)
                except ValueError:
                    pass

        return list(subdomains)

    def _extract_imports(self, content: str) -> list[str]:
        """Extract import/module references."""
        imports: list[str] = []
        patterns = [
            re.compile(r'import\s+.*?from\s+["\']([^"\']+)["\']'),
            re.compile(r'require\(["\']([^"\']+)["\']'),
            re.compile(r'import\(["\']([^"\']+)["\']'),
        ]

        for pattern in patterns:
            for match in pattern.finditer(content):
                imports.append(match.group(1))

        return list(set(imports))
