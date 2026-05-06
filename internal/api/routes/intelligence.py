"""V2 Intelligence routes - JS analysis, DNS, API discovery, cloud exposure."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from internal.integrations.js_analysis import JSAnalyzer
from internal.integrations.dns_intelligence import DNSIntelligence
from internal.integrations.api_discovery import APIDiscovery
from internal.integrations.cloud_exposure import CloudExposureChecker
from internal.utils.security import validate_domain

router = APIRouter(prefix="/intelligence", tags=["intelligence-v2"])


class JSAnalysisRequest(BaseModel):
    url: str


class CloudExposureRequest(BaseModel):
    domain: str


class APIDiscoveryRequest(BaseModel):
    url: str


@router.post(
    "/js-analysis",
    summary="Analyze JavaScript files for endpoints and secrets",
)
async def analyze_javascript(payload: JSAnalysisRequest):
    """Analyze a web application's JavaScript files.

    Extracts:
    - API endpoints
    - Hardcoded secrets/tokens
    - Subdomain references
    - Import paths
    """
    analyzer = JSAnalyzer()
    result = await analyzer.analyze_url(payload.url)

    return {
        "source_url": result.source_url,
        "endpoints": [
            {
                "url": ep.url,
                "type": ep.endpoint_type,
                "method": ep.method,
                "full_url": ep.full_url,
                "source": ep.source_file,
            }
            for ep in result.endpoints[:100]
        ],
        "secrets": [
            {
                "type": s.secret_type,
                "value": s.value,  # Already masked
                "source": s.source_file,
                "line": s.line_number,
                "confidence": s.confidence,
            }
            for s in result.secrets
        ],
        "subdomains": result.subdomains[:50],
        "imports": result.imports[:50],
        "errors": result.errors,
        "duration_seconds": result.duration_seconds,
    }


@router.get(
    "/dns/{domain}",
    summary="Gather DNS intelligence for a domain",
)
async def gather_dns_intelligence(domain: str):
    """Gather comprehensive DNS intelligence.

    Includes:
    - All DNS record types (A, AAAA, CNAME, MX, NS, TXT, SOA)
    - Zone transfer attempt
    - ASN/country lookup
    - Reverse DNS
    """
    domain = validate_domain(domain)
    intel = DNSIntelligence()
    result = await intel.gather(domain)

    return {
        "domain": result.domain,
        "records": {
            rtype: [
                {"name": r.name, "value": r.value, "ttl": r.ttl}
                for r in records
            ]
            for rtype, records in result.records.items()
        },
        "zone_transfers": [
            {
                "nameserver": zr.nameserver,
                "success": zr.success,
                "error": zr.error,
            }
            for zr in result.zone_transfers
        ],
        "asn_info": {
            "ip": result.asn_info.ip,
            "asn": result.asn_info.asn,
            "name": result.asn_info.asn_name,
            "country": result.asn_info.country,
        } if result.asn_info else None,
        "reverse_dns": result.reverse_dns,
        "errors": result.errors,
    }


@router.post(
    "/api-discovery",
    summary="Discover API endpoints, Swagger docs, and GraphQL",
)
async def discover_apis(payload: APIDiscoveryRequest):
    """Discover API-related endpoints on a target.

    Checks for:
    - Swagger/OpenAPI documentation
    - GraphQL endpoints with introspection
    - Common API base paths
    - Spring Boot actuator endpoints
    - WordPress JSON API
    - OpenID configuration
    """
    discovery = APIDiscovery()
    result = await discovery.discover(payload.url)

    return {
        "base_url": result.base_url,
        "swagger_endpoints": [
            {
                "url": s.url,
                "type": s.swagger_type,
                "version": s.version,
                "title": s.title,
                "paths_count": s.paths_count,
            }
            for s in result.swagger_endpoints
        ],
        "graphql_endpoints": [
            {
                "url": g.url,
                "has_introspection": g.has_introspection,
                "has_playground": g.has_playground,
                "schema_fields": g.schema_fields[:20],
            }
            for g in result.graphql_endpoints
        ],
        "api_endpoints": [
            {
                "url": a.url,
                "type": a.endpoint_type,
                "status_code": a.status_code,
                "content_type": a.content_type,
            }
            for a in result.api_endpoints
        ],
        "total_found": result.total_found,
        "errors": result.errors,
    }


@router.post(
    "/cloud-exposure",
    summary="Check for exposed cloud storage buckets",
)
async def check_cloud_exposure(payload: CloudExposureRequest):
    """Check for exposed cloud storage assets.

    Scans for:
    - Public/listable AWS S3 buckets
    - Exposed Azure Blob containers
    - Public GCP Cloud Storage buckets

    Uses common naming patterns derived from the target domain.
    """
    domain = validate_domain(payload.domain)
    checker = CloudExposureChecker()
    result = await checker.check(domain)

    return {
        "domain": result.domain,
        "s3_buckets": [
            {
                "url": b.url,
                "bucket_name": b.bucket_name,
                "exists": b.exists,
                "is_public": b.is_public,
                "is_listable": b.is_listable,
                "status_code": b.status_code,
            }
            for b in result.s3_buckets if b.exists
        ],
        "azure_blobs": [
            {
                "url": b.url,
                "account_name": b.account_name,
                "exists": b.exists,
                "is_public": b.is_public,
                "status_code": b.status_code,
            }
            for b in result.azure_blobs if b.exists
        ],
        "gcp_buckets": [
            {
                "url": b.url,
                "bucket_name": b.bucket_name,
                "exists": b.exists,
                "is_public": b.is_public,
                "status_code": b.status_code,
            }
            for b in result.gcp_buckets if b.exists
        ],
        "public_exposures": result.public_exposures,
        "errors": result.errors,
    }


@router.get(
    "/cloud-exposure/{domain}",
    summary="Check cloud exposure (GET alias)",
)
async def check_cloud_exposure_get(domain: str):
    """GET alias for cloud exposure check."""
    payload = CloudExposureRequest(domain=domain)
    return await check_cloud_exposure(payload)
