"""Cloud exposure checks for S3, Azure Blob, and cloud assets."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from internal.utils.logging import get_logger
from internal.utils.security import validate_domain

logger = get_logger(module="cloud_exposure")

# AWS S3 endpoints
S3_ENDPOINTS = [
    "https://{bucket}.s3.amazonaws.com",
    "https://{bucket}.s3.{region}.amazonaws.com",
    "https://s3.amazonaws.com/{bucket}",
    "https://s3.{region}.amazonaws.com/{bucket}",
]

S3_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3",
    "eu-central-1", "eu-north-1",
    "ap-south-1", "ap-southeast-1", "ap-southeast-2",
    "ap-northeast-1", "ap-northeast-2",
    "sa-east-1", "ca-central-1",
]

# Azure Blob endpoints
AZURE_ENDPOINTS = [
    "https://{account}.blob.core.windows.net/{container}",
    "https://{account}.blob.core.windows.net",
]

# GCP Cloud Storage endpoints
GCP_ENDPOINTS = [
    "https://storage.googleapis.com/{bucket}",
    "https://storage.cloud.google.com/{bucket}",
]

# Common bucket/container name patterns
BUCKET_PATTERNS = [
    "{domain}",
    "{domain}-assets",
    "{domain}-static",
    "{domain}-media",
    "{domain}-uploads",
    "{domain}-backups",
    "{domain}-data",
    "{domain}-storage",
    "{domain}-logs",
    "{domain}-cdn",
    "{domain}-dev",
    "{domain}-staging",
    "{domain}-prod",
    "{domain}-test",
    "{domain}-images",
    "{domain}-files",
    "{domain}-public",
    "{domain}-private",
    "{domain}-documents",
    "{domain}-config",
]


@dataclass
class S3BucketResult:
    """S3 bucket check result."""

    url: str
    bucket_name: str
    exists: bool
    is_public: bool = False
    is_listable: bool = False
    status_code: int = 0
    error: str = ""


@dataclass
class AzureBlobResult:
    """Azure Blob storage check result."""

    url: str
    account_name: str
    container_name: str
    exists: bool
    is_public: bool = False
    status_code: int = 0
    error: str = ""


@dataclass
class GCPBucketResult:
    """GCP Cloud Storage check result."""

    url: str
    bucket_name: str
    exists: bool
    is_public: bool = False
    status_code: int = 0
    error: str = ""


@dataclass
class CloudExposureResult:
    """Complete cloud exposure check results."""

    domain: str
    s3_buckets: list[S3BucketResult] = field(default_factory=list)
    azure_blobs: list[AzureBlobResult] = field(default_factory=list)
    gcp_buckets: list[GCPBucketResult] = field(default_factory=list)
    public_exposures: int = 0
    errors: list[str] = field(default_factory=list)


class CloudExposureChecker:
    """Checks for exposed cloud storage assets.

    Scans for:
    - Public/listable AWS S3 buckets
    - Exposed Azure Blob containers
    - Public GCP Cloud Storage buckets
    """

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    async def check(self, domain: str) -> CloudExposureResult:
        """Run all cloud exposure checks for a domain."""
        domain = validate_domain(domain)
        result = CloudExposureResult(domain=domain)

        # Generate bucket names from domain
        domain_base = domain.split(".")[0]
        bucket_names = []
        for pattern in BUCKET_PATTERNS:
            bucket_names.append(pattern.format(domain=domain_base))
            bucket_names.append(pattern.format(domain=domain.replace(".", "-")))

        # Check S3 buckets (limit to prevent abuse)
        await self._check_s3(bucket_names[:10], result)

        # Check Azure blobs
        await self._check_azure(domain, domain_base, result)

        # Check GCP buckets
        await self._check_gcp(bucket_names[:10], result)

        result.public_exposures = sum(
            1 for b in result.s3_buckets if b.is_public
        ) + sum(
            1 for b in result.azure_blobs if b.is_public
        ) + sum(
            1 for b in result.gcp_buckets if b.is_public
        )

        return result

    async def _check_s3(self, bucket_names: list[str], result: CloudExposureResult) -> None:
        """Check for exposed S3 buckets."""
        urls_to_check = []
        for bucket in bucket_names:
            bucket = bucket.lower().replace("_", "-")
            urls_to_check.append({
                "url": f"https://{bucket}.s3.amazonaws.com",
                "bucket": bucket,
            })

        # Check concurrently
        tasks = []
        for url_info in urls_to_check:
            tasks.append(self._check_s3_url(url_info["url"], url_info["bucket"]))

        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for resp in responses:
            if isinstance(resp, S3BucketResult):
                result.s3_buckets.append(resp)
            else:
                result.errors.append(f"S3 check error: {resp}")

    async def _check_s3_url(self, url: str, bucket: str) -> S3BucketResult:
        """Check a single S3 bucket URL."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.get(url)
                result = S3BucketResult(
                    url=url,
                    bucket_name=bucket,
                    exists=response.status_code != 404,
                    status_code=response.status_code,
                )

                # Check if bucket is listable
                if response.status_code == 200 and "ListBucketResult" in response.text:
                    result.is_listable = True
                    result.is_public = True

                # Check for access denied vs not found
                if response.status_code == 403:
                    result.exists = True
                elif response.status_code == 404:
                    result.exists = False

                return result

            except Exception as e:
                return S3BucketResult(
                    url=url,
                    bucket_name=bucket,
                    exists=False,
                    error=str(e),
                )

    async def _check_azure(self, domain: str, domain_base: str, result: CloudExposureResult) -> None:
        """Check for exposed Azure Blob storage."""
        account_names = [
            domain_base,
            domain.replace(".", ""),
            domain.replace("-", ""),
        ]

        for account in account_names:
            account = account.lower()
            url = f"https://{account}.blob.core.windows.net"

            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(url)

                    azure_result = AzureBlobResult(
                        url=url,
                        account_name=account,
                        container_name="",
                        exists=response.status_code not in (400, 404),
                        status_code=response.status_code,
                    )

                    # Check for public access
                    if response.status_code == 200 or (
                        response.status_code == 403 and "AuthenticationFailed" not in response.text
                    ):
                        azure_result.is_public = True

                    result.azure_blobs.append(azure_result)

            except Exception as e:
                result.errors.append(f"Azure check error: {e}")

    async def _check_gcp(self, bucket_names: list[str], result: CloudExposureResult) -> None:
        """Check for exposed GCP Cloud Storage buckets."""
        urls_to_check = []
        for bucket in bucket_names:
            bucket = bucket.lower().replace("_", "-")
            urls_to_check.append({
                "url": f"https://storage.googleapis.com/{bucket}",
                "bucket": bucket,
            })

        tasks = []
        for url_info in urls_to_check:
            tasks.append(self._check_gcp_url(url_info["url"], url_info["bucket"]))

        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for resp in responses:
            if isinstance(resp, GCPBucketResult):
                result.gcp_buckets.append(resp)
            else:
                result.errors.append(f"GCP check error: {resp}")

    async def _check_gcp_url(self, url: str, bucket: str) -> GCPBucketResult:
        """Check a single GCP Cloud Storage bucket URL."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.get(url)

                result = GCPBucketResult(
                    url=url,
                    bucket_name=bucket,
                    exists=response.status_code != 404,
                    status_code=response.status_code,
                )

                # Check if publicly accessible
                if response.status_code == 200:
                    result.is_public = True

                return result

            except Exception as e:
                return GCPBucketResult(
                    url=url,
                    bucket_name=bucket,
                    exists=False,
                    error=str(e),
                )
