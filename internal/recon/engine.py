"""Recon engine - orchestrates the full scan pipeline.

Coordinates subfinder -> httpx -> naabu -> nuclei in sequence.
Each stage feeds results into the next stage.
Results are persisted to PostgreSQL after each stage.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from internal.config import Settings
from internal.scanners.base import ScanConfig, ScanOutput
from internal.scanners.subfinder import SubfinderScanner
from internal.scanners.httpx import HttpxScanner
from internal.scanners.naabu import NaabuScanner
from internal.scanners.nuclei import NucleiScanner
from internal.database.models import (
    ScanJob,
    ScanResult,
    Subdomain,
    LiveHost,
    Port,
    Finding,
    Vulnerability,
    Technology,
)
from internal.findings.normalizer import FindingNormalizer
from internal.utils.logging import get_logger

logger = get_logger(module="recon_engine")


@dataclass
class ScanPipelineConfig:
    """Configuration for a scan pipeline execution."""

    run_recon: bool = True
    run_httpx: bool = True
    run_naabu: bool = True
    run_nuclei: bool = True
    subfinder_sources: list[str] | None = None
    httpx_ports: list[int] | None = None
    naabu_top_ports: int = 100
    nuclei_severities: list[str] | None = None
    nuclei_rate_limit: int = 50
    nuclei_concurrency: int = 25
    timeout: int = 3600


@dataclass
class PipelineResult:
    """Final result from a complete pipeline execution."""

    scan_job_id: uuid.UUID
    success: bool
    stages_completed: list[str] = field(default_factory=list)
    subdomains_found: int = 0
    live_hosts_found: int = 0
    ports_found: int = 0
    findings_found: int = 0
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0


class ReconEngine:
    """Main reconnaissance engine orchestrating the scan pipeline.

    Pipeline stages:
    1. Subfinder: Enumerate subdomains
    2. httpx: Detect live hosts on subdomains
    3. naabu: Port scan live hosts
    4. nuclei: Vulnerability scan all HTTP endpoints

    Each stage result is persisted to the database immediately.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.normalizer = FindingNormalizer()

    async def run_pipeline(
        self,
        db: AsyncSession,
        scan_job: ScanJob,
        target_value: str,
        config: ScanPipelineConfig | None = None,
    ) -> PipelineResult:
        """Execute the full reconnaissance pipeline.

        Args:
            db: Active database session
            scan_job: The ScanJob record to update
            target_value: The root domain or target
            config: Pipeline configuration

        Returns:
            PipelineResult with summary of all stages
        """
        import time
        start = time.monotonic()
        config = config or ScanPipelineConfig()
        result = PipelineResult(scan_job_id=scan_job.id, success=True)

        # Update job status
        scan_job.status = "running"
        scan_job.started_at = datetime.now(timezone.utc)
        await db.commit()

        logger.info(
            "pipeline_started",
            scan_job_id=str(scan_job.id),
            target=target_value,
        )

        try:
            # Stage 1: Subdomain enumeration
            if config.run_recon:
                stage_result = await self._run_recon_stage(
                    db, scan_job, target_value, config
                )
                result.stages_completed.append("recon")
                result.subdomains_found = stage_result.metadata.get("total_found", 0)
                scan_job.subdomains_found = result.subdomains_found
                await db.commit()

            # Get all subdomains for next stage
            subdomains = await self._get_subdomains(db, scan_job.target_id)

            # Stage 2: Live host detection
            if config.run_httpx and subdomains:
                stage_result = await self._run_httpx_stage(
                    db, scan_job, subdomains, config
                )
                result.stages_completed.append("httpx")
                result.live_hosts_found = stage_result.metadata.get("live_hosts", 0)
                scan_job.live_hosts_found = result.live_hosts_found
                await db.commit()

            # Get live hosts for port scanning
            live_hosts = await self._get_live_hosts(db, scan_job.target_id)

            # Stage 3: Port scanning
            if config.run_naabu and live_hosts:
                stage_result = await self._run_naabu_stage(
                    db, scan_job, live_hosts, config
                )
                result.stages_completed.append("naabu")
                result.ports_found = stage_result.metadata.get("open_ports_found", 0)
                scan_job.ports_found = result.ports_found
                await db.commit()

            # Stage 4: Vulnerability scanning
            if config.run_nuclei:
                targets_for_nuclei = await self._get_nuclei_targets(db, scan_job.target_id)
                if targets_for_nuclei:
                    stage_result = await self._run_nuclei_stage(
                        db, scan_job, targets_for_nuclei, config
                    )
                    result.stages_completed.append("nuclei")
                    result.findings_found = stage_result.metadata.get("total_findings", 0)
                    scan_job.findings_count = result.findings_found
                    await db.commit()

            # Mark complete
            scan_job.status = "completed"
            scan_job.completed_at = datetime.now(timezone.utc)
            await db.commit()

            logger.info(
                "pipeline_completed",
                scan_job_id=str(scan_job.id),
                stages=result.stages_completed,
                duration=round(time.monotonic() - start, 2),
            )

        except Exception as e:
            logger.exception("pipeline_failed", scan_job_id=str(scan_job.id), error=str(e))
            scan_job.status = "failed"
            scan_job.error_message = str(e)
            scan_job.completed_at = datetime.now(timezone.utc)
            await db.commit()
            result.success = False
            result.errors.append(str(e))

        result.duration_seconds = round(time.monotonic() - start, 2)
        return result

    async def _run_recon_stage(
        self,
        db: AsyncSession,
        scan_job: ScanJob,
        domain: str,
        config: ScanPipelineConfig,
    ) -> ScanOutput:
        """Stage 1: Subfinder subdomain enumeration."""
        logger.info("stage_recon_start", domain=domain)

        stage = ScanResult(
            scan_job_id=scan_job.id,
            stage="recon",
            status="running",
            tool_name="subfinder",
            started_at=datetime.now(timezone.utc),
        )
        db.add(stage)
        await db.commit()

        scanner = SubfinderScanner(
            binary_path=self.settings.subfinder_path,
            config=ScanConfig(
                timeout=config.timeout,
                output_dir=self.settings.scan_results_dir,
            ),
        )

        output = await scanner.run(
            target=domain,
            sources=config.subfinder_sources,
        )

        # Persist subdomains
        if output.success and output.items:
            for item in output.items:
                subdomain = Subdomain(
                    target_id=scan_job.target_id,
                    domain=item["domain"].lower().strip(),
                    source=item.get("source", "subfinder"),
                    resolved_ip=item.get("resolved_ip"),
                    first_seen_scan_id=scan_job.id,
                    last_seen_scan_id=scan_job.id,
                )
                db.add(subdomain)

        stage.status = "completed"
        stage.completed_at = datetime.now(timezone.utc)
        stage.duration_seconds = output.duration_seconds
        stage.item_count = len(output.items) if output.items else 0
        stage.output_summary = output.metadata
        await db.commit()

        return output

    async def _run_httpx_stage(
        self,
        db: AsyncSession,
        scan_job: ScanJob,
        subdomains: list[str],
        config: ScanPipelineConfig,
    ) -> ScanOutput:
        """Stage 2: httpx live host detection."""
        logger.info("stage_httpx_start", subdomain_count=len(subdomains))

        stage = ScanResult(
            scan_job_id=scan_job.id,
            stage="live_hosts",
            status="running",
            tool_name="httpx",
            started_at=datetime.now(timezone.utc),
        )
        db.add(stage)
        await db.commit()

        scanner = HttpxScanner(
            binary_path=self.settings.httpx_path,
            config=ScanConfig(
                timeout=config.timeout,
                rate_limit=self.settings.scan_rate_limit_per_minute,
                threads=self.settings.nuclei_concurrency,
                output_dir=self.settings.scan_results_dir,
            ),
        )

        # Write subdomains to temp file for httpx
        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, dir="/tmp"
        ) as f:
            for sub in subdomains:
                f.write(sub + "\n")
            input_file = f.name

        try:
            output = await scanner.run(
                target="",
                input_file=input_file,
                ports=config.httpx_ports,
            )

            # Persist live hosts
            if output.success and output.items:
                for item in output.items:
                    if not item.get("url"):
                        continue

                    # Upsert: find existing or create new
                    host = LiveHost(
                        target_id=scan_job.target_id,
                        hostname=item.get("host", ""),
                        url=item["url"],
                        ip=item.get("ip"),
                        port=item.get("port", 443),
                        scheme=item.get("scheme", "https"),
                        status_code=item.get("status_code"),
                        title=item.get("title"),
                        content_type=item.get("content_type"),
                        content_length=item.get("content_length"),
                        response_time_ms=item.get("response_time_ms"),
                        tech_stack=item.get("tech", []),
                        webserver=item.get("webserver"),
                        hash=item.get("hash"),
                        last_scan_id=scan_job.id,
                    )
                    db.add(host)

                    # Persist technologies
                    for tech_name in item.get("tech", []):
                        tech = Technology(
                            target_id=scan_job.target_id,
                            name=tech_name,
                        )
                        db.add(tech)

            stage.status = "completed"
            stage.completed_at = datetime.now(timezone.utc)
            stage.duration_seconds = output.duration_seconds
            stage.item_count = len(output.items) if output.items else 0
            stage.output_summary = output.metadata

        finally:
            import os
            try:
                os.unlink(input_file)
            except OSError:
                pass

        await db.commit()
        return output

    async def _run_naabu_stage(
        self,
        db: AsyncSession,
        scan_job: ScanJob,
        live_hosts: list[dict[str, str]],
        config: ScanPipelineConfig,
    ) -> ScanOutput:
        """Stage 3: naabu port scanning."""
        logger.info("stage_naabu_start", host_count=len(live_hosts))

        stage = ScanResult(
            scan_job_id=scan_job.id,
            stage="port_scan",
            status="running",
            tool_name="naabu",
            started_at=datetime.now(timezone.utc),
        )
        db.add(stage)
        await db.commit()

        scanner = NaabuScanner(
            binary_path=self.settings.naabu_path,
            config=ScanConfig(
                timeout=config.timeout,
                output_dir=self.settings.scan_results_dir,
            ),
        )

        all_ports = []
        for host_info in live_hosts:
            host = host_info["host"]
            output = await scanner.run(
                target=host,
                top_ports=config.naabu_top_ports,
            )

            if output.success and output.items:
                all_ports.extend(output.items)

                # Persist ports
                for port_item in output.items:
                    port = Port(
                        target_id=scan_job.target_id,
                        host=port_item["host"],
                        ip=port_item.get("ip"),
                        port_number=port_item["port"],
                        protocol=port_item.get("protocol", "tcp"),
                        state="open",
                        scan_id=scan_job.id,
                    )
                    db.add(port)

        # Aggregate results
        output = ScanOutput(
            success=True,
            items=all_ports,
            metadata={"open_ports_found": len(all_ports)},
            duration_seconds=sum(o.duration_seconds for o in [output]),
        )

        stage.status = "completed"
        stage.completed_at = datetime.now(timezone.utc)
        stage.duration_seconds = output.duration_seconds
        stage.item_count = len(all_ports)
        stage.output_summary = output.metadata
        await db.commit()

        return output

    async def _run_nuclei_stage(
        self,
        db: AsyncSession,
        scan_job: ScanJob,
        targets: list[str],
        config: ScanPipelineConfig,
    ) -> ScanOutput:
        """Stage 4: nuclei vulnerability scanning."""
        logger.info("stage_nuclei_start", target_count=len(targets))

        stage = ScanResult(
            scan_job_id=scan_job.id,
            stage="vuln_scan",
            status="running",
            tool_name="nuclei",
            started_at=datetime.now(timezone.utc),
        )
        db.add(stage)
        await db.commit()

        scanner = NucleiScanner(
            binary_path=self.settings.nuclei_path,
            config=ScanConfig(
                timeout=config.timeout,
                output_dir=self.settings.scan_results_dir,
            ),
            templates_path=self.settings.nuclei_templates_path or None,
            severity_filter=self.settings.nuclei_severity_filter,
            rate_limit=config.nuclei_rate_limit,
            concurrency=config.nuclei_concurrency,
        )

        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, dir="/tmp"
        ) as f:
            for t in targets:
                f.write(t + "\n")
            input_file = f.name

        try:
            output = await scanner.run(
                target="",
                input_file=input_file,
                severities=config.nuclei_severities,
                rate_limit=config.nuclei_rate_limit,
                concurrency=config.nuclei_concurrency,
            )

            # Persist findings and vulnerabilities
            if output.success and output.items:
                for item in output.items:
                    # Normalize to finding
                    finding = self.normalizer.normalize_nuclei(item, scan_job)
                    db.add(finding)

                    # Also store as structured vulnerability
                    vuln = Vulnerability(
                        target_id=scan_job.target_id,
                        template_id=item.get("template_id", ""),
                        template_name=item.get("template_name", ""),
                        severity=item.get("severity", "unknown"),
                        host=item.get("host", ""),
                        matched_url=item.get("matched_url"),
                        matched_at=item.get("matched_at"),
                        extracted_results=item.get("extracted_results"),
                        cve_ids=item.get("cve_ids"),
                        cwe_ids=item.get("cwe_ids"),
                        cvss_metrics={"score": item.get("cvss_score")},
                        curl_command=item.get("curl_command"),
                        request=item.get("request"),
                        response=item.get("response"),
                        info={
                            "type": item.get("type"),
                            "description": item.get("description"),
                            "reference": item.get("reference"),
                            "tags": item.get("tags"),
                        },
                    )
                    db.add(vuln)

            stage.status = "completed"
            stage.completed_at = datetime.now(timezone.utc)
            stage.duration_seconds = output.duration_seconds
            stage.item_count = len(output.items) if output.items else 0
            stage.output_summary = output.metadata

        finally:
            import os
            try:
                os.unlink(input_file)
            except OSError:
                pass

        await db.commit()
        return output

    async def _get_subdomains(self, db: AsyncSession, target_id: uuid.UUID) -> list[str]:
        """Get all subdomains for a target."""
        stmt = select(Subdomain.domain).where(Subdomain.target_id == target_id)
        result = await db.execute(stmt)
        return [row[0] for row in result.all()]

    async def _get_live_hosts(
        self, db: AsyncSession, target_id: uuid.UUID
    ) -> list[dict[str, str]]:
        """Get all live hosts for a target."""
        stmt = select(LiveHost.hostname, LiveHost.url).where(
            LiveHost.target_id == target_id,
            LiveHost.status_code.isnot(None),
        )
        result = await db.execute(stmt)
        return [{"host": row[0], "url": row[1]} for row in result.all()]

    async def _get_nuclei_targets(
        self, db: AsyncSession, target_id: uuid.UUID
    ) -> list[str]:
        """Get URLs for nuclei scanning (live HTTP hosts)."""
        stmt = select(LiveHost.url).where(
            LiveHost.target_id == target_id,
            LiveHost.status_code.isnot(None),
        )
        result = await db.execute(stmt)
        urls = [row[0] for row in result.all()]

        # Also include subdomains without explicit live host detection
        stmt2 = select(Subdomain.domain).where(Subdomain.target_id == target_id)
        result2 = await db.execute(stmt2)
        domains = [row[0] for row in result2.all()]

        # Combine and deduplicate
        all_targets = set()
        for u in urls:
            all_targets.add(u)
        for d in domains:
            all_targets.add(f"https://{d}")
            all_targets.add(f"http://{d}")

        return list(all_targets)
