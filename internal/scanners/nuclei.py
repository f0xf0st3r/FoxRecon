"""Nuclei adapter for template-based vulnerability scanning."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from internal.scanners.base import BaseScanner, ScanConfig, ScanOutput
from internal.utils.logging import get_logger
from internal.utils.subprocess import SecureProcess, ExecutionPolicy

logger = get_logger(module="nuclei")


class NucleiScanner(BaseScanner):
    """Adapter for ProjectDiscovery's nuclei vulnerability scanner.

    Template-based scanner for CVEs, misconfigurations, and exposures.
    """

    tool_name = "nuclei"

    SEVERITY_MAP = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
        "unknown": 0,
    }

    def __init__(
        self,
        binary_path: str = "nuclei",
        config: ScanConfig | None = None,
        templates_path: str | None = None,
        severity_filter: str = "low,medium,high,critical",
        rate_limit: int = 50,
        concurrency: int = 25,
    ) -> None:
        super().__init__(binary_path, config)
        self.templates_path = templates_path
        self.severity_filter = severity_filter
        self.rate_limit = rate_limit
        self.concurrency = concurrency

    async def run(
        self,
        target: str,
        input_file: str | None = None,
        templates: list[str] | None = None,
        severities: list[str] | None = None,
        exclude_severities: list[str] | None = None,
        tags: list[str] | None = None,
        exclude_tags: list[str] | None = None,
        rate_limit: int | None = None,
        concurrency: int | None = None,
        **kwargs: Any,
    ) -> ScanOutput:
        """Run nuclei against targets.

        Args:
            target: Single target URL/host
            input_file: File with list of targets
            templates: Specific template paths or IDs
            severities: Filter by severity levels
            exclude_severities: Exclude these severities
            tags: Filter by template tags
            exclude_tags: Exclude templates with these tags
            rate_limit: Requests per second
            concurrency: Number of concurrent templates
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, dir=self.config.output_dir or "/tmp"
        ) as tf:
            output_file = tf.name

        try:
            args = ["-jsonl", "-o", output_file, "-silent"]

            if input_file:
                args.extend(["-l", input_file])
            else:
                args.extend(["-u", target])

            if self.templates_path:
                args.extend(["-t", self.templates_path])
            elif templates:
                args.extend(["-t", ",".join(templates)])

            severity = severities or self.severity_filter.split(",")
            if severity:
                args.extend(["-s", ",".join(severity)])

            if exclude_severities:
                args.extend(["-exclude-severity", ",".join(exclude_severities)])

            if tags:
                args.extend(["-tags", ",".join(tags)])

            if exclude_tags:
                args.extend(["-exclude-tags", ",".join(exclude_tags)])

            rl = rate_limit or self.rate_limit
            if rl > 0:
                args.extend(["-rate-limit", str(rl)])

            conc = concurrency or self.concurrency
            if conc > 0:
                args.extend(["-c", str(conc)])

            if self.config.timeout > 0:
                args.extend(["-timeout", str(self.config.timeout)])

            if self.config.proxy:
                args.extend(["-proxy", self.config.proxy])

            policy = ExecutionPolicy(
                timeout=self.config.timeout,
                max_output_size=100 * 1024 * 1024,  # 100MB
            )
            proc = SecureProcess(policy=policy)
            result = await proc.execute(self.binary_path, args)

            items = self._parse_output_file(output_file)

            if not items and result.stdout:
                items = self.parse_output(result.stdout)

            # Count by severity
            severity_counts: dict[str, int] = {}
            for item in items:
                sev = item.get("severity", "unknown")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            return ScanOutput(
                success=True,
                items=items,
                metadata={
                    "total_findings": len(items),
                    "severity_counts": severity_counts,
                    "target": target,
                    "templates_path": self.templates_path or "default",
                    "tool_version": await self.get_version(),
                },
                raw_output=result.stdout,
                errors=[result.stderr] if result.stderr and result.returncode != 0 else [],
                duration_seconds=result.duration_seconds,
            )

        finally:
            try:
                Path(output_file).unlink(missing_ok=True)
            except OSError:
                pass

    def parse_output(self, raw: str) -> list[dict[str, Any]]:
        """Parse nuclei JSONL output into normalized vulnerability records."""
        items = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                info = record.get("info", {})
                items.append({
                    "template_id": record.get("template-id", record.get("templateID", "")),
                    "template_name": info.get("name", record.get("template-id", "")),
                    "template_path": record.get("template-path", ""),
                    "severity": info.get("severity", record.get("severity", "unknown")).lower(),
                    "host": record.get("host", ""),
                    "matched_at": record.get("matched-at", record.get("matchedAt", "")),
                    "matched_url": record.get("matched-at", record.get("matchedAt", "")),
                    "type": info.get("type", record.get("type", "")),
                    "description": info.get("description", ""),
                    "reference": info.get("reference", []),
                    "tags": info.get("tags", []),
                    "cve_ids": info.get("classification", {}).get("cve-id", []),
                    "cwe_ids": info.get("classification", {}).get("cwe-id", []),
                    "cvss_score": info.get("classification", {}).get("cvss-score"),
                    "curl_command": record.get("curl-command", ""),
                    "extracted_results": record.get("extracted-results", []),
                    "request": record.get("request", ""),
                    "response": record.get("response", ""),
                    "ip": record.get("ip", ""),
                    "timestamp": record.get("timestamp", ""),
                })
            except json.JSONDecodeError:
                logger.warning("failed_to_parse_nuclei_line", line=line[:100])

        # Sort by severity (critical first)
        items.sort(
            key=lambda x: self.SEVERITY_MAP.get(x.get("severity", "unknown"), 0),
            reverse=True,
        )

        return items

    def _parse_output_file(self, filepath: str) -> list[dict[str, Any]]:
        try:
            content = Path(filepath).read_text(encoding="utf-8", errors="replace")
            return self.parse_output(content)
        except OSError:
            return []
