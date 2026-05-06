"""httpx adapter for live host detection and HTTP fingerprinting."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from internal.scanners.base import BaseScanner, ScanConfig, ScanOutput
from internal.utils.logging import get_logger
from internal.utils.subprocess import SecureProcess, ExecutionPolicy

logger = get_logger(module="httpx")


class HttpxScanner(BaseScanner):
    """Adapter for ProjectDiscovery's httpx tool.

    Detects live HTTP/HTTPS services, collects titles, status codes,
    technologies, and response metadata.
    """

    tool_name = "httpx"

    def __init__(self, binary_path: str = "httpx", config: ScanConfig | None = None) -> None:
        super().__init__(binary_path, config)

    async def run(
        self,
        target: str,
        input_file: str | None = None,
        ports: list[int] | None = None,
        tech_detect: bool = True,
        title: bool = True,
        status_code: bool = True,
        content_length: bool = True,
        response_time: bool = True,
        follow_redirects: bool = True,
        **kwargs: Any,
    ) -> ScanOutput:
        """Run httpx against targets.

        Args:
            target: Single target or domain
            input_file: File containing list of targets (one per line)
            ports: Specific ports to probe
            tech_detect: Enable technology detection
            title: Extract page titles
            status_code: Collect HTTP status codes
            content_length: Collect content lengths
            response_time: Collect response times
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, dir=self.config.output_dir or "/tmp"
        ) as tf:
            output_file = tf.name

        try:
            args = ["-json", "-o", output_file, "-silent"]

            if tech_detect:
                args.append("-tech-detect")
            if title:
                args.append("-title")
            if status_code:
                args.append("-status-code")
            if content_length:
                args.append("-content-length")
            if response_time:
                args.append("-response-time")
            if follow_redirects:
                args.append("-follow-redirects")

            if ports:
                port_str = ",".join(str(p) for p in ports)
                args.extend(["-ports", port_str])

            if self.config.timeout > 0:
                args.extend(["-timeout", str(self.config.timeout)])

            if self.config.rate_limit > 0:
                args.extend(["-rate-limit", str(self.config.rate_limit)])

            if self.config.threads > 0:
                args.extend(["-threads", str(self.config.threads)])

            # Input source
            if input_file:
                args.extend(["-l", input_file])
            else:
                # Pass target via stdin
                pass

            policy = ExecutionPolicy(
                timeout=self.config.timeout,
                max_output_size=50 * 1024 * 1024,
            )
            proc = SecureProcess(policy=policy)

            if not input_file:
                result = await proc.execute(
                    self.binary_path, args, input_data=target
                )
            else:
                result = await proc.execute(self.binary_path, args)

            if result.returncode != 0 and not Path(output_file).exists():
                return ScanOutput(
                    success=False,
                    errors=[result.stderr or f"httpx exited with code {result.returncode}"],
                    raw_output=result.stdout + "\n" + result.stderr,
                    duration_seconds=result.duration_seconds,
                )

            items = self._parse_output_file(output_file)

            if not items and result.stdout:
                items = self.parse_output(result.stdout)

            return ScanOutput(
                success=True,
                items=items,
                metadata={
                    "total_targets": len(items),
                    "live_hosts": sum(1 for i in items if i.get("status_code")),
                    "tool_version": await self.get_version(),
                },
                raw_output=result.stdout,
                duration_seconds=result.duration_seconds,
            )

        finally:
            try:
                Path(output_file).unlink(missing_ok=True)
            except OSError:
                pass

    def parse_output(self, raw: str) -> list[dict[str, Any]]:
        """Parse httpx JSON lines output into normalized records."""
        items = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                items.append({
                    "url": record.get("url", ""),
                    "host": record.get("host", record.get("input", "")),
                    "ip": record.get("a", [""])[0] if record.get("a") else None,
                    "port": record.get("port", 443),
                    "scheme": record.get("scheme", "https"),
                    "status_code": record.get("status_code"),
                    "title": record.get("title", ""),
                    "content_type": record.get("content_type", ""),
                    "content_length": record.get("content_length"),
                    "response_time_ms": record.get("response_time"),
                    "tech": record.get("tech", []),
                    "webserver": record.get("webserver", ""),
                    "hash": record.get("body_sha256", record.get("hash", "")),
                    "headers": dict(record.get("header", {})),
                })
            except json.JSONDecodeError:
                # Plain URL output
                if line.startswith(("http://", "https://")):
                    items.append({"url": line, "host": line})

        return items

    def _parse_output_file(self, filepath: str) -> list[dict[str, Any]]:
        try:
            content = Path(filepath).read_text(encoding="utf-8", errors="replace")
            return self.parse_output(content)
        except OSError:
            return []
