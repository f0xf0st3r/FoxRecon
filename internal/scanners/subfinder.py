"""Subfinder adapter for passive subdomain enumeration."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from internal.scanners.base import BaseScanner, ScanConfig, ScanOutput
from internal.utils.logging import get_logger
from internal.utils.subprocess import SecureProcess, ExecutionPolicy

logger = get_logger(module="subfinder")


class SubfinderScanner(BaseScanner):
    """Adapter for ProjectDiscovery's subfinder tool.

    Enumerates subdomains using passive OSINT sources.
    Output format: JSON lines (one domain per line)
    """

    tool_name = "subfinder"

    def __init__(self, binary_path: str = "subfinder", config: ScanConfig | None = None) -> None:
        super().__init__(binary_path, config)
        self._sources: list[str] = []

    async def run(
        self,
        target: str,
        sources: list[str] | None = None,
        recursive: bool = False,
        all_sources: bool = True,
        **kwargs: Any,
    ) -> ScanOutput:
        """Run subfinder against a domain.

        Args:
            target: Root domain to enumerate
            sources: Specific sources to use (optional)
            recursive: Enable recursive subdomain enumeration
            all_sources: Use all available sources
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, dir=self.config.output_dir or "/tmp"
        ) as tf:
            output_file = tf.name

        try:
            args = ["-d", target, "-json", "-o", output_file, "-silent"]

            if all_sources and not sources:
                args.append("-all")
            elif sources:
                args.extend(["-s", ",".join(sources)])

            if recursive:
                args.append("-recursive")

            if self.config.timeout > 0:
                args.extend(["-timeout", str(self.config.timeout)])

            policy = ExecutionPolicy(
                timeout=self.config.timeout,
                max_output_size=50 * 1024 * 1024,  # 50MB
            )
            proc = SecureProcess(policy=policy)
            result = await proc.execute(self.binary_path, args)

            if result.returncode != 0 and not Path(output_file).exists():
                return ScanOutput(
                    success=False,
                    errors=[result.stderr or f"subfinder exited with code {result.returncode}"],
                    raw_output=result.stdout + "\n" + result.stderr,
                    duration_seconds=result.duration_seconds,
                )

            # Parse JSON lines output
            items = self._parse_output_file(output_file)

            # If file is empty, try parsing stdout
            if not items and result.stdout:
                items = self.parse_output(result.stdout)

            return ScanOutput(
                success=True,
                items=items,
                metadata={
                    "domain": target,
                    "sources_used": sources or ["all"],
                    "total_found": len(items),
                    "tool_version": await self.get_version(),
                },
                raw_output=result.stdout,
                duration_seconds=result.duration_seconds,
            )

        finally:
            # Cleanup temp file
            try:
                Path(output_file).unlink(missing_ok=True)
            except OSError:
                pass

    def parse_output(self, raw: str) -> list[dict[str, Any]]:
        """Parse subfinder JSON lines output."""
        items = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                items.append({
                    "domain": record.get("host", ""),
                    "source": record.get("source", ""),
                    "resolved_ip": record.get("resolved", ""),
                })
            except json.JSONDecodeError:
                # Fallback: treat each line as a plain domain
                if line and "." in line:
                    items.append({"domain": line.strip(), "source": "unknown"})

        # Deduplicate
        seen = set()
        unique_items = []
        for item in items:
            domain = item.get("domain", "").lower().strip()
            if domain and domain not in seen:
                seen.add(domain)
                unique_items.append(item)

        return unique_items

    def _parse_output_file(self, filepath: str) -> list[dict[str, Any]]:
        """Parse output from a file."""
        try:
            content = Path(filepath).read_text(encoding="utf-8", errors="replace")
            return self.parse_output(content)
        except OSError:
            return []
