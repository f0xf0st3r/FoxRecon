"""Naabu adapter for fast port scanning."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from internal.scanners.base import BaseScanner, ScanConfig, ScanOutput
from internal.utils.logging import get_logger
from internal.utils.subprocess import SecureProcess, ExecutionPolicy

logger = get_logger(module="naabu")


class NaabuScanner(BaseScanner):
    """Adapter for ProjectDiscovery's naabu port scanner.

    Fast SYN/CONNECT port scanner with service detection.
    """

    tool_name = "naabu"

    def __init__(self, binary_path: str = "naabu", config: ScanConfig | None = None) -> None:
        super().__init__(binary_path, config)

    async def run(
        self,
        target: str,
        top_ports: int = 100,
        ports: str | None = None,
        rate: int = 0,
        syn_scan: bool = True,
        **kwargs: Any,
    ) -> ScanOutput:
        """Run naabu against a target.

        Args:
            target: Host, domain, or CIDR to scan
            top_ports: Number of top ports to scan (1-1000)
            ports: Specific port range (e.g., "80,443,8080" or "1-1000")
            rate: Packets per second rate limit
            syn_scan: Use SYN scan (requires root)
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, dir=self.config.output_dir or "/tmp"
        ) as tf:
            output_file = tf.name

        try:
            args = ["-host", target, "-json", "-o", output_file, "-silent"]

            if ports:
                args.extend(["-port", ports])
            else:
                args.extend(["-top-ports", str(top_ports)])

            if rate > 0:
                args.extend(["-rate", str(rate)])

            if syn_scan:
                args.append("-s")  # SYN scan
            else:
                args.append("-c")  # Connect scan

            if self.config.timeout > 0:
                args.extend(["-timeout", str(self.config.timeout)])

            if self.config.threads > 0:
                args.extend(["-c", str(self.config.threads)])

            policy = ExecutionPolicy(
                timeout=self.config.timeout,
                max_output_size=50 * 1024 * 1024,
            )
            proc = SecureProcess(policy=policy)
            result = await proc.execute(self.binary_path, args)

            # naabu may return non-zero even with results
            items = self._parse_output_file(output_file)

            if not items and result.stdout:
                items = self.parse_output(result.stdout)

            return ScanOutput(
                success=True,
                items=items,
                metadata={
                    "target": target,
                    "ports_scanned": ports or f"top-{top_ports}",
                    "open_ports_found": len(items),
                    "scan_type": "syn" if syn_scan else "connect",
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
        """Parse naabu JSON output into normalized port records."""
        items = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                host = record.get("host", record.get("ip", ""))
                items.append({
                    "host": host,
                    "ip": record.get("ip", host),
                    "port": record.get("port", 0),
                    "protocol": record.get("protocol", "tcp"),
                    "tls": record.get("tls", False),
                })
            except json.JSONDecodeError:
                # Format: host:port
                if ":" in line:
                    parts = line.rsplit(":", 1)
                    if len(parts) == 2 and parts[1].isdigit():
                        items.append({
                            "host": parts[0],
                            "ip": parts[0],
                            "port": int(parts[1]),
                            "protocol": "tcp",
                            "tls": False,
                        })

        # Deduplicate
        seen = set()
        unique = []
        for item in items:
            key = (item["host"], item["port"], item["protocol"])
            if key not in seen:
                seen.add(key)
                unique.append(item)

        return unique

    def _parse_output_file(self, filepath: str) -> list[dict[str, Any]]:
        try:
            content = Path(filepath).read_text(encoding="utf-8", errors="replace")
            return self.parse_output(content)
        except OSError:
            return []
