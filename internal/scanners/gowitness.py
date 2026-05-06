"""gowitness adapter for screenshot capture."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from internal.scanners.base import BaseScanner, ScanConfig, ScanOutput
from internal.utils.logging import get_logger
from internal.utils.subprocess import SecureProcess, ExecutionPolicy

logger = get_logger(module="gowitness")


class GowitnessScanner(BaseScanner):
    """Adapter for gowitness - web screenshot utility.

    Captures screenshots of web applications and collects metadata.
    """

    tool_name = "gowitness"

    def __init__(self, binary_path: str = "gowitness", config: ScanConfig | None = None) -> None:
        super().__init__(binary_path, config)

    async def run(
        self,
        target: str = "",
        input_file: str | None = None,
        screenshot_path: str | None = None,
        resolution_x: int = 1440,
        resolution_y: int = 900,
        threads: int = 8,
        timeout: int = 30,
        delay: int = 0,
        user_agent: str | None = None,
        **kwargs: Any,
    ) -> ScanOutput:
        """Run gowitness against targets.

        Args:
            target: Single target URL
            input_file: File with list of URLs
            screenshot_path: Directory to save screenshots
            resolution_x: Screenshot width
            resolution_y: Screenshot height
            threads: Number of concurrent goroutines
            timeout: Page load timeout per URL
            delay: Delay between screenshots
            user_agent: Custom user agent string
        """
        output_dir = screenshot_path or tempfile.mkdtemp(prefix="gowitness_")

        # Build SQLite database path
        db_path = str(Path(output_dir) / "gowitness.sqlite3")

        try:
            args = [
                "file",
                "-f", input_file or "/dev/stdin",
                "-s", output_dir,
                "-t", str(threads),
                "--resolution-x", str(resolution_x),
                "--resolution-y", str(resolution_y),
                "--timeout", str(timeout),
                "--db", db_path,
            ]

            if delay > 0:
                args.extend(["--delay", str(delay)])

            if user_agent:
                args.extend(["--user-agent", user_agent])

            policy = ExecutionPolicy(
                timeout=self.config.timeout,
                max_output_size=10 * 1024 * 1024,
            )
            proc = SecureProcess(policy=policy)

            if not input_file:
                result = await proc.execute(
                    self.binary_path, args, input_data=target
                )
            else:
                result = await proc.execute(self.binary_path, args)

            # Parse results from SQLite
            items = self._parse_sqlite_db(db_path)

            return ScanOutput(
                success=True,
                items=items,
                metadata={
                    "total_screenshots": len(items),
                    "output_dir": output_dir,
                    "db_path": db_path,
                    "tool_version": await self.get_version(),
                },
                raw_output=result.stdout,
                errors=[result.stderr] if result.stderr and result.returncode != 0 else [],
                duration_seconds=result.duration_seconds,
            )

        except Exception as e:
            logger.exception("gowitness_failed", error=str(e))
            return ScanOutput(
                success=False,
                errors=[str(e)],
                duration_seconds=0,
            )

    def parse_output(self, raw: str) -> list[dict[str, Any]]:
        """Parse gowitness output (handled via SQLite)."""
        return []

    def _parse_sqlite_db(self, db_path: str) -> list[dict[str, Any]]:
        """Extract results from gowitness SQLite database."""
        items = []
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Check if tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

            if "urls" in tables:
                cursor.execute("SELECT * FROM urls")
                for row in cursor.fetchall():
                    item = dict(row)
                    items.append({
                        "url": item.get("url", ""),
                        "final_url": item.get("final_url", item.get("url", "")),
                        "title": item.get("title", ""),
                        "status_code": item.get("code", item.get("status_code", 0)),
                        "content_length": item.get("content_length", 0),
                        "file_name": item.get("file", ""),
                        "proto": item.get("proto", ""),
                        "tls": item.get("tls", False),
                        "technologies": item.get("technologies", ""),
                        "perception_hash": item.get("perception_hash", ""),
                    })

            conn.close()
        except (sqlite3.Error, Exception) as e:
            logger.warning("failed_to_parse_sqlite", error=str(e))

        return items
