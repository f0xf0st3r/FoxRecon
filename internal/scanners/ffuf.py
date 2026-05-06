"""ffuf adapter for content/discovery enumeration."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from internal.scanners.base import BaseScanner, ScanConfig, ScanOutput
from internal.utils.logging import get_logger
from internal.utils.subprocess import SecureProcess, ExecutionPolicy

logger = get_logger(module="ffuf")


class FfufScanner(BaseScanner):
    """Adapter for ffuf - Fast web fuzzer.

    Discovers hidden directories, files, and parameters.
    Supports wordlists, multiple methods, and recursive scanning.
    """

    tool_name = "ffuf"

    def __init__(
        self,
        binary_path: str = "ffuf",
        config: ScanConfig | None = None,
        default_wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ) -> None:
        super().__init__(binary_path, config)
        self.default_wordlist = default_wordlist

    async def run(
        self,
        target: str,
        wordlist: str | None = None,
        extensions: str | None = None,
        methods: str = "GET",
        threads: int = 50,
        rate: int = 0,
        follow_redirects: bool = True,
        max_time: int = 0,
        recursion: bool = False,
        recursion_depth: int = 4,
        match_status: str | None = None,
        filter_status: str | None = None,
        filter_size: str | None = None,
        filter_words: int = 0,
        **kwargs: Any,
    ) -> ScanOutput:
        """Run ffuf against a target URL.

        Args:
            target: Base URL with FUZZ keyword (e.g., https://example.com/FUZZ)
            wordlist: Path to wordlist file
            extensions: Comma-separated extensions to append
            methods: HTTP methods (GET,POST,PUT,etc.)
            threads: Number of concurrent threads
            rate: Requests per second limit
            follow_redirects: Follow 3xx responses
            max_time: Maximum execution time in seconds
            recursion: Enable recursive scanning
            recursion_depth: Max recursion depth
            match_status: Match only these status codes
            filter_status: Filter out these status codes
            filter_size: Filter out these response sizes
            filter_words: Filter out responses with this word count
        """
        if "FUZZ" not in target:
            target = target.rstrip("/") + "/FUZZ"

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, dir="/tmp"
        ) as tf:
            output_file = tf.name

        try:
            args = [
                "-u", target,
                "-w", wordlist or self.default_wordlist,
                "-o", output_file,
                "-of", "json",
                "-s",  # Silent mode
            ]

            args.extend(["-mc", match_status or "200,204,301,302,307,401,403,405,500"])

            if extensions:
                args.extend(["-e", extensions])
            if methods != "GET":
                args.extend(["-X", methods])
            if threads > 0:
                args.extend(["-t", str(threads)])
            if rate > 0:
                args.extend(["-rate", str(rate)])
            if follow_redirects:
                args.append("-fr")
            else:
                args.append("-fc")
                args.append("301,302")
            if max_time > 0:
                args.extend(["-maxtime", str(max_time)])
            if recursion:
                args.append("-recursion")
                args.extend(["-recursion-depth", str(recursion_depth)])
            if filter_status:
                args.extend(["-fc", filter_status])
            if filter_size:
                args.extend(["-fs", filter_size])
            if filter_words > 0:
                args.extend(["-fw", str(filter_words)])

            policy = ExecutionPolicy(
                timeout=self.config.timeout,
                max_output_size=50 * 1024 * 1024,
            )
            proc = SecureProcess(policy=policy)
            result = await proc.execute(self.binary_path, args)

            items = self._parse_output_file(output_file)

            if not items and result.stdout:
                items = self.parse_output(result.stdout)

            return ScanOutput(
                success=True,
                items=items,
                metadata={
                    "target": target,
                    "wordlist": wordlist or self.default_wordlist,
                    "paths_found": len(items),
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
        """Parse ffuf JSON output into normalized records."""
        items = []
        try:
            data = json.loads(raw)
            for result in data.get("results", []):
                items.append({
                    "url": result.get("url", ""),
                    "path": result.get("input", {}).get("FUZZ", ""),
                    "status": result.get("status", 0),
                    "length": result.get("length", 0),
                    "words": result.get("words", 0),
                    "lines": result.get("lines", 0),
                    "content_type": result.get("content_type", ""),
                    "redirect_location": result.get("redirectlocation", ""),
                })
        except json.JSONDecodeError:
            # Try line-by-line JSON
            for line in raw.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    items.append({
                        "url": record.get("url", ""),
                        "path": record.get("input", {}).get("FUZZ", ""),
                        "status": record.get("status", 0),
                        "length": record.get("length", 0),
                        "words": record.get("words", 0),
                        "lines": record.get("lines", 0),
                        "content_type": record.get("content_type", ""),
                    })
                except json.JSONDecodeError:
                    pass

        return items

    def _parse_output_file(self, filepath: str) -> list[dict[str, Any]]:
        try:
            content = Path(filepath).read_text(encoding="utf-8", errors="replace")
            return self.parse_output(content)
        except OSError:
            return []
