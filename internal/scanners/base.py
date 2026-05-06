"""Base scanner interface for all reconnaissance tools.

Defines the contract that all tool adapters must implement.
Follows the Strategy pattern for tool interchangeability.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanConfig:
    """Configuration for a scan execution."""

    timeout: int = 300
    rate_limit: int = 0  # 0 = no limit
    threads: int = 10
    proxy: str | None = None
    extra_args: list[str] = field(default_factory=list)
    wordlist: str | None = None
    output_dir: str | None = None


@dataclass
class ScanOutput:
    """Normalized output from any scanner."""

    success: bool
    items: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    raw_output: str | None = None
    duration_seconds: float = 0.0


class BaseScanner(ABC):
    """Abstract base class for all scanner adapters.

    Each scanner tool (subfinder, httpx, naabu, nuclei) must implement
    this interface. This allows:
    - Swapping tools without changing pipeline logic
    - Consistent output normalization
    - Unified error handling
    - Test mocking
    """

    tool_name: str = "base"
    tool_version: str = "unknown"

    def __init__(self, binary_path: str, config: ScanConfig | None = None) -> None:
        self.binary_path = binary_path
        self.config = config or ScanConfig()
        self._version: str | None = None

    @abstractmethod
    async def run(self, target: str, **kwargs: Any) -> ScanOutput:
        """Execute the scanner against a target.

        Args:
            target: The scan target (domain, URL, IP, etc.)
            **kwargs: Tool-specific parameters

        Returns:
            Normalized ScanOutput with structured results
        """
        ...

    @abstractmethod
    def parse_output(self, raw: str) -> list[dict[str, Any]]:
        """Parse raw tool output into normalized dictionaries."""
        ...

    async def get_version(self) -> str:
        """Get the tool version string."""
        if self._version:
            return self._version

        from internal.utils.subprocess import SecureProcess, ExecutionPolicy, SecurityError

        policy = ExecutionPolicy(timeout=10)
        proc = SecureProcess(policy=policy)

        try:
            result = await proc.execute(self.binary_path, ["-version"])
            self._version = (result.stdout or result.stderr or "unknown").strip().split("\n")[0]
        except SecurityError:
            self._version = "unknown"

        return self._version

    def _build_args(self, base_args: list[str], **kwargs: Any) -> list[str]:
        """Build argument list from config and kwargs."""
        args = list(base_args)
        args.extend(self.config.extra_args)

        if self.config.timeout > 0:
            args.extend(["-timeout", str(self.config.timeout)])

        if self.config.rate_limit > 0:
            args.extend(["-rate-limit", str(self.config.rate_limit)])

        if self.config.threads > 0 and self._supports_threads():
            args.extend(["-threads", str(self.config.threads)])

        if self.config.proxy:
            args.extend(["-proxy", self.config.proxy])

        return args

    def _supports_threads(self) -> bool:
        """Whether this tool supports -threads flag."""
        return True
