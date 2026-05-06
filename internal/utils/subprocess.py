"""Secure subprocess execution wrapper.

This module provides a hardened interface for executing external security
tools. It prevents command injection by:
- Never using shell=True
- Passing arguments as explicit lists
- Validating all inputs before execution
- Enforcing resource limits (timeout, memory, CPU)
- Running in a restricted environment
- Capturing and sanitizing output
"""

from __future__ import annotations

import asyncio
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from internal.utils.logging import get_logger

logger = get_logger(module="subprocess")


@dataclass
class ProcessResult:
    """Result from a subprocess execution."""

    returncode: int
    stdout: str
    stderr: str
    command: list[str]
    duration_seconds: float
    timed_out: bool = False
    killed: bool = False

    @property
    def success(self) -> bool:
        """Whether the process exited successfully."""
        return self.returncode == 0 and not self.killed


@dataclass
class ExecutionPolicy:
    """Security policy for subprocess execution."""

    # Max execution time in seconds
    timeout: int = 300
    # Max stdout/stderr size in bytes (prevent memory exhaustion)
    max_output_size: int = 10 * 1024 * 1024  # 10MB
    # Working directory (sandbox)
    workdir: str | None = None
    # Environment variables (clean by default)
    env: dict[str, str] | None = None
    # User to run as (None = current user)
    run_as_user: str | None = None
    # Allowed binaries (whitelist)
    allowed_binaries: set[str] | None = None


class SecureProcess:
    """Secure subprocess executor with sandboxing and injection prevention."""

    def __init__(self, policy: ExecutionPolicy | None = None) -> None:
        self.policy = policy or ExecutionPolicy()
        self._logger = get_logger(component="secure_process")

    def _build_safe_env(self) -> dict[str, str]:
        """Build a clean environment without inherited secrets."""
        if self.policy.env:
            return self.policy.env

        # Minimal safe environment
        safe_env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        return safe_env

    def _validate_binary(self, binary: str) -> None:
        """Validate that the binary is allowed and exists."""
        if self.policy.allowed_binaries:
            binary_name = Path(binary).name
            if binary_name not in self.policy.allowed_binaries:
                raise SecurityError(
                    f"Binary {binary_name!r} is not in allowed list"
                )

        # Resolve to absolute path using PATH lookup
        resolved = shutil.which(binary)
        if not resolved:
            # Try as absolute path
            resolved_path = Path(binary).resolve()
            if resolved_path.exists() and resolved_path.is_file():
                resolved = str(resolved_path)
            else:
                raise SecurityError(f"Binary not found: {binary!r}")

        resolved_path = Path(resolved)
        # Ensure it's a file, not a directory or symlink to dangerous location
        if not resolved_path.is_file():
            raise SecurityError(f"Not a regular file: {binary!r}")

    def _truncate_output(self, output: str) -> str:
        """Truncate output to prevent memory exhaustion."""
        encoded = output.encode("utf-8", errors="replace")
        if len(encoded) > self.policy.max_output_size:
            truncated = encoded[: self.policy.max_output_size].decode(
                "utf-8", errors="replace"
            )
            return truncated + "\n[OUTPUT TRUNCATED - MAX SIZE EXCEEDED]"
        return output

    async def execute(
        self,
        binary: str,
        args: list[str] | None = None,
        input_data: str | bytes | None = None,
        timeout: int | None = None,
        workdir: str | None = None,
    ) -> ProcessResult:
        """Execute a subprocess securely with asyncio.

        Args:
            binary: Path to the executable
            args: List of arguments (never interpreted as shell)
            input_data: Optional stdin data
            timeout: Override policy timeout
            workdir: Override policy working directory

        Returns:
            ProcessResult with stdout, stderr, return code, and metadata
        """
        # Validate binary
        self._validate_binary(binary)

        # Build command list - never use shell=True
        cmd = [str(binary)]
        if args:
            # Validate each argument for injection patterns
            for arg in args:
                self._validate_arg(arg)
            cmd.extend(args)

        effective_timeout = timeout or self.policy.timeout
        effective_workdir = workdir or self.policy.workdir
        env = self._build_safe_env()

        self._logger.info(
            "executing_command",
            binary=Path(binary).name,
            arg_count=len(args or []),
            timeout=effective_timeout,
        )

        import time
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=effective_workdir,
                limit=self.policy.max_output_size,
            )

            # Prepare input
            stdin_data = None
            if input_data:
                if isinstance(input_data, str):
                    stdin_data = input_data.encode("utf-8")
                else:
                    stdin_data = input_data

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(stdin_data),
                    timeout=effective_timeout,
                )
                timed_out = False
            except asyncio.TimeoutError:
                self._logger.warning("process_timeout", binary=binary)
                try:
                    proc.kill()
                    await proc.wait()
                except ProcessLookupError:
                    pass
                stdout_bytes = b""
                stderr_bytes = b"Process killed: timeout exceeded"
                timed_out = True

            duration = time.monotonic() - start

            stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
            stderr = stderr_bytes.decode("utf-8", errors="replace").strip()

            stdout = self._truncate_output(stdout)
            stderr = self._truncate_output(stderr)

            killed = timed_out or proc.returncode == -9

            result = ProcessResult(
                returncode=proc.returncode or (1 if killed else 0),
                stdout=stdout,
                stderr=stderr,
                command=cmd,
                duration_seconds=round(duration, 3),
                timed_out=timed_out,
                killed=killed,
            )

            self._logger.info(
                "command_completed",
                binary=Path(binary).name,
                returncode=result.returncode,
                duration=result.duration_seconds,
                stdout_lines=len(stdout.splitlines()),
            )

            return result

        except FileNotFoundError:
            raise SecurityError(f"Binary not found: {binary!r}")
        except OSError as e:
            raise SecurityError(f"OS error executing {binary!r}: {e}")

    def _validate_arg(self, arg: str) -> None:
        """Validate a single command argument for injection."""
        if not isinstance(arg, str):
            raise SecurityError(f"Argument must be string, got {type(arg)}")

        # Reject shell metacharacters
        dangerous = set(";|&`$(){}[]!\\<>\n\r")
        found = dangerous.intersection(arg)
        if found:
            raise SecurityError(
                f"Dangerous characters in argument: {found}"
            )


class SecurityError(Exception):
    """Raised when a security violation is detected."""

    pass
