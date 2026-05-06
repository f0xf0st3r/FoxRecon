"""Unit tests for secure subprocess wrapper."""

import pytest

from internal.utils.subprocess import SecureProcess, ExecutionPolicy, SecurityError, ProcessResult


class TestSecureProcess:
    @pytest.fixture
    def secure_proc(self):
        return SecureProcess(
            policy=ExecutionPolicy(
                timeout=10,
                allowed_binaries={"echo", "true", "cat", "ls"},
            )
        )

    @pytest.mark.asyncio
    async def test_safe_execution(self, secure_proc):
        result = await secure_proc.execute("echo", ["hello"])
        assert result.returncode == 0
        assert "hello" in result.stdout

    @pytest.mark.asyncio
    async def test_binary_not_allowed(self, secure_proc):
        with pytest.raises(SecurityError, match="not in allowed list"):
            await secure_proc.execute("rm", ["-rf", "/"])

    @pytest.mark.asyncio
    async def test_binary_not_found(self, secure_proc):
        with pytest.raises(SecurityError, match="not in allowed list"):
            await secure_proc.execute("/nonexistent/binary")

    def test_injection_in_arg(self, secure_proc):
        with pytest.raises(SecurityError, match="Dangerous characters"):
            secure_proc._validate_arg("test;rm -rf /")

    def test_injection_backtick(self, secure_proc):
        with pytest.raises(SecurityError):
            secure_proc._validate_arg("test`id`")

    def test_injection_dollar(self, secure_proc):
        with pytest.raises(SecurityError):
            secure_proc._validate_arg("$(cat /etc/passwd)")


class TestProcessResult:
    def test_success_property(self):
        result = ProcessResult(
            returncode=0,
            stdout="hello",
            stderr="",
            command=["echo", "hello"],
            duration_seconds=0.1,
        )
        assert result.success is True

    def test_failure_property(self):
        result = ProcessResult(
            returncode=1,
            stdout="",
            stderr="error",
            command=["false"],
            duration_seconds=0.1,
        )
        assert result.success is False

    def test_killed_not_success(self):
        result = ProcessResult(
            returncode=-9,
            stdout="",
            stderr="",
            command=["sleep", "100"],
            duration_seconds=10.0,
            killed=True,
        )
        assert result.success is False

    def test_result_fields(self):
        result = ProcessResult(
            returncode=0,
            stdout="hello",
            stderr="",
            command=["echo", "hello"],
            duration_seconds=0.1,
        )
        assert result.returncode == 0
        assert result.stdout == "hello"
        assert result.duration_seconds == 0.1


class TestTruncatedOutput:
    def test_small_output_unchanged(self):
        proc = SecureProcess(
            policy=ExecutionPolicy(max_output_size=1000)
        )
        small = "hello world"
        result = proc._truncate_output(small)
        assert result == "hello world"

    def test_large_output_truncated(self):
        proc = SecureProcess(
            policy=ExecutionPolicy(max_output_size=10)
        )
        large = "a" * 1000
        truncated = proc._truncate_output(large)
        assert "TRUNCATED" in truncated
        assert len(truncated.encode()) > 10  # Truncation message adds bytes


class TestExecutionPolicy:
    def test_default_policy(self):
        policy = ExecutionPolicy()
        assert policy.timeout == 300
        assert policy.max_output_size == 10 * 1024 * 1024
        assert policy.allowed_binaries is None
