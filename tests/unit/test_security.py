"""Unit tests for security utilities."""

import pytest

from internal.utils.security import (
    validate_domain,
    validate_ip,
    validate_cidr,
    validate_target,
    _check_injection,
    sanitize_filename,
)


class TestDomainValidation:
    def test_valid_domain(self):
        assert validate_domain("example.com") == "example.com"

    def test_valid_subdomain(self):
        assert validate_domain("api.example.com") == "api.example.com"

    def test_lowercase(self):
        assert validate_domain("Example.COM") == "example.com"

    def test_injection_semicolon(self):
        with pytest.raises(ValueError, match="dangerous characters"):
            validate_domain("example.com;ls")

    def test_injection_pipe(self):
        with pytest.raises(ValueError, match="dangerous characters"):
            validate_domain("example.com|cat /etc/passwd")

    def test_injection_backtick(self):
        with pytest.raises(ValueError, match="dangerous characters"):
            validate_domain("`id`")

    def test_injection_dollar(self):
        with pytest.raises(ValueError, match="dangerous characters"):
            validate_domain("$(whoami)")

    def test_too_long(self):
        with pytest.raises(ValueError, match="maximum length"):
            validate_domain("a" * 300 + ".com")

    def test_invalid_chars(self):
        with pytest.raises(ValueError):
            validate_domain("exam ple.com")


class TestIPValidation:
    def test_valid_ipv4(self):
        assert validate_ip("192.168.1.1") == "192.168.1.1"

    def test_valid_ipv6(self):
        assert validate_ip("::1") == "::1"

    def test_invalid_ip(self):
        with pytest.raises(ValueError):
            validate_ip("999.999.999.999")


class TestCIDRValidation:
    def test_valid_cidr(self):
        assert validate_cidr("192.168.1.0/24") == "192.168.1.0/24"

    def test_invalid_cidr(self):
        with pytest.raises(ValueError):
            validate_cidr("192.168.1.0/33")


class TestTargetValidation:
    def test_domain_target(self):
        t, v = validate_target("example.com")
        assert t == "domain"
        assert v == "example.com"

    def test_ip_target(self):
        t, v = validate_target("1.2.3.4")
        assert t == "ip"
        assert v == "1.2.3.4"

    def test_cidr_target(self):
        t, v = validate_target("10.0.0.0/8")
        assert t == "cidr"

    def test_url_target(self):
        t, v = validate_target("https://example.com")
        assert t == "url"


class TestFilenameSanitization:
    def test_safe_name(self):
        assert sanitize_filename("report.md") == "report.md"

    def test_dangerous_chars(self):
        result = sanitize_filename("report<>:/\\|?*.md")
        assert "<" not in result
        assert ">" not in result
        assert "/" not in result

    def test_truncation(self):
        long_name = "a" * 300 + ".md"
        result = sanitize_filename(long_name)
        assert len(result) <= 200
