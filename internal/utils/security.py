"""Security utilities for input validation and sanitization."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# Strict domain regex - prevents command injection
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)

# CIDR regex for network ranges
_CIDR_RE = re.compile(
    r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/(?:[0-9]|[1-2][0-9]|3[0-2])$",
)

# IP address regex
_IP_RE = re.compile(
    r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
)


def validate_domain(domain: str) -> str:
    """Validate and sanitize a domain name.

    Raises ValueError if the domain is invalid or potentially malicious.
    """
    domain = domain.strip().lower()

    # Reject anything with shell metacharacters
    _check_injection(domain)

    # Reject excessively long domains (check before regex)
    if len(domain) > 253:
        raise ValueError("Domain exceeds maximum length of 253 characters")

    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"Invalid domain format: {domain!r}")

    return domain


def validate_ip(ip: str) -> str:
    """Validate an IP address."""
    ip = ip.strip()
    _check_injection(ip)

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip!r}")

    return ip


def validate_cidr(cidr: str) -> str:
    """Validate a CIDR notation network range."""
    cidr = cidr.strip()
    _check_injection(cidr)

    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        raise ValueError(f"Invalid CIDR notation: {cidr!r}")

    return cidr


def validate_target(target: str) -> tuple[str, str]:
    """Validate a scan target and return (type, value).

    Returns one of:
        ("domain", domain)
        ("ip", ip_address)
        ("cidr", cidr_range)
        ("url", url)
    """
    target = target.strip()
    _check_injection(target)

    # Try as URL first
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        if parsed.hostname:
            return ("url", target)
        raise ValueError(f"Invalid URL: {target!r}")

    # Try as CIDR
    if _CIDR_RE.match(target):
        return ("cidr", validate_cidr(target))

    # Try as IP
    if _IP_RE.match(target):
        return ("ip", validate_ip(target))

    # Try as domain
    return ("domain", validate_domain(target))


def _check_injection(value: str) -> None:
    """Check for command injection patterns."""
    dangerous_chars = set(";|&`$(){}[]!\\<>#'\"\\n\\r")
    found = dangerous_chars.intersection(value)
    if found:
        raise ValueError(
            f"Potentially dangerous characters detected: {found}"
        )

    # Check for common injection patterns
    injection_patterns = [
        r"\$\(.*\)",  # Command substitution
        r"`.*`",       # Backtick execution
        r"\|\|",        # Pipe chains
        r";\s*\w+",    # Command chaining
        r"\b(cat|rm|dd|mkfs|chmod|chown)\b",  # Dangerous commands
    ]
    for pattern in injection_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            raise ValueError(
                f"Potentially malicious pattern detected in input"
            )


def sanitize_filename(name: str) -> str:
    """Sanitize a filename for safe filesystem storage."""
    # Replace dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    # Truncate to reasonable length
    return sanitized[:200]
