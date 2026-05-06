"""Pytest configuration."""

import pytest


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "slow: mark test as slow (integration)")
    config.addinivalue_line("markers", "requires_tools: mark test that requires external tools")
