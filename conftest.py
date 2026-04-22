"""Pytest configuration for sigma-mcp-server tests."""

import pytest


@pytest.fixture
def anyio_backend() -> str:
    """Run async tests with asyncio."""
    return "asyncio"
