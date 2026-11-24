"""Pytest configuration for sigma-mcp-server tests."""

import pytest


@pytest.fixture
def anyio_backend() -> str:
    """Run async tests with asyncio."""
    return "asyncio"


@pytest.fixture(autouse=True)
def clear_session_cache() -> None:
    """Clear the session state variables before each test to ensure test isolation."""
    import sigma.mcp.tools.rules as rules_module

    rules_module._current_validator_names = None
    rules_module._current_exclusions = []

    yield

    # Clear again after test
    rules_module._current_validator_names = None
    rules_module._current_exclusions = []
