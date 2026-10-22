"""Pytest configuration for sigma-mcp-server tests."""

import pytest


@pytest.fixture
def anyio_backend() -> str:
    """Run async tests with asyncio."""
    return "asyncio"


@pytest.fixture(autouse=True)
def clear_session_cache() -> None:
    """Clear the session state variables before each test to ensure test isolation."""
    import sigma.mcp.main as main_module

    main_module._current_validator_names = None
    main_module._current_exclusions = []

    yield

    # Clear again after test
    main_module._current_validator_names = None
    main_module._current_exclusions = []
