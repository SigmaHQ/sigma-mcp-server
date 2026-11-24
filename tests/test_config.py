"""Tests for sigma.mcp.config."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from sigma.mcp import config


class TestDataDir:
    def test_env_var_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SIGMA_MCP_DATA_DIR", "~/sigma-data")
        assert config.data_dir() == Path.home() / "sigma-data"

    def test_linux_uses_xdg_cache_home(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SIGMA_MCP_DATA_DIR")
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setenv("XDG_CACHE_HOME", "/xdg")
        assert config.data_dir() == Path("/xdg/sigma-mcp-server")

    def test_linux_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SIGMA_MCP_DATA_DIR")
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
        assert config.data_dir() == Path.home() / ".cache" / "sigma-mcp-server"

    def test_macos(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SIGMA_MCP_DATA_DIR")
        monkeypatch.setattr("sys.platform", "darwin")
        expected = Path.home() / "Library" / "Caches" / "sigma-mcp-server"
        assert config.data_dir() == expected

    def test_windows_local_app_data(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SIGMA_MCP_DATA_DIR")
        monkeypatch.setattr("sys.platform", "win32")
        monkeypatch.setenv("LOCALAPPDATA", "/lad")
        assert config.data_dir() == Path("/lad/sigma-mcp-server")

    def test_windows_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SIGMA_MCP_DATA_DIR")
        monkeypatch.setattr("sys.platform", "win32")
        monkeypatch.delenv("LOCALAPPDATA", raising=False)
        expected = Path.home() / "AppData" / "Local" / "sigma-mcp-server"
        assert config.data_dir() == expected


class TestWarmup:
    @pytest.mark.parametrize("value", ["1", "true", "YES", " on "])
    def test_disabled(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        monkeypatch.setenv("SIGMA_MCP_NO_WARMUP", value)
        assert config.warmup_enabled() is False

    @pytest.mark.parametrize("value", ["", "0", "false"])
    def test_enabled(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        monkeypatch.setenv("SIGMA_MCP_NO_WARMUP", value)
        assert config.warmup_enabled() is True

    def test_enabled_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SIGMA_MCP_NO_WARMUP")
        assert config.warmup_enabled() is True


class TestIndexMaxAge:
    def test_default(self) -> None:
        assert config.index_max_age() == timedelta(days=7)

    def test_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SIGMA_MCP_INDEX_MAX_AGE_DAYS", "1.5")
        assert config.index_max_age() == timedelta(days=1.5)

    @pytest.mark.parametrize("value", ["0", "-3"])
    def test_disabled(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        monkeypatch.setenv("SIGMA_MCP_INDEX_MAX_AGE_DAYS", value)
        assert config.index_max_age() is None

    def test_invalid_falls_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SIGMA_MCP_INDEX_MAX_AGE_DAYS", "weekly")
        assert config.index_max_age() == timedelta(days=7)


class TestToolTimeLimit:
    def test_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SIGMA_MCP_TOOL_TIME_LIMIT", raising=False)
        assert config.tool_time_limit() == 20.0

    @pytest.mark.parametrize(
        ("value", "expected"), [("5", 5.0), ("0", None), ("x", 20.0)]
    )
    def test_configured(
        self, monkeypatch: pytest.MonkeyPatch, value: str, expected: float | None
    ) -> None:
        monkeypatch.setenv("SIGMA_MCP_TOOL_TIME_LIMIT", value)
        assert config.tool_time_limit() == expected
