"""Tests for running the server over HTTP and in public mode."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import anyio
import pytest
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.exceptions import ToolError
from starlette.testclient import TestClient

from sigma.mcp import config
from sigma.mcp.index_manager import index_manager
from sigma.mcp.main import main, mcp, parse_args, prepare
from sigma.mcp.public import (
    ConcurrencyLimitMiddleware,
    InputSizeMiddleware,
    apply_public_mode,
    client_id,
)
from sigma.mcp.repo import RepoSnapshot

RULE_NO_ID = """\
title: Test rule
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        Image|endswith: '\\\\cmd.exe'
    condition: sel
level: low
"""

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class TestConfig:
    def test_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in (
            config.ENV_TRANSPORT,
            config.ENV_HOST,
            config.ENV_PORT,
            "PORT",
            config.ENV_PUBLIC,
            config.ENV_MAX_INPUT_BYTES,
            config.ENV_RATE_LIMIT,
            config.ENV_MAX_CONCURRENT_TOOLS,
        ):
            monkeypatch.delenv(name, raising=False)
        assert config.transport() == "stdio"
        assert config.host() == "127.0.0.1"
        assert config.port() == 8000
        assert config.public_mode() is False
        assert config.max_input_bytes() == config.DEFAULT_MAX_INPUT_BYTES
        assert config.rate_limit() == config.DEFAULT_RATE_LIMIT
        assert config.max_concurrent_tools() == config.DEFAULT_MAX_CONCURRENT_TOOLS

    def test_values_from_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(config.ENV_TRANSPORT, "HTTP")
        monkeypatch.setenv(config.ENV_HOST, "0.0.0.0")
        monkeypatch.setenv(config.ENV_PORT, "9000")
        monkeypatch.setenv(config.ENV_PUBLIC, "yes")
        monkeypatch.setenv(config.ENV_MAX_INPUT_BYTES, "1000")
        monkeypatch.setenv(config.ENV_RATE_LIMIT, "0.5")
        monkeypatch.setenv(config.ENV_MAX_CONCURRENT_TOOLS, "0")
        assert config.transport() == "http"
        assert config.host() == "0.0.0.0"
        assert config.port() == 9000
        assert config.public_mode() is True
        assert config.max_input_bytes() == 1000
        assert config.rate_limit() == 0.5
        assert config.max_concurrent_tools() == 1

    def test_port_falls_back_to_platform_port(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(config.ENV_PORT, raising=False)
        monkeypatch.setenv("PORT", "7860")
        assert config.port() == 7860
        monkeypatch.setenv(config.ENV_PORT, "not-a-port")
        assert config.port() == 7860

    def test_invalid_values_fall_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(config.ENV_TRANSPORT, "carrier-pigeon")
        monkeypatch.setenv(config.ENV_RATE_LIMIT, "fast")
        monkeypatch.setenv(config.ENV_MAX_INPUT_BYTES, "-5")
        monkeypatch.setenv(config.ENV_PORT, "70000")
        monkeypatch.delenv("PORT", raising=False)
        assert config.transport() == "stdio"
        assert config.rate_limit() == config.DEFAULT_RATE_LIMIT
        assert config.max_input_bytes() == 0
        assert config.port() == 8000


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


class TestCommandLine:
    def test_parse_args_defaults_from_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(config.ENV_TRANSPORT, "http")
        monkeypatch.setenv(config.ENV_PUBLIC, "1")
        args = parse_args([])
        assert args.transport == "http"
        assert args.public is True
        assert args.prepare is False

    def test_main_runs_http(self) -> None:
        with (
            patch.object(mcp, "run") as mock_run,
            patch("sigma.mcp.main.apply_public_mode") as mock_public,
        ):
            main(["--transport", "http", "--host", "0.0.0.0", "--port", "9123"])
        mock_public.assert_not_called()
        kwargs = mock_run.call_args.kwargs
        assert kwargs["transport"] == "http"
        assert kwargs["host"] == "0.0.0.0"
        assert kwargs["port"] == 9123
        assert kwargs["uvicorn_config"]["proxy_headers"] is True

    def test_main_public_applies_hardening(self) -> None:
        with (
            patch.object(mcp, "run"),
            patch("sigma.mcp.main.apply_public_mode") as mock_public,
        ):
            main(["--public"])
        mock_public.assert_called_once_with(mcp)

    def test_main_prepare_exits(self) -> None:
        with (
            patch("sigma.mcp.main.prepare", return_value=0) as mock_prepare,
            patch.object(mcp, "run") as mock_run,
            pytest.raises(SystemExit) as exc_info,
        ):
            main(["--prepare"])
        assert exc_info.value.code == 0
        mock_prepare.assert_called_once()
        mock_run.assert_not_called()


def test_public_mode_from_environment_on_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``fastmcp run sigma/mcp/main.py:mcp`` must honour SIGMA_MCP_PUBLIC."""
    import importlib

    import sigma.mcp.main as main_module

    monkeypatch.setenv(config.ENV_PUBLIC, "1")
    with patch("sigma.mcp.public.apply_public_mode") as mock_public:
        importlib.reload(main_module)
    mock_public.assert_called_once_with(mcp)
    monkeypatch.delenv(config.ENV_PUBLIC)
    importlib.reload(main_module)


class TestPrepare:
    def test_builds_the_index(
        self,
        fake_downloader: Callable[[Path], RepoSnapshot],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        index_manager.downloader = fake_downloader
        assert prepare() == 0
        assert "Rule index ready" in capsys.readouterr().out
        assert index_manager.paths().index_file.exists()

    def test_reports_failure(self, capsys: pytest.CaptureFixture[str]) -> None:
        def failing(target: Path) -> RepoSnapshot:
            raise OSError("no network")

        index_manager.downloader = failing
        assert prepare() == 1
        assert "failed" in capsys.readouterr().err

    def test_warns_about_missing_reference_data(
        self,
        fake_downloader: Callable[[Path], RepoSnapshot],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        index_manager.downloader = fake_downloader
        missing = [{"name": "MITRE ATT&CK", "status": "failed"}]
        with patch("sigma.mcp.main.reference_data.describe", return_value=missing):
            assert prepare() == 0
        assert "Warning" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


def test_health_route() -> None:
    client = TestClient(mcp.http_app())
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "index_status": "not_started"}


# ---------------------------------------------------------------------------
# Public mode
# ---------------------------------------------------------------------------


def _server(*middleware: Any) -> FastMCP:
    server: FastMCP = FastMCP("test")

    @server.tool()
    def echo(text: str) -> str:
        return text

    @server.tool()
    async def slow(seconds: float) -> str:
        await anyio.sleep(seconds)
        return "done"

    for item in middleware:
        server.add_middleware(item)
    return server


class TestPublicMode:
    @pytest.mark.anyio
    async def test_removes_private_tools_and_limits_input(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(config.ENV_MAX_INPUT_BYTES, "100")
        monkeypatch.setenv(config.ENV_RATE_LIMIT, "100")
        server = _server()

        @server.tool()
        def update_sigma_repository() -> str:
            return "updated"

        apply_public_mode(server)
        apply_public_mode(server)  # a second call must not fail
        async with Client(server) as client:
            names = {tool.name for tool in await client.list_tools()}
            assert "update_sigma_repository" not in names
            assert "echo" in names
            with pytest.raises(ToolError):
                await client.call_tool("update_sigma_repository", {})
            result = await client.call_tool("echo", {"text": "short"})
            assert result.data == "short"
            with pytest.raises(ToolError, match="at most 100 bytes"):
                await client.call_tool("echo", {"text": "x" * 200})

    @pytest.mark.anyio
    async def test_rate_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(config.ENV_RATE_LIMIT, "0.001")
        server = _server()
        apply_public_mode(server)
        with pytest.raises(Exception, match="[Rr]ate limit"):
            async with Client(server) as client:
                for _ in range(5):
                    await client.call_tool("echo", {"text": "hi"})

    @pytest.mark.anyio
    async def test_limits_can_be_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(config.ENV_RATE_LIMIT, "0")
        monkeypatch.setenv(config.ENV_MAX_INPUT_BYTES, "0")
        server = _server()
        apply_public_mode(server)
        async with Client(server) as client:
            for _ in range(20):
                result = await client.call_tool("echo", {"text": "x" * 1000})
            assert result.data == "x" * 1000

    @pytest.mark.anyio
    async def test_concurrency_limit_rejects_when_busy(self) -> None:
        server = _server(ConcurrencyLimitMiddleware(limit=1, timeout=0.2))
        outcomes: list[str] = []

        async def call(seconds: float) -> None:
            async with Client(server) as client:
                try:
                    result = await client.call_tool("slow", {"seconds": seconds})
                    outcomes.append(str(result.data))
                except ToolError as exc:
                    outcomes.append(str(exc))

        async with anyio.create_task_group() as tg:
            tg.start_soon(call, 1.0)
            await anyio.sleep(0.1)
            tg.start_soon(call, 0.0)
        assert "done" in outcomes
        assert any("busy" in outcome for outcome in outcomes)

    @pytest.mark.anyio
    async def test_concurrency_limit_waits_for_a_slot(self) -> None:
        server = _server(ConcurrencyLimitMiddleware(limit=1, timeout=5))
        results: list[str] = []

        async def call(seconds: float) -> None:
            async with Client(server) as client:
                result = await client.call_tool("slow", {"seconds": seconds})
                results.append(str(result.data))

        async with anyio.create_task_group() as tg:
            tg.start_soon(call, 0.2)
            tg.start_soon(call, 0.0)
        assert results == ["done", "done"]

    @pytest.mark.anyio
    async def test_input_size_middleware_counts_utf8_bytes(self) -> None:
        server = _server(InputSizeMiddleware(max_bytes=40))
        async with Client(server) as client:
            with pytest.raises(ToolError):
                await client.call_tool("echo", {"text": "ä" * 20})

    def test_client_id_without_http_request(self) -> None:
        assert client_id(None) == "local"  # type: ignore[arg-type]

    def test_client_id_from_http_request(self) -> None:
        class FakeRequest:
            class client:  # noqa: N801 - mimics starlette's attribute
                host = "203.0.113.7"

        with patch("sigma.mcp.public.get_http_request", return_value=FakeRequest()):
            assert client_id(None) == "203.0.113.7"  # type: ignore[arg-type]

    def test_client_id_without_peer(self) -> None:
        class FakeRequest:
            client = None

        with patch("sigma.mcp.public.get_http_request", return_value=FakeRequest()):
            assert client_id(None) == "unknown"  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Validator configuration on a shared server
# ---------------------------------------------------------------------------


class TestValidatorIsolation:
    @pytest.mark.anyio
    async def test_configuration_does_not_leak_between_http_clients(self) -> None:
        """Over HTTP, one client's configuration must not reach other clients."""
        with patch("sigma.mcp.tools.rules._single_client", return_value=False):
            async with Client(mcp) as first:
                result = await first.call_tool(
                    "configure_validators", {"exclusions": ["identifier_existence"]}
                )
                assert "note" in result.data
            async with Client(mcp) as second:
                issues = await second.call_tool(
                    "validate_rule", {"rule_yaml": RULE_NO_ID}
                )
        assert "identifier_existence" in {i["validator"] for i in issues.data}

    @pytest.mark.anyio
    async def test_per_call_exclusions(self) -> None:
        async with Client(mcp) as client:
            issues = await client.call_tool(
                "validate_rule",
                {"rule_yaml": RULE_NO_ID, "exclusions": ["identifier_existence"]},
            )
        assert "identifier_existence" not in {i["validator"] for i in issues.data}

    @pytest.mark.anyio
    async def test_per_call_validator_names(self) -> None:
        async with Client(mcp) as client:
            issues = await client.call_tool(
                "validate_rule",
                {"rule_yaml": RULE_NO_ID, "validator_names": ["identifier_existence"]},
            )
        assert {i["validator"] for i in issues.data} == {"identifier_existence"}

    @pytest.mark.anyio
    async def test_per_call_unknown_validator(self) -> None:
        async with Client(mcp) as client:
            issues = await client.call_tool(
                "validate_rule",
                {"rule_yaml": RULE_NO_ID, "exclusions": ["no_such_validator"]},
            )
        assert issues.data[0]["type"] == "UnknownValidator"

    @pytest.mark.anyio
    async def test_per_call_arguments_override_stored_configuration(self) -> None:
        async with Client(mcp) as client:
            await client.call_tool(
                "configure_validators", {"exclusions": ["identifier_existence"]}
            )
            issues = await client.call_tool(
                "validate_rule", {"rule_yaml": RULE_NO_ID, "exclusions": []}
            )
        assert "identifier_existence" in {i["validator"] for i in issues.data}
