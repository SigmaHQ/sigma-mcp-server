"""End-to-end tests of the rule index tools and resource through an MCP client."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastmcp.client import Client

from conftest import FIXTURE_COMMIT
from sigma.mcp.index import build_index, save_index
from sigma.mcp.index_manager import IndexManager, index_manager
from sigma.mcp.main import mcp
from sigma.mcp.repo import RepoSnapshot

PSEXEC_ID = "0b5b3d5c-1a8e-4d4c-9f29-3c6c8e0b7a01"


@pytest.fixture
def ready_index(fake_downloader: Callable[[Path], RepoSnapshot]) -> None:
    """Download (fake) and index the fixture rules, as a real refresh would."""
    index_manager.downloader = fake_downloader
    index_manager.start_refresh()
    index_manager.wait(10)
    assert index_manager.status.value == "ready"


async def _call(name: str, arguments: dict[str, Any] | None = None) -> Any:
    async with Client(mcp) as client:
        result = await client.call_tool(name, arguments or {})
        return result.structured_content


class TestListed:
    @pytest.mark.anyio
    async def test_tools_and_resource_registered(self) -> None:
        async with Client(mcp) as client:
            tools = {tool.name for tool in await client.list_tools()}
            resources = {str(r.uri) for r in await client.list_resources()}
        assert {
            "search_rules",
            "get_rule",
            "get_logsource_statistics",
            "update_sigma_repository",
            "get_index_status",
        } <= tools
        assert "sigma://statistics/logsources" in resources


class TestWithoutIndex:
    @pytest.mark.anyio
    async def test_search_reports_state(self) -> None:
        data = await _call("search_rules", {"query": "psexec"})
        assert data["index_status"] == "not_started"
        assert data["results"] == []
        assert "update_sigma_repository" in data["message"]

    @pytest.mark.anyio
    async def test_get_rule_reports_state(self) -> None:
        data = await _call("get_rule", {"rule_id": PSEXEC_ID})
        assert data["rule"] is None and "message" in data

    @pytest.mark.anyio
    async def test_statistics_report_state(self) -> None:
        data = await _call("get_logsource_statistics")
        assert data["logsources"] == [] and data["total_rules"] == 0
        assert "message" in data

    @pytest.mark.anyio
    async def test_resource_reports_state(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://statistics/logsources")
        data = json.loads(contents[0].text)
        assert data["index_status"] == "not_started"
        assert "message" in data

    @pytest.mark.anyio
    async def test_saved_index_is_loaded_on_demand(self, rules_root: Path) -> None:
        save_index(build_index(rules_root), IndexManager.paths().index_file)
        data = await _call("search_rules", {"query": "psexec"})
        assert data["index_status"] == "ready"
        assert data["results"][0]["id"] == PSEXEC_ID


@pytest.mark.usefixtures("ready_index")
class TestWithIndex:
    @pytest.mark.anyio
    async def test_search(self) -> None:
        data = await _call("search_rules", {"query": "psexec lateral"})
        assert "message" not in data
        first = data["results"][0]
        assert first["id"] == PSEXEC_ID
        assert first["score"] == 3 + 2
        assert first["logsource"] == {
            "product": "windows",
            "category": "process_creation",
        }
        assert first["rule_set"] == "rules"

    @pytest.mark.anyio
    async def test_search_notes_ignored_keywords(self) -> None:
        query = "psexec " + " ".join(f"word{n}" for n in range(40))
        data = await _call("search_rules", {"query": query})
        assert "first 32 of 41 keywords" in data["note"]
        assert data["results"][0]["id"] == PSEXEC_ID
        assert "note" not in await _call("search_rules", {"query": "psexec"})

    @pytest.mark.anyio
    async def test_search_limits_results(self) -> None:
        many = await _call("search_rules", {"query": "windows", "max_results": 0})
        assert len(many["results"]) == 1
        capped = await _call("search_rules", {"query": "windows", "max_results": 999})
        assert len(capped["results"]) <= 50

    @pytest.mark.anyio
    async def test_long_description_is_shortened(self) -> None:
        entry = index_manager.get_index()
        assert entry is not None
        long_rule = entry.find(PSEXEC_ID)
        assert long_rule is not None
        object.__setattr__(long_rule, "description", "x" * 400)
        data = await _call("search_rules", {"query": "psexec"})
        description = data["results"][0]["description"]
        assert len(description) == 301 and description.endswith("…")

    @pytest.mark.anyio
    async def test_get_rule_by_id_and_path(self) -> None:
        by_id = await _call("get_rule", {"rule_id": PSEXEC_ID})
        rule = by_id["rule"]
        assert rule["title"] == "PsExec Remote Execution"
        assert "PsExec.exe" in rule["yaml"]
        by_path = await _call("get_rule", {"rule_id": rule["path"]})
        assert by_path["rule"]["id"] == PSEXEC_ID

    @pytest.mark.anyio
    async def test_get_rule_unknown(self) -> None:
        data = await _call("get_rule", {"rule_id": "nope"})
        assert data["rule"] is None
        assert "No rule with ID or path 'nope'" in data["message"]

    @pytest.mark.anyio
    async def test_get_rule_file_missing(self) -> None:
        index = index_manager.get_index()
        assert index is not None
        entry = index.find(PSEXEC_ID)
        assert entry is not None
        (IndexManager.paths().rules_dir / entry.path).unlink()
        data = await _call("get_rule", {"rule_id": PSEXEC_ID})
        assert data["rule"] is None
        assert "could not be read" in data["message"]

    @pytest.mark.anyio
    async def test_statistics(self) -> None:
        data = await _call("get_logsource_statistics", {"max_fields": 2})
        assert data["total_rules"] == 7
        first = data["logsources"][0]
        assert first["key"] == "windows/process_creation"
        assert first["rule_count"] == 3
        assert first["field_count"] == 4
        assert first["top_fields"] == [
            {"field": "Image", "rule_count": 3},
            {"field": "CommandLine", "rule_count": 2},
        ]

    @pytest.mark.anyio
    async def test_statistics_filter(self) -> None:
        data = await _call("get_logsource_statistics", {"logsource_filter": "LINUX"})
        assert [ls["key"] for ls in data["logsources"]] == [
            "linux",
            "linux/process_creation",
        ]

    @pytest.mark.anyio
    async def test_statistics_resource(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://statistics/logsources")
        data = json.loads(contents[0].text)
        assert data["source_commit"] == FIXTURE_COMMIT
        assert data["total_rules"] == 7
        security = data["logsources"]["windows/security"]
        assert security["service"] == "security"
        assert security["fields"] == {"EventID": 2, "TargetUserName": 1}

    @pytest.mark.anyio
    async def test_index_status(self) -> None:
        data = await _call("get_index_status")
        assert data["status"] == "ready"
        assert data["rule_count"] == 8
        assert data["refreshing"] is False


class TestUpdate:
    @pytest.mark.anyio
    async def test_update_starts_background_refresh(
        self, fake_downloader: Callable[[Path], RepoSnapshot]
    ) -> None:
        index_manager.downloader = fake_downloader
        data = await _call("update_sigma_repository")
        assert data["started"] is True
        index_manager.wait(10)
        status = await _call("get_index_status")
        assert status["status"] == "ready"
        assert status["source_commit"] == FIXTURE_COMMIT


class TestLifespanWarmup:
    @pytest.mark.anyio
    async def test_client_connect_starts_warmup(
        self,
        fake_downloader: Callable[[Path], RepoSnapshot],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("SIGMA_MCP_NO_WARMUP", "0")
        index_manager.downloader = fake_downloader
        async with Client(mcp) as client:
            assert index_manager.status.value in ("downloading", "indexing", "ready")
            index_manager.wait(10)
            result = await client.call_tool("search_rules", {"query": "psexec"})
        assert result.structured_content["results"][0]["id"] == PSEXEC_ID

    @pytest.mark.anyio
    async def test_no_warmup_by_default_in_tests(self) -> None:
        async with Client(mcp):
            assert index_manager.status.value == "not_started"
