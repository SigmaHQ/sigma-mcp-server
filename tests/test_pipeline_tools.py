"""End-to-end tests of the pipeline tools and resource through an MCP client."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastmcp.client import Client

from sigma.mcp.index_manager import index_manager
from sigma.mcp.main import mcp
from sigma.mcp.repo import RepoSnapshot

PIPELINE = """
name: example
transformations:
  - id: proc_fields
    type: field_name_mapping
    mapping: {Image: process.executable}
    rule_conditions: [{type: logsource, product: windows, category: process_creation}]
  - id: linux_unsupported
    type: rule_failure
    message: Linux logs are not collected
    rule_conditions: [{type: logsource, product: linux}]
"""

RULE = """
title: Test
logsource: {product: windows, category: process_creation}
detection:
  selection: {Image|endswith: '\\\\cmd.exe'}
  condition: selection
"""


async def _call(name: str, arguments: dict[str, Any]) -> Any:
    async with Client(mcp) as client:
        result = await client.call_tool(name, arguments)
        return result.structured_content


@pytest.fixture
def ready_index(fake_downloader: Callable[[Path], RepoSnapshot]) -> None:
    index_manager.downloader = fake_downloader
    index_manager.start_refresh()
    index_manager.wait(10)


class TestValidatePipeline:
    @pytest.mark.anyio
    async def test_valid(self) -> None:
        data = await _call("validate_pipeline", {"pipeline_yaml": PIPELINE})
        assert data["valid"] is True
        assert [t["id"] for t in data["summary"]["transformations"]] == [
            "proc_fields",
            "linux_unsupported",
        ]

    @pytest.mark.anyio
    async def test_invalid(self) -> None:
        data = await _call("validate_pipeline", {"pipeline_yaml": "- nope"})
        assert data["valid"] is False and data["errors"]


class TestApplyPipeline:
    @pytest.mark.anyio
    async def test_apply(self) -> None:
        data = await _call(
            "apply_pipeline", {"rule_yaml": RULE, "pipeline_yamls": [PIPELINE]}
        )
        (rule,) = data["rules"]
        assert rule["detections"] == {"selection": "process.executable = '*\\cmd.exe'"}
        assert rule["applied_transformations"] == ["proc_fields"]

    @pytest.mark.anyio
    async def test_error(self) -> None:
        data = await _call("apply_pipeline", {"rule_yaml": RULE, "pipeline_yamls": []})
        assert "error" in data


class TestCoverage:
    @pytest.mark.anyio
    async def test_without_index(self) -> None:
        data = await _call("analyze_pipeline_coverage", {"pipeline_yaml": PIPELINE})
        assert data["index_status"] == "not_started"
        assert "update_sigma_repository" in data["message"]

    @pytest.mark.anyio
    async def test_invalid_input(self) -> None:
        invalid = await _call("analyze_pipeline_coverage", {"pipeline_yaml": "- x"})
        assert invalid["error"].startswith("The pipeline is invalid")
        threshold = await _call(
            "analyze_pipeline_coverage",
            {"pipeline_yaml": PIPELINE, "field_threshold": 2},
        )
        assert threshold == {"error": "field_threshold must be between 0 and 1."}

    @pytest.mark.anyio
    @pytest.mark.usefixtures("ready_index")
    async def test_with_index(self) -> None:
        data = await _call(
            "analyze_pipeline_coverage",
            {"pipeline_yaml": PIPELINE, "max_logsources": 2},
        )
        assert data["index_status"] == "ready"
        assert data["summary"]["logsources"] == {
            "covered": 1,
            "uncovered": 1,
            "unsupported": 2,
        }
        assert data["summary"]["field_threshold"] == 0.05
        assert [ls["key"] for ls in data["logsources"]] == [
            "windows/process_creation",
            "windows/security",
        ]
        assert data["omitted_logsources"] == 2
        proc = data["logsources"][0]
        assert proc["status"] == "covered"
        assert proc["fields"]["mapped"] == {"Image": ["process.executable"]}

    @pytest.mark.anyio
    @pytest.mark.usefixtures("ready_index")
    async def test_filter(self) -> None:
        data = await _call(
            "analyze_pipeline_coverage",
            {"pipeline_yaml": PIPELINE, "logsource_filter": "linux"},
        )
        assert {ls["status"] for ls in data["logsources"]} == {"unsupported"}
        assert data["omitted_logsources"] == 0


class TestCatalogResource:
    @pytest.mark.anyio
    async def test_resource(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://pipelines/transformations")
        data = json.loads(contents[0].text)
        assert "field_name_mapping" in data["transformations"]
        assert "logsource" in data["rule_conditions"]
