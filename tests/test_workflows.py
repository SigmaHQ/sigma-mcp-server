"""Tests for the workflow prompts, resource tools and MITRE reference data."""

from __future__ import annotations

import json
import re
import threading
from types import SimpleNamespace
from typing import Any

import pytest
from fastmcp.client import Client

from pathlib import Path

from sigma.mcp import reference_data as reference_module
from sigma.mcp.index_manager import index_manager
from sigma.mcp.main import mcp
from sigma.mcp.reference_data import (
    Dataset,
    DatasetStatus,
    ReferenceData,
    default_datasets,
    reference_data,
)
from sigma.mcp.workflows import PIPELINE_WORKFLOW, SIGMA_RULE_WORKFLOW

RULE = """
title: Test Rule
id: 0b5b3d5c-1a8e-4d4c-9f29-3c6c8e0b7a01
logsource: {product: windows, category: process_creation}
detection:
  selection: {Image|endswith: '\\\\cmd.exe'}
  condition: selection
tags: [attack.execution]
"""


async def _prompt_text(name: str, arguments: dict[str, Any] | None = None) -> str:
    async with Client(mcp) as client:
        result = await client.get_prompt(name, arguments or {})
    content = result.messages[0].content
    assert content.type == "text"
    return str(content.text)


class TestWorkflowPrompts:
    @pytest.mark.anyio
    async def test_listed(self) -> None:
        async with Client(mcp) as client:
            names = {p.name for p in await client.list_prompts()}
        assert {"create_sigma_rules", "create_processing_pipeline"} <= names

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("name", "text"),
        [
            ("create_sigma_rules", SIGMA_RULE_WORKFLOW),
            ("create_processing_pipeline", PIPELINE_WORKFLOW),
        ],
    )
    async def test_without_task_is_system_prompt(self, name: str, text: str) -> None:
        assert await _prompt_text(name) == text

    @pytest.mark.anyio
    async def test_with_task(self) -> None:
        text = await _prompt_text(
            "create_processing_pipeline", {"task": "  Elastic with ECS  "}
        )
        assert text.startswith(PIPELINE_WORKFLOW)
        assert text.endswith("## Task\n\nElastic with ECS\n")

    @pytest.mark.anyio
    async def test_blank_task_is_ignored(self) -> None:
        assert await _prompt_text("create_sigma_rules", {"task": "  "}) == (
            SIGMA_RULE_WORKFLOW
        )

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("text", "expected_tools"),
        [
            (
                SIGMA_RULE_WORKFLOW,
                {
                    "search_rules",
                    "get_rule",
                    "get_logsource_info",
                    "generate_uuid",
                    "validate_rule",
                    "suggest_rule_filename",
                    "match_events",
                    "read_resource",
                },
            ),
            (
                PIPELINE_WORKFLOW,
                {
                    "get_logsource_statistics",
                    "validate_pipeline",
                    "search_rules",
                    "get_rule",
                    "apply_pipeline",
                    "match_events",
                    "analyze_pipeline_coverage",
                    "update_sigma_repository",
                    "read_resource",
                },
            ),
        ],
    )
    async def test_referenced_tools_and_resources_exist(
        self, text: str, expected_tools: set[str]
    ) -> None:
        async with Client(mcp) as client:
            tools = {t.name for t in await client.list_tools()}
            uris = {str(r.uri) for r in await client.list_resources()}
            templates = {t.uri_template for t in await client.list_resource_templates()}
        named = set(re.findall(r"`([a-z_]+)`", text))
        assert expected_tools <= named, "workflow no longer mentions a tool"
        assert expected_tools <= tools, "workflow mentions a tool that does not exist"
        resources = re.findall(r"`(sigma://[^`]+)`", text)
        assert resources
        for uri in resources:
            assert uri in uris or uri in templates, uri

    @pytest.mark.parametrize("text", [SIGMA_RULE_WORKFLOW, PIPELINE_WORKFLOW])
    def test_mentions_validator_issues_are_harmless(self, text: str) -> None:
        assert "ValidatorSkipped" in text and "ValidatorError" in text

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("name", "arguments"),
        [
            ("create_sigma_rule_from_description", {"description": "PsExec"}),
            ("create_sigma_rules_from_url", {"url": "https://example.com"}),
        ],
    )
    async def test_older_prompts_do_not_loop_on_skipped_validators(
        self, name: str, arguments: dict[str, Any]
    ) -> None:
        text = await _prompt_text(name, arguments)
        assert "ValidatorSkipped" in text
        assert "suggest_rule_filename" in text


class TestResourcesAsTools:
    @pytest.mark.anyio
    async def test_tools_listed(self) -> None:
        async with Client(mcp) as client:
            tools = {t.name for t in await client.list_tools()}
        assert {"list_resources", "read_resource"} <= tools

    @pytest.mark.anyio
    async def test_list_and_read(self) -> None:
        async with Client(mcp) as client:
            listed = await client.call_tool("list_resources", {})
            text = listed.content[0].text
            assert "sigma://pipelines/transformations" in text
            assert "sigma://fields/{category}" in text
            read = await client.call_tool(
                "read_resource", {"uri": "sigma://pipelines/transformations"}
            )
        payload = read.content[0].text
        assert "field_name_mapping" in json.dumps(payload)


def _dataset(loader: Any, validators: tuple[str, ...] = ("attacktag",)) -> Dataset:
    return Dataset("Test data", validators, loader)


def _fail() -> object:
    raise RuntimeError("HTTP Error 403: Forbidden")


def _no_download(target: Path) -> Any:
    raise OSError("tests do not download")


class TestReferenceData:
    def test_success(self) -> None:
        data = ReferenceData([_dataset(lambda: {"T1059": "x"})])
        assert set(data.unavailable_validators()) == {"attacktag"}
        data.start_loading()
        data.wait(10)
        assert data.unavailable_validators() == {}
        assert data.describe() == [
            {
                "name": "Test data",
                "status": "ready",
                "validators": ["attacktag"],
                "error": None,
            }
        ]

    def test_loading_reason(self) -> None:
        release = threading.Event()
        data = ReferenceData([_dataset(lambda: release.wait(10))])
        data.start_loading()
        assert "still being downloaded" in data.unavailable_validators()["attacktag"]
        data.start_loading()  # already loading: no second thread
        assert len(data._threads) == 1
        release.set()
        data.wait(10)

    def test_failure_and_retry_delay(self) -> None:
        calls: list[int] = []

        def failing() -> object:
            calls.append(1)
            return _fail()

        data = ReferenceData([_dataset(failing)], retry_after=3600)
        data.start_loading()
        data.wait(10)
        reason = data.unavailable_validators()["attacktag"]
        assert "could not be downloaded (HTTP Error 403: Forbidden)" in reason
        data.start_loading()
        data.wait(10)
        assert len(calls) == 1  # not retried before retry_after

        data.retry_after = 0
        data.start_loading()
        data.wait(10)
        assert len(calls) == 2

    def test_default_datasets_use_pysigma(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            reference_module,
            "mitre_attack",
            SimpleNamespace(mitre_attack_techniques={"T1": "a"}),
        )
        monkeypatch.setattr(
            reference_module,
            "mitre_d3fend",
            SimpleNamespace(mitre_d3fend_techniques={"D3-1": "b"}),
        )
        datasets = default_datasets()
        assert [d.validators for d in datasets] == [("attacktag",), ("d3_fendtag",)]
        assert [d.loader() for d in datasets] == [{"T1": "a"}, {"D3-1": "b"}]


class TestValidateRuleSkipsUnavailableValidators:
    @pytest.mark.anyio
    async def test_skipped_when_data_failed(self) -> None:
        reference_data.datasets = [
            Dataset(
                "MITRE ATT&CK",
                ("attacktag",),
                _fail,
                status=DatasetStatus.FAILED,
                error="offline",
                failed_at=float("inf"),
            )
        ]
        async with Client(mcp) as client:
            result = await client.call_tool("validate_rule", {"rule_yaml": RULE})
        issues = result.data
        attack = [i for i in issues if i["validator"] == "attacktag"]
        assert [i["type"] for i in attack] == ["ValidatorSkipped"]
        assert "could not be downloaded (offline)" in attack[0]["description"]
        assert "not a problem with the rule" in attack[0]["description"]

    @pytest.mark.anyio
    async def test_excluded_validator_is_not_reported_as_skipped(self) -> None:
        reference_data.datasets = [
            Dataset(
                "MITRE ATT&CK",
                ("attacktag",),
                _fail,
                status=DatasetStatus.FAILED,
                error="offline",
                failed_at=float("inf"),
            )
        ]
        async with Client(mcp) as client:
            await client.call_tool(
                "configure_validators", {"exclusions": ["attacktag"]}
            )
            result = await client.call_tool("validate_rule", {"rule_yaml": RULE})
        assert not [i for i in result.data if i["validator"] == "attacktag"]

    @pytest.mark.anyio
    async def test_lifespan_starts_loading(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SIGMA_MCP_NO_WARMUP", "0")
        monkeypatch.setattr(index_manager, "downloader", _no_download)
        loaded = threading.Event()
        reference_data.datasets = [_dataset(loaded.set)]
        async with Client(mcp):
            assert loaded.wait(10)
        reference_data.wait(10)
        assert reference_data.unavailable_validators() == {}
