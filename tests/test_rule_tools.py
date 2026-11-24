"""Tests for the extended rule tools: collections, logsources, file names."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastmcp.client import Client
from sigma.validators.base import SigmaRuleValidator

from sigma.mcp.index_manager import index_manager
from sigma.mcp.knowledge.correlation import CORRELATION_RULES_SPEC
from sigma.mcp.knowledge.logsources import LOGSOURCES
from sigma.mcp.knowledge.specification import SPEC_URL_CORRELATION, _spec_cache
from sigma.mcp.main import mcp
from sigma.mcp.naming import build_filename, filename_issues, filename_prefix
from sigma.mcp.repo import RepoSnapshot
from sigma.mcp.validation import parse_rules, run_validators

BASE_RULE = """
title: Failed Logon
id: 1f2e3d4c-5b6a-4798-8a7b-6c5d4e3f2a07
name: failed_logon
status: test
description: A failed logon.
author: Test
date: 2024-01-01
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
level: low
"""

CORRELATION = """
title: Many Failed Logons
id: 2a3b4c5d-6e7f-4a8b-9c0d-1e2f3a4b5c08
status: test
author: Test
date: 2024-01-01
correlation:
    type: event_count
    rules:
        - failed_logon
    group-by:
        - IpAddress
    timespan: 10m
    condition:
        gte: 10
level: medium
"""


async def _call(name: str, arguments: dict[str, Any]) -> Any:
    async with Client(mcp) as client:
        result = await client.call_tool(name, arguments)
        if result.structured_content is not None and "result" in (
            result.structured_content
        ):
            return result.structured_content["result"]
        return result.structured_content


@pytest.fixture
def ready_index(fake_downloader: Callable[[Path], RepoSnapshot]) -> None:
    index_manager.downloader = fake_downloader
    index_manager.start_refresh()
    index_manager.wait(10)


class TestParseRules:
    def test_collection_with_correlation(self) -> None:
        rules, issues = parse_rules(BASE_RULE + "---" + CORRELATION)
        assert issues == []
        assert [r.title for r in rules] == ["Failed Logon", "Many Failed Logons"]

    def test_missing_reference_is_reported_and_rest_parsed(self) -> None:
        rules, issues = parse_rules(CORRELATION)
        assert [r.title for r in rules] == ["Many Failed Logons"]
        (issue,) = issues
        assert issue["type"] == "SigmaParseError"
        assert issue["error_class"] == "SigmaRuleNotFoundError"
        assert "failed_logon" in issue["description"]
        assert "same YAML" in issue["description"]

    def test_rule_errors_keep_valid_rules(self) -> None:
        broken = "title: [1, 2]\nlogsource: {product: w}\n"
        broken += "detection: {sel: {a: b}, condition: sel}"
        rules, issues = parse_rules(BASE_RULE + "---\n" + broken)
        assert [r.title for r in rules] == ["Failed Logon"]
        assert issues[0]["error_class"] == "SigmaTitleError"
        assert issues[0]["rules"] == ["[1, 2]"]

    def test_document_that_is_no_mapping(self) -> None:
        rules, issues = parse_rules(BASE_RULE + "---\n- a list")
        assert len(rules) == 1
        assert issues[0]["error_class"] == "SigmaCollectionError"
        assert issues[0]["rules"] == []

    @pytest.mark.parametrize(
        ("text", "error_class", "fragment"),
        [
            ("a: [b", "YAMLError", "Invalid YAML"),
            ("", "SigmaParseError", "no Sigma rule"),
        ],
    )
    def test_unparseable(self, text: str, error_class: str, fragment: str) -> None:
        rules, issues = parse_rules(text)
        assert rules == []
        assert issues[0]["error_class"] == error_class
        assert fragment in issues[0]["description"]

    def test_unexpected_exception(self) -> None:
        with patch(
            "sigma.mcp.validation.SigmaCollection.from_yaml",
            side_effect=RuntimeError("boom"),
        ):
            rules, issues = parse_rules(BASE_RULE)
        assert rules == []
        assert issues[0]["error_class"] == "RuntimeError"
        assert issues[0]["description"] == "RuntimeError('boom')"


class _CrashingValidator(SigmaRuleValidator):
    def validate(self, rule: Any) -> list[Any]:
        raise ValueError("crash")


class TestRunValidators:
    def test_uniqueness_across_documents(self) -> None:
        from sigma.validators.core import validators

        duplicate = BASE_RULE.replace("name: failed_logon\n", "")
        rules, _ = parse_rules(BASE_RULE + "---" + duplicate)
        active = {"identifier_uniqueness": validators["identifier_uniqueness"]}
        issues = run_validators(rules, active)
        assert [i["validator"] for i in issues] == ["identifier_uniqueness"]

    def test_crashing_validator_is_reported(self) -> None:
        rules, _ = parse_rules(BASE_RULE)
        issues = run_validators(rules, {"crashing": _CrashingValidator})
        assert issues[0]["type"] == "ValidatorError"
        assert "crash" in issues[0]["description"]
        assert issues[0]["rules"] == ["1f2e3d4c-5b6a-4798-8a7b-6c5d4e3f2a07"]


class TestValidateRuleTool:
    @pytest.mark.anyio
    async def test_correlation_with_base_rule(self) -> None:
        issues = await _call(
            "validate_rule", {"rule_yaml": BASE_RULE + "---" + CORRELATION}
        )
        assert not [i for i in issues if i["validator"] == "parser"]

    @pytest.mark.anyio
    async def test_missing_reference(self) -> None:
        issues = await _call("validate_rule", {"rule_yaml": CORRELATION})
        parser = [i for i in issues if i["validator"] == "parser"]
        assert parser[0]["error_class"] == "SigmaRuleNotFoundError"


class TestGetLogsourceInfo:
    @pytest.mark.anyio
    async def test_matches_and_fields(self) -> None:
        data = await _call(
            "get_logsource_info",
            {"activity_description": "scheduled task created via schtasks"},
        )
        assert data["fallback"] is False
        assert 1 <= len(data["results"]) <= 4
        keys = [r["key"] for r in data["results"]]
        assert "taskscheduler" in keys or "security_windows" in keys
        first = data["results"][0]
        assert set(first) >= {"logsource", "fields", "event_ids", "tips"}
        assert first["sigmahq"] is None
        assert data["index_status"] == "not_started"

    @pytest.mark.anyio
    async def test_event_id_match(self) -> None:
        data = await _call(
            "get_logsource_info",
            {"activity_description": "4624 logon", "max_results": 1},
        )
        assert data["results"][0]["logsource"] == {
            "service": "security",
            "product": "windows",
        }

    @pytest.mark.anyio
    async def test_fallback(self) -> None:
        data = await _call(
            "get_logsource_info", {"activity_description": "xyzzy qwrtz"}
        )
        assert data["fallback"] is True
        assert [r["key"] for r in data["results"]] == ["process_creation_windows"]

    @pytest.mark.anyio
    async def test_only_the_first_words_count(self) -> None:
        filler = " ".join(f"zz{n:03d}" for n in range(32))
        data = await _call(
            "get_logsource_info", {"activity_description": f"{filler} 4624"}
        )
        assert data["fallback"] is True

    @pytest.mark.anyio
    async def test_max_results_clamped(self) -> None:
        data = await _call(
            "get_logsource_info",
            {
                "activity_description": "windows process file registry",
                "max_results": 99,
            },
        )
        assert len(data["results"]) == 10

    @pytest.mark.anyio
    @pytest.mark.usefixtures("ready_index")
    async def test_sigmahq_usage(self) -> None:
        data = await _call(
            "get_logsource_info",
            {"activity_description": "process creation windows", "max_results": 10},
        )
        by_key = {r["key"]: r for r in data["results"]}
        usage = by_key["process_creation_windows"]["sigmahq"]
        assert usage["rule_count"] == 3
        assert usage["top_fields"][0] == {"field": "Image", "rule_count": 3}
        dns = await _call(
            "get_logsource_info",
            {"activity_description": "dns query", "max_results": 1},
        )
        assert dns["results"][0]["key"] == "dns_query"
        assert dns["results"][0]["sigmahq"] == {"rule_count": 0, "top_fields": []}

    def test_curated_logsources_use_sigmahq_names(self) -> None:
        categories = {info["logsource"].get("category") for info in LOGSOURCES.values()}
        assert "driver_load" in categories
        assert "driver_loaded" not in categories


class TestNaming:
    @pytest.mark.parametrize(
        ("logsource", "prefix"),
        [
            (
                {"product": "windows", "category": "process_creation"},
                "proc_creation_win_",
            ),
            (
                {"product": "linux", "category": "process_creation"},
                "proc_creation_lnx_",
            ),
            ({"product": "windows", "category": "registry_set"}, "registry_set_"),
            ({"product": "windows", "service": "security"}, "win_security_"),
            ({"product": "linux", "service": "auditd"}, "lnx_auditd_"),
            ({"product": "aws", "service": "cloudtrail"}, "aws_"),
            ({"product": "windows", "category": "antivirus"}, ""),
            ({}, ""),
        ],
    )
    def test_prefix(self, logsource: dict[str, str], prefix: str) -> None:
        assert filename_prefix(logsource) == prefix

    def test_build(self) -> None:
        filename, prefix = build_filename(
            "Lateral Movement via PsExec!",
            {"product": "windows", "category": "process_creation"},
        )
        assert filename == "proc_creation_win_lateral_movement_via_psexec.yml"
        assert prefix == "proc_creation_win_"

    def test_prefix_not_repeated(self) -> None:
        filename, _ = build_filename(
            "Win Security Audit Log Cleared",
            {"product": "windows", "service": "security"},
        )
        assert filename == "win_security_audit_log_cleared.yml"

    def test_long_title_is_cut_at_word_boundary(self) -> None:
        title = "Suspicious " + "Very Long Words " * 20
        filename, _ = build_filename(title, {"product": "windows", "service": "system"})
        assert len(filename) <= 90
        assert filename.endswith("_words.yml") or filename.endswith("_long.yml")
        assert "__" not in filename

    def test_long_title_without_spaces(self) -> None:
        filename, _ = build_filename("x" * 200, {})
        assert len(filename) == 90

    def test_issues(self) -> None:
        assert filename_issues("proc_creation_win_test.yml") == []
        short = filename_issues("ab.yml")
        assert any("shorter" in issue for issue in short)
        assert any("underscore" in issue for issue in short)
        assert any("a-z" in issue for issue in filename_issues("Bad_Name_Here.yml"))


class TestSuggestRuleFilenameTool:
    @pytest.mark.anyio
    async def test_without_index(self) -> None:
        data = await _call("suggest_rule_filename", {"rule_yaml": BASE_RULE})
        assert data == {
            "filename": "win_security_failed_logon.yml",
            "prefix": "win_security_",
            "issues": [],
            "sigmahq": None,
        }

    @pytest.mark.anyio
    async def test_correlation_uses_first_title_and_logsource(self) -> None:
        data = await _call(
            "suggest_rule_filename", {"rule_yaml": CORRELATION + "---" + BASE_RULE}
        )
        assert data["filename"] == "win_security_many_failed_logons.yml"

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("text", "error"),
        [
            ("a: [b", "Invalid YAML"),
            ("logsource: {product: windows}", "non-empty 'title'"),
            ("- x\n---\ntitle: '  '", "non-empty 'title'"),
        ],
    )
    async def test_errors(self, text: str, error: str) -> None:
        data = await _call("suggest_rule_filename", {"rule_yaml": text})
        assert error in data["error"]

    @pytest.mark.anyio
    async def test_alias_bomb_is_refused(self) -> None:
        anchors = ["l0: &l0 [" + ", ".join(["lol"] * 9) + "]"]
        for n in range(1, 6):
            anchors.append(f"l{n}: &l{n} [" + ", ".join([f"*l{n - 1}"] * 9) + "]")
        rule = "title: Some rule title\n" + "\n".join(anchors)
        rule += "\nlogsource:\n  product: *l5\n"
        data = await _call("suggest_rule_filename", {"rule_yaml": rule})
        assert "billion laughs" in data["error"]

    @pytest.mark.anyio
    async def test_non_string_logsource_values_are_ignored(self) -> None:
        rule = (
            "title: Failed Logon\n"
            "logsource: {product: windows, service: [security], category: 5}\n"
        )
        data = await _call("suggest_rule_filename", {"rule_yaml": rule})
        assert data["filename"] == "failed_logon.yml"
        assert data["prefix"] == ""

    @pytest.mark.anyio
    @pytest.mark.usefixtures("ready_index")
    async def test_with_index(self) -> None:
        rule = """
title: Sysinternals PsExec Remote
logsource: {product: windows, category: process_creation}
detection: {sel: {Image: x}, condition: sel}
"""
        data = await _call("suggest_rule_filename", {"rule_yaml": rule})
        assert data["filename"] == "proc_creation_win_sysinternals_psexec_remote.yml"
        sigmahq = data["sigmahq"]
        assert sigmahq["existing_rule"] == (
            "rules/windows/process_creation/"
            "proc_creation_win_sysinternals_psexec_remote.yml"
        )
        assert sigmahq["suggested_directory"] == "rules/windows/process_creation"
        assert any("already has a rule" in issue for issue in data["issues"])

    @pytest.mark.anyio
    @pytest.mark.usefixtures("ready_index")
    async def test_unknown_logsource_with_index(self) -> None:
        rule = "title: Okta Admin Role Assigned\nlogsource: {product: okta}\n"
        data = await _call("suggest_rule_filename", {"rule_yaml": rule})
        assert data["filename"] == "okta_admin_role_assigned.yml"
        assert data["sigmahq"] == {"existing_rule": None, "suggested_directory": None}


class TestCorrelationSpecification:
    @pytest.mark.anyio
    async def test_fetched(self) -> None:
        _spec_cache[SPEC_URL_CORRELATION] = "# Official correlation spec"
        try:
            async with Client(mcp) as client:
                contents = await client.read_resource(
                    "sigma://specification/correlation"
                )
            assert contents[0].text == "# Official correlation spec"
        finally:
            _spec_cache.pop(SPEC_URL_CORRELATION, None)

    @pytest.mark.anyio
    async def test_fallback_when_offline(self) -> None:
        with patch(
            "sigma.mcp.resources.fetch_spec",
            AsyncMock(side_effect=httpx.ConnectError("offline")),
        ):
            async with Client(mcp) as client:
                contents = await client.read_resource(
                    "sigma://specification/correlation"
                )
        assert contents[0].text == CORRELATION_RULES_SPEC
        assert "event_count" in contents[0].text
