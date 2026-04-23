"""Tests for sigma.mcp.main."""

from __future__ import annotations

import json
from collections.abc import Generator
from typing import Any
from unittest.mock import patch

import pytest
from fastmcp.client import Client
from mcp.types import TextContent

from sigma.mcp.main import (
    _fetch_spec,
    _get_active_validators,
    _issue_to_dict,
    _parse_fields,
    _parse_logsources,
    _parse_tags,
    _parse_win_event_channel,
    _parse_win_event_title,
    _spec_cache,
    _SPEC_URL_RULES,
    _SPEC_URL_TAGS,
    _SPEC_URL_TAXONOMY,
    _WIN_EVENT_INDEX,
    _win_event_content_cache,
    all_validators,
    mcp,
)
from sigma.validators.core.metadata import (
    IdentifierExistenceIssue,
    IdentifierExistenceValidator,
)

# ---------------------------------------------------------------------------
# Minimal realistic markdown fixtures used in parser unit tests and to
# pre-populate the spec cache (avoids network calls in integration tests)
# ---------------------------------------------------------------------------

_TAXONOMY_MD = """\
# Sigma Taxonomy

## Log Sources

### Windows Folder

#### Category

| Product | Logsource | Description |
| ------- | --------- | ----------- |
| windows | product: windows<br>category: process_creation | EventID: 1 |
| windows | product: windows<br>category: network_connection | EventID: 3 |

#### Service

| Product | Logsource | Description |
| ------- | --------- | ----------- |
| windows | product: windows<br>service: security | Channel: Security |
| windows | product: windows<br>service: sysmon | Channel: Microsoft-Windows-Sysmon/Operational |

### Linux Folder

#### Category

| Product | Logsource | Description |
| ------- | --------- | ----------- |
| Linux   | product: linux<br>category: process_creation | EventID: 1<br>service: sysmon |

## Fields

### Generic

#### Process Creation Events

| Field Name | Example Value | Comment |
| ---------- | ------------- | ------- |
| Image | C:\\Windows\\System32\\cmd.exe | |
| CommandLine | cmd.exe /c whoami | |
| ProcessId | 1028 | |
| ParentImage | C:\\Windows\\System32\\explorer.exe | |

## History
"""

_TAGS_MD = """\
# Sigma Tags

## Namespaces

- attack: Categorization according to MITRE ATT&CK.
- cve: Categorization according MITRE CVE.

### Namespace: attack

Categorization according to MITRE ATT&CK. To get the current supported version
of ATT&CK please visit MITRE CTI.

- t1234: technique
- initial-access: Initial Access

### Namespace: cve

Use the CVE tag from MITRE in lower case separated by dots. Example: cve.2021-44228.

### Namespace: detection

Use the detection tag to indicate the type of a rule.

- detection.dfir
- detection.threat-hunting

## History
"""

_RULES_MD = """\
# Sigma Rules Specification

Version 2.1.0

## Overview

A Sigma rule is a YAML document with the following required fields: title, status,
logsource, and detection.

## Required Fields

- title: Human-readable rule title.
- status: One of stable, test, experimental, deprecated, unsupported.
"""


@pytest.fixture(autouse=True)
def prepopulate_spec_cache() -> Generator[None, None, None]:
    """Pre-fill the module-level spec cache with static fixtures.

    This prevents any network calls during tests and makes the test suite
    fully offline-capable.
    """
    _spec_cache[_SPEC_URL_TAXONOMY] = _TAXONOMY_MD
    _spec_cache[_SPEC_URL_TAGS] = _TAGS_MD
    _spec_cache[_SPEC_URL_RULES] = _RULES_MD
    yield
    # Clean up after each test so tests are isolated
    _spec_cache.pop(_SPEC_URL_TAXONOMY, None)
    _spec_cache.pop(_SPEC_URL_TAGS, None)
    _spec_cache.pop(_SPEC_URL_RULES, None)


# ---------------------------------------------------------------------------
# Sample Sigma rules used across tests
# ---------------------------------------------------------------------------

# Minimal valid rule lacking a UUID (triggers identifier_existence issue)
RULE_NO_ID = """\
title: Test Rule
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"""

# Rule with a v4 UUID – should NOT trigger identifier_existence
RULE_WITH_ID = """\
title: Test Rule
id: 12345678-1234-4321-abcd-1234567890ab
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"""

# Rule that will fail pySigma's parser (no detection section)
INVALID_RULE = """\
title: Bad Rule
status: test
logsource:
    category: process_creation
    product: windows
"""


# ---------------------------------------------------------------------------
# Unit tests for helper functions
# ---------------------------------------------------------------------------


class TestGetActiveValidators:
    def test_all_validators_when_names_is_none(self) -> None:
        active = _get_active_validators(None, [])
        assert active == all_validators

    def test_specific_validators_selected(self) -> None:
        active = _get_active_validators(["identifier_existence"], [])
        assert list(active.keys()) == ["identifier_existence"]

    def test_exclusion_removes_validator(self) -> None:
        active = _get_active_validators(None, ["identifier_existence"])
        assert "identifier_existence" not in active
        assert len(active) == len(all_validators) - 1

    def test_exclusion_applied_after_allow_list(self) -> None:
        active = _get_active_validators(
            ["identifier_existence", "identifier_uniqueness"],
            ["identifier_existence"],
        )
        assert "identifier_existence" not in active
        assert "identifier_uniqueness" in active

    def test_unknown_name_in_allow_list_is_silently_ignored(self) -> None:
        active = _get_active_validators(["nonexistent"], [])
        assert active == {}

    def test_empty_allow_list_returns_nothing(self) -> None:
        active = _get_active_validators([], [])
        assert active == {}


class TestIssueToDict:
    def _make_rule(self) -> Any:
        """Parse the no-ID rule so we have a real SigmaRule for issue injection."""
        from sigma.rule import SigmaRule

        return SigmaRule.from_yaml(RULE_NO_ID)

    def test_required_keys_present(self) -> None:
        rule = self._make_rule()
        issue = IdentifierExistenceIssue(rules=[rule])
        result = _issue_to_dict("identifier_existence", issue)
        assert set(result.keys()) >= {
            "validator",
            "type",
            "severity",
            "description",
            "rules",
        }

    def test_validator_name_stored(self) -> None:
        rule = self._make_rule()
        issue = IdentifierExistenceIssue(rules=[rule])
        result = _issue_to_dict("identifier_existence", issue)
        assert result["validator"] == "identifier_existence"

    def test_severity_is_lowercase_string(self) -> None:
        rule = self._make_rule()
        issue = IdentifierExistenceIssue(rules=[rule])
        result = _issue_to_dict("identifier_existence", issue)
        assert result["severity"] == "medium"

    def test_rules_list_contains_rule_title(self) -> None:
        rule = self._make_rule()
        issue = IdentifierExistenceIssue(rules=[rule])
        result = _issue_to_dict("identifier_existence", issue)
        assert "Test Rule" in result["rules"]

    def test_extra_fields_from_subclass_included(self) -> None:
        from uuid import UUID

        from sigma.validators.core.metadata import IdentifierCollisionIssue

        rule = self._make_rule()
        uid = UUID("12345678-1234-4321-abcd-1234567890ab")
        issue = IdentifierCollisionIssue(rules=[rule], identifier=uid)
        result = _issue_to_dict("identifier_uniqueness", issue)
        assert "identifier" in result
        assert result["identifier"] == str(uid)

    def test_rule_with_uuid_uses_uuid_in_rules_list(self) -> None:
        from sigma.rule import SigmaRule

        rule = SigmaRule.from_yaml(RULE_WITH_ID)
        issue = IdentifierExistenceIssue(rules=[rule])
        result = _issue_to_dict("identifier_existence", issue)
        # rule has an ID, so the UUID string should appear
        assert "12345678-1234-4321-abcd-1234567890ab" in result["rules"]


# ---------------------------------------------------------------------------
# Integration tests via FastMCP Client (in-memory transport)
# ---------------------------------------------------------------------------


class TestValidateRule:
    @pytest.mark.anyio
    async def test_no_issues_for_valid_rule_with_id(self) -> None:
        async with Client(mcp) as client:
            result = await client.call_tool(
                "validate_rule", {"rule_yaml": RULE_WITH_ID}
            )
            assert isinstance(result.data, list)
            validators_hit = [i["validator"] for i in result.data]
            assert "identifier_existence" not in validators_hit

    @pytest.mark.anyio
    async def test_identifier_existence_issue_for_rule_without_id(self) -> None:
        async with Client(mcp) as client:
            result = await client.call_tool("validate_rule", {"rule_yaml": RULE_NO_ID})
            assert isinstance(result.data, list)
            validators_hit = [i["validator"] for i in result.data]
            assert "identifier_existence" in validators_hit

    @pytest.mark.anyio
    async def test_parse_error_returned_for_invalid_rule(self) -> None:
        async with Client(mcp) as client:
            result = await client.call_tool(
                "validate_rule", {"rule_yaml": INVALID_RULE}
            )
            assert isinstance(result.data, list)
            assert len(result.data) >= 1
            types = [i["type"] for i in result.data]
            assert "SigmaParseError" in types

    @pytest.mark.anyio
    async def test_issue_dict_has_required_keys(self) -> None:
        async with Client(mcp) as client:
            result = await client.call_tool("validate_rule", {"rule_yaml": RULE_NO_ID})
            assert isinstance(result.data, list)
            assert len(result.data) > 0
            issue = result.data[0]
            for key in ("validator", "type", "severity", "description", "rules"):
                assert key in issue

    @pytest.mark.anyio
    async def test_severity_values_are_valid(self) -> None:
        async with Client(mcp) as client:
            result = await client.call_tool("validate_rule", {"rule_yaml": RULE_NO_ID})
            assert isinstance(result.data, list)
            for issue in result.data:
                assert issue["severity"] in ("low", "medium", "high")

    @pytest.mark.anyio
    async def test_default_state_uses_all_validators(self) -> None:
        """Without any configure_validators call the full set is applied."""
        async with Client(mcp) as client:
            result = await client.call_tool("validate_rule", {"rule_yaml": RULE_NO_ID})
            assert isinstance(result.data, list)
            # We should get at least the identifier_existence issue
            validators_hit = {i["validator"] for i in result.data}
            assert "identifier_existence" in validators_hit


class TestConfigureValidators:
    @pytest.mark.anyio
    async def test_default_configure_returns_null_names_and_empty_exclusions(
        self,
    ) -> None:
        async with Client(mcp) as client:
            result = await client.call_tool("configure_validators", {})
            assert result.data == {"validator_names": None, "exclusions": []}

    @pytest.mark.anyio
    async def test_configure_stores_exclusions(self) -> None:
        async with Client(mcp) as client:
            result = await client.call_tool(
                "configure_validators",
                {"exclusions": ["identifier_existence"]},
            )
            assert result.data["exclusions"] == ["identifier_existence"]
            assert result.data["validator_names"] is None

    @pytest.mark.anyio
    async def test_configure_stores_validator_names(self) -> None:
        async with Client(mcp) as client:
            result = await client.call_tool(
                "configure_validators",
                {"validator_names": ["identifier_existence"]},
            )
            assert result.data["validator_names"] == ["identifier_existence"]

    @pytest.mark.anyio
    async def test_exclusion_persists_across_tool_calls(self) -> None:
        """State set by configure_validators must be visible in validate_rule."""
        async with Client(mcp) as client:
            await client.call_tool(
                "configure_validators",
                {"exclusions": ["identifier_existence"]},
            )
            validate_result = await client.call_tool(
                "validate_rule", {"rule_yaml": RULE_NO_ID}
            )
            assert isinstance(validate_result.data, list)
            validators_hit = [i["validator"] for i in validate_result.data]
            assert "identifier_existence" not in validators_hit

    @pytest.mark.anyio
    async def test_validator_names_restricts_to_listed_validators(self) -> None:
        async with Client(mcp) as client:
            await client.call_tool(
                "configure_validators",
                {"validator_names": ["identifier_existence"]},
            )
            validate_result = await client.call_tool(
                "validate_rule", {"rule_yaml": RULE_NO_ID}
            )
            assert isinstance(validate_result.data, list)
            active = {i["validator"] for i in validate_result.data}
            assert active == {"identifier_existence"}

    @pytest.mark.anyio
    async def test_invalid_validator_name_returns_error(self) -> None:
        async with Client(mcp) as client:
            result = await client.call_tool(
                "configure_validators",
                {"validator_names": ["nonexistent_validator"]},
            )
            assert "error" in result.data

    @pytest.mark.anyio
    async def test_invalid_exclusion_name_returns_error(self) -> None:
        async with Client(mcp) as client:
            result = await client.call_tool(
                "configure_validators",
                {"exclusions": ["nonexistent_validator"]},
            )
            assert "error" in result.data

    @pytest.mark.anyio
    async def test_empty_exclusions_list_clears_exclusions(self) -> None:
        async with Client(mcp) as client:
            # First exclude something
            await client.call_tool(
                "configure_validators",
                {"exclusions": ["identifier_existence"]},
            )
            # Then clear
            await client.call_tool("configure_validators", {"exclusions": []})
            validate_result = await client.call_tool(
                "validate_rule", {"rule_yaml": RULE_NO_ID}
            )
            assert isinstance(validate_result.data, list)
            validators_hit = [i["validator"] for i in validate_result.data]
            assert "identifier_existence" in validators_hit

    @pytest.mark.anyio
    async def test_validator_names_and_exclusions_combined(self) -> None:
        async with Client(mcp) as client:
            await client.call_tool(
                "configure_validators",
                {
                    "validator_names": [
                        "identifier_existence",
                        "identifier_uniqueness",
                    ],
                    "exclusions": ["identifier_existence"],
                },
            )
            validate_result = await client.call_tool(
                "validate_rule", {"rule_yaml": RULE_NO_ID}
            )
            assert isinstance(validate_result.data, list)
            active = {i["validator"] for i in validate_result.data}
            assert "identifier_existence" not in active


class TestResources:
    @pytest.mark.anyio
    async def test_list_validators_resource_returns_dict(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://validators")
            data = json.loads(contents[0].text)
            assert isinstance(data, dict)
            assert len(data) > 0

    @pytest.mark.anyio
    async def test_list_validators_contains_known_validators(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://validators")
            data = json.loads(contents[0].text)
            assert "identifier_existence" in data
            assert "identifier_uniqueness" in data

    @pytest.mark.anyio
    async def test_list_validators_values_are_strings(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://validators")
            data = json.loads(contents[0].text)
            for val in data.values():
                assert isinstance(val, str)

    @pytest.mark.anyio
    async def test_list_modifiers_resource_returns_dict(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://modifiers")
            data = json.loads(contents[0].text)
            assert isinstance(data, dict)
            assert len(data) > 0

    @pytest.mark.anyio
    async def test_list_modifiers_contains_core_modifiers(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://modifiers")
            data = json.loads(contents[0].text)
            for expected in ("contains", "startswith", "endswith", "re", "base64"):
                assert expected in data

    @pytest.mark.anyio
    async def test_list_modifiers_values_are_strings(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://modifiers")
            data = json.loads(contents[0].text)
            for val in data.values():
                assert isinstance(val, str)

    @pytest.mark.anyio
    async def test_list_modifiers_is_sorted(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://modifiers")
            data = json.loads(contents[0].text)
            keys = list(data.keys())
            assert keys == sorted(keys)


# ---------------------------------------------------------------------------
# Unit tests for markdown parsing helpers
# ---------------------------------------------------------------------------


class TestParseLogsources:
    def test_returns_list(self) -> None:
        result = _parse_logsources(_TAXONOMY_MD)
        assert isinstance(result, list)
        assert len(result) > 0

    def test_windows_process_creation_present(self) -> None:
        result = _parse_logsources(_TAXONOMY_MD)
        entry = next(
            (
                e
                for e in result
                if e.get("product") == "windows"
                and e.get("category") == "process_creation"
            ),
            None,
        )
        assert entry is not None

    def test_windows_security_service_present(self) -> None:
        result = _parse_logsources(_TAXONOMY_MD)
        entry = next(
            (
                e
                for e in result
                if e.get("product") == "windows" and e.get("service") == "security"
            ),
            None,
        )
        assert entry is not None

    def test_entries_have_at_least_one_logsource_key(self) -> None:
        result = _parse_logsources(_TAXONOMY_MD)
        logsource_keys = {"product", "category", "service"}
        for entry in result:
            assert logsource_keys & entry.keys(), f"Entry has no logsource key: {entry}"

    def test_description_included_when_present(self) -> None:
        result = _parse_logsources(_TAXONOMY_MD)
        entry = next(
            (
                e
                for e in result
                if e.get("product") == "windows" and e.get("service") == "security"
            ),
            None,
        )
        assert entry is not None
        assert "description" in entry


class TestParseFields:
    def test_returns_dict(self) -> None:
        result = _parse_fields(_TAXONOMY_MD)
        assert isinstance(result, dict)

    def test_process_creation_fields_present(self) -> None:
        result = _parse_fields(_TAXONOMY_MD)
        assert any("process_creation" in k for k in result)

    def test_known_fields_included(self) -> None:
        result = _parse_fields(_TAXONOMY_MD)
        all_fields: list[str] = []
        for fields in result.values():
            all_fields.extend(fields)
        assert "Image" in all_fields
        assert "CommandLine" in all_fields

    def test_fields_are_sorted(self) -> None:
        result = _parse_fields(_TAXONOMY_MD)
        for category, fields in result.items():
            assert fields == sorted(fields), f"Fields for {category} are not sorted"

    def test_empty_markdown_returns_empty_dict(self) -> None:
        assert _parse_fields("# No fields here") == {}


class TestParseTags:
    def test_returns_dict(self) -> None:
        result = _parse_tags(_TAGS_MD)
        assert isinstance(result, dict)

    def test_attack_namespace_present(self) -> None:
        result = _parse_tags(_TAGS_MD)
        assert "attack" in result

    def test_cve_namespace_present(self) -> None:
        result = _parse_tags(_TAGS_MD)
        assert "cve" in result

    def test_description_is_string(self) -> None:
        result = _parse_tags(_TAGS_MD)
        for namespace, description in result.items():
            assert isinstance(
                description, str
            ), f"Description for {namespace} is not str"

    def test_attack_description_non_empty(self) -> None:
        result = _parse_tags(_TAGS_MD)
        assert result["attack"].strip() != ""

    def test_empty_markdown_returns_empty_dict(self) -> None:
        assert _parse_tags("# No namespaces") == {}


# ---------------------------------------------------------------------------
# Integration tests for the new resources
# ---------------------------------------------------------------------------


class TestNewResources:
    @pytest.mark.anyio
    async def test_logsources_returns_list(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://logsources")
            data = json.loads(contents[0].text)
            assert isinstance(data, list)
            assert len(data) > 0

    @pytest.mark.anyio
    async def test_logsources_entries_have_logsource_keys(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://logsources")
            data = json.loads(contents[0].text)
            logsource_keys = {"product", "category", "service"}
            for entry in data:
                assert logsource_keys & entry.keys()

    @pytest.mark.anyio
    async def test_logsources_contains_windows_process_creation(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://logsources")
            data = json.loads(contents[0].text)
            entry = next(
                (
                    e
                    for e in data
                    if e.get("product") == "windows"
                    and e.get("category") == "process_creation"
                ),
                None,
            )
            assert entry is not None

    @pytest.mark.anyio
    async def test_fields_for_known_category_returns_list(self) -> None:
        async with Client(mcp) as client:
            fields_map = _parse_fields(_TAXONOMY_MD)
            if not fields_map:
                pytest.skip("No field categories in fixture")
            category = next(iter(fields_map))
            contents = await client.read_resource(f"sigma://fields/{category}")
            data = json.loads(contents[0].text)
            assert isinstance(data, list)
            assert len(data) > 0

    @pytest.mark.anyio
    async def test_fields_for_unknown_category_returns_empty_list(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://fields/nonexistent_category")
            data = json.loads(contents[0].text)
            assert data == []

    @pytest.mark.anyio
    async def test_tags_returns_dict(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://tags")
            data = json.loads(contents[0].text)
            assert isinstance(data, dict)
            assert len(data) > 0

    @pytest.mark.anyio
    async def test_tags_contains_attack_namespace(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://tags")
            data = json.loads(contents[0].text)
            assert "attack" in data

    @pytest.mark.anyio
    async def test_tags_values_are_strings(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://tags")
            data = json.loads(contents[0].text)
            for val in data.values():
                assert isinstance(val, str)

    @pytest.mark.anyio
    async def test_specification_returns_string(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://specification")
            assert isinstance(contents[0].text, str)
            assert len(contents[0].text) > 0

    @pytest.mark.anyio
    async def test_specification_contains_sigma_content(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://specification")
            text = contents[0].text
            assert "Sigma" in text


class TestFetchSpec:
    @pytest.mark.anyio
    async def test_cache_hit_does_not_require_network(self) -> None:
        """When the URL is already in the cache, the cached value is returned."""
        _spec_cache["https://example.com/test"] = "cached content"
        try:
            result = await _fetch_spec("https://example.com/test")
            assert result == "cached content"
        finally:
            _spec_cache.pop("https://example.com/test", None)

    @pytest.mark.anyio
    async def test_cache_populated_after_fetch(self) -> None:
        """Result is stored in cache after a (mocked) HTTP fetch."""
        from unittest.mock import AsyncMock, MagicMock

        test_url = "https://example.com/mock"
        _spec_cache.pop(test_url, None)
        try:
            mock_response = MagicMock()
            mock_response.text = "mock markdown"
            mock_response.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.get = AsyncMock(return_value=mock_response)

            with patch("sigma.mcp.main.httpx.AsyncClient", return_value=mock_client):
                result = await _fetch_spec(test_url)

            assert result == "mock markdown"
            assert _spec_cache[test_url] == "mock markdown"
        finally:
            _spec_cache.pop(test_url, None)


class TestMain:
    def test_main_calls_mcp_run(self) -> None:
        from sigma.mcp.main import main

        with patch.object(mcp, "run") as mock_run:
            main()
            mock_run.assert_called_once()


class TestPrompts:
    @pytest.mark.anyio
    async def test_prompt_create_listed(self) -> None:
        async with Client(mcp) as client:
            prompts = await client.list_prompts()
            names = [p.name for p in prompts]
            assert "create_sigma_rule_from_description" in names

    @pytest.mark.anyio
    async def test_prompt_create_content(self) -> None:
        async with Client(mcp) as client:
            result = await client.get_prompt(
                "create_sigma_rule_from_description",
                {"description": "lateral movement via PsExec"},
            )
            text = " ".join(
                msg.content.text
                for msg in result.messages
                if isinstance(msg.content, TextContent)
            )
            assert "validate_rule" in text
            assert "lateral movement via PsExec" in text

    @pytest.mark.anyio
    async def test_prompt_url_listed(self) -> None:
        async with Client(mcp) as client:
            prompts = await client.list_prompts()
            names = [p.name for p in prompts]
            assert "create_sigma_rules_from_url" in names

    @pytest.mark.anyio
    async def test_prompt_url_content(self) -> None:
        async with Client(mcp) as client:
            result = await client.get_prompt(
                "create_sigma_rules_from_url",
                {"url": "https://example.com/blog"},
            )
            text = " ".join(
                msg.content.text
                for msg in result.messages
                if isinstance(msg.content, TextContent)
            )
            assert "validate_rule" in text
            assert "https://example.com/blog" in text


# ---------------------------------------------------------------------------
# Windows event helpers and resources
# ---------------------------------------------------------------------------

_WIN_EVENTS_SAMPLE_MD = """\
# 4624(S): An account was successfully logged on.

<Event>
  <Channel>Security</Channel>
  <EventID>4624</EventID>
</Event>

Some description here.
"""


@pytest.fixture(autouse=True)
def clear_win_event_content_cache() -> Generator[None, None, None]:
    """Clear the Windows event content cache before and after each test."""
    _win_event_content_cache.clear()
    yield
    _win_event_content_cache.clear()


class TestParseWinEventTitle:
    def test_extracts_h1_title(self) -> None:
        assert _parse_win_event_title(_WIN_EVENTS_SAMPLE_MD) == (
            "An account was successfully logged on."
        )

    def test_returns_empty_string_when_no_h1(self) -> None:
        assert _parse_win_event_title("No heading here\nJust text.") == ""

    def test_strips_whitespace(self) -> None:
        md = "#  Spaced Title  \nBody"
        assert _parse_win_event_title(md) == "Spaced Title"


class TestParseWinEventChannel:
    def test_extracts_security_channel(self) -> None:
        assert _parse_win_event_channel(_WIN_EVENTS_SAMPLE_MD) == "security"

    def test_lowercases_channel(self) -> None:
        md = "<Channel>SECURITY</Channel>"
        assert _parse_win_event_channel(md) == "security"

    def test_defaults_to_security_when_absent(self) -> None:
        assert _parse_win_event_channel("No channel XML here.") == "security"


class TestWinEventIndex:
    def test_index_is_non_empty_dict(self) -> None:
        assert isinstance(_WIN_EVENT_INDEX, dict)
        assert len(_WIN_EVENT_INDEX) > 0

    def test_security_channel_present(self) -> None:
        assert "security" in _WIN_EVENT_INDEX

    def test_event_4624_present(self) -> None:
        assert "4624" in _WIN_EVENT_INDEX["security"]

    def test_event_titles_are_strings(self) -> None:
        for event_id, title in _WIN_EVENT_INDEX["security"].items():
            assert isinstance(event_id, str)
            assert isinstance(title, str)
            assert len(title) > 0


class TestWindowsEventsResource:
    @pytest.mark.anyio
    async def test_list_windows_events_returns_dict(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://events/windows")
            data = json.loads(contents[0].text)
            assert isinstance(data, dict)

    @pytest.mark.anyio
    async def test_list_windows_events_has_security_channel(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://events/windows")
            data = json.loads(contents[0].text)
            assert "security" in data

    @pytest.mark.anyio
    async def test_list_windows_events_security_values_are_strings(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://events/windows")
            data = json.loads(contents[0].text)
            for _eid, title in data["security"].items():
                assert isinstance(title, str)

    @pytest.mark.anyio
    async def test_get_windows_event_returns_markdown(self) -> None:
        with patch("sigma.mcp.main.httpx.AsyncClient") as mock_client_cls:
            mock_response = mock_client_cls.return_value.__aenter__.return_value
            mock_response.get = mock_response.get
            import asyncio

            async def _fake_get(url: str) -> Any:
                class _R:
                    text = _WIN_EVENTS_SAMPLE_MD

                    def raise_for_status(self) -> None:
                        pass

                return _R()

            mock_response.get = _fake_get
            async with Client(mcp) as client:
                contents = await client.read_resource(
                    "sigma://events/windows/security/4624"
                )
                assert "4624" in contents[0].text

    @pytest.mark.anyio
    async def test_get_windows_event_cached_after_first_fetch(self) -> None:
        with patch("sigma.mcp.main.httpx.AsyncClient") as mock_client_cls:
            mock_response = mock_client_cls.return_value.__aenter__.return_value

            async def _fake_get(url: str) -> Any:
                class _R:
                    text = _WIN_EVENTS_SAMPLE_MD

                    def raise_for_status(self) -> None:
                        pass

                return _R()

            mock_response.get = _fake_get
            async with Client(mcp) as client:
                await client.read_resource("sigma://events/windows/security/4624")
            assert "4624" in _win_event_content_cache

    @pytest.mark.anyio
    async def test_get_windows_event_uses_cache_on_second_call(self) -> None:
        _win_event_content_cache["4624"] = _WIN_EVENTS_SAMPLE_MD
        with patch("sigma.mcp.main.httpx.AsyncClient") as mock_client_cls:
            async with Client(mcp) as client:
                contents = await client.read_resource(
                    "sigma://events/windows/security/4624"
                )
            mock_client_cls.assert_not_called()
        assert _WIN_EVENTS_SAMPLE_MD in contents[0].text
