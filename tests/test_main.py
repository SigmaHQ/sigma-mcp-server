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
    _extract_win_event_channel,
    _fetch_spec,
    _get_active_validators,
    _issue_to_dict,
    _parse_fields,
    _parse_logsources,
    _parse_tags,
    _parse_win_event_front_matter,
    _spec_cache,
    _SPEC_URL_RULES,
    _SPEC_URL_TAGS,
    _SPEC_URL_TAXONOMY,
    _WIN_EVENTS_BASE_URL,
    _WIN_EVENTS_INDEX_URL,
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

# ---------------------------------------------------------------------------
# Windows event knowledge-base fixtures
# ---------------------------------------------------------------------------

_WIN_EVENT_4624_MD = f"""\
---
title: 4624(S) An account was successfully logged on. (Windows 10)
description: Describes security event 4624(S) An account was successfully logged on.
ms.pagetype: security
ms.prod: w10
author: Mir0sh
---

# 4624(S): An account was successfully logged on.

***Event XML:***
```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
 <EventID>4624</EventID>
 <Channel>Security</Channel>
 </System>
</Event>
```

Event details here.
"""

_WIN_EVENT_4625_MD = f"""\
---
title: 4625(F) An account failed to log on. (Windows 10)
description: Describes security event 4625(F) An account failed to log on.
ms.pagetype: security
ms.prod: w10
author: Mir0sh
---

# 4625(F): An account failed to log on.

***Event XML:***
```
- <Event>
- <System>
 <EventID>4625</EventID>
 <Channel>Security</Channel>
 </System>
</Event>
```

Event details here.
"""

# Minimal GitHub API JSON listing returned for _WIN_EVENTS_INDEX_URL
_WIN_EVENT_INDEX_JSON = json.dumps(
    [
        {
            "name": "event-4624.md",
            "type": "file",
            "download_url": f"{_WIN_EVENTS_BASE_URL}/event-4624.md",
        },
        {
            "name": "event-4625.md",
            "type": "file",
            "download_url": f"{_WIN_EVENTS_BASE_URL}/event-4625.md",
        },
        # Non-event file — must be filtered out by list_windows_events
        {
            "name": "audit-logon.md",
            "type": "file",
            "download_url": f"{_WIN_EVENTS_BASE_URL}/audit-logon.md",
        },
    ]
)


@pytest.fixture(autouse=True)
def prepopulate_spec_cache() -> Generator[None, None, None]:
    """Pre-fill the module-level spec cache with static fixtures.

    This prevents any network calls during tests and makes the test suite
    fully offline-capable.
    """
    _spec_cache[_SPEC_URL_TAXONOMY] = _TAXONOMY_MD
    _spec_cache[_SPEC_URL_TAGS] = _TAGS_MD
    _spec_cache[_SPEC_URL_RULES] = _RULES_MD
    _spec_cache[_WIN_EVENTS_INDEX_URL] = _WIN_EVENT_INDEX_JSON
    _spec_cache[f"{_WIN_EVENTS_BASE_URL}/event-4624.md"] = _WIN_EVENT_4624_MD
    _spec_cache[f"{_WIN_EVENTS_BASE_URL}/event-4625.md"] = _WIN_EVENT_4625_MD
    yield
    # Clean up after each test so tests are isolated
    _spec_cache.pop(_SPEC_URL_TAXONOMY, None)
    _spec_cache.pop(_SPEC_URL_TAGS, None)
    _spec_cache.pop(_SPEC_URL_RULES, None)
    _spec_cache.pop(_WIN_EVENTS_INDEX_URL, None)
    _spec_cache.pop(f"{_WIN_EVENTS_BASE_URL}/event-4624.md", None)
    _spec_cache.pop(f"{_WIN_EVENTS_BASE_URL}/event-4625.md", None)


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
            assert "create_and_validate_sigma_rule" in names

    @pytest.mark.anyio
    async def test_prompt_create_content(self) -> None:
        async with Client(mcp) as client:
            result = await client.get_prompt(
                "create_and_validate_sigma_rule",
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
# Unit tests for Windows event markdown parsing helpers
# ---------------------------------------------------------------------------


class TestParseWinEventFrontMatter:
    def test_returns_dict_with_title(self) -> None:
        result = _parse_win_event_front_matter(_WIN_EVENT_4624_MD)
        assert "title" in result
        assert "4624" in result["title"]

    def test_returns_dict_with_description(self) -> None:
        result = _parse_win_event_front_matter(_WIN_EVENT_4624_MD)
        assert "description" in result
        assert result["description"] != ""

    def test_keys_are_lowercased(self) -> None:
        result = _parse_win_event_front_matter(_WIN_EVENT_4624_MD)
        for key in result:
            assert key == key.lower(), f"Key '{key}' is not lower-cased"

    def test_dotted_keys_parsed(self) -> None:
        result = _parse_win_event_front_matter(_WIN_EVENT_4624_MD)
        assert "ms.pagetype" in result
        assert result["ms.pagetype"] == "security"

    def test_empty_dict_when_no_front_matter(self) -> None:
        result = _parse_win_event_front_matter(
            "# No front matter here\n\nJust content."
        )
        assert result == {}

    def test_empty_dict_for_empty_string(self) -> None:
        result = _parse_win_event_front_matter("")
        assert result == {}


class TestExtractWinEventChannel:
    def test_extracts_security_channel(self) -> None:
        result = _extract_win_event_channel(_WIN_EVENT_4624_MD)
        assert result == "security"

    def test_channel_is_lowercased(self) -> None:
        md = "<Channel>SECURITY</Channel>"
        result = _extract_win_event_channel(md)
        assert result == "security"

    def test_returns_empty_string_when_no_channel(self) -> None:
        result = _extract_win_event_channel("# No XML here")
        assert result == ""

    def test_returns_empty_string_for_empty_input(self) -> None:
        result = _extract_win_event_channel("")
        assert result == ""

    def test_strips_whitespace_from_channel(self) -> None:
        md = "<Channel>  Security  </Channel>"
        result = _extract_win_event_channel(md)
        assert result == "security"


# ---------------------------------------------------------------------------
# Integration tests for the Windows event resources
# ---------------------------------------------------------------------------


class TestWindowsEventResources:
    @pytest.mark.anyio
    async def test_list_windows_events_returns_list(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://events/windows")
            data = json.loads(contents[0].text)
            assert isinstance(data, list)

    @pytest.mark.anyio
    async def test_list_windows_events_contains_event_4624(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://events/windows")
            data = json.loads(contents[0].text)
            event_ids = [e["event_id"] for e in data]
            assert "4624" in event_ids

    @pytest.mark.anyio
    async def test_list_windows_events_entry_has_required_keys(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://events/windows")
            data = json.loads(contents[0].text)
            assert len(data) > 0
            for entry in data:
                for key in (
                    "event_id",
                    "title",
                    "description",
                    "channel",
                    "resource_url",
                ):
                    assert key in entry, f"Key '{key}' missing from entry {entry}"

    @pytest.mark.anyio
    async def test_list_windows_events_sorted_by_event_id(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://events/windows")
            data = json.loads(contents[0].text)
            ids = [int(e["event_id"]) for e in data]
            assert ids == sorted(ids)

    @pytest.mark.anyio
    async def test_list_windows_events_filters_non_event_files(self) -> None:
        """Files not matching event-<digits>.md must not appear in the overview."""
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://events/windows")
            data = json.loads(contents[0].text)
            names = [e.get("event_id") for e in data]
            # audit-logon.md is in the fixture but should be absent
            assert "audit-logon" not in names

    @pytest.mark.anyio
    async def test_list_windows_events_channel_populated(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://events/windows")
            data = json.loads(contents[0].text)
            entry_4624 = next(e for e in data if e["event_id"] == "4624")
            assert entry_4624["channel"] == "security"

    @pytest.mark.anyio
    async def test_list_windows_events_resource_url_format(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://events/windows")
            data = json.loads(contents[0].text)
            entry_4624 = next(e for e in data if e["event_id"] == "4624")
            assert entry_4624["resource_url"] == "sigma://events/windows/security/4624"

    @pytest.mark.anyio
    async def test_get_windows_event_returns_markdown(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource(
                "sigma://events/windows/security/4624"
            )
            text = contents[0].text
            assert isinstance(text, str)
            assert len(text) > 0

    @pytest.mark.anyio
    async def test_get_windows_event_content_contains_event_id(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource(
                "sigma://events/windows/security/4624"
            )
            assert "4624" in contents[0].text

    @pytest.mark.anyio
    async def test_get_windows_event_uses_shared_cache(self) -> None:
        """After list_windows_events is called, detail lookups must be cache hits."""
        # Pre-load the overview (populates cache for individual events)
        async with Client(mcp) as client:
            await client.read_resource("sigma://events/windows")
            # Now fetch a detail — the cache entry was populated by the overview call
            contents = await client.read_resource(
                "sigma://events/windows/security/4624"
            )
            assert "4624" in contents[0].text

    @pytest.mark.anyio
    async def test_get_windows_event_channel_ignored_for_lookup(self) -> None:
        """The channel segment is cosmetic; any value should return the same content."""
        async with Client(mcp) as client:
            contents_a = await client.read_resource(
                "sigma://events/windows/security/4624"
            )
            contents_b = await client.read_resource("sigma://events/windows/other/4624")
            assert contents_a[0].text == contents_b[0].text
