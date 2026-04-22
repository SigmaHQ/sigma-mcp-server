"""Tests for sigma.mcp.main."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest
from fastmcp.client import Client

from sigma.mcp.main import (
    _get_active_validators,
    _issue_to_dict,
    all_validators,
    mcp,
)
from sigma.validators.core.metadata import (
    IdentifierExistenceIssue,
    IdentifierExistenceValidator,
)

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
    async def test_list_modifiers_resource_returns_list(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://modifiers")
            data = json.loads(contents[0].text)
            assert isinstance(data, list)
            assert len(data) > 0

    @pytest.mark.anyio
    async def test_list_modifiers_contains_core_modifiers(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://modifiers")
            data = json.loads(contents[0].text)
            for expected in ("contains", "startswith", "endswith", "re", "base64"):
                assert expected in data

    @pytest.mark.anyio
    async def test_list_modifiers_is_sorted(self) -> None:
        async with Client(mcp) as client:
            contents = await client.read_resource("sigma://modifiers")
            data = json.loads(contents[0].text)
            assert data == sorted(data)


class TestMain:
    def test_main_calls_mcp_run(self) -> None:
        from sigma.mcp.main import main

        with patch.object(mcp, "run") as mock_run:
            main()
            mock_run.assert_called_once()
