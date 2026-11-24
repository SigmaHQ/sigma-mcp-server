"""MCP tools for creating and validating Sigma rules."""

from __future__ import annotations

import uuid
from typing import Any

from fastmcp import Context
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule
from sigma.validators.base import SigmaRuleValidator

from sigma.mcp.server import mcp
from sigma.mcp.validation import all_validators, get_active_validators, issue_to_dict

# Session state keys
_STATE_VALIDATOR_NAMES = "validator_names"
_STATE_EXCLUSIONS = "excluded_validators"

# Workaround for FastMCP state persistence issue: maintain session state separately
# Store state at module level as tests run sequentially and clear between tests
_current_validator_names: list[str] | None = None
_current_exclusions: list[str] = []


@mcp.tool()
async def validate_rule(ctx: Context, rule_yaml: str) -> list[dict[str, Any]]:
    """Validate a Sigma rule using configured pySigma validators.

    A fresh validator instance is created for every call so that stateful
    validators (e.g. uniqueness checks) produce correct results for a single
    rule without carrying over state from previous calls.

    This is the canonical way to validate Sigma rules — do not use pytest,
    shell commands, or any external test runner for validation.

    Args:
        rule_yaml: Complete Sigma rule in YAML format.

    Returns:
        List of validation issue dicts.  Each dict contains at minimum the keys
        ``validator``, ``type``, ``severity``, ``description`` and ``rules``.
        An empty list means no issues were found.
    """
    validator_names: list[str] | None = await ctx.get_state(_STATE_VALIDATOR_NAMES)
    raw_exclusions: list[str] | None = await ctx.get_state(_STATE_EXCLUSIONS)
    # Check module-level cache first, as a workaround for FastMCP state persistence issues
    if _current_validator_names is not None:
        validator_names = _current_validator_names
    if _current_exclusions:
        raw_exclusions = _current_exclusions
    exclusions: list[str] = raw_exclusions if raw_exclusions is not None else []
    active = get_active_validators(validator_names, exclusions)

    try:
        rule = SigmaRule.from_yaml(rule_yaml)
    except SigmaError as exc:
        return [
            {
                "validator": "parser",
                "type": "SigmaParseError",
                "severity": "high",
                "description": str(exc),
                "rules": [],
            }
        ]

    issues: list[dict[str, Any]] = []
    for name, validator_cls in active.items():
        v: SigmaRuleValidator = validator_cls()
        for issue in v.validate(rule):
            issues.append(issue_to_dict(name, issue))
        for issue in v.finalize():
            issues.append(issue_to_dict(name, issue))

    return issues


@mcp.tool()
async def configure_validators(
    ctx: Context,
    validator_names: list[str] | None = None,
    exclusions: list[str] | None = None,
) -> dict[str, Any]:
    """Configure which pySigma validators are used for rule validation.

    The configuration is stored in the MCP session and persists for all
    subsequent ``validate_rule`` calls within the same session.

    Args:
        validator_names: Explicit allow-list of validator identifiers to use.
            Pass ``null`` / ``None`` to use *all* available validators (the
            default after a fresh session start).
        exclusions: Validator identifiers to exclude.  Applied after
            ``validator_names`` filtering, so validators can be excluded even
            when ``validator_names`` is ``null``.

    Returns:
        Dict with the stored ``validator_names`` and ``exclusions`` values, or
        an ``error`` key with a description when unknown identifiers are given.
    """
    if validator_names is not None:
        invalid = [n for n in validator_names if n not in all_validators]
        if invalid:
            return {"error": f"Unknown validators: {invalid}"}

    exc_list: list[str] = exclusions if exclusions is not None else []
    invalid_exc = [n for n in exc_list if n not in all_validators]
    if invalid_exc:
        return {"error": f"Unknown validators in exclusions: {invalid_exc}"}

    await ctx.set_state(_STATE_EXCLUSIONS, exc_list)
    await ctx.set_state(_STATE_VALIDATOR_NAMES, validator_names)
    # Store in module-level variables as a workaround for FastMCP state persistence issues
    global _current_validator_names, _current_exclusions
    _current_validator_names = validator_names
    _current_exclusions = exc_list
    return {"validator_names": validator_names, "exclusions": exc_list}


@mcp.tool()
def generate_uuid() -> str:
    """Generate a unique UUID (version 4) for a Sigma rule ID.

    Returns a new universally unique identifier in standard format
    (e.g. ``12345678-1234-5678-1234-567812345678``).

    Use this tool when creating a new Sigma rule to ensure the rule has a
    valid, unique ``id`` field.

    Returns:
        A UUID string suitable for use as a Sigma rule ``id`` field.
    """
    return str(uuid.uuid4())
