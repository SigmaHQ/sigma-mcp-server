"""Sigma MCP server exposing pySigma functionality via FastMCP."""

from __future__ import annotations

import dataclasses
from typing import Any

from fastmcp import Context, FastMCP
from sigma.exceptions import SigmaError
from sigma.modifiers import modifier_mapping
from sigma.rule import SigmaRule
from sigma.validators.base import SigmaRuleValidator, SigmaValidationIssue
from sigma.validators.core import validators as _raw_validators

# Typed reference to the core validator registry
all_validators: dict[str, type[SigmaRuleValidator]] = dict(_raw_validators)

# Session state keys
_STATE_VALIDATOR_NAMES = "validator_names"
_STATE_EXCLUSIONS = "excluded_validators"

mcp: FastMCP = FastMCP("sigma-mcp-server")


def _issue_to_dict(validator_name: str, issue: SigmaValidationIssue) -> dict[str, Any]:
    """Convert a SigmaValidationIssue to a JSON-serialisable dict.

    The returned dict always contains the keys ``validator``, ``type``,
    ``severity``, ``description`` and ``rules``.  Any extra instance fields
    defined on the concrete issue subclass (e.g. ``identifier`` for UUID
    collision issues) are included as additional string-valued keys.
    """
    rule_refs: list[str] = [str(r.id) if r.id else str(r.title) for r in issue.rules]
    extra: dict[str, Any] = {
        f.name: str(getattr(issue, f.name))
        for f in dataclasses.fields(issue)
        if f.name != "rules"
    }
    return {
        "validator": validator_name,
        "type": type(issue).__name__,
        "severity": issue.severity.name.lower(),
        "description": issue.description,
        "rules": rule_refs,
        **extra,
    }


def _get_active_validators(
    validator_names: list[str] | None,
    exclusions: list[str],
) -> dict[str, type[SigmaRuleValidator]]:
    """Return the set of validators that should be applied for a validation run.

    Args:
        validator_names: Explicit allow-list of validator identifiers. ``None``
            means *all* registered validators are included before exclusions are
            applied.
        exclusions: Validator identifiers to remove from the active set.

    Returns:
        Ordered dict mapping identifier → validator class for every validator
        that should be instantiated and executed.
    """
    if validator_names is not None:
        selected: dict[str, type[SigmaRuleValidator]] = {
            n: all_validators[n] for n in validator_names if n in all_validators
        }
    else:
        selected = dict(all_validators)
    return {n: cls for n, cls in selected.items() if n not in exclusions}


@mcp.tool()
async def validate_rule(rule_yaml: str, ctx: Context) -> list[dict[str, Any]]:
    """Validate a Sigma rule using configured pySigma validators.

    A fresh validator instance is created for every call so that stateful
    validators (e.g. uniqueness checks) produce correct results for a single
    rule without carrying over state from previous calls.

    Args:
        rule_yaml: Complete Sigma rule in YAML format.

    Returns:
        List of validation issue dicts.  Each dict contains at minimum the keys
        ``validator``, ``type``, ``severity``, ``description`` and ``rules``.
        An empty list means no issues were found.
    """
    validator_names: list[str] | None = await ctx.get_state(_STATE_VALIDATOR_NAMES)
    raw_exclusions: list[str] | None = await ctx.get_state(_STATE_EXCLUSIONS)
    exclusions: list[str] = raw_exclusions if raw_exclusions is not None else []
    active = _get_active_validators(validator_names, exclusions)

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
            issues.append(_issue_to_dict(name, issue))
        for issue in v.finalize():
            issues.append(_issue_to_dict(name, issue))

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

    await ctx.set_state(_STATE_VALIDATOR_NAMES, validator_names)
    await ctx.set_state(_STATE_EXCLUSIONS, exc_list)
    return {"validator_names": validator_names, "exclusions": exc_list}


@mcp.resource("sigma://validators")
def list_validators() -> dict[str, str]:
    """List all available Sigma rule validators.

    Returns a dict mapping validator identifier (e.g. ``identifier_existence``)
    to its human-readable description (the class docstring).
    """
    return {name: cls.__doc__ or "" for name, cls in all_validators.items()}


@mcp.resource("sigma://modifiers")
def list_modifiers() -> list[str]:
    """List all available Sigma value modifiers.

    Returns a sorted list of modifier names (e.g. ``contains``, ``re``,
    ``base64``) that can be used in Sigma rule detection conditions.
    """
    return sorted(modifier_mapping.keys())


def main() -> None:
    """Entry point for the sigma-mcp-server command."""
    mcp.run()
