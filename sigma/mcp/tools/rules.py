"""MCP tools for creating and validating Sigma rules."""

from __future__ import annotations

import uuid
from collections import Counter
from typing import Any

import yaml
from fastmcp import Context
from sigma.exceptions import SigmaError
from sigma.rule.base import check_alias_expansion

from sigma.mcp.index_manager import index_manager
from sigma.mcp.knowledge.logsources import LOGSOURCES
from sigma.mcp.index import logsource_key
from sigma.mcp.naming import build_filename, filename_issues
from sigma.mcp.reference_data import reference_data
from sigma.mcp.server import mcp
from sigma.mcp.validation import (
    all_validators,
    get_active_validators,
    parse_rules,
    run_validators,
)

# Session state keys
_STATE_VALIDATOR_NAMES = "validator_names"
_STATE_EXCLUSIONS = "excluded_validators"

# Fallback for connections without a session (2026-07-28 protocol), where
# ctx.set_state does not persist between requests.  The process-wide copy is
# only used on transports that serve a single client (stdio, in-memory): over
# HTTP it would leak one client's configuration to everybody else.
_current_validator_names: list[str] | None = None
_current_exclusions: list[str] = []

_SHARED_TRANSPORTS = ("sse", "streamable-http")


def _single_client(ctx: Context) -> bool:
    """Return ``True`` when this process serves only the calling client."""
    return ctx.transport not in _SHARED_TRANSPORTS


def _unknown(names: list[str]) -> list[str]:
    return [n for n in names if n not in all_validators]


@mcp.tool()
async def validate_rule(
    ctx: Context,
    rule_yaml: str,
    validator_names: list[str] | None = None,
    exclusions: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Validate Sigma rules using the configured pySigma validators.

    Accepts a single rule or several YAML documents separated by ``---``,
    including correlation rules together with the rules they reference.
    Fresh validator instances are created for every call; within one call
    they check all rules, so uniqueness checks work across them.

    This is the canonical way to validate Sigma rules — do not use pytest,
    shell commands, or any external test runner for validation.

    Args:
        rule_yaml: Complete Sigma rule(s) in YAML format.
        validator_names: Validators to use for this call only, instead of
            the ones stored with ``configure_validators`` (``null`` = stored
            configuration, by default all validators).
        exclusions: Validators to skip for this call only, instead of the
            stored exclusions.

    Returns:
        List of validation issue dicts.  Each dict contains at minimum the keys
        ``validator``, ``type``, ``severity``, ``description`` and ``rules``.
        Rules that cannot be parsed are reported with ``validator: parser``,
        ``type: SigmaParseError`` and the pySigma exception in
        ``error_class``; they are not run through the validators.  A
        correlation rule referencing a rule missing from *rule_yaml* is
        reported the same way.  Issues of type ``ValidatorError`` (a
        validator crashed) and ``ValidatorSkipped`` (its MITRE ATT&CK or
        D3FEND data is not available yet) are not problems with the rule.
        An empty list means no issues were found.
    """
    invalid = _unknown((validator_names or []) + (exclusions or []))
    if invalid:
        return [
            {
                "validator": "configuration",
                "type": "UnknownValidator",
                "severity": "high",
                "description": f"Unknown validators: {invalid}",
                "rules": [],
            }
        ]
    if validator_names is None:
        validator_names = await ctx.get_state(_STATE_VALIDATOR_NAMES)
        if _single_client(ctx) and _current_validator_names is not None:
            validator_names = _current_validator_names
    if exclusions is None:
        exclusions = await ctx.get_state(_STATE_EXCLUSIONS)
        if _single_client(ctx) and _current_exclusions:
            exclusions = _current_exclusions
    active = get_active_validators(validator_names, exclusions or [])

    # Validators whose MITRE data is not loaded yet would block on a
    # download; skip them and say so (see sigma.mcp.reference_data).
    reference_data.start_loading()
    skipped = {
        name: reason
        for name, reason in reference_data.unavailable_validators().items()
        if name in active
    }
    active = {name: cls for name, cls in active.items() if name not in skipped}

    rules, issues = parse_rules(rule_yaml)
    issues += run_validators(rules, active)
    issues += [
        {
            "validator": name,
            "type": "ValidatorSkipped",
            "severity": "low",
            "description": (
                f"The validator was skipped because {reason}. This is not a "
                "problem with the rule."
            ),
            "rules": [],
        }
        for name, reason in skipped.items()
    ]
    return issues


@mcp.tool()
async def configure_validators(
    ctx: Context,
    validator_names: list[str] | None = None,
    exclusions: list[str] | None = None,
) -> dict[str, Any]:
    """Configure which pySigma validators are used for rule validation.

    The configuration is stored in the MCP session and persists for all
    subsequent ``validate_rule`` calls within the same session.  Over HTTP,
    clients without a session (protocol 2026-07-28) cannot keep it between
    calls; pass ``validator_names`` and ``exclusions`` to ``validate_rule``
    instead.

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
    result: dict[str, Any] = {
        "validator_names": validator_names,
        "exclusions": exc_list,
    }
    if _single_client(ctx):
        global _current_validator_names, _current_exclusions
        _current_validator_names = validator_names
        _current_exclusions = exc_list
    else:
        result["note"] = (
            "On this shared HTTP server the configuration only persists for "
            "clients with an MCP session. To be sure, pass validator_names "
            "and exclusions to validate_rule directly."
        )
    return result


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


_MAX_LOGSOURCE_RESULTS = 10
_MIN_QUERY_WORD = 3


def _searchable(key: str, info: dict[str, Any]) -> str:
    parts = [
        key,
        info.get("description", ""),
        " ".join(info["logsource"].values()),
        " ".join(info.get("tips", [])),
        " ".join(info.get("fields", {})),
        " ".join(f"{eid} {text}" for eid, text in info.get("event_ids", {}).items()),
    ]
    return " ".join(parts).lower()


def _sigmahq_usage(logsource: dict[str, str]) -> dict[str, Any] | None:
    index = index_manager.get_index()
    if index is None:
        return None
    stats = index.logsources.get(
        logsource_key(
            logsource.get("product"),
            logsource.get("category"),
            logsource.get("service"),
        )
    )
    if stats is None:
        return {"rule_count": 0, "top_fields": []}
    return {
        "rule_count": stats.rule_count,
        "top_fields": [
            {"field": name, "rule_count": count} for name, count in stats.top_fields(10)
        ],
    }


@mcp.tool()
def get_logsource_info(
    activity_description: str, max_results: int = 4
) -> dict[str, Any]:
    """Suggest Sigma logsources for an activity, with fields, event IDs and tips.

    Call this before drafting a rule to choose the logsource and field names.
    Generic categories (e.g. ``process_creation``) are usually preferable to
    a specific service and event ID.

    Args:
        activity_description: What should be detected, e.g. ``"scheduled
            task created via schtasks"`` or ``"4624 logon from new IP"``.
        max_results: Number of logsources to return (1–10).

    Returns:
        Dict with ``results``, best match first.  Each has ``key``,
        ``logsource`` (the YAML ``logsource`` block to use), ``description``,
        ``fields`` (field → meaning), ``event_ids``, ``tips`` and
        ``sigmahq`` (``rule_count`` and the ``top_fields`` that SigmaHQ
        rules use for it, or ``null`` while the rule index is not ready).
        ``fallback`` is ``true`` when nothing matched and the most common
        logsource is returned instead.  ``sigma://logsources`` lists every
        logsource of the specification.
    """
    words = [
        w for w in activity_description.lower().split() if len(w) >= _MIN_QUERY_WORD
    ]
    scored: list[tuple[int, str]] = []
    for key, info in LOGSOURCES.items():
        text = _searchable(key, info)
        score = sum(2 for word in words if word in text)
        if score:
            scored.append((score, key))
    scored.sort(key=lambda item: (-item[0], item[1]))
    fallback = not scored
    if fallback:
        scored = [(0, "process_creation_windows")]
    limit = min(max(max_results, 1), _MAX_LOGSOURCE_RESULTS)
    results = []
    for score, key in scored[:limit]:
        info = LOGSOURCES[key]
        results.append(
            {
                "key": key,
                "score": score,
                "logsource": dict(info["logsource"]),
                "description": info.get("description", ""),
                "fields": dict(info.get("fields", {})),
                "event_ids": dict(info.get("event_ids", {})),
                "tips": list(info.get("tips", [])),
                "sigmahq": _sigmahq_usage(info["logsource"]),
            }
        )
    return {
        "index_status": index_manager.status.value,
        "fallback": fallback,
        "results": results,
    }


def _first_documents(rule_yaml: str) -> tuple[str | None, dict[str, str]]:
    """Return the first title and the first logsource found in *rule_yaml*.

    Raises:
        yaml.YAMLError: The YAML is invalid.
        SigmaError: YAML aliases would expand to too many nodes.
    """
    documents = list(yaml.safe_load_all(rule_yaml))
    # Reject alias bombs before any value is turned into text.
    check_alias_expansion(documents)
    title: str | None = None
    logsource: dict[str, str] = {}
    for document in documents:
        if not isinstance(document, dict):
            continue
        if title is None and isinstance(document.get("title"), str):
            title = document["title"]
        raw = document.get("logsource")
        if not logsource and isinstance(raw, dict):
            logsource = {
                k: v
                for k, v in raw.items()
                if k in ("product", "category", "service") and isinstance(v, str) and v
            }
    return title, logsource


@mcp.tool()
def suggest_rule_filename(rule_yaml: str) -> dict[str, Any]:
    """Suggest a file name for a Sigma rule following the SigmaHQ conventions.

    The name is the logsource prefix SigmaHQ requires (for example
    ``proc_creation_win_`` or ``win_security_``) followed by the title in
    lower case with underscores, at most 90 characters, ending in ``.yml``.
    For several YAML documents the first title and the first logsource are
    used.

    Args:
        rule_yaml: The rule in YAML format.

    Returns:
        Dict with ``filename``, ``prefix`` and ``issues`` (naming rules the
        suggestion still violates, e.g. a title that is too short).
        ``sigmahq`` has ``existing_rule`` (path of a SigmaHQ rule with the
        same file name, which must be avoided) and ``suggested_directory``
        (where SigmaHQ keeps rules with this logsource); it is ``null``
        while the rule index is not ready.  On invalid input the dict holds
        only ``error``.
    """
    try:
        title, logsource = _first_documents(rule_yaml)
    except (yaml.YAMLError, SigmaError) as exc:
        return {"error": f"Invalid YAML: {exc}"}
    if not title or not title.strip():
        return {"error": "The rule needs a non-empty 'title'."}
    filename, prefix = build_filename(title, logsource)
    result: dict[str, Any] = {
        "filename": filename,
        "prefix": prefix,
        "issues": filename_issues(filename),
        "sigmahq": None,
    }
    index = index_manager.get_index()
    if index is not None:
        existing = next(
            (e.path for e in index.rules if e.path.rsplit("/", 1)[-1] == filename),
            None,
        )
        key = logsource_key(
            logsource.get("product"),
            logsource.get("category"),
            logsource.get("service"),
        )
        directories = Counter(
            e.path.rsplit("/", 1)[0]
            for e in index.rules
            if e.rule_set == "rules"
            and logsource_key(
                e.logsource.get("product"),
                e.logsource.get("category"),
                e.logsource.get("service"),
            )
            == key
        )
        result["sigmahq"] = {
            "existing_rule": existing,
            "suggested_directory": (
                directories.most_common(1)[0][0] if directories else None
            ),
        }
        if existing:
            result["issues"].append(
                f"SigmaHQ already has a rule with this file name ({existing}). "
                "Make the title more specific."
            )
    return result
