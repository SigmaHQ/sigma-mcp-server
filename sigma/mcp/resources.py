"""MCP resources exposing Sigma reference data."""

from __future__ import annotations

import json
from typing import Any

from sigma.modifiers import modifier_mapping

from sigma.mcp.knowledge.specification import (
    SPEC_URL_RULES,
    SPEC_URL_TAGS,
    SPEC_URL_TAXONOMY,
    fetch_spec,
    parse_fields,
    parse_logsources,
    parse_tags,
)
from sigma.mcp.knowledge.windows_events import WIN_EVENT_INDEX, fetch_windows_event
from sigma.mcp.index_manager import index_manager
from sigma.mcp.pipelines import pipeline_catalog
from sigma.mcp.server import mcp
from sigma.mcp.validation import all_validators


@mcp.resource("sigma://validators")
def list_validators() -> dict[str, str]:
    """List all available Sigma rule validators.

    Returns a dict mapping validator identifier (e.g. ``identifier_existence``)
    to its human-readable description (the class docstring).
    """
    return {name: cls.__doc__ or "" for name, cls in all_validators.items()}


@mcp.resource("sigma://modifiers")
def list_modifiers() -> dict[str, str]:
    """List all available Sigma value modifiers with descriptions.

    Returns a dict mapping modifier name (e.g. ``contains``, ``re``,
    ``base64``) to its description string (the class docstring, or an empty
    string if the class has no docstring).
    """
    return {
        name: (cls.__doc__ or "").strip()
        for name, cls in sorted(modifier_mapping.items())
    }


@mcp.resource("sigma://logsources")
async def list_logsources() -> list[dict[str, str]]:
    """List all valid Sigma log source combinations from the official specification.

    Fetches the Sigma taxonomy appendix on first call and caches it for the
    server's lifetime.  Each entry contains some combination of the keys
    ``product``, ``category``, ``service`` (only keys that are present in the
    spec for that entry) and optionally ``description``.

    Use this resource to choose a valid ``logsource`` block when writing a
    Sigma rule.
    """
    markdown = await fetch_spec(SPEC_URL_TAXONOMY)
    return parse_logsources(markdown)


@mcp.resource("sigma://fields/{category}")
async def get_fields_for_category(category: str) -> str:
    """Return the known field names for a Sigma log source category.

    Fetches the Sigma taxonomy appendix on first call and caches it.  Only
    categories that have an explicit field table in the specification are
    covered (most notably ``process_creation``); other categories will return
    an empty JSON array.  Consult ``sigma://specification`` for the full
    narrative.

    Args:
        category: Log source category slug, e.g. ``process_creation``.

    Returns:
        JSON-encoded sorted list of field name strings, or ``[]`` if the
        category is not documented in the spec.
    """
    markdown = await fetch_spec(SPEC_URL_TAXONOMY)
    fields_map = parse_fields(markdown)
    return json.dumps(fields_map.get(category, []))


@mcp.resource("sigma://tags")
async def list_tags() -> dict[str, str]:
    """List the valid Sigma tag namespaces and their descriptions.

    Fetches the Sigma tags appendix on first call and caches it.  Returns a
    dict mapping namespace name (e.g. ``attack``, ``cve``, ``detection``) to
    a prose description of what the namespace represents and how to use it.

    Use this resource to ensure rule ``tags`` use a recognised namespace and
    follow the correct format (e.g. ``attack.t1059.001``, ``cve.2021-44228``,
    ``detection.threat-hunting``).
    """
    markdown = await fetch_spec(SPEC_URL_TAGS)
    return parse_tags(markdown)


@mcp.resource("sigma://specification")
async def get_specification() -> str:
    """Return the full Sigma rules specification as a Markdown string.

    Fetches the official Sigma Rules Specification document from GitHub on
    first call and caches it for the server's lifetime.

    Use this resource to understand the complete Sigma rule format, including
    required and optional fields, detection syntax, condition grammar, and
    field modifiers, before writing or reviewing a rule.
    """
    return await fetch_spec(SPEC_URL_RULES)


@mcp.resource("sigma://events/windows")
def list_windows_events() -> dict[str, dict[str, str]]:
    """List all documented Windows Security Auditing events grouped by log channel.

    Returns the statically bundled event index as a dict mapping channel name
    (e.g. ``"security"``) to a nested dict mapping event ID string (e.g.
    ``"4624"``) to the event title string.
    Use this resource to identify relevant event IDs when writing Sigma rules
    that target Windows Security logs (``product: windows, service: security``).
    Then read ``sigma://events/windows/{channel}/{event_id}`` for the full
    field-level description of a specific event.
    """
    return WIN_EVENT_INDEX


@mcp.resource("sigma://events/windows/{channel}/{event_id}")
async def get_windows_event(channel: str, event_id: str) -> str:
    """Return the full Microsoft documentation for a Windows event as Markdown.

    Fetched from duckxing/windows-itpro-docs GitHub mirror on first access
    and cached for the server's lifetime. Includes event description, all field
    definitions, and security monitoring recommendations.

    Args:
        channel: Log channel name, e.g. ``security``. Accepted for URI
            consistency; routing is by ``event_id`` alone.
        event_id: Numeric event ID string, e.g. ``4624``.

    Returns:
        Raw Markdown text of the event documentation page.
    """
    return await fetch_windows_event(event_id)


@mcp.resource("sigma://statistics/logsources")
def get_logsource_statistics_resource() -> dict[str, Any]:
    """Full logsource statistics of the SigmaHQ rule repository.

    Returns a dict with ``index_status``, ``generated_at``, ``source_commit``,
    ``total_rules`` and ``logsources``, which maps each logsource key
    (``product/category/service``) to its ``product``, ``category``,
    ``service``, ``rule_count`` and ``fields`` (field name → number of rules
    using it).  While the rule index is not available, the dict holds
    ``index_status`` and a ``message`` instead.
    """
    index = index_manager.get_index()
    if index is None:
        return {
            "index_status": index_manager.status.value,
            "message": index_manager.unavailable_message(),
        }
    return {
        "index_status": index_manager.status.value,
        "generated_at": index.generated_at.isoformat(),
        "source_commit": index.source_commit,
        "total_rules": index.rules_with_logsource,
        "logsources": {
            key: {
                "product": stats.product,
                "category": stats.category,
                "service": stats.service,
                "rule_count": stats.rule_count,
                "fields": dict(stats.top_fields()),
            }
            for key, stats in index.logsources.items()
        },
    }


@mcp.resource("sigma://pipelines/transformations")
def list_pipeline_building_blocks() -> dict[str, dict[str, str]]:
    """All building blocks of Sigma processing pipelines, with descriptions.

    Returns a dict with the sections ``transformations``,
    ``rule_conditions``, ``detection_item_conditions``,
    ``field_name_conditions``, ``postprocessing`` and ``finalizers``.  Each
    maps the identifier used as ``type:`` in pipeline YAML (e.g.
    ``field_name_mapping``, ``logsource``, ``include_fields``) to the first
    paragraph of its pySigma documentation.  Generated from the installed
    pySigma version, so it always matches what ``validate_pipeline``
    accepts.
    """
    return pipeline_catalog()
