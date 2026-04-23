"""Sigma MCP server exposing pySigma functionality via FastMCP."""

from __future__ import annotations

import dataclasses
import re
from typing import Any

import httpx
from fastmcp import Context, FastMCP
from fastmcp.prompts import Message
from sigma.exceptions import SigmaError
from sigma.modifiers import modifier_mapping
from sigma.rule import SigmaRule
from sigma.validators.base import SigmaRuleValidator, SigmaValidationIssue
from sigma.validators.core import validators as _raw_validators

# Typed reference to the core validator registry
all_validators: dict[str, type[SigmaRuleValidator]] = dict(_raw_validators)

# ---------------------------------------------------------------------------
# Sigma specification URLs (fetched once, cached for server lifetime)
# ---------------------------------------------------------------------------

_SPEC_URL_TAXONOMY = (
    "https://raw.githubusercontent.com/SigmaHQ/sigma-specification/main/"
    "specification/sigma-appendix-taxonomy.md"
)
_SPEC_URL_TAGS = (
    "https://raw.githubusercontent.com/SigmaHQ/sigma-specification/main/"
    "specification/sigma-appendix-tags.md"
)
_SPEC_URL_RULES = (
    "https://raw.githubusercontent.com/SigmaHQ/sigma-specification/main/"
    "specification/sigma-rules-specification.md"
)

_spec_cache: dict[str, str] = {}


async def _fetch_spec(url: str) -> str:
    """Fetch *url* and return the response text.

    Results are cached in ``_spec_cache`` keyed by URL so that each remote
    document is fetched at most once per server process lifetime.
    """
    if url not in _spec_cache:
        async with httpx.AsyncClient(follow_redirects=True, timeout=30) as client:
            response = await client.get(url)
            response.raise_for_status()
            _spec_cache[url] = response.text
    return _spec_cache[url]


# ---------------------------------------------------------------------------
# Markdown parsing helpers (pure, sync)
# ---------------------------------------------------------------------------


def _parse_logsources(markdown: str) -> list[dict[str, str]]:
    """Parse the Sigma taxonomy appendix and return all valid log source entries.

    Each entry is a dict with some subset of the keys ``product``, ``category``,
    ``service`` (derived from the ``<br>``-separated ``key: value`` pairs in the
    Logsource table column), plus ``description`` when present.  Keys that are
    absent from a particular table row are omitted from the returned dict.

    Args:
        markdown: Full text of the sigma-appendix-taxonomy.md document.

    Returns:
        List of log source dicts, one per table row that contains logsource data.
    """
    results: list[dict[str, str]] = []
    # Each table row: | Product col | Logsource col | Description col |
    row_re = re.compile(r"^\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|$", re.MULTILINE)
    for m in row_re.finditer(markdown):
        logsource_cell = m.group(2)
        description_cell = m.group(3).strip()
        # Only rows that contain logsource key:value pairs
        if ":" not in logsource_cell:
            continue
        # Split on <br> (case-insensitive) to get individual key: value pairs
        parts = re.split(r"<br>", logsource_cell, flags=re.IGNORECASE)
        entry: dict[str, str] = {}
        for part in parts:
            kv = part.strip()
            if ":" in kv:
                key, _, value = kv.partition(":")
                key = key.strip().lower()
                value = value.strip()
                if key in ("product", "category", "service") and value:
                    entry[key] = value
        if entry:
            if description_cell and not description_cell.startswith("-"):
                entry["description"] = description_cell
            results.append(entry)
    return results


def _parse_fields(markdown: str) -> dict[str, list[str]]:
    """Parse field-name tables from the ``## Fields`` section of the taxonomy.

    Returns a mapping of *category slug* → sorted list of field names.  Only
    categories that have an explicit table in the spec are included; most
    Sysmon-based Windows categories share the ``process_creation`` field set and
    are not repeated in the spec.

    Args:
        markdown: Full text of the sigma-appendix-taxonomy.md document.

    Returns:
        Dict mapping category name to sorted list of field name strings.
    """
    # Locate the ## Fields section (everything after it up to the next ## section)
    fields_match = re.search(r"^## Fields\s*$", markdown, re.MULTILINE)
    if not fields_match:
        return {}
    fields_section = markdown[fields_match.end() :]
    # Truncate at the next level-2 heading
    next_h2 = re.search(r"^## ", fields_section, re.MULTILINE)
    if next_h2:
        fields_section = fields_section[: next_h2.start()]

    results: dict[str, list[str]] = {}

    # Find all level-3/4 headings that indicate a category, then collect table rows
    # Strategy: find subsection headings and the table rows that follow them
    subsection_re = re.compile(r"^#{3,4}\s+(.+)$", re.MULTILINE)
    table_row_re = re.compile(r"^\|\s*`?([A-Za-z_][A-Za-z0-9_.]*)`?\s*\|", re.MULTILINE)

    # Split section by subsection headings to find field tables per heading
    positions = [
        (m.start(), m.group(1).strip()) for m in subsection_re.finditer(fields_section)
    ]
    positions.append((len(fields_section), ""))

    for i, (start, heading) in enumerate(positions[:-1]):
        end = positions[i + 1][0]
        chunk = fields_section[start:end]
        # Extract first-column values from table rows (skip header/separator rows)
        fields: list[str] = []
        for row_m in table_row_re.finditer(chunk):
            candidate = row_m.group(1).strip()
            # Skip markdown separator rows and column header rows
            if re.match(r"^[-:]+$", candidate) or candidate.lower() in (
                "field name",
                "field",
                "name",
            ):
                continue
            fields.append(candidate)
        if fields:
            # Derive a slug from the heading: lowercase, spaces → underscore
            slug = re.sub(r"\s+", "_", heading.lower())
            slug = re.sub(r"[^a-z0-9_]", "", slug)
            results[slug] = sorted(set(fields))

    return results


def _parse_tags(markdown: str) -> dict[str, str]:
    """Parse the tag namespace descriptions from the Sigma tags appendix.

    Args:
        markdown: Full text of the sigma-appendix-tags.md document.

    Returns:
        Dict mapping namespace name (e.g. ``attack``) to a description string
        taken from the prose immediately following the ``### Namespace: X`` heading.
    """
    results: dict[str, str] = {}
    # Find all "### Namespace: X" headings
    ns_re = re.compile(r"^### Namespace:\s*(\S+)\s*$", re.MULTILINE)
    matches = list(ns_re.finditer(markdown))
    for idx, m in enumerate(matches):
        name = m.group(1).strip()
        # Capture text until next ### heading or end of string
        start = m.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(markdown)
        body = markdown[start:end].strip()
        # Take only non-bullet, non-table prose lines for the description
        prose_lines: list[str] = []
        for line in body.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith(("-", "*", "|", "#")):
                break
            prose_lines.append(stripped)
        description = " ".join(prose_lines).strip()
        results[name] = description
    return results


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
    markdown = await _fetch_spec(_SPEC_URL_TAXONOMY)
    return _parse_logsources(markdown)


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
    import json as _json

    markdown = await _fetch_spec(_SPEC_URL_TAXONOMY)
    fields_map = _parse_fields(markdown)
    return _json.dumps(fields_map.get(category, []))


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
    markdown = await _fetch_spec(_SPEC_URL_TAGS)
    return _parse_tags(markdown)


@mcp.resource("sigma://specification")
async def get_specification() -> str:
    """Return the full Sigma rules specification as a Markdown string.

    Fetches the official Sigma Rules Specification document from GitHub on
    first call and caches it for the server's lifetime.

    Use this resource to understand the complete Sigma rule format, including
    required and optional fields, detection syntax, condition grammar, and
    field modifiers, before writing or reviewing a rule.
    """
    return await _fetch_spec(_SPEC_URL_RULES)


@mcp.prompt
def create_sigma_rule_from_description(description: str) -> list[Message]:
    """Guide an LLM to create and validate a Sigma detection rule from a description.

    The prompt instructs the LLM to draft a Sigma rule for the described threat
    or behaviour and then use the ``validate_rule`` MCP tool — not pytest or any
    shell command — to validate it, iterating until all issues are resolved.

    Args:
        description: Natural language description of the threat or behaviour to detect.
    """
    return [
        Message(
            f"Create a Sigma detection rule for the following threat or behaviour:\n\n"
            f"{description}\n\n"
            f"Follow these steps:\n"
            f"1. Read the **sigma://logsources** resource to find valid product/"
            f"category/service combinations, then choose the most appropriate log "
            f"source for the threat described.\n"
            f"2. Read the **sigma://fields/{{category}}** resource (substituting the "
            f"chosen category) to discover the correct field names for that log source. "
            f"Read **sigma://modifiers** for valid field-value modifiers. "
            f"Read **sigma://tags** to select appropriate rule tags. "
            f"Read **sigma://specification** to get a full understanding of the Sigma rule format.\n"
            f"3. Draft a complete Sigma rule in YAML format.\n"
            f"4. Use the **validate_rule** MCP tool to validate the rule — "
            f"do NOT use pytest, shell commands, or any external test runner. "
            f"Pass the complete YAML as the `rule_yaml` argument.\n"
            f"5. If validate_rule returns any issues, fix them in the YAML and call "
            f"validate_rule again.\n"
            f"6. Repeat step 5 until validate_rule returns an empty list.\n"
            f"7. Derive a filename from the rule's `title` field: lowercase, "
            f"spaces replaced by underscores, with a `.yml` extension "
            f"(e.g. title 'Lateral Movement via PsExec' → "
            f"`lateral_movement_via_psexec.yml`).\n"
            f"8. Save the final validated rule YAML to that file using your "
            f"available file-writing tools."
        )
    ]


@mcp.prompt
def create_sigma_rules_from_url(url: str) -> list[Message]:
    """Guide an LLM to create and validate Sigma rules from a blog post or threat report URL.

    The prompt instructs the LLM to fetch the URL using its own tools, extract
    every distinct detection opportunity, and then use the ``validate_rule`` MCP
    tool — not pytest or any shell command — to validate each rule.

    Args:
        url: URL of the blog post or threat intelligence report to process.
    """
    return [
        Message(
            f"Create Sigma detection rules based on the content at this URL:\n\n"
            f"{url}\n\n"
            f"Follow these steps:\n"
            f"1. Fetch the URL using your available tools (web browser, fetch, etc.).\n"
            f"2. Analyse the content to identify every distinct detection opportunity "
            f"(TTPs, attacker behaviours, malicious commands, IOCs expressible as "
            f"log-based detections).\n"
            f"3. Read the **sigma://logsources** resource once to understand valid "
            f"product/category/service combinations. Read **sigma://modifiers** for "
            f"valid field-value modifiers and **sigma://tags** for tag namespaces.\n"
            f"Read **sigma://specification** to get a full understanding of the Sigma rule format.\n"
            f"4. For each detection opportunity:\n"
            f"   a. Choose an appropriate Sigma log source from **sigma://logsources**.\n"
            f"   b. Read **sigma://fields/{{category}}** (substituting the chosen "
            f"category) to use the correct field names.\n"
            f"   c. Draft a complete Sigma rule in YAML format.\n"
            f"   d. Use the **validate_rule** MCP tool to validate the rule — "
            f"do NOT use pytest, shell commands, or any external test runner. "
            f"Pass the complete YAML as the `rule_yaml` argument.\n"
            f"   e. If validate_rule returns any issues, fix them and call "
            f"validate_rule again.\n"
            f"   f. Repeat until validate_rule returns an empty list.\n"
            f"   g. Derive a filename from the rule's `title` field: lowercase, "
            f"spaces replaced by underscores, with a `.yml` extension "
            f"(e.g. title 'Lateral Movement via PsExec' → "
            f"`lateral_movement_via_psexec.yml`).\n"
            f"   h. Save the validated rule YAML to that file using your "
            f"available file-writing tools.\n"
            f"5. After all rules are saved, summarise the files that were written."
        )
    ]


def main() -> None:
    """Entry point for the sigma-mcp-server command."""
    mcp.run()
