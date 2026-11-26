"""Fetching and parsing of the official Sigma specification documents."""

from __future__ import annotations

import re

import httpx

# ---------------------------------------------------------------------------
# Sigma specification URLs (fetched once, cached for server lifetime)
# ---------------------------------------------------------------------------

SPEC_URL_TAXONOMY = (
    "https://raw.githubusercontent.com/SigmaHQ/sigma-specification/main/"
    "specification/sigma-appendix-taxonomy.md"
)
SPEC_URL_TAGS = (
    "https://raw.githubusercontent.com/SigmaHQ/sigma-specification/main/"
    "specification/sigma-appendix-tags.md"
)
SPEC_URL_CORRELATION = (
    "https://raw.githubusercontent.com/SigmaHQ/sigma-specification/main/"
    "specification/sigma-correlation-rules-specification.md"
)
SPEC_URL_RULES = (
    "https://raw.githubusercontent.com/SigmaHQ/sigma-specification/main/"
    "specification/sigma-rules-specification.md"
)

_spec_cache: dict[str, str] = {}


async def fetch_spec(url: str) -> str:
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


def parse_logsources(markdown: str) -> list[dict[str, str]]:
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


def parse_fields(markdown: str) -> dict[str, list[str]]:
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
            # Headings name the events ("Process Creation Events"); the log
            # source category is the slug without that suffix (process_creation)
            slug = re.sub(r"_events?$", "", slug)
            results[slug] = sorted(set(fields))

    return results


def parse_tags(markdown: str) -> dict[str, str]:
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
