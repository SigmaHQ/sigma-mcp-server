"""MCP tools for searching the SigmaHQ rules and their logsource statistics.

All tools return immediately.  While the rule index is still being built in
the background they return an ``index_status`` and a ``message`` explaining
the state instead of results.
"""

from __future__ import annotations

from typing import Any

from sigma.mcp.index import RuleEntry, RuleIndex
from sigma.mcp.index_manager import index_manager
from sigma.mcp.server import mcp

MAX_SEARCH_RESULTS = 50
_DESCRIPTION_PREVIEW = 300


def _index_or_status() -> tuple[RuleIndex | None, dict[str, Any]]:
    """Return the index, plus the status fields every response carries."""
    index = index_manager.get_index()
    info: dict[str, Any] = {"index_status": index_manager.status.value}
    if index is None:
        info["message"] = index_manager.unavailable_message()
    return index, info


def _entry_summary(entry: RuleEntry) -> dict[str, Any]:
    description = entry.description
    if len(description) > _DESCRIPTION_PREVIEW:
        description = description[:_DESCRIPTION_PREVIEW].rstrip() + "…"
    return {
        "id": entry.id,
        "title": entry.title,
        "status": entry.status,
        "level": entry.level,
        "kind": entry.kind,
        "description": description,
        "logsource": entry.logsource,
        "tags": entry.tags,
        "path": entry.path,
        "rule_set": entry.rule_set,
    }


@mcp.tool()
def search_rules(query: str, max_results: int = 10) -> dict[str, Any]:
    """Search the SigmaHQ rule repository for rules similar to a detection idea.

    Use this before writing a new rule to find out whether SigmaHQ already
    covers the behaviour, and to learn from similar rules.  Matching is by
    keyword (case-insensitive, at least three characters each): title matches
    rank highest, then tags, then description, logsource, field names and
    file path.  Passing a rule ID returns that rule first.

    Args:
        query: Space-separated keywords, e.g. ``"psexec lateral movement"``,
            ``"lsass memory dump"`` or ``"attack.t1003"``.
        max_results: Number of results to return (1–50).

    Returns:
        Dict with ``index_status`` and ``results``, a list of rule summaries
        (``id``, ``title``, ``status``, ``level``, ``kind``, ``description``,
        ``logsource``, ``tags``, ``path``, ``rule_set``, ``score``), best
        match first.  Use ``get_rule`` with an ``id`` to read the full rule.
        While the index is not available, ``results`` is empty and
        ``message`` explains why.
    """
    index, info = _index_or_status()
    limit = min(max(max_results, 1), MAX_SEARCH_RESULTS)
    results: list[dict[str, Any]] = []
    if index is not None:
        for score, entry in index.search(query, limit):
            results.append({**_entry_summary(entry), "score": score})
    return {**info, "results": results}


@mcp.tool()
def get_rule(rule_id: str) -> dict[str, Any]:
    """Return the full YAML of a rule from the SigmaHQ repository.

    Args:
        rule_id: The rule's ``id`` (UUID) or its ``path`` as returned by
            ``search_rules``.

    Returns:
        Dict with ``index_status`` and ``rule``: the rule summary plus
        ``yaml``, the complete file content.  ``rule`` is ``null`` and
        ``message`` explains why when the rule is unknown or the index is not
        available.
    """
    index, info = _index_or_status()
    if index is None:
        return {**info, "rule": None}
    entry = index.find(rule_id)
    if entry is None:
        return {
            **info,
            "rule": None,
            "message": f"No rule with ID or path {rule_id!r} in the SigmaHQ index.",
        }
    rule_file = index_manager.paths().rules_dir.joinpath(*entry.path.split("/"))
    try:
        content = rule_file.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {
            **info,
            "rule": None,
            "message": (
                f"The rule file {entry.path} could not be read ({exc}). Call "
                "update_sigma_repository to download the rules again."
            ),
        }
    return {**info, "rule": {**_entry_summary(entry), "yaml": content}}


@mcp.tool()
def get_logsource_statistics(
    logsource_filter: str = "", max_fields: int = 10
) -> dict[str, Any]:
    """Show how often each logsource and its fields are used in SigmaHQ rules.

    Use this to decide which logsources and fields a processing pipeline must
    support, or which field names rules for a logsource typically use.

    Args:
        logsource_filter: Case-insensitive substring of the logsource key,
            e.g. ``"windows"`` or ``"process_creation"``.  Empty for all.
        max_fields: Number of most frequent fields to list per logsource.

    Returns:
        Dict with ``index_status``, ``total_rules`` (rules with a logsource)
        and ``logsources``: a list sorted by rule count, each with ``key``
        (``product/category/service``), ``product``, ``category``,
        ``service``, ``rule_count``, ``field_count`` and ``top_fields``
        (``field``, ``rule_count``).  The full statistics are available as
        the ``sigma://statistics/logsources`` resource.
    """
    index, info = _index_or_status()
    if index is None:
        return {**info, "total_rules": 0, "logsources": []}
    needle = logsource_filter.strip().lower()
    selected = [
        stats
        for key, stats in index.logsources.items()
        if not needle or needle in key.lower()
    ]
    selected.sort(key=lambda stats: (-stats.rule_count, stats.key))
    limit = max(max_fields, 0)
    return {
        **info,
        "total_rules": index.rules_with_logsource,
        "logsources": [
            {
                "key": stats.key,
                "product": stats.product,
                "category": stats.category,
                "service": stats.service,
                "rule_count": stats.rule_count,
                "field_count": len(stats.fields),
                "top_fields": [
                    {"field": name, "rule_count": count}
                    for name, count in stats.top_fields(limit)
                ],
            }
            for stats in selected
        ],
    }


@mcp.tool()
def update_sigma_repository() -> dict[str, Any]:
    """Download the latest SigmaHQ rules and rebuild the rule index.

    The update runs in the background and this tool returns at once.  The
    previous index stays usable until the new one is ready.  Call
    ``get_index_status`` to follow the progress.

    Returns:
        Dict with ``started`` (``false`` if an update was already running)
        and the fields of ``get_index_status``.
    """
    started = index_manager.start_refresh()
    return {"started": started, **index_manager.describe()}


@mcp.tool()
def get_index_status() -> dict[str, Any]:
    """Report the state of the SigmaHQ rule index.

    Returns:
        Dict with ``status`` (``not_started``, ``downloading``, ``indexing``,
        ``ready`` or ``failed``), ``refreshing``, ``detail``, ``last_error``,
        ``has_index`` and ``data_dir``.  When an index is available it also
        has ``generated_at``, ``source_commit``, ``rule_count``,
        ``logsource_count`` and ``stale``; otherwise ``message`` explains
        what to do.
    """
    return index_manager.describe()
