"""MCP tool for matching Sigma rules against log events."""

from __future__ import annotations

import time
from functools import partial
from typing import Any

import anyio.to_thread

from sigma.mcp import config
from sigma.mcp.matching import match_events as _match_events
from sigma.mcp.server import mcp


@mcp.tool()
async def match_events(
    rule_yaml: str,
    events: list[Any] | str,
    pipeline_yamls: list[str] | None = None,
    logsource: dict[str, str] | None = None,
    timestamp_field: str | None = None,
) -> dict[str, Any]:
    """Test Sigma rules against log events with pySigma's rule matcher.

    Use this to check that a rule detects the activity it is written for,
    with events from threat reports, sandbox runs, attack datasets or
    incident logs, and that it stays quiet on benign events.  Correlation
    rules are evaluated as well; pass them together with the rules they
    reference (documents separated by ``---``).

    Args:
        rule_yaml: One or more Sigma rules in YAML (several documents and
            correlation rules allowed).
        events: The events: a list of JSON objects (or log lines for keyword
            rules), or text with a JSON array or JSON Lines.  Nested objects
            are flattened to dotted names (``process.executable``); leaf
            names that occur once are also available on their own
            (``Event.EventData.Image`` as ``Image``).  Digit strings are
            compared as numbers.  At most 10 000 events.
        pipeline_yamls: Processing pipelines applied to the rules before
            matching, e.g. a ``field_name_mapping`` from Sigma field names to
            the events' field names (ECS, vendor schemas).
        logsource: ``product``/``category``/``service`` of the events.  Then
            only rules whose logsource matches are tested; the others are
            ``skipped``.  Omit it to test every rule against every event.
        timestamp_field: Field with the event time (ISO 8601 or Unix
            seconds/milliseconds), used to order events for correlations.
            When omitted, the first of ``@timestamp``, ``timestamp``,
            ``UtcTime``, ``TimeCreated``, … that an event has is used.

    Returns:
        Dict with ``complete``, ``summary`` (rules, rules with matches,
        events, matched events), ``events`` (count, ``timestamp_fields``
        used, the field names found, most frequent first) and ``rules``.  Each
        rule has ``status`` (``ok``, ``failed`` when a pipeline rejects it or
        it cannot be compiled, ``skipped`` for another logsource), a
        ``message`` when not ok, ``match_count`` and ``matched_events``
        (positions in ``events``, starting at 0).  Rules also list
        ``detections`` (events matching each named detection on its own,
        to see which selection or filter decides) and ``missing_fields``
        (rule fields no event has, usually a field name mismatch);
        correlations list ``matches`` with ``group`` values and the
        contributing events.  ``events_without_match`` lists events no rule
        matched, ``issues`` rules that could not be parsed and ``notes``
        hints.  When the time limit is reached, ``complete`` is ``false``
        and ``unprocessed_events`` counts the rest.  Invalid input gives a
        dict with ``error``.
    """
    limit = config.tool_time_limit()
    deadline = None if limit is None else time.monotonic() + limit
    # Matching is CPU-bound; keep the event loop free for other requests.
    return await anyio.to_thread.run_sync(
        partial(
            _match_events,
            rule_yaml,
            events,
            pipeline_yamls=pipeline_yamls,
            logsource=logsource,
            timestamp_field=timestamp_field,
            deadline=deadline,
        )
    )
