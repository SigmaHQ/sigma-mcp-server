"""Match Sigma rules against log events with pySigma's ``sigma.matching``.

Events come from MCP clients, typically samples from threat intelligence
sources (sandbox reports, attack datasets, incident logs).  They are
normalised before matching, because pySigma's matcher looks fields up by
exact name in a flat mapping:

* Nested objects are flattened to dotted field names (``process.executable``),
  and leaf names that occur only once are added as well, so that
  ``{"Event": {"EventData": {"Image": ...}}}`` matches the field ``Image``.
* Strings of digits become integers, so that ``EventID: "4688"`` matches
  ``EventID: 4688``.  String comparisons still see the same text.
* Lists of scalars become their elements joined by spaces.

Rules and pipelines are parsed as by the other tools: rules with the
validation size limit, pipelines with the safe policy (RE2 regular
expressions).  The matcher compiles all regular expressions and wildcards
with the same policy.
"""

from __future__ import annotations

import json
import re
import time
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, cast

from sigma.collection import SigmaCollection
from sigma.conditions import SigmaCondition
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaError
from sigma.matching import Event, EventLogSource, SigmaMatch, SigmaMatcher
from sigma.matching.compiler import CompiledMatcher, MatchCompiler
from sigma.rule import SigmaLogSource, SigmaRule

from sigma.mcp.pipelines import (
    PIPELINE_POLICY,
    ParsedPipeline,
    PipelineParseError,
    combine_pipelines,
    parse_pipeline,
    rule_fields,
    run_pipeline,
    too_many_items,
)
from sigma.mcp.validation import parse_rules

MAX_EVENTS = 10_000
"""Most events one call matches."""

MAX_DEPTH = 32
"""Nesting depth up to which events are flattened; deeper values are kept as
JSON text."""

MAX_LISTED_EVENTS = 100
"""Most event positions listed per rule (and for events without a match)."""

MAX_LISTED_MATCHES = 20
"""Most correlation matches listed per correlation rule."""

MAX_LISTED_FIELDS = 200
"""Most field names listed in the event summary."""

MAX_INTEGER_DIGITS = 18
"""Longer digit strings stay strings."""

TIMESTAMP_FIELDS = (
    "@timestamp",
    "timestamp",
    "Timestamp",
    "UtcTime",
    "TimeCreated",
    "TimeCreated.SystemTime",
    "Event.System.TimeCreated.SystemTime",
    "TimeGenerated",
    "EventTime",
    "event.created",
    "_time",
    "time",
)
"""Fields searched for the event time when no ``timestamp_field`` is given."""

LOGSOURCE_KEYS = ("product", "category", "service")

_INTEGER = re.compile(r"-?(0|[1-9][0-9]*)")
_ANY_LOGSOURCE = SigmaLogSource(product="sigma-mcp-any")
"""Logsource given to rules and events when the events' logsource is not
known, so that every rule is matched against every event."""
_NO_TIMESTAMP = datetime(1970, 1, 1, tzinfo=timezone.utc)


class MatchInputError(Exception):
    """The events or options cannot be used.  The message is for the client."""


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


def load_events(events: list[Any] | str) -> list[Any]:
    """Return the events as a list.

    Args:
        events: A list of events (objects or log lines), or text holding a
            JSON array, a single JSON object or one JSON object per line
            (JSON Lines).

    Raises:
        MatchInputError: The text is not JSON, or there are no or too many
            events.
    """
    if isinstance(events, str):
        events = _load_text(events)
    if not events:
        raise MatchInputError("Pass at least one event.")
    if len(events) > MAX_EVENTS:
        raise MatchInputError(
            f"{len(events)} events were passed; at most {MAX_EVENTS} are "
            "accepted per call. Match the events in several calls."
        )
    return events


def _load_text(text: str) -> list[Any]:
    stripped = text.strip()
    if not stripped:
        return []
    try:
        loaded = json.loads(stripped)
    except RecursionError as exc:
        raise MatchInputError("The events are nested too deeply.") from exc
    except ValueError:
        return _load_lines(stripped)
    return loaded if isinstance(loaded, list) else [loaded]


def _load_lines(text: str) -> list[Any]:
    events: list[Any] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except RecursionError as exc:
            raise MatchInputError(
                f"Event on line {number} is nested too deeply."
            ) from exc
        except ValueError as exc:
            raise MatchInputError(
                "The events are neither a JSON array nor JSON Lines (one JSON "
                f"object per line): line {number}: {exc}"
            ) from exc
    return events


def _normalize(value: Any) -> Any:
    """Make a scalar comparable the way Sigma rules expect."""
    if isinstance(value, str) and len(value) <= MAX_INTEGER_DIGITS + 1:
        if _INTEGER.fullmatch(value):
            return int(value)
    return value


def _scalar_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _flatten(
    value: Any, prefix: str, depth: int, out: dict[str, Any], leaves: Counter[str]
) -> None:
    if isinstance(value, Mapping):
        items: Iterable[tuple[str, Any]] = ((str(k), v) for k, v in value.items())
    elif isinstance(value, list) and any(isinstance(v, (Mapping, list)) for v in value):
        items = ((str(n), v) for n, v in enumerate(value))
    else:
        if isinstance(value, list):
            value = " ".join(_scalar_text(v) for v in value)
        out[prefix] = _normalize(value)
        return
    if depth >= MAX_DEPTH:
        try:
            out[prefix] = json.dumps(value, default=str)
        except RecursionError:
            out[prefix] = "<nested too deeply>"
        return
    for key, child in items:
        name = f"{prefix}.{key}" if prefix else key
        if prefix and not key.isdigit():
            leaves[key] += 1
        _flatten(child, name, depth + 1, out, leaves)


def flatten_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Flatten a nested event into a mapping of field names to scalars.

    Nested fields get dotted names; leaf names that occur only once in the
    event and are no top-level field are added as well.
    """
    flat: dict[str, Any] = {}
    leaves: Counter[str] = Counter()
    for key, value in event.items():
        _flatten(value, str(key), 1, flat, leaves)
    for path, value in list(flat.items()):
        leaf = path.rsplit(".", 1)[-1]
        if leaf != path and leaves[leaf] == 1 and leaf not in flat:
            flat[leaf] = value
    return flat


def parse_timestamp(value: Any) -> datetime | None:
    """Parse an ISO 8601 time or a Unix time in seconds or milliseconds."""
    if isinstance(value, bool):
        return None
    try:
        if isinstance(value, (int, float)):
            seconds = value / 1000 if abs(value) > 1e11 else value
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.strip())
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
    except (ValueError, OverflowError, OSError):
        return None
    return None


@dataclass
class PreparedEvents:
    """The events of one call, ready for matching."""

    events: list[Event]
    """In input order; ``events[n]`` is the event at position ``n``."""
    timestamp_fields: list[str]
    """Fields the event times came from, most used first."""
    with_timestamp: int
    non_objects: int
    """Events that were no JSON object; they are matched as log lines."""
    fields: Counter[str] = field(default_factory=Counter)

    def summary(self) -> dict[str, Any]:
        """The event summary of the reply."""
        names = sorted(self.fields, key=lambda name: (-self.fields[name], name))
        summary: dict[str, Any] = {
            "count": len(self.events),
            "timestamp_fields": self.timestamp_fields,
            "with_timestamp": self.with_timestamp,
            "fields": names[:MAX_LISTED_FIELDS],
        }
        if len(names) > MAX_LISTED_FIELDS:
            summary["omitted_fields"] = len(names) - MAX_LISTED_FIELDS
        if self.non_objects:
            summary["log_lines"] = self.non_objects
        return summary


def _event_time(
    data: Mapping[str, Any], timestamp_field: str | None
) -> tuple[datetime | None, str | None]:
    """The time of one event and the field it came from."""
    for name in (timestamp_field,) if timestamp_field else TIMESTAMP_FIELDS:
        if name in data:
            parsed = parse_timestamp(data[name])
            if parsed is not None:
                return parsed, name
    return None, None


def prepare_events(
    raw_events: list[Any],
    logsource: EventLogSource,
    timestamp_field: str | None = None,
) -> PreparedEvents:
    """Flatten the events and give each a timestamp and the logsource.

    The time comes from *timestamp_field*, or else from the first field of
    :data:`TIMESTAMP_FIELDS` that holds a time.  Events without a time get
    the time of the previous event (the first ones the time of the first
    event with one), so that correlations see them in input order.
    """
    flat_events: list[dict[str, Any]] = []
    raws: list[str] = []
    non_objects = 0
    for raw_event in raw_events:
        if isinstance(raw_event, Mapping):
            flat = flatten_event(raw_event)
            raws.append("\n".join(_scalar_text(v) for v in flat.values()))
        else:
            non_objects += 1
            flat = {}
            raws.append(
                raw_event
                if isinstance(raw_event, str)
                else json.dumps(raw_event, default=str)
            )
        flat_events.append(flat)
    found = [_event_time(data, timestamp_field) for data in flat_events]
    times = [timestamp for timestamp, _ in found]
    sources = Counter(name for _, name in found if name is not None)
    previous = next((t for t in times if t is not None), _NO_TIMESTAMP)
    events: list[Event] = []
    fields: Counter[str] = Counter()
    for data, raw, timestamp in zip(flat_events, raws, times):
        previous = timestamp or previous
        fields.update(data.keys())
        events.append(
            Event(timestamp=previous, logsource=logsource, data=data, raw=raw)
        )
    return PreparedEvents(
        events=events,
        timestamp_fields=sorted(sources, key=lambda name: -sources[name]),
        with_timestamp=sum(t is not None for t in times),
        non_objects=non_objects,
        fields=fields,
    )


def event_logsource(logsource: Mapping[str, Any] | None) -> EventLogSource:
    """The logsource of the events, or the "any" logsource for ``None``.

    Raises:
        MatchInputError: Unknown keys, values that are not strings, or no
            value at all.
    """
    if logsource is None:
        return EventLogSource(product=_ANY_LOGSOURCE.product)
    unknown = sorted(set(logsource) - set(LOGSOURCE_KEYS))
    if unknown:
        raise MatchInputError(
            f"Unknown logsource keys {unknown}; use {list(LOGSOURCE_KEYS)}."
        )
    values = {k: v for k, v in logsource.items() if v not in (None, "")}
    if not values:
        raise MatchInputError(
            "The logsource needs a product, category or service; omit it to "
            "match every rule against every event."
        )
    if not all(isinstance(v, str) for v in values.values()):
        raise MatchInputError("Logsource values must be strings.")
    return EventLogSource(**values)


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def _detection_matcher(
    compiler: MatchCompiler, rule: SigmaRule, name: str
) -> CompiledMatcher:
    """Compile the named detection of *rule* as if it were the condition."""
    stand_in = SimpleNamespace(
        detection=SimpleNamespace(
            parsed_condition=[
                SigmaCondition(name, rule.detection, rule.detection.source)
            ]
        )
    )
    return compiler.compile_rule(cast(SigmaRule, stand_in))


@dataclass
class RuleResult:
    """What one rule did with the events."""

    rule: SigmaRule | SigmaCorrelationRule
    logsource: dict[str, str]
    status: str = "ok"
    message: str | None = None
    transformation: str | None = None
    matches: list[SigmaMatch] = field(default_factory=list)
    detections: dict[str, tuple[CompiledMatcher, list[int]]] = field(
        default_factory=dict
    )
    fields: set[str] = field(default_factory=set)

    def to_json(
        self, positions: Mapping[int, int], event_fields: Counter[str]
    ) -> dict[str, Any]:
        """The rule's entry in the reply; *positions* maps ``id(event)``."""
        rule = self.rule
        is_correlation = isinstance(rule, SigmaCorrelationRule)
        result: dict[str, Any] = {
            "title": rule.title,
            "id": str(rule.id) if rule.id else None,
            "name": rule.name,
            "kind": "correlation" if is_correlation else "rule",
            "status": self.status,
        }
        if self.logsource:
            result["logsource"] = self.logsource
        if self.status != "ok":
            result["message"] = self.message
            if self.transformation is not None:
                result["transformation"] = self.transformation
            return result
        result["match_count"] = len(self.matches)
        if is_correlation:
            result["matches"] = [
                {
                    "timestamp": match.timestamp.isoformat(),
                    "group": match.group_values,
                    "events": sorted({positions[id(e)] for e in match.events}),
                }
                for match in self.matches[:MAX_LISTED_MATCHES]
            ]
            if len(self.matches) > MAX_LISTED_MATCHES:
                result["omitted_matches"] = len(self.matches) - MAX_LISTED_MATCHES
            return result
        matched = [positions[id(m.events[0])] for m in self.matches if m.events]
        result["matched_events"] = matched[:MAX_LISTED_EVENTS]
        result["detections"] = {
            name: len(hits) for name, (_, hits) in self.detections.items()
        }
        missing = sorted(f for f in self.fields if f not in event_fields)
        if missing:
            result["missing_fields"] = missing
        return result


def _logsource_dict(rule: SigmaRule | SigmaCorrelationRule) -> dict[str, str]:
    if not isinstance(rule, SigmaRule):
        return {}
    return {
        key: value
        for key in LOGSOURCE_KEYS
        if (value := getattr(rule.logsource, key)) is not None
    }


def _parse_pipelines(pipeline_yamls: list[str]) -> ParsedPipeline | None:
    parsed: list[ParsedPipeline] = []
    for position, pipeline_yaml in enumerate(pipeline_yamls, start=1):
        try:
            parsed.append(parse_pipeline(pipeline_yaml))
        except PipelineParseError as exc:
            raise MatchInputError(f"Pipeline {position} is invalid: {exc}") from exc
    if not parsed:
        return None
    items_error = too_many_items(sum(len(p.pipeline.items) for p in parsed))
    if items_error is not None:
        raise MatchInputError(items_error)
    return combine_pipelines(parsed)


def _prepare_rule(
    result: RuleResult,
    pipeline: ParsedPipeline | None,
    compiler: MatchCompiler,
    logsource: EventLogSource,
) -> None:
    """Apply the pipeline, check the logsource and compile *result.rule*.

    Sets ``status`` to ``failed`` or ``skipped`` when the rule cannot be
    matched.
    """
    rule = result.rule
    if pipeline is not None:
        outcome = run_pipeline(pipeline.pipeline, rule)
        if outcome.error is not None:
            result.status = "failed"
            result.message = (
                f"The processing pipeline rejected the rule: {outcome.error}"
            )
            if outcome.failed_item is not None:
                result.transformation = pipeline.labels[outcome.failed_item]
            return
    if not isinstance(rule, SigmaRule):
        return
    if logsource.product == _ANY_LOGSOURCE.product:
        rule.logsource = _ANY_LOGSOURCE
    else:
        events_logsource = SigmaLogSource(
            category=logsource.category,
            product=logsource.product,
            service=logsource.service,
        )
        if events_logsource not in rule.logsource:
            result.status = "skipped"
            result.message = (
                "The rule's logsource does not match the logsource of the "
                "events (after the processing pipelines, if any)."
            )
            return
    try:
        compiler.compile_rule(rule)
        result.detections = {
            name: (_detection_matcher(compiler, rule, name), [])
            for name in rule.detection.detections
        }
    except Exception as exc:  # noqa: BLE001 - reported to the client
        result.status = "failed"
        message = str(exc) if isinstance(exc, SigmaError) else repr(exc)
        result.message = f"The rule could not be compiled for matching: {message}"
        return
    result.fields = rule_fields(rule)


def match_events(
    rule_yaml: str,
    events: list[Any] | str,
    pipeline_yamls: list[str] | None = None,
    logsource: Mapping[str, Any] | None = None,
    timestamp_field: str | None = None,
    deadline: float | None = None,
) -> dict[str, Any]:
    """Match the rules in *rule_yaml* against *events*.

    Args:
        rule_yaml: One or more Sigma rules, including correlation rules.
        events: The events (see :func:`load_events`).
        pipeline_yamls: Processing pipelines applied to the rules first,
            e.g. to map Sigma field names to the events' field names.
        logsource: The logsource of the events.  ``None`` matches every
            rule against every event.
        timestamp_field: Field holding the event time; found automatically
            when ``None`` (see :data:`TIMESTAMP_FIELDS`).
        deadline: :func:`time.monotonic` value after which no further event
            is matched.

    Returns:
        The reply of the ``match_events`` tool, or a dict with ``error``.
    """
    try:
        loaded = load_events(events)
        events_logsource = event_logsource(logsource)
        pipeline = _parse_pipelines(pipeline_yamls or [])
    except MatchInputError as exc:
        return {"error": str(exc)}
    rules, issues = parse_rules(rule_yaml)
    if not rules:
        return {"error": "No rule could be parsed.", "issues": issues}
    prepared = prepare_events(loaded, events_logsource, timestamp_field)

    compiler = MatchCompiler(policy=PIPELINE_POLICY)
    results = [RuleResult(rule=rule, logsource=_logsource_dict(rule)) for rule in rules]
    for result in results:
        _prepare_rule(result, pipeline, compiler, events_logsource)
    ready = [r for r in results if r.status == "ok"]
    matcher = SigmaMatcher(
        SigmaCollection([r.rule for r in ready], resolve_references=False),
        max_events_per_match=MAX_LISTED_EVENTS,
        policy=PIPELINE_POLICY,
    )
    by_rule = {id(r.rule): r for r in ready}
    positions = {id(event): n for n, event in enumerate(prepared.events)}
    errors: list[dict[str, Any]] = []
    matched_positions: set[int] = set()
    order = sorted(
        range(len(prepared.events)), key=lambda n: prepared.events[n].timestamp
    )
    processed = 0
    for position in order:
        if deadline is not None and time.monotonic() >= deadline:
            break
        event = prepared.events[position]
        processed += 1
        _count_detections(ready, event, position)
        try:
            matches = matcher.match(event)
        except Exception as exc:  # noqa: BLE001 - reported to the client
            errors.append({"event": position, "error": repr(exc)})
            continue
        for match in matches:
            by_rule[id(match.rule)].matches.append(match)
            matched_positions.update(positions[id(e)] for e in match.events)

    unmatched = [n for n in range(len(prepared.events)) if n not in matched_positions]
    reply: dict[str, Any] = {
        "complete": processed == len(prepared.events),
        "summary": {
            "rules": len(results),
            "rules_with_matches": sum(bool(r.matches) for r in results),
            "events": len(prepared.events),
            "matched_events": len(matched_positions),
        },
        "events": prepared.summary(),
        "rules": [r.to_json(positions, prepared.fields) for r in results],
        "events_without_match": unmatched[:MAX_LISTED_EVENTS],
    }
    notes = _notes(results, prepared)
    if notes:
        reply["notes"] = notes
    if issues:
        reply["issues"] = issues
    if errors:
        reply["event_errors"] = errors[:MAX_LISTED_EVENTS]
    if processed < len(prepared.events):
        reply["unprocessed_events"] = len(prepared.events) - processed
        reply["message"] = (
            f"The time limit was reached after {processed} of "
            f"{len(prepared.events)} events (in time order). Match fewer "
            "events or rules at once."
        )
    return reply


def _count_detections(results: list[RuleResult], event: Event, position: int) -> None:
    raw = event.get_raw()
    for result in results:
        for matcher, hits in result.detections.values():
            try:
                if matcher(event.data, raw):
                    hits.append(position)
            except Exception:  # noqa: BLE001 - matching the rule reports it
                pass


def _notes(results: list[RuleResult], prepared: PreparedEvents) -> list[str]:
    notes: list[str] = []
    has_correlation = any(
        isinstance(r.rule, SigmaCorrelationRule) and r.status == "ok" for r in results
    )
    if has_correlation and prepared.with_timestamp < len(prepared.events):
        if prepared.with_timestamp == 0:
            notes.append(
                "No event has a timestamp, so correlations treat all events as "
                "simultaneous, in input order. Pass timestamp_field to use the "
                "events' times."
            )
        else:
            notes.append(
                f"{len(prepared.events) - prepared.with_timestamp} events have no "
                "timestamp; they got the time of the event before them."
            )
    if any(r.fields and set(r.fields) - set(prepared.fields) for r in results):
        notes.append(
            "Some rules use fields that no event has (missing_fields). Map the "
            "rule fields to the events' field names with a processing pipeline "
            "(pipeline_yamls), or check the field names."
        )
    return notes


__all__ = [
    "MAX_EVENTS",
    "MatchInputError",
    "event_logsource",
    "flatten_event",
    "load_events",
    "match_events",
    "parse_timestamp",
    "prepare_events",
]
