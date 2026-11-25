"""Tests for matching Sigma rules against events (sigma.mcp.matching)."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

import pytest
from fastmcp.client import Client
from sigma.matching import EventLogSource, SigmaMatcher
from sigma.matching.compiler import MatchCompiler

from sigma.mcp import matching
from sigma.mcp.main import mcp
from sigma.mcp.matching import (
    MatchInputError,
    event_logsource,
    flatten_event,
    load_events,
    match_events,
    parse_timestamp,
    prepare_events,
)

RULE = """
title: Cmd Started
id: 5f1e0c6a-7f3b-4b55-9d64-0f5d2a6e3c11
name: cmd_started
logsource: {product: windows, category: process_creation}
detection:
  selection: {Image|endswith: '\\\\cmd.exe'}
  filter: {CommandLine|contains: 'benign'}
  condition: selection and not filter
"""

CORRELATION = """
title: Many Cmds
correlation:
  type: event_count
  rules: [cmd_started]
  group-by: [User]
  timespan: 5m
  condition: {gte: 2}
"""

KEYWORD_RULE = """
title: Wget Download
logsource: {product: linux}
detection:
  keywords: ['wget http*']
  condition: keywords
"""

MALICIOUS = {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c whoami"}
BENIGN = {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd benign"}
OTHER = {"Image": "C:\\Windows\\explorer.exe"}

ANY = EventLogSource(product="sigma-mcp-any")


def _rule(reply: dict[str, Any], title: str) -> dict[str, Any]:
    rules: list[dict[str, Any]] = [r for r in reply["rules"] if r["title"] == title]
    (rule,) = rules
    return rule


class TestLoadEvents:
    def test_list(self) -> None:
        assert load_events([MALICIOUS]) == [MALICIOUS]

    def test_json_array(self) -> None:
        assert load_events(json.dumps([MALICIOUS, OTHER])) == [MALICIOUS, OTHER]

    def test_single_object(self) -> None:
        assert load_events(json.dumps(MALICIOUS)) == [MALICIOUS]

    def test_json_lines(self) -> None:
        text = f"{json.dumps(MALICIOUS)}\n\n{json.dumps(OTHER)}\n"
        assert load_events(text) == [MALICIOUS, OTHER]

    def test_invalid_line(self) -> None:
        with pytest.raises(MatchInputError, match="line 2"):
            load_events('{"a": 1}\n{nope\n')

    @pytest.mark.parametrize("events", [[], "", "  \n"])
    def test_empty(self, events: Any) -> None:
        with pytest.raises(MatchInputError, match="at least one event"):
            load_events(events)

    def test_too_many(self) -> None:
        with pytest.raises(MatchInputError, match="at most"):
            load_events([{}] * (matching.MAX_EVENTS + 1))

    def test_deeply_nested_text(self) -> None:
        with pytest.raises(MatchInputError, match="nested too deeply"):
            load_events("[" * 100_000 + "]" * 100_000)

    def test_deeply_nested_line(self) -> None:
        deep = "[" * 100_000 + "]" * 100_000
        with pytest.raises(MatchInputError, match="line 2 is nested"):
            load_events('{"a": 1}\n' + deep + "\n")


class TestFlattenEvent:
    def test_nested_objects_and_unique_leaves(self) -> None:
        flat = flatten_event(
            {"Event": {"EventData": {"Image": "a.exe"}, "System": {"EventID": 1}}}
        )
        assert flat == {
            "Event.EventData.Image": "a.exe",
            "Event.System.EventID": 1,
            "Image": "a.exe",
            "EventID": 1,
        }

    def test_ambiguous_leaf_and_top_level_names_are_kept(self) -> None:
        flat = flatten_event(
            {
                "source": {"ip": "1.1.1.1"},
                "destination": {"ip": "2.2.2.2"},
                "a": {"b": 1},
                "b": 2,
            }
        )
        assert "ip" not in flat
        assert flat["b"] == 2 and flat["a.b"] == 1

    def test_digit_strings_become_integers(self) -> None:
        flat = flatten_event(
            {"EventID": "4688", "Code": "0x10", "Zip": "0123", "Neg": "-5"}
        )
        assert flat == {"EventID": 4688, "Code": "0x10", "Zip": "0123", "Neg": -5}

    def test_long_digit_strings_stay_strings(self) -> None:
        digits = "9" * 30
        assert flatten_event({"n": digits}) == {"n": digits}

    def test_lists(self) -> None:
        flat = flatten_event(
            {"tags": ["a", None, True, 3], "procs": [{"name": "x"}, ["y"]]}
        )
        assert flat["tags"] == "a  true 3"
        assert flat["procs.0.name"] == "x" and flat["procs.1"] == "y"
        assert flat["name"] == "x"

    def test_depth_limit(self) -> None:
        event: dict[str, Any] = {"leaf": 1}
        for _ in range(matching.MAX_DEPTH + 5):
            event = {"n": event}
        flat = flatten_event(event)
        (value,) = flat.values()
        assert isinstance(value, str) and '"leaf": 1' in value

    def test_extreme_depth(self) -> None:
        event: dict[str, Any] = {}
        for _ in range(200_000):
            event = {"n": event}
        (value,) = flatten_event(event).values()
        assert value == "<nested too deeply>"


class TestParseTimestamp:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (
                "2024-01-02T03:04:05Z",
                datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
            ),
            (
                "2024-01-02 03:04:05.000",
                datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
            ),
            (1704164645, datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
            (1704164645000, datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
            (True, None),
            ("yesterday", None),
            (None, None),
            (1e300, None),
        ],
    )
    def test_values(self, value: Any, expected: datetime | None) -> None:
        assert parse_timestamp(value) == expected


class TestPrepareEvents:
    def test_times_are_filled_from_previous_events(self) -> None:
        prepared = prepare_events(
            [{"a": 1}, {"@timestamp": "2024-01-01T00:00:00Z"}, {"b": 1}], ANY
        )
        times = {e.timestamp for e in prepared.events}
        assert times == {datetime(2024, 1, 1, tzinfo=timezone.utc)}
        assert prepared.with_timestamp == 1
        assert prepared.timestamp_fields == ["@timestamp"]

    def test_unparseable_time_falls_back_to_next_field(self) -> None:
        prepared = prepare_events(
            [{"@timestamp": "garbage", "UtcTime": "2024-01-01 00:00:00"}], ANY
        )
        assert prepared.events[0].timestamp.year == 2024
        assert prepared.timestamp_fields == ["UtcTime"]

    def test_explicit_field(self) -> None:
        prepared = prepare_events(
            [{"when": 1704164645, "@timestamp": "2020-01-01T00:00:00Z"}], ANY, "when"
        )
        assert prepared.events[0].timestamp.year == 2024
        assert prepared.timestamp_fields == ["when"]

    def test_log_lines_and_other_values(self) -> None:
        prepared = prepare_events(["a log line", 42], ANY)
        assert [e.get_raw() for e in prepared.events] == ["a log line", "42"]
        assert prepared.summary()["log_lines"] == 2

    def test_field_summary_is_limited(self) -> None:
        event = {f"f{n}": n for n in range(matching.MAX_LISTED_FIELDS + 3)}
        summary = prepare_events([event], ANY).summary()
        assert len(summary["fields"]) == matching.MAX_LISTED_FIELDS
        assert summary["omitted_fields"] == 3


class TestEventLogsource:
    def test_none_means_any(self) -> None:
        assert event_logsource(None) == ANY

    def test_values(self) -> None:
        assert event_logsource({"product": "windows", "service": ""}) == EventLogSource(
            product="windows"
        )

    @pytest.mark.parametrize(
        ("logsource", "message"),
        [
            ({"vendor": "x"}, "Unknown logsource keys"),
            ({"product": None}, "needs a product"),
            ({"product": 1}, "must be strings"),
        ],
    )
    def test_errors(self, logsource: dict[str, Any], message: str) -> None:
        with pytest.raises(MatchInputError, match=message):
            event_logsource(logsource)


class TestMatchEvents:
    def test_rule_matches_malicious_events_only(self) -> None:
        reply = match_events(RULE, [MALICIOUS, BENIGN, OTHER])
        assert reply["complete"] is True
        assert reply["summary"] == {
            "rules": 1,
            "rules_with_matches": 1,
            "events": 3,
            "matched_events": 1,
        }
        rule = _rule(reply, "Cmd Started")
        assert rule["status"] == "ok"
        assert rule["match_count"] == 1
        assert rule["matched_events"] == [0]
        assert rule["detections"] == {"selection": 2, "filter": 1}
        assert rule["logsource"] == {
            "product": "windows",
            "category": "process_creation",
        }
        assert reply["events_without_match"] == [1, 2]
        assert "missing_fields" not in rule and "notes" not in reply

    def test_case_insensitive_and_numbers(self) -> None:
        rule = RULE.replace("selection: {", "selection: {EventID: 1, ")
        event = {"Image": "C:\\X\\CMD.EXE", "EventID": "1", "CommandLine": "x"}
        reply = match_events(rule, [event])
        assert _rule(reply, "Cmd Started")["matched_events"] == [0]

    def test_nested_events(self) -> None:
        event = {"Event": {"EventData": MALICIOUS, "System": {"EventID": 1}}}
        reply = match_events(RULE, [event])
        assert _rule(reply, "Cmd Started")["matched_events"] == [0]

    def test_events_as_json_lines(self) -> None:
        text = "\n".join(json.dumps(e) for e in [OTHER, MALICIOUS])
        reply = match_events(RULE, text)
        assert _rule(reply, "Cmd Started")["matched_events"] == [1]

    def test_missing_fields(self) -> None:
        reply = match_events(RULE, [{"process.executable": "C:\\cmd.exe"}])
        rule = _rule(reply, "Cmd Started")
        assert rule["match_count"] == 0
        assert rule["missing_fields"] == ["CommandLine", "Image"]
        assert any("missing_fields" in note for note in reply["notes"])

    def test_pipeline_maps_fields(self) -> None:
        pipeline = """
name: ecs
transformations:
  - id: ecs_process
    type: field_name_mapping
    mapping: {Image: process.executable, CommandLine: process.command_line}
"""
        event = {"process": {"executable": "C:\\cmd.exe", "command_line": "cmd /c x"}}
        reply = match_events(RULE, [event], pipeline_yamls=[pipeline])
        rule = _rule(reply, "Cmd Started")
        assert rule["matched_events"] == [0]
        assert "missing_fields" not in rule

    def test_pipeline_rejects_rule(self) -> None:
        pipeline = """
name: no linux
transformations:
  - id: linux_unsupported
    type: rule_failure
    message: Linux logs are not collected
    rule_conditions: [{type: logsource, product: linux}]
"""
        reply = match_events(
            RULE + "---\n" + KEYWORD_RULE, [MALICIOUS], pipeline_yamls=[pipeline]
        )
        rule = _rule(reply, "Wget Download")
        assert rule["status"] == "failed"
        assert "Linux logs are not collected" in rule["message"]
        assert rule["transformation"] == "linux_unsupported"
        assert _rule(reply, "Cmd Started")["matched_events"] == [0]

    def test_invalid_pipeline(self) -> None:
        reply = match_events(RULE, [MALICIOUS], pipeline_yamls=["- nope"])
        assert reply["error"].startswith("Pipeline 1 is invalid")

    def test_too_many_transformations(self) -> None:
        items = "\n".join(
            f"  - {{type: field_name_mapping, mapping: {{a{n}: b}}}}"
            for n in range(501)
        )
        reply = match_events(
            RULE, [MALICIOUS], pipeline_yamls=[f"name: big\ntransformations:\n{items}"]
        )
        assert "at most 500" in reply["error"]

    def test_logsource_selects_rules(self) -> None:
        reply = match_events(
            RULE + "---\n" + KEYWORD_RULE,
            [MALICIOUS, "wget http://evil"],
            logsource={"product": "windows", "category": "process_creation"},
        )
        assert _rule(reply, "Cmd Started")["matched_events"] == [0]
        skipped = _rule(reply, "Wget Download")
        assert skipped["status"] == "skipped" and "logsource" in skipped["message"]

    def test_without_logsource_every_rule_is_tested(self) -> None:
        reply = match_events(
            RULE + "---\n" + KEYWORD_RULE, [MALICIOUS, "wget http://evil"]
        )
        assert _rule(reply, "Cmd Started")["matched_events"] == [0]
        assert _rule(reply, "Wget Download")["matched_events"] == [1]

    def test_keyword_in_object_values(self) -> None:
        reply = match_events(KEYWORD_RULE, [{"message": "x wget http://evil"}])
        assert _rule(reply, "Wget Download")["matched_events"] == [0]

    def test_invalid_logsource(self) -> None:
        reply = match_events(RULE, [MALICIOUS], logsource={"os": "windows"})
        assert "Unknown logsource keys" in reply["error"]

    def test_invalid_events(self) -> None:
        assert "Pass at least one event" in match_events(RULE, [])["error"]

    def test_no_rule(self) -> None:
        reply = match_events("title: broken\n", [MALICIOUS])
        assert reply["error"] == "No rule could be parsed."
        assert reply["issues"]

    def test_parse_issues_are_reported(self) -> None:
        reply = match_events(RULE + "---\ntitle: broken\nlogsource: {}\n", [MALICIOUS])
        assert reply["issues"]
        assert _rule(reply, "Cmd Started")["matched_events"] == [0]

    def test_correlation(self) -> None:
        events = [
            {**MALICIOUS, "User": "bob", "@timestamp": "2024-01-01T00:02:00Z"},
            {**MALICIOUS, "User": "alice", "@timestamp": "2024-01-01T00:01:00Z"},
            {**MALICIOUS, "User": "bob", "@timestamp": "2024-01-01T00:00:00Z"},
            {**MALICIOUS, "User": "alice", "@timestamp": "2024-01-01T01:00:00Z"},
        ]
        reply = match_events(RULE + "---\n" + CORRELATION, events)
        correlation = _rule(reply, "Many Cmds")
        assert correlation["kind"] == "correlation"
        assert correlation["match_count"] == 1
        (match,) = correlation["matches"]
        assert match["group"] == {"User": "bob"}
        assert match["events"] == [0, 2]
        assert match["timestamp"] == "2024-01-01T00:02:00+00:00"
        assert reply["events"]["with_timestamp"] == 4
        assert "notes" not in reply

    def test_correlation_matches_are_limited(self) -> None:
        events = [MALICIOUS] * (matching.MAX_LISTED_MATCHES + 3)
        reply = match_events(
            RULE + "---\n" + CORRELATION.replace("[User]", "[Image]"), events
        )
        correlation = _rule(reply, "Many Cmds")
        assert len(correlation["matches"]) == matching.MAX_LISTED_MATCHES
        assert correlation["omitted_matches"] == 2
        assert any("No event has a timestamp" in note for note in reply["notes"])

    def test_some_events_without_timestamp(self) -> None:
        events = [{**MALICIOUS, "@timestamp": "2024-01-01T00:00:00Z"}, MALICIOUS]
        reply = match_events(RULE + "---\n" + CORRELATION, events)
        assert any("1 events have no timestamp" in note for note in reply["notes"])

    def test_missing_correlation_reference(self) -> None:
        reply = match_events(CORRELATION, [MALICIOUS])
        assert reply["issues"][0]["error_class"] == "SigmaRuleNotFoundError"
        assert _rule(reply, "Many Cmds")["match_count"] == 0

    def test_event_errors_are_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def broken(self: Any, event: Any) -> Any:
            raise TypeError("broken")

        monkeypatch.setattr(SigmaMatcher, "match", broken)
        reply = match_events(RULE, [MALICIOUS])
        assert reply["event_errors"] == [{"event": 0, "error": "TypeError('broken')"}]

    def test_comparison_with_text_does_not_crash(self) -> None:
        rule = """
title: Many Bytes
logsource: {category: network}
detection:
  selection: {Bytes|gt: 100}
  condition: selection
"""
        reply = match_events(rule, [{"Bytes": "many"}, {"Bytes": "1000"}])
        result = _rule(reply, "Many Bytes")
        assert result["matched_events"] == [1]
        assert result["detections"] == {"selection": 1}
        assert reply["event_errors"][0]["event"] == 0

    def test_compile_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def broken(self: Any, rule: Any) -> Any:
            raise RecursionError("too deep")

        monkeypatch.setattr(MatchCompiler, "compile_rule", broken)
        reply = match_events(RULE, [MALICIOUS])
        rule = _rule(reply, "Cmd Started")
        assert rule["status"] == "failed"
        assert "could not be compiled" in rule["message"]

    def test_time_limit(self) -> None:
        reply = match_events(RULE, [MALICIOUS, OTHER], deadline=time.monotonic() - 1)
        assert reply["complete"] is False
        assert reply["unprocessed_events"] == 2
        assert "time limit" in reply["message"]

    def test_regex_uses_safe_policy(self) -> None:
        rule = """
title: Regex
logsource: {product: windows}
detection:
  selection: {CommandLine|re: '(a+)+$'}
  condition: selection
"""
        reply = match_events(
            rule, [{"CommandLine": "a" * 50_000 + "!"}, {"CommandLine": "aa"}]
        )
        assert _rule(reply, "Regex")["matched_events"] == [1]


class TestMatchEventsTool:
    @pytest.mark.anyio
    async def test_tool(self) -> None:
        async with Client(mcp) as client:
            result = await client.call_tool(
                "match_events",
                {
                    "rule_yaml": RULE,
                    "events": [MALICIOUS, BENIGN],
                    "logsource": {"product": "windows", "category": "process_creation"},
                },
            )
        data = result.structured_content
        assert data is not None
        assert data["rules"][0]["matched_events"] == [0]

    @pytest.mark.anyio
    async def test_tool_with_text_and_time_limit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SIGMA_MCP_TOOL_TIME_LIMIT", "0")
        async with Client(mcp) as client:
            result = await client.call_tool(
                "match_events", {"rule_yaml": RULE, "events": json.dumps([MALICIOUS])}
            )
        data = result.structured_content
        assert data is not None
        assert data["complete"] is True
        assert data["rules"][0]["matched_events"] == [0]
