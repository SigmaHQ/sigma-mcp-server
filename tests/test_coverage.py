"""Tests for sigma.mcp.coverage (pipeline coverage of the SigmaHQ rules)."""

from __future__ import annotations

import time

from pathlib import Path

import pytest

from sigma.mcp.coverage import (
    LogsourceCoverage,
    analyze_coverage,
    select_logsources,
    expected_fields,
    summarize,
)
from sigma.mcp.index import LogsourceStats, RuleIndex, build_index
from sigma.mcp.pipelines import parse_pipeline

PIPELINE = """
name: example
transformations:
  - id: index_windows
    type: add_condition
    conditions:
      event.module: windows
    rule_conditions:
      - type: logsource
        product: windows
  - id: proc_fields
    type: field_name_mapping
    mapping:
      Image: process.executable
      CommandLine: process.command_line
    rule_conditions:
      - type: logsource
        product: windows
        category: process_creation
  - id: prefix
    type: field_name_prefix_mapping
    mapping:
      Target: winlog.event_data.Target
    rule_conditions:
      - type: logsource
        service: security
  - id: drop_eventid
    type: drop_detection_item
    field_name_conditions:
      - type: include_fields
        fields: [EventID]
  - id: no_ofn
    type: detection_item_failure
    message: OriginalFileName is not collected
    field_name_conditions:
      - type: include_fields
        fields: [OriginalFileName]
  - id: linux_unsupported
    type: rule_failure
    message: Linux logs are not collected
    rule_conditions:
      - type: logsource
        product: linux
  - id: global_suffix
    type: field_name_suffix
    suffix: ""
"""


@pytest.fixture
def index(rules_root: Path) -> RuleIndex:
    return build_index(rules_root)


def _by_key(results: list[LogsourceCoverage]) -> dict[str, LogsourceCoverage]:
    return {result.stats.key: result for result in results}


class TestAnalyzeCoverage:
    def test_statuses(self, index: RuleIndex) -> None:
        results = _by_key(analyze_coverage(parse_pipeline(PIPELINE), index))
        assert results["windows/process_creation"].status == "covered"
        assert results["windows/process_creation"].transformations == [
            "index_windows",
            "proc_fields",
        ]
        assert results["windows/security"].status == "covered"
        linux = results["linux/process_creation"]
        assert linux.status == "unsupported"
        assert linux.message == "Linux logs are not collected"
        assert linux.mapped == {} and linux.unmapped == []

    def test_field_results(self, index: RuleIndex) -> None:
        results = _by_key(analyze_coverage(parse_pipeline(PIPELINE), index))
        proc = results["windows/process_creation"]
        assert proc.mapped == {
            "Image": ["process.executable"],
            "CommandLine": ["process.command_line"],
        }
        # Fields added by add_condition do not make a field count as mapped.
        assert proc.unmapped == ["ParentImage"]
        assert proc.unsupported == {
            "OriginalFileName": "OriginalFileName is not collected"
        }
        security = results["windows/security"]
        assert security.dropped == ["EventID"]
        assert security.mapped == {
            "TargetUserName": ["winlog.event_data.TargetUserName"]
        }

    def test_uncovered_logsource(self, index: RuleIndex) -> None:
        only_linux = """
transformations:
  - id: linux_index
    type: add_condition
    conditions: {index: linux}
    rule_conditions: [{type: logsource, product: linux}]
"""
        results = _by_key(analyze_coverage(parse_pipeline(only_linux), index))
        assert results["linux/process_creation"].status == "covered"
        windows = results["windows/process_creation"]
        assert windows.status == "uncovered"
        assert windows.transformations == []
        assert "Image" in windows.unmapped

    def test_global_failure_marks_everything_unsupported(
        self, index: RuleIndex
    ) -> None:
        fail_all = """
transformations:
  - id: nothing
    type: rule_failure
    message: Not supported
"""
        results = analyze_coverage(parse_pipeline(fail_all), index)
        assert {r.status for r in results} == {"unsupported"}
        assert all(r.transformations == [] for r in results)

    def test_threshold_and_filter(self, index: RuleIndex) -> None:
        parsed = parse_pipeline(PIPELINE)
        results = analyze_coverage(
            parsed, index, field_threshold=1.0, logsource_filter="PROCESS_CREATION"
        )
        assert [r.stats.key for r in results] == [
            "windows/process_creation",
            "linux/process_creation",
        ]
        proc = results[0]
        assert list(proc.mapped) == ["Image"]  # only field used by every rule
        assert proc.unmapped == [] and proc.unsupported == {}

    def test_deadline_stops_between_logsources(self, index: RuleIndex) -> None:
        parsed = parse_pipeline(PIPELINE)
        assert analyze_coverage(parsed, index, deadline=time.monotonic() - 1) == []
        everything = analyze_coverage(parsed, index, deadline=time.monotonic() + 60)
        assert [r.stats.key for r in everything] == [
            s.key for s in select_logsources(index)
        ]

    def test_invalid_field_name(self) -> None:
        stats = LogsourceStats("windows", "windows", None, None, 1, {"bad|": 1})
        index = RuleIndex(
            generated_at=build_index(Path("/nonexistent")).generated_at,
            source_commit=None,
            rules=[],
            logsources={"windows": stats},
        )
        (result,) = analyze_coverage(parse_pipeline("transformations: []"), index)
        assert result.status == "uncovered"
        assert "bad|" in result.unsupported


class TestHelpers:
    def test_expected_fields(self) -> None:
        stats = LogsourceStats("x", None, None, None, 20, {"a": 20, "b": 1, "c": 2})
        assert expected_fields(stats, 0.05) == ["a", "c", "b"]
        assert expected_fields(stats, 0.1) == ["a", "c"]
        empty = LogsourceStats("y", None, None, None, 0, {"a": 1})
        assert expected_fields(empty, 0.05) == []

    def test_summarize_and_json(self, index: RuleIndex) -> None:
        results = analyze_coverage(parse_pipeline(PIPELINE), index)
        summary = summarize(results)
        assert summary == {
            "logsources": {"covered": 2, "uncovered": 0, "unsupported": 2},
            "rules": {"covered": 5, "uncovered": 0, "unsupported": 2},
            "total_rules": 7,
        }
        data = _by_key(results)["linux/process_creation"].to_json()
        assert data["message"] == "Linux logs are not collected"
        assert data["fields"] == {
            "mapped": {},
            "unmapped": [],
            "unsupported": {},
            "dropped": [],
        }
        assert "message" not in _by_key(results)["windows/security"].to_json()
