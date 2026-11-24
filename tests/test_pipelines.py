"""Tests for sigma.mcp.pipelines (validation, application and rendering)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import SigmaType

from sigma.mcp.pipelines import (
    MAX_LABEL_LENGTH,
    PIPELINE_POLICY,
    PipelineParseError,
    _item_label,
    apply_pipelines,
    combine_pipelines,
    parse_pipeline,
    pipeline_catalog,
    render_value,
    rule_fields,
    run_pipeline,
    validate_pipeline,
)

PSEXEC_RULE = """
title: PsExec Remote Execution
id: 0b5b3d5c-1a8e-4d4c-9f29-3c6c8e0b7a01
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\\PsExec.exe'
        - OriginalFileName: 'psexec.c'
    selection_cli:
        CommandLine|contains: 'accepteula'
    filter:
        ParentImage|endswith: '\\services.exe'
    condition: all of selection_* and not filter
"""

ECS_PIPELINE = """
name: ecs
priority: 20
transformations:
  - id: map_proc
    type: field_name_mapping
    mapping:
      Image: process.executable
      CommandLine: [process.command_line, process.args]
    rule_conditions:
      - type: logsource
        product: windows
        category: process_creation
  - type: set_state
    key: index
    val: logs-windows
"""

FAIL_PIPELINE = """
name: base
priority: 10
transformations:
  - id: fail_ofn
    type: detection_item_failure
    message: OriginalFileName is not available
    field_name_conditions:
      - type: include_fields
        fields: [OriginalFileName]
"""


def _rule(yaml_text: str) -> SigmaRule:
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    assert isinstance(rule, SigmaRule)
    return rule


class TestParse:
    def test_labels(self) -> None:
        parsed = parse_pipeline(ECS_PIPELINE)
        assert parsed.labels == ["map_proc", "#2 (set_state)"]
        assert parsed.pipeline.priority == 20

    def test_safe_policy(self) -> None:
        parsed = parse_pipeline(ECS_PIPELINE)
        assert parsed.pipeline.policy is PIPELINE_POLICY
        assert PIPELINE_POLICY.allow_template_vars is False
        assert PIPELINE_POLICY.allow_external_sources is False

    def test_non_mapping_item(self) -> None:
        with pytest.raises(PipelineParseError):
            parse_pipeline("transformations: [42]")

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("a: [b", "Invalid YAML"),
            ("- a", "must be a YAML mapping"),
            ("transformations: [{type: nope}]", "Unknown transformation type"),
        ],
    )
    def test_errors(self, text: str, expected: str) -> None:
        with pytest.raises(PipelineParseError, match=expected):
            parse_pipeline(text)

    def test_sandboxed_inline_template_is_allowed(self) -> None:
        template = """
transformations:
  - id: tpl
    type: query_expression_placeholders
    expression: "{field} in list({id})"
postprocessing:
  - type: template
    template: "{{ query }} | head 10"
"""
        assert len(parse_pipeline(template).pipeline.postprocessing_items) == 1

    @pytest.mark.parametrize("section", ["transformations", "postprocessing"])
    def test_vars_file_is_refused_even_if_env_allows_it(
        self, section: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        marker = tmp_path / "EXECUTED"
        helpers = tmp_path / "helpers.py"
        helpers.write_text(f"open({str(marker)!r}, 'w').write('x')\nvars = {{}}\n")
        monkeypatch.setenv("PYSIGMA_ALLOW_VARS_EXECUTION", "1")
        pipeline = f"""
{section}:
  - type: template
    template: "{{{{ query }}}}"
    vars: {helpers}
"""
        with pytest.raises(PipelineParseError, match="executes Python code"):
            parse_pipeline(pipeline)
        assert validate_pipeline(pipeline)["valid"] is False
        assert not marker.exists()

    def test_template_directory_is_refused(self, tmp_path: Path) -> None:
        (tmp_path / "t.j2").write_text("{{ query }}")
        pipeline = f"""
postprocessing:
  - type: template
    template: t.j2
    path: {tmp_path}
"""
        with pytest.raises(PipelineParseError, match="SigmaSecurityError"):
            parse_pipeline(pipeline)

    def test_non_list_sections_are_left_to_pysigma(self) -> None:
        with pytest.raises(PipelineParseError):
            parse_pipeline("postprocessing: {vars: x}")

    @pytest.mark.parametrize(
        "item",
        [
            # 'vars' sends the item down the early error path, which builds a
            # label from 'id' or 'type' before pySigma sees the document.
            "{id: *bomb, vars: x, type: field_name_mapping, mapping: {a: b}}",
            "{type: *bomb, vars: x}",
            "{id: *bomb, type: field_name_mapping, mapping: {a: b}}",
        ],
    )
    def test_alias_bomb_is_refused(self, item: str) -> None:
        pipeline = f"{_alias_bomb(6)}\ntransformations:\n  - {item}\n"
        with pytest.raises(PipelineParseError, match="billion laughs") as info:
            parse_pipeline(pipeline)
        assert len(str(info.value)) < 500
        result = validate_pipeline(pipeline)
        assert result["valid"] is False
        assert len(result["errors"][0]) < 500

    def test_recursive_yaml_is_refused(self) -> None:
        with pytest.raises(PipelineParseError, match="Recursive"):
            parse_pipeline("transformations: &loop [*loop]")

    @pytest.mark.parametrize(
        ("item", "label"),
        [
            ({"id": ["a", "b"], "type": "set_state"}, "#1 (set_state)"),
            ({"id": True, "type": {"x": 1}}, "#1 (unknown)"),
            ({"id": 7}, "7"),
            ({"id": "x" * 300}, "x" * MAX_LABEL_LENGTH),
        ],
    )
    def test_labels_only_use_short_scalars(
        self, item: dict[str, Any], label: str
    ) -> None:
        assert _item_label(1, item) == label


def _alias_bomb(levels: int) -> str:
    """Anchors whose top level ``*bomb`` expands to 9**levels values."""
    lines = ["l0: &l0 [" + ", ".join(["lol"] * 9) + "]"]
    for n in range(1, levels - 1):
        lines.append(f"l{n}: &l{n} [" + ", ".join([f"*l{n - 1}"] * 9) + "]")
    lines.append(f"top: &bomb [" + ", ".join([f"*l{levels - 2}"] * 9) + "]")
    return "\n".join(lines)


class TestCombine:
    def test_priority_order_and_labels(self) -> None:
        combined = combine_pipelines(
            [parse_pipeline(ECS_PIPELINE), parse_pipeline(FAIL_PIPELINE)]
        )
        assert combined.labels == ["fail_ofn", "map_proc", "#2 (set_state)"]
        assert len(combined.pipeline.items) == 3

    def test_empty(self) -> None:
        combined = combine_pipelines([])
        assert combined.labels == [] and combined.pipeline.items == []


class TestValidate:
    def test_valid_with_warnings(self) -> None:
        result = validate_pipeline(ECS_PIPELINE)
        assert result["valid"] is True and result["errors"] == []
        assert any("#2 (set_state) has no 'id'" in w for w in result["warnings"])
        assert any("no conditions" in w for w in result["warnings"])
        summary = result["summary"]
        assert summary["name"] == "ecs" and summary["priority"] == 20
        assert summary["transformations"][0] == {
            "position": 1,
            "id": "map_proc",
            "type": "field_name_mapping",
            "logsource_conditions": [
                {"product": "windows", "category": "process_creation"}
            ],
        }
        assert summary["postprocessing_count"] == 0

    def test_field_name_conditions_count_as_conditions(self) -> None:
        result = validate_pipeline(FAIL_PIPELINE)
        assert result["warnings"] == []

    def test_duplicate_ids_and_empty(self) -> None:
        duplicate = """
transformations:
  - id: same
    type: field_name_suffix
    suffix: .keyword
    rule_conditions: [{type: logsource, product: windows}]
  - id: same
    type: field_name_suffix
    suffix: .text
    rule_conditions: [{type: logsource, product: linux}]
"""
        assert validate_pipeline(duplicate)["warnings"] == [
            "The id 'same' is used 2 times."
        ]
        assert validate_pipeline("name: empty")["warnings"] == [
            "The pipeline has no transformations."
        ]

    def test_odd_rule_conditions_value(self) -> None:
        odd = """
transformations:
  - id: x
    type: field_name_suffix
    suffix: .k
    rule_conditions: {type: logsource, product: windows}
"""
        result = validate_pipeline(odd)
        if result["valid"]:
            assert result["summary"]["transformations"][0]["logsource_conditions"] == []

    def test_invalid(self) -> None:
        result = validate_pipeline("transformations: [{type: nope}]")
        assert result["valid"] is False
        assert "Unknown transformation type 'nope'" in result["errors"][0]
        assert "summary" not in result


class TestApply:
    def test_mapping_and_rendering(self) -> None:
        result = apply_pipelines(PSEXEC_RULE, [ECS_PIPELINE])
        (rule,) = result["rules"]
        assert rule["status"] == "ok" and rule["error"] is None
        assert rule["applied_transformations"] == ["map_proc", "#2 (set_state)"]
        assert rule["field_mappings"] == {
            "CommandLine": ["process.args", "process.command_line"],
            "Image": ["process.executable"],
        }
        assert rule["unmapped_fields"] == ["OriginalFileName", "ParentImage"]
        assert rule["state"] == {"index": "logs-windows"}
        assert rule["logsource"] == {
            "product": "windows",
            "category": "process_creation",
        }
        assert rule["detections"] == {
            "selection_img": (
                "(process.executable = '*\\PsExec.exe' OR "
                "OriginalFileName = 'psexec.c')"
            ),
            "selection_cli": (
                "(process.command_line = '*accepteula*' OR "
                "process.args = '*accepteula*')"
            ),
            "filter": "ParentImage = '*\\services.exe'",
        }
        assert rule["condition"] == ["all of selection_* and not filter"]
        assert result["pipeline_order"] == [
            {"position": 1, "name": "ecs", "priority": 20}
        ]
        assert "not run" in result["note"]

    def test_identity_mapping_counts_as_unmapped(self) -> None:
        identity = """
transformations:
  - id: same
    type: field_name_mapping
    mapping: {Image: Image}
"""
        (rule,) = apply_pipelines(PSEXEC_RULE, [identity])["rules"]
        assert rule["field_mappings"] == {"Image": ["Image"]}
        assert "Image" in rule["unmapped_fields"]

    def test_state_values_are_json_safe(self) -> None:
        dated = """
transformations:
  - id: since
    type: set_state
    key: since
    val: 2024-01-01
"""
        (rule,) = apply_pipelines(PSEXEC_RULE, [dated])["rules"]
        assert rule["state"] == {"since": "2024-01-01"}

    def test_failure_names_transformation(self) -> None:
        result = apply_pipelines(PSEXEC_RULE, [ECS_PIPELINE, FAIL_PIPELINE])
        (rule,) = result["rules"]
        assert rule["status"] == "failed"
        assert rule["error"] == {
            "message": "OriginalFileName is not available",
            "transformation": "fail_ofn",
        }
        assert [p["name"] for p in result["pipeline_order"]] == ["base", "ecs"]

    def test_logsource_change(self) -> None:
        change = """
transformations:
  - id: to_sysmon
    type: change_logsource
    product: windows
    service: sysmon
    rule_conditions: [{type: logsource, category: process_creation}]
"""
        (rule,) = apply_pipelines(PSEXEC_RULE, [change])["rules"]
        assert rule["logsource"] == {"product": "windows", "service": "sysmon"}

    def test_correlation_rule(self) -> None:
        rules = """
title: Failed Logon
name: failed_logon
logsource: {product: windows, service: security}
detection:
  selection: {EventID: 4625}
  condition: selection
---
title: Many Failed Logons
correlation:
  type: event_count
  rules: [failed_logon]
  group-by: [IpAddress]
  timespan: 10m
  condition: {gte: 10}
"""
        mapping = """
transformations:
  - id: ip
    type: field_name_mapping
    mapping: {IpAddress: source.ip, EventID: event.code}
"""
        result = apply_pipelines(rules, [mapping])
        base, correlation = result["rules"]
        assert base["detections"] == {"selection": "event.code = 4625"}
        assert correlation["kind"] == "correlation"
        assert correlation["group_by"] == ["source.ip"]
        assert "detections" not in correlation

    @pytest.mark.parametrize(
        ("rule_yaml", "pipelines", "expected"),
        [
            (PSEXEC_RULE, [], "at least one"),
            (PSEXEC_RULE, [ECS_PIPELINE, "- x"], "Pipeline 2 is invalid"),
            ("title: x", [ECS_PIPELINE], "could not be parsed"),
            ("a: [b", [ECS_PIPELINE], "not valid YAML"),
            ("", [ECS_PIPELINE], "no Sigma rule"),
        ],
    )
    def test_errors(self, rule_yaml: str, pipelines: list[str], expected: str) -> None:
        result = apply_pipelines(rule_yaml, pipelines)
        assert set(result) == {"error"}
        assert expected in result["error"]


class _ExplodingPipeline(ProcessingPipeline):
    def apply(self, rule: SigmaRule | SigmaCorrelationRule) -> Any:
        self.applied = [True] * len(self.items)
        raise RuntimeError("boom")


class TestRunPipeline:
    def test_unexpected_exception_after_all_items(self) -> None:
        pipeline = _ExplodingPipeline()
        outcome = run_pipeline(pipeline, _rule(PSEXEC_RULE))
        assert outcome.error == "RuntimeError('boom')"
        assert outcome.failed_item is None
        assert outcome.applied == []


class TestRenderValues:
    def _detections(self, detection: str, pipeline: str | None = None) -> Any:
        rule_yaml = (
            "title: t\nlogsource: {product: windows}\ndetection:\n"
            + detection
            + "\n  condition: all of them\n"
        )
        pipelines = [pipeline or "transformations: []"]
        return apply_pipelines(rule_yaml, pipelines)["rules"][0]["detections"]

    def test_value_types(self) -> None:
        detections = self._detections("""
  strings:
    Name|cased: 'Ab'
    Quote: "it's"
    Flag: true
    Number: 3
    Missing: null
  regex:
    User|re|i|m: '^nt.*'
  network:
    Ip|cidr: 10.0.0.0/8
    Count|gt: 5
    Count2|lte: 1
    Other|fieldref: Ip
  exist:
    Field|exists: true
  expansion:
    CommandLine|windash: ' -s '
  keywords:
    - foo
    - bar
  all_values:
    Path|contains|all: [a, b]
""")
        assert detections["strings"] == (
            "(Name = cased 'Ab' AND Quote = 'it''s' AND Flag = true AND "
            "Number = 3 AND Missing is null)"
        )
        assert detections["regex"] == "User =~ /^nt.*/im"
        assert detections["network"] == (
            "(Ip in cidr 10.0.0.0/8 AND Count > 5 AND Count2 <= 1 AND "
            "Other = field(Ip))"
        )
        assert detections["exist"] == "Field exists"
        assert detections["expansion"].startswith("CommandLine = (' -s ' OR ")
        assert detections["keywords"] == "('foo' OR 'bar')"
        assert detections["all_values"] == "(Path = '*a*' AND Path = '*b*')"

    def test_negated_item_and_query_expression(self) -> None:
        pipeline = """
transformations:
  - id: placeholders
    type: query_expression_placeholders
    expression: "{field} in list({id})"
"""
        detections = self._detections(
            "  sel:\n    User|expand: '%admins%'", pipeline=pipeline
        )
        assert detections["sel"] == "User = query({field} in list({id}))"

    def test_unknown_value_type_and_exists_false(self) -> None:
        class Odd(SigmaType):
            pass

        assert render_value(Odd(None)) == "Odd"
        detections = self._detections("  sel:\n    Field|exists: false")
        assert detections["sel"] == "Field not exists"

    def test_rule_fields(self) -> None:
        assert rule_fields(_rule(PSEXEC_RULE)) == {
            "Image",
            "OriginalFileName",
            "CommandLine",
            "ParentImage",
        }


class TestCatalog:
    def test_sections(self) -> None:
        catalog = pipeline_catalog()
        assert set(catalog) == {
            "transformations",
            "rule_conditions",
            "detection_item_conditions",
            "field_name_conditions",
            "postprocessing",
            "finalizers",
        }
        assert "field_name_mapping" in catalog["transformations"]
        assert "logsource" in catalog["rule_conditions"]
        assert "include_fields" in catalog["field_name_conditions"]
        assert all("\n\n" not in text for text in catalog["transformations"].values())
