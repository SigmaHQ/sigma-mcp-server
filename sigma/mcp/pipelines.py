"""Parsing, validating and applying Sigma processing pipelines.

Pipelines come from MCP clients, so they are always parsed with
:data:`PIPELINE_POLICY`, pySigma's safe policy: the RE2 regular expression
engine, no template variables and no external sources.

Transformed rules are reported as expressions instead of Sigma YAML.  After
a processing pipeline has run, a rule can hold structures that Sigma YAML
cannot express faithfully (for example a field mapped to two fields becomes
an OR of both); pySigma's ``to_dict()`` would print those as an AND.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from functools import reduce
from typing import Any

import yaml
from sigma.collection import SigmaCollection
from sigma.conditions import ConditionOR
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaError
from sigma.policy import SigmaPolicy
from sigma.policy.profiles import SafePolicy
from sigma.processing.conditions import (
    detection_item_conditions,
    field_name_conditions,
    rule_conditions,
)
from sigma.processing.finalization import finalizers
from sigma.processing.pipeline import ProcessingPipeline
from sigma.processing.postprocessing import query_postprocessing_transformations
from sigma.processing.transformations import transformations
from sigma.rule import SigmaRule
from sigma.rule.detection import SigmaDetection, SigmaDetectionItem
from sigma.types import (
    CompareOperators,
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaQueryExpression,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SigmaType,
)

from sigma.mcp.validation import too_many_values

PIPELINE_POLICY: SigmaPolicy = SafePolicy
"""Policy for every pipeline parsed by the server."""

NOT_RUN_NOTE = (
    "Postprocessing and finalizers are backend-specific and were not run; "
    "this result shows the rules after the transformations only."
)


class PipelineParseError(Exception):
    """A pipeline could not be parsed.  The message is meant for the client."""


@dataclass
class ParsedPipeline:
    """A parsed pipeline plus a readable label for each of its items."""

    pipeline: ProcessingPipeline
    labels: list[str]
    """One label per processing item: its ``id``, or ``#<n> (<type>)``."""
    document: dict[str, Any] = field(default_factory=dict)


def _item_label(position: int, item: object) -> str:
    if isinstance(item, Mapping):
        identifier = item.get("id")
        if identifier:
            return str(identifier)
        return f"#{position} ({item.get('type', 'unknown')})"
    return f"#{position}"


_ITEM_SECTIONS = ("transformations", "postprocessing", "finalizers")


def _reject_code_execution(document: Mapping[str, Any]) -> None:
    """Refuse template ``vars`` files, which make pySigma execute Python code.

    pySigma blocks them under :data:`PIPELINE_POLICY` unless the environment
    variable ``PYSIGMA_ALLOW_VARS_EXECUTION`` is set.  A user may have set it
    for their own pipelines; pipelines sent by MCP clients must still never
    run code, so the server refuses them regardless of that variable.
    """
    for section in _ITEM_SECTIONS:
        items = document.get(section)
        if not isinstance(items, list):
            continue
        for position, item in enumerate(items, start=1):
            if isinstance(item, Mapping) and "vars" in item:
                raise PipelineParseError(
                    f"{section} item {_item_label(position, item)} uses 'vars', "
                    "which executes Python code from a file. sigma-mcp-server "
                    "does not allow this; use the pipeline-level 'vars' mapping "
                    "for template variables instead."
                )


def parse_pipeline(pipeline_yaml: str) -> ParsedPipeline:
    """Parse one pipeline YAML document with :data:`PIPELINE_POLICY`.

    Template ``vars`` files are always refused (see
    :func:`_reject_code_execution`).

    Raises:
        PipelineParseError: The YAML is invalid, the pipeline would execute
            code, or pySigma rejects the pipeline.
    """
    try:
        document = yaml.safe_load(pipeline_yaml)
    except yaml.YAMLError as exc:
        raise PipelineParseError(f"Invalid YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise PipelineParseError(
            "A processing pipeline must be a YAML mapping with a "
            "'transformations' list."
        )
    _reject_code_execution(document)
    try:
        pipeline = ProcessingPipeline.from_dict(document, policy=PIPELINE_POLICY)
    except Exception as exc:  # noqa: BLE001 - pySigma raises many types here
        raise PipelineParseError(f"{type(exc).__name__}: {exc}") from exc
    raw_items = document.get("transformations") or []
    labels = [_item_label(n, item) for n, item in enumerate(raw_items, start=1)]
    return ParsedPipeline(pipeline=pipeline, labels=labels, document=document)


def combine_pipelines(parsed: Iterable[ParsedPipeline]) -> ParsedPipeline:
    """Merge pipelines in order of their ``priority`` (lowest first).

    This is the order in which pySigma's resolver and sigma-cli apply
    several pipelines.  Pipelines with the same priority keep their order.
    """
    ordered = sorted(parsed, key=lambda p: p.pipeline.priority)
    if not ordered:
        return ParsedPipeline(pipeline=ProcessingPipeline(), labels=[])
    pipeline = reduce(lambda a, b: a + b, (p.pipeline for p in ordered))
    labels = [label for p in ordered for label in p.labels]
    return ParsedPipeline(pipeline=pipeline, labels=labels)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _logsource_scope(item: Mapping[str, Any]) -> list[dict[str, Any]]:
    conditions = item.get("rule_conditions") or []
    if not isinstance(conditions, list):
        return []
    return [
        {k: v for k, v in cond.items() if k in ("product", "category", "service")}
        for cond in conditions
        if isinstance(cond, Mapping) and cond.get("type") == "logsource"
    ]


def validate_pipeline(pipeline_yaml: str) -> dict[str, Any]:
    """Validate a pipeline and summarise its structure.

    Returns:
        Dict with ``valid``, ``errors`` (parse errors, which make the pipeline
        unusable), ``warnings`` (style issues that pySigma accepts) and, for a
        valid pipeline, ``summary``.
    """
    try:
        parsed = parse_pipeline(pipeline_yaml)
    except PipelineParseError as exc:
        return {"valid": False, "errors": [str(exc)], "warnings": []}

    document = parsed.document
    raw_items = document.get("transformations") or []
    warnings: list[str] = []
    if not raw_items:
        warnings.append("The pipeline has no transformations.")
    seen: dict[str, int] = {}
    items_summary: list[dict[str, Any]] = []
    for position, (item, label) in enumerate(zip(raw_items, parsed.labels), 1):
        mapping: Mapping[str, Any] = item if isinstance(item, Mapping) else {}
        identifier = mapping.get("id")
        if not identifier:
            warnings.append(
                f"Transformation {label} has no 'id'. IDs make conversion "
                "results and errors traceable."
            )
        else:
            seen[str(identifier)] = seen.get(str(identifier), 0) + 1
        has_condition = any(
            mapping.get(key)
            for key in (
                "rule_conditions",
                "detection_item_conditions",
                "field_name_conditions",
            )
        )
        if not has_condition:
            warnings.append(
                f"Transformation {label} has no conditions and applies to every "
                "rule. Add 'rule_conditions' of type 'logsource' unless that is "
                "intended."
            )
        items_summary.append(
            {
                "position": position,
                "id": identifier,
                "type": mapping.get("type"),
                "logsource_conditions": _logsource_scope(mapping),
            }
        )
    for identifier, count in seen.items():
        if count > 1:
            warnings.append(f"The id {identifier!r} is used {count} times.")

    pipeline = parsed.pipeline
    return {
        "valid": True,
        "errors": [],
        "warnings": warnings,
        "summary": {
            "name": pipeline.name,
            "priority": pipeline.priority,
            "transformations": items_summary,
            "postprocessing_count": len(pipeline.postprocessing_items),
            "finalizer_count": len(pipeline.finalizers),
            "allowed_backends": sorted(pipeline.allowed_backends),
            "vars": sorted(pipeline.vars),
        },
    }


# ---------------------------------------------------------------------------
# Rendering transformed rules
# ---------------------------------------------------------------------------

_COMPARE_SYMBOLS = {
    CompareOperators.LT: "<",
    CompareOperators.LTE: "<=",
    CompareOperators.GT: ">",
    CompareOperators.GTE: ">=",
    CompareOperators.NEQ: "!=",
}
_REGEX_FLAG_LETTERS = {
    SigmaRegularExpressionFlag.IGNORECASE: "i",
    SigmaRegularExpressionFlag.MULTILINE: "m",
    SigmaRegularExpressionFlag.DOTALL: "s",
}


def _quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def render_value(value: SigmaType) -> str:
    """Render a processed Sigma value (see :func:`render_detection`)."""
    if isinstance(value, SigmaCasedString):
        return "cased " + _quote(str(value))
    if isinstance(value, SigmaString):
        return _quote(str(value))
    if isinstance(value, SigmaBool):
        return "true" if value.boolean else "false"
    if isinstance(value, SigmaNumber):
        return str(value.number)
    if isinstance(value, SigmaNull):
        return "null"
    if isinstance(value, SigmaRegularExpression):
        flags = "".join(sorted(_REGEX_FLAG_LETTERS[f] for f in value.flags))
        return f"/{value.regexp}/{flags}"
    if isinstance(value, SigmaCIDRExpression):
        return f"cidr {value.cidr}"
    if isinstance(value, SigmaCompareExpression):
        return f"{_COMPARE_SYMBOLS[value.op]} {value.number.number}"
    if isinstance(value, SigmaFieldReference):
        return f"field({value.field})"
    if isinstance(value, SigmaQueryExpression):
        return f"query({value.expr})"
    if isinstance(value, SigmaExpansion):
        return "(" + " OR ".join(render_value(v) for v in value.values) + ")"
    if isinstance(value, SigmaExists):
        return "exists" if value.exists else "not exists"
    return type(value).__name__


def _render_comparison(field_name: str, value: SigmaType) -> str:
    rendered = render_value(value)
    if isinstance(value, SigmaRegularExpression):
        return f"{field_name} =~ {rendered}"
    if isinstance(value, SigmaCompareExpression):
        return f"{field_name} {rendered}"
    if isinstance(value, SigmaExists):
        return f"{field_name} {rendered}"
    if isinstance(value, SigmaCIDRExpression):
        return f"{field_name} in {rendered}"
    if isinstance(value, SigmaNull):
        return f"{field_name} is null"
    return f"{field_name} = {rendered}"


def _join(parts: list[str], operator: str) -> str:
    if len(parts) == 1:
        return parts[0]
    return "(" + f" {operator} ".join(parts) + ")"


def _render_item(item: SigmaDetectionItem) -> str:
    joiner = "OR" if item.value_linking is ConditionOR else "AND"
    if item.field is None:
        parts = [render_value(v) for v in item.value]
    else:
        parts = [_render_comparison(item.field, v) for v in item.value]
    rendered = _join(parts, joiner) if parts else "(no value)"
    return f"NOT {rendered}" if item.negated else rendered


def render_detection(detection: SigmaDetection | SigmaDetectionItem) -> str:
    """Render a detection as a boolean expression.

    Notation: ``field = 'value'`` with ``*`` and ``?`` as wildcards (values
    appear as the backend receives them, after modifiers such as
    ``contains`` were applied), ``field =~ /regex/flags``, ``field in cidr
    10.0.0.0/8``, ``field > 5``, ``field is null``, ``field exists``,
    ``field = field(other)`` for field references, plain values for keyword
    detections, and ``AND`` / ``OR`` / ``NOT`` with parentheses.
    """
    if isinstance(detection, SigmaDetectionItem):
        return _render_item(detection)
    joiner = "OR" if detection.item_linking is ConditionOR else "AND"
    parts = [render_detection(child) for child in detection.detection_items]
    if not parts:
        return "(empty)"
    return _join(parts, joiner)


def detection_fields(detection: SigmaDetection | SigmaDetectionItem) -> set[str]:
    """Return all field names used in *detection*."""
    if isinstance(detection, SigmaDetectionItem):
        return {detection.field} if detection.field is not None else set()
    found: set[str] = set()
    for child in detection.detection_items:
        found |= detection_fields(child)
    return found


def rule_fields(rule: SigmaRule | SigmaCorrelationRule) -> set[str]:
    """Return the field names a rule uses in its detections or ``group-by``."""
    if isinstance(rule, SigmaCorrelationRule):
        return set(rule.group_by or [])
    found: set[str] = set()
    for detection in rule.detection.detections.values():
        found |= detection_fields(detection)
    return found


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)


# ---------------------------------------------------------------------------
# Applying
# ---------------------------------------------------------------------------


@dataclass
class ApplyOutcome:
    """What happened when a pipeline was applied to one rule."""

    applied: list[int]
    """Positions (0-based) of the processing items that applied."""
    error: str | None = None
    failed_item: int | None = None
    """Position of the item that raised ``error``, if known."""


def run_pipeline(
    pipeline: ProcessingPipeline, rule: SigmaRule | SigmaCorrelationRule
) -> ApplyOutcome:
    """Apply *pipeline* to *rule* in place and report what happened.

    A ``rule_failure`` or ``detection_item_failure`` transformation stops
    processing; the outcome then names the failing item.
    """
    try:
        pipeline.apply(rule)
    except Exception as exc:  # noqa: BLE001 - reported to the client
        applied = [n for n, done in enumerate(pipeline.applied) if done]
        failed = len(pipeline.applied)
        failed_item = failed if failed < len(pipeline.items) else None
        message = str(exc) if isinstance(exc, SigmaError) else repr(exc)
        return ApplyOutcome(applied, message, failed_item)
    return ApplyOutcome([n for n, done in enumerate(pipeline.applied) if done])


def _logsource_dict(rule: SigmaRule) -> dict[str, str]:
    logsource = rule.logsource
    return {
        key: value
        for key, value in (
            ("product", logsource.product),
            ("category", logsource.category),
            ("service", logsource.service),
        )
        if value
    }


def _apply_to_rule(
    parsed: ParsedPipeline, rule: SigmaRule | SigmaCorrelationRule
) -> dict[str, Any]:
    pipeline = parsed.pipeline
    original_fields = rule_fields(rule)
    outcome = run_pipeline(pipeline, rule)
    mappings = {
        source: sorted(targets)
        for source, targets in sorted(pipeline.field_mappings.items())
    }
    final_fields = rule_fields(rule)
    renamed = {source for source, targets in mappings.items() if targets != [source]}
    result: dict[str, Any] = {
        "title": rule.title,
        "id": str(rule.id) if rule.id else None,
        "kind": "correlation" if isinstance(rule, SigmaCorrelationRule) else "rule",
        "status": "failed" if outcome.error else "ok",
        "error": None,
        "applied_transformations": [parsed.labels[n] for n in outcome.applied],
        "field_mappings": mappings,
        "unmapped_fields": sorted((final_fields & original_fields) - renamed),
        "state": {key: _json_safe(value) for key, value in pipeline.state.items()},
    }
    if outcome.error is not None:
        result["error"] = {
            "message": outcome.error,
            "transformation": (
                parsed.labels[outcome.failed_item]
                if outcome.failed_item is not None
                else None
            ),
        }
    if isinstance(rule, SigmaCorrelationRule):
        result["group_by"] = list(rule.group_by or [])
    else:
        result["logsource"] = _logsource_dict(rule)
        result["detections"] = {
            name: render_detection(detection)
            for name, detection in rule.detection.detections.items()
        }
        result["condition"] = list(rule.detection.condition)
    return result


def apply_pipelines(rule_yaml: str, pipeline_yamls: list[str]) -> dict[str, Any]:
    """Apply one or more pipelines to the rules in *rule_yaml*.

    Returns:
        Dict with ``rules`` (one result per rule, see :func:`_apply_to_rule`),
        ``pipeline_order`` and ``note``; or ``error`` when a pipeline or the
        rules cannot be parsed.
    """
    if not pipeline_yamls:
        return {"error": "Pass at least one processing pipeline."}
    parsed_list: list[ParsedPipeline] = []
    for position, pipeline_yaml in enumerate(pipeline_yamls, start=1):
        try:
            parsed_list.append(parse_pipeline(pipeline_yaml))
        except PipelineParseError as exc:
            return {"error": f"Pipeline {position} is invalid: {exc}"}
    # pySigma expands modifiers such as windash while parsing (see
    # sigma.mcp.validation.MAX_EXPANDED_VALUES).
    too_many = too_many_values(rule_yaml)
    if too_many is not None:
        return {"error": too_many["description"]}
    try:
        collection = SigmaCollection.from_yaml(rule_yaml)
    except SigmaError as exc:
        return {"error": f"The rule could not be parsed: {exc}"}
    except yaml.YAMLError as exc:
        return {"error": f"The rule is not valid YAML: {exc}"}
    if not collection.rules:
        return {"error": "The YAML contains no Sigma rule."}

    order = [
        {"position": n, "name": p.pipeline.name, "priority": p.pipeline.priority}
        for n, p in sorted(
            enumerate(parsed_list, start=1), key=lambda np: np[1].pipeline.priority
        )
    ]
    combined = combine_pipelines(parsed_list)
    results: list[dict[str, Any]] = []
    for rule in collection.rules:
        if isinstance(rule, (SigmaRule, SigmaCorrelationRule)):
            results.append(_apply_to_rule(combined, rule))
    return {"rules": results, "pipeline_order": order, "note": NOT_RUN_NOTE}


# ---------------------------------------------------------------------------
# Reference catalogue
# ---------------------------------------------------------------------------


def _describe(classes: Mapping[str, type]) -> dict[str, str]:
    return {
        name: inspect.cleandoc(cls.__doc__ or "").split("\n\n", 1)[0]
        for name, cls in sorted(classes.items())
    }


def pipeline_catalog() -> dict[str, dict[str, str]]:
    """Return every pipeline building block pySigma knows, with descriptions.

    The keys are the identifiers used in pipeline YAML (``type:`` values).
    """
    return {
        "transformations": _describe(transformations),
        "rule_conditions": _describe(rule_conditions),
        "detection_item_conditions": _describe(detection_item_conditions),
        "field_name_conditions": _describe(field_name_conditions),
        "postprocessing": _describe(query_postprocessing_transformations),
        "finalizers": _describe(finalizers),
    }
