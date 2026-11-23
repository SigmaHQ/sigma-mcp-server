"""How well a processing pipeline covers the SigmaHQ rules.

The analysis runs the pipeline with pySigma on small probe rules instead of
reading the pipeline YAML, so every kind of condition (logsource, field name
and detection item conditions, condition expressions, negation) and every
transformation is evaluated exactly as a backend would.

For each logsource in the rule index:

1. A probe rule with that logsource is processed.  The logsource is
   ``unsupported`` if the pipeline raises an error for it (typically a
   ``rule_failure`` transformation), ``covered`` if at least one
   transformation applies that does not also apply to an unrelated
   logsource, and ``uncovered`` otherwise.
2. For every field used by at least ``field_threshold`` of the logsource's
   rules, a probe rule using only that field is processed.  The field is
   ``mapped`` (renamed, with the new names), ``unmapped`` (passed through
   unchanged), ``unsupported`` (the pipeline raises an error, typically a
   ``detection_item_failure``) or ``dropped`` (removed from the rule).

Probe rules compare each field with the placeholder value ``x``.
Transformations whose conditions depend on specific values are therefore not
reflected in the field results.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

from sigma.mcp.index import LogsourceStats, RuleIndex
from sigma.mcp.pipelines import ParsedPipeline, detection_fields, run_pipeline

DEFAULT_FIELD_THRESHOLD = 0.05
"""Fields used by fewer than 5 % of a logsource's rules are not checked."""

_PROBE_FIELD = "SigmaMcpCoverageProbe"
_PROBE_DETECTION = "probe"
_UNRELATED_LOGSOURCE = {"product": "sigma-mcp-coverage-probe"}


@dataclass
class LogsourceCoverage:
    """Coverage of one logsource."""

    stats: LogsourceStats
    status: str
    """``covered``, ``uncovered`` or ``unsupported``."""
    message: str | None = None
    transformations: list[str] = field(default_factory=list)
    mapped: dict[str, list[str]] = field(default_factory=dict)
    unmapped: list[str] = field(default_factory=list)
    unsupported: dict[str, str] = field(default_factory=dict)
    dropped: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""
        data: dict[str, Any] = {
            "key": self.stats.key,
            "product": self.stats.product,
            "category": self.stats.category,
            "service": self.stats.service,
            "rule_count": self.stats.rule_count,
            "status": self.status,
            "transformations": self.transformations,
            "fields": {
                "mapped": self.mapped,
                "unmapped": self.unmapped,
                "unsupported": self.unsupported,
                "dropped": self.dropped,
            },
        }
        if self.message is not None:
            data["message"] = self.message
        return data


def _probe_rule(logsource: dict[str, str], field_name: str) -> SigmaRule:
    return SigmaRule.from_dict(
        {
            "title": "sigma-mcp-server coverage probe",
            "logsource": logsource,
            "detection": {
                _PROBE_DETECTION: {field_name: "x"},
                "condition": _PROBE_DETECTION,
            },
        }
    )


def _logsource_of(stats: LogsourceStats) -> dict[str, str]:
    return {
        key: value
        for key, value in (
            ("product", stats.product),
            ("category", stats.category),
            ("service", stats.service),
        )
        if value
    }


def expected_fields(stats: LogsourceStats, threshold: float) -> list[str]:
    """Fields used by at least *threshold* of the logsource's rules, most used first."""
    if stats.rule_count == 0:
        return []
    return [
        name
        for name, count in stats.top_fields()
        if count / stats.rule_count >= threshold
    ]


def _check_field(
    parsed: ParsedPipeline,
    logsource: dict[str, str],
    field_name: str,
    result: LogsourceCoverage,
) -> None:
    try:
        rule = _probe_rule(logsource, field_name)
    except SigmaError as exc:
        result.unsupported[field_name] = f"Not a valid Sigma field name: {exc}"
        return
    outcome = run_pipeline(parsed.pipeline, rule)
    if outcome.error is not None:
        result.unsupported[field_name] = outcome.error
        return
    targets = parsed.pipeline.field_mappings.get(field_name)
    # Only the probe detection counts: transformations like add_condition add
    # detections with fields of their own.
    probe = rule.detection.detections.get(_PROBE_DETECTION)
    final = detection_fields(probe) if probe is not None else set()
    if targets and set(targets) != {field_name}:
        result.mapped[field_name] = sorted(targets)
    elif final == {field_name}:
        result.unmapped.append(field_name)
    elif not final:
        result.dropped.append(field_name)
    else:
        result.mapped[field_name] = sorted(final)


def analyze_logsource(
    parsed: ParsedPipeline,
    stats: LogsourceStats,
    generic_items: set[int],
    threshold: float,
) -> LogsourceCoverage:
    """Analyse one logsource (see the module documentation)."""
    logsource = _logsource_of(stats)
    outcome = run_pipeline(parsed.pipeline, _probe_rule(logsource, _PROBE_FIELD))
    specific = [n for n in outcome.applied if n not in generic_items]
    if outcome.error is not None:
        return LogsourceCoverage(
            stats=stats,
            status="unsupported",
            message=outcome.error,
            transformations=[parsed.labels[n] for n in specific],
        )
    result = LogsourceCoverage(
        stats=stats,
        status="covered" if specific else "uncovered",
        transformations=[parsed.labels[n] for n in specific],
    )
    for field_name in expected_fields(stats, threshold):
        _check_field(parsed, logsource, field_name, result)
    return result


def analyze_coverage(
    parsed: ParsedPipeline,
    index: RuleIndex,
    field_threshold: float = DEFAULT_FIELD_THRESHOLD,
    logsource_filter: str = "",
) -> list[LogsourceCoverage]:
    """Analyse every logsource of *index*, most used logsource first.

    Args:
        parsed: The pipeline to analyse.
        index: The rule index providing logsources and field statistics.
        field_threshold: Minimum share of a logsource's rules a field must
            appear in to be checked (0–1).
        logsource_filter: Case-insensitive substring of logsource keys to
            restrict the analysis to.
    """
    generic = run_pipeline(
        parsed.pipeline, _probe_rule(_UNRELATED_LOGSOURCE, _PROBE_FIELD)
    )
    generic_items = set(generic.applied)
    if generic.failed_item is not None:
        generic_items.add(generic.failed_item)
    needle = logsource_filter.strip().lower()
    selected = sorted(
        (s for k, s in index.logsources.items() if not needle or needle in k.lower()),
        key=lambda s: (-s.rule_count, s.key),
    )
    return [
        analyze_logsource(parsed, stats, generic_items, field_threshold)
        for stats in selected
    ]


def summarize(results: list[LogsourceCoverage]) -> dict[str, Any]:
    """Count logsources and rules per status."""
    logsources = {"covered": 0, "uncovered": 0, "unsupported": 0}
    rules = dict(logsources)
    for result in results:
        logsources[result.status] += 1
        rules[result.status] += result.stats.rule_count
    return {
        "logsources": logsources,
        "rules": rules,
        "total_rules": sum(rules.values()),
    }
