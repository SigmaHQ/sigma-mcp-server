"""MCP tools for developing Sigma processing pipelines."""

from __future__ import annotations

from typing import Any

from sigma.mcp import coverage
from sigma.mcp.index_manager import index_manager
from sigma.mcp.pipelines import (
    PipelineParseError,
    apply_pipelines,
    parse_pipeline,
)
from sigma.mcp.pipelines import validate_pipeline as _validate_pipeline
from sigma.mcp.server import mcp

MAX_COVERAGE_LOGSOURCES = 200


@mcp.tool()
def validate_pipeline(pipeline_yaml: str) -> dict[str, Any]:
    """Validate a Sigma processing pipeline with pySigma.

    This is the canonical way to check a pipeline; call it after every change
    and fix all errors before using the pipeline.

    Args:
        pipeline_yaml: Complete processing pipeline in YAML format (top-level
            keys such as ``name``, ``priority``, ``vars``, ``transformations``,
            ``postprocessing``, ``finalizers``).

    Returns:
        Dict with ``valid``, ``errors`` (reasons the pipeline cannot be
        used), ``warnings`` (accepted by pySigma, but worth fixing, e.g.
        transformations without ``id`` or without conditions) and, when
        valid, a ``summary`` listing each transformation with its position,
        ``id``, ``type`` and logsource conditions.  Read
        ``sigma://pipelines/transformations`` for all transformation and
        condition types.
    """
    return _validate_pipeline(pipeline_yaml)


@mcp.tool()
def apply_pipeline(rule_yaml: str, pipeline_yamls: list[str]) -> dict[str, Any]:
    """Show what processing pipelines do to a Sigma rule.

    Use this to check field mappings and other transformations against real
    rules without a SIEM backend.  Several pipelines are applied in the order
    of their ``priority`` (lowest first), as sigma-cli does.

    Args:
        rule_yaml: One or more Sigma rules in YAML (multiple documents and
            correlation rules are allowed).
        pipeline_yamls: The processing pipelines to apply, each a complete
            YAML document.

    Returns:
        Dict with ``rules``, ``pipeline_order`` and ``note``.  Each rule has
        ``status`` (``ok`` or ``failed``), ``error`` (``message`` and the
        ``transformation`` that raised it, e.g. a ``rule_failure``),
        ``applied_transformations``, ``field_mappings`` (original field →
        new fields), ``unmapped_fields`` (fields passed through unchanged),
        the pipeline ``state``, the resulting ``logsource``, ``condition``
        and ``detections``.  Detections are boolean expressions:
        ``field = 'value'`` with ``*``/``?`` wildcards as the backend
        receives them (modifiers like ``contains`` already applied),
        ``field =~ /regex/``, ``field in cidr …``, ``field > n``,
        ``field is null``, combined with ``AND``/``OR``/``NOT``.
        Postprocessing and finalizers are backend-specific and are not run.
        On invalid input, the dict holds only ``error``.
    """
    return apply_pipelines(rule_yaml, pipeline_yamls)


@mcp.tool()
def analyze_pipeline_coverage(
    pipeline_yaml: str,
    logsource_filter: str = "",
    max_logsources: int = 30,
    field_threshold: float = coverage.DEFAULT_FIELD_THRESHOLD,
) -> dict[str, Any]:
    """Measure how well a processing pipeline covers the SigmaHQ rules.

    The pipeline is run with pySigma on probe rules for every logsource in
    the SigmaHQ rule index, and for every field that logsource's rules
    commonly use.

    Args:
        pipeline_yaml: The processing pipeline in YAML format.
        logsource_filter: Case-insensitive substring of logsource keys
            (``product/category/service``) to restrict the analysis to.
        max_logsources: Number of logsources to list in detail, most used
            first (the summary always counts all).
        field_threshold: Only fields used by at least this share of a
            logsource's rules are checked (0–1, default 0.05).

    Returns:
        Dict with ``index_status``, ``summary`` (logsources and rules per
        status), ``logsources`` and ``omitted_logsources``.  Each logsource
        has a ``status``: ``covered`` (a transformation specific to it
        applies), ``uncovered`` (nothing specific applies; consider adding
        transformations or a ``rule_failure``) or ``unsupported`` (the
        pipeline rejects its rules, ``message`` says why).  ``fields``
        sorts the commonly used fields into ``mapped`` (with new names),
        ``unmapped`` (passed through unchanged; fine if the target uses
        Sigma's field names), ``unsupported`` (rejected, e.g. by a
        ``detection_item_failure``) and ``dropped``.  On an invalid pipeline,
        or while the rule index is not ready, the dict holds ``error`` or
        ``message`` instead.
    """
    if not 0 <= field_threshold <= 1:
        return {"error": "field_threshold must be between 0 and 1."}
    try:
        parsed = parse_pipeline(pipeline_yaml)
    except PipelineParseError as exc:
        return {"error": f"The pipeline is invalid: {exc}"}
    index = index_manager.get_index()
    info: dict[str, Any] = {"index_status": index_manager.status.value}
    if index is None:
        return {**info, "message": index_manager.unavailable_message()}
    results = coverage.analyze_coverage(
        parsed, index, field_threshold, logsource_filter
    )
    limit = min(max(max_logsources, 0), MAX_COVERAGE_LOGSOURCES)
    return {
        **info,
        "summary": {**coverage.summarize(results), "field_threshold": field_threshold},
        "logsources": [result.to_json() for result in results[:limit]],
        "omitted_logsources": max(len(results) - limit, 0),
    }
