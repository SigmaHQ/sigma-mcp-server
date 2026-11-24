"""YAML alias bombs ("billion laughs") in client input are refused early."""

from __future__ import annotations

from typing import Any

import pytest

from sigma.mcp.pipelines import (
    MAX_LABEL_LENGTH,
    PipelineParseError,
    _item_label,
    parse_pipeline,
    validate_pipeline,
)


def _alias_bomb(levels: int) -> str:
    """Anchors whose top level ``*bomb`` expands to 9**levels values."""
    lines = ["l0: &l0 [" + ", ".join(["lol"] * 9) + "]"]
    for n in range(1, levels - 1):
        lines.append(f"l{n}: &l{n} [" + ", ".join([f"*l{n - 1}"] * 9) + "]")
    lines.append("top: &bomb [" + ", ".join([f"*l{levels - 2}"] * 9) + "]")
    return "\n".join(lines)


class TestPipelines:
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
