"""Tests for sigma.mcp.index (rule index, search and logsource statistics)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from conftest import FIXTURE_COMMIT
from sigma.mcp.index import (
    INDEX_SCHEMA_VERSION,
    LogsourceStats,
    RuleIndex,
    build_index,
    extract_detection_fields,
    load_index,
    logsource_key,
    parse_rule_file,
    save_index,
)

PSEXEC_ID = "0b5b3d5c-1a8e-4d4c-9f29-3c6c8e0b7a01"
LSASS_ID = "6c4c5b2e-2f3a-4b8e-8c9d-1e2f3a4b5c02"
PSEXEC_PATH = (
    "rules/windows/process_creation/proc_creation_win_sysinternals_psexec_remote.yml"
)


@pytest.fixture
def index(rules_root: Path) -> RuleIndex:
    return build_index(rules_root, FIXTURE_COMMIT)


class TestLogsourceKey:
    def test_all_parts(self) -> None:
        assert logsource_key("windows", "process_creation", "sysmon") == (
            "windows/process_creation/sysmon"
        )

    def test_product_and_service(self) -> None:
        assert logsource_key("windows", None, "security") == "windows/security"

    def test_empty(self) -> None:
        assert logsource_key(None, None, None) == "unknown"


class TestExtractDetectionFields:
    def test_maps_lists_and_modifiers(self) -> None:
        detection = {
            "selection": {"Image|endswith": "x", "CommandLine|contains|all": ["a"]},
            "selection_list": [{"OriginalFileName": "a"}, {"Product": "b"}],
            "filter_main": {"ParentImage": "y"},
            "keywords": ["plain", "values"],
            "condition": "selection and not filter_main",
            "timeframe": "5m",
        }
        assert extract_detection_fields(detection) == {
            "Image",
            "CommandLine",
            "OriginalFileName",
            "Product",
            "ParentImage",
        }

    def test_keyword_only_modifier_has_no_field(self) -> None:
        assert extract_detection_fields({"sel": {"|re": "abc"}}) == set()

    def test_not_a_dict(self) -> None:
        assert extract_detection_fields(None) == set()
        assert extract_detection_fields(["a"]) == set()


class TestBuildIndex:
    def test_counts_rules_and_correlations(self, index: RuleIndex) -> None:
        kinds = sorted(entry.kind for entry in index.rules)
        # 7 detection rules (one in a multi-document file) + 1 correlation.
        assert kinds == ["correlation"] + ["rule"] * 7
        assert index.source_commit == FIXTURE_COMMIT
        assert index.generated_at.tzinfo is not None

    def test_skips_broken_and_non_rules(self, index: RuleIndex) -> None:
        titles = {entry.title for entry in index.rules}
        assert "Broken" not in titles
        assert "Not A Rule" not in titles

    def test_entry_metadata(self, index: RuleIndex) -> None:
        entry = index.find(PSEXEC_ID)
        assert entry is not None
        assert entry.title == "PsExec Remote Execution"
        assert entry.path == PSEXEC_PATH
        assert entry.rule_set == "rules"
        assert entry.date == "2023-02-14"
        assert entry.logsource == {"product": "windows", "category": "process_creation"}
        assert entry.fields == [
            "CommandLine",
            "Image",
            "OriginalFileName",
            "ParentImage",
        ]
        assert "attack.t1569.002" in entry.tags

    def test_string_date_kept(self, index: RuleIndex) -> None:
        entry = index.find(LSASS_ID)
        assert entry is not None and entry.date == "2022/08/01"

    def test_logsource_statistics(self, index: RuleIndex) -> None:
        assert set(index.logsources) == {
            "linux",
            "linux/process_creation",
            "windows/process_creation",
            "windows/security",
        }
        proc = index.logsources["windows/process_creation"]
        # psexec, lsass and the emerging-threats rule
        assert proc.rule_count == 3
        assert proc.fields["Image"] == 3
        assert proc.fields["CommandLine"] == 2
        assert proc.top_fields(2) == [("Image", 3), ("CommandLine", 2)]
        # The correlation rule has no logsource and is not counted.
        assert index.logsources["windows/security"].rule_count == 2
        assert index.logsources["linux"].fields == {}
        assert index.rules_with_logsource == 7

    def test_explicit_file_list(self, rules_root: Path) -> None:
        only = rules_root / PSEXEC_PATH
        index = build_index(rules_root, files=[only])
        assert [entry.id for entry in index.rules] == [PSEXEC_ID]
        assert index.source_commit is None

    def test_tags_and_logsource_values_normalised(self, tmp_path: Path) -> None:
        rule = tmp_path / "rules" / "odd.yml"
        rule.parent.mkdir()
        rule.write_text(
            "title: Odd\ntags: not-a-list\nlogsource:\n  product: 42\n  category: ''\n"
            "detection:\n  sel:\n    a: b\n  condition: sel\n"
        )
        (entry,) = parse_rule_file(rule, tmp_path)
        assert entry.tags == []
        assert entry.logsource == {"product": "42"}
        assert entry.id == "" and entry.status == ""


class TestSearch:
    def test_title_match_ranks_first(self, index: RuleIndex) -> None:
        results = index.search("psexec")
        assert results[0][1].id == PSEXEC_ID
        assert results[0][0] == 3

    def test_tag_and_text_matches(self, index: RuleIndex) -> None:
        tag_hit = index.search("attack.t1003.001")
        assert [entry.id for _, entry in tag_hit] == [LSASS_ID]
        assert tag_hit[0][0] == 2
        text_hit = index.search("minidump")
        assert [(score, e.id) for score, e in text_hit] == [(1, LSASS_ID)]

    def test_scores_add_up_over_keywords(self, index: RuleIndex) -> None:
        score, entry = index.search("lsass comsvcs credential")[0]
        assert entry.id == LSASS_ID
        assert score == 3 + 3 + 2

    def test_field_names_are_searchable(self, index: RuleIndex) -> None:
        ids = {entry.id for _, entry in index.search("originalfilename")}
        assert PSEXEC_ID in ids

    def test_exact_id_ranks_first(self, index: RuleIndex) -> None:
        results = index.search(LSASS_ID)
        assert results[0][1].id == LSASS_ID
        assert results[0][0] >= 1000

    def test_short_keywords_ignored(self, index: RuleIndex) -> None:
        assert index.search("a of") == []
        assert index.search("") == []

    def test_max_results_and_stable_order(self, index: RuleIndex) -> None:
        results = index.search("windows", max_results=2)
        assert len(results) == 2
        assert results == index.search("windows", max_results=2)

    def test_no_match(self, index: RuleIndex) -> None:
        assert index.search("kubernetes") == []

    def test_find_by_path_and_unknown(self, index: RuleIndex) -> None:
        entry = index.find(f"  {PSEXEC_PATH} ")
        assert entry is not None and entry.id == PSEXEC_ID
        assert index.find("does-not-exist") is None


class TestPersistence:
    def test_round_trip(self, index: RuleIndex, tmp_path: Path) -> None:
        path = tmp_path / "nested" / "index.json"
        save_index(index, path)
        loaded = load_index(path)
        assert loaded == index
        assert [p.name for p in path.parent.iterdir()] == ["index.json"]

    def test_missing_file(self, tmp_path: Path) -> None:
        assert load_index(tmp_path / "missing.json") is None

    @pytest.mark.parametrize(
        "content",
        [
            "{not json",
            "[]",
            json.dumps({"schema_version": INDEX_SCHEMA_VERSION + 1}),
            json.dumps({"schema_version": INDEX_SCHEMA_VERSION}),
            json.dumps(
                {
                    "schema_version": INDEX_SCHEMA_VERSION,
                    "generated_at": "2024-01-01T00:00:00+00:00",
                    "source_commit": None,
                    "rules": [{"unexpected": 1}],
                    "logsources": {},
                }
            ),
        ],
    )
    def test_invalid_content(self, tmp_path: Path, content: str) -> None:
        path = tmp_path / "index.json"
        path.write_text(content)
        assert load_index(path) is None

    def test_to_json_layout(self) -> None:
        index = RuleIndex(
            generated_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            source_commit=None,
            rules=[],
            logsources={"linux": LogsourceStats("linux", "linux", None, None, 1)},
        )
        data = index.to_json()
        assert data["schema_version"] == INDEX_SCHEMA_VERSION
        assert data["generated_at"] == "2024-01-01T00:00:00+00:00"
        assert data["logsources"]["linux"]["rule_count"] == 1
