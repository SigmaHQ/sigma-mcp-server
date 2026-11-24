"""Index of the SigmaHQ rules: search entries and logsource statistics.

A single pass over the downloaded rule files produces both

* one :class:`RuleEntry` per rule, used by the rule search, and
* one :class:`LogsourceStats` per logsource, counting how many rules use the
  logsource and how often each field appears in their detections.  Pipeline
  coverage analysis builds on these statistics.

The index is persisted as JSON so a restarted server can use it at once.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

INDEX_SCHEMA_VERSION = 1
"""Bumped whenever the JSON layout changes; older files are ignored."""

_RULE_SUFFIXES = (".yml", ".yaml")
_LOGSOURCE_KEYS = ("product", "category", "service")
_NON_FIELD_DETECTION_KEYS = {"condition", "timeframe"}
_TITLE_WEIGHT = 3
_TAG_WEIGHT = 2
_TEXT_WEIGHT = 1
_ID_MATCH_SCORE = 1000
_MIN_KEYWORD_LENGTH = 3


@dataclass(frozen=True)
class RuleEntry:
    """Metadata of one rule in the SigmaHQ repository."""

    id: str
    title: str
    description: str
    status: str
    level: str
    author: str
    date: str
    tags: list[str]
    logsource: dict[str, str]
    fields: list[str]
    path: str
    """Path relative to the rules root, with ``/`` separators."""
    rule_set: str
    """Top-level directory, e.g. ``rules`` or ``rules-emerging-threats``."""
    kind: str
    """``rule`` for detection rules, ``correlation`` for correlation rules."""

    def search_text(self) -> str:
        """Return the lower-cased text that keyword search matches against."""
        return " ".join(
            [
                self.id,
                self.title,
                self.description,
                " ".join(self.tags),
                " ".join(self.logsource.values()),
                " ".join(self.fields),
                self.path,
            ]
        ).lower()


@dataclass
class LogsourceStats:
    """How often a logsource and its fields are used across the rules."""

    key: str
    product: str | None
    category: str | None
    service: str | None
    rule_count: int = 0
    fields: dict[str, int] = field(default_factory=dict)

    def top_fields(self, limit: int | None = None) -> list[tuple[str, int]]:
        """Return ``(field, rule count)`` pairs, most frequent first."""
        ranked = sorted(self.fields.items(), key=lambda item: (-item[1], item[0]))
        return ranked if limit is None else ranked[:limit]


@dataclass
class RuleIndex:
    """Search entries and logsource statistics built from one rule snapshot."""

    generated_at: datetime
    source_commit: str | None
    rules: list[RuleEntry]
    logsources: dict[str, LogsourceStats]

    @property
    def rules_with_logsource(self) -> int:
        """Number of rules that contribute to the logsource statistics."""
        return sum(stats.rule_count for stats in self.logsources.values())

    def find(self, identifier: str) -> RuleEntry | None:
        """Return the rule with the given ID or repository path."""
        wanted = identifier.strip()
        for entry in self.rules:
            if entry.id == wanted or entry.path == wanted:
                return entry
        return None

    def search(self, query: str, max_results: int = 10) -> list[tuple[int, RuleEntry]]:
        """Rank rules by how well they match the keywords in *query*.

        Each keyword (at least three characters, case-insensitive) scores
        3 points when it occurs in the title, otherwise 2 points in a tag,
        otherwise 1 point anywhere else in the rule's metadata, logsource or
        detection field names.  A query equal to a rule ID ranks that rule
        first.  Rules without any matching keyword are not returned.

        Returns:
            Up to *max_results* ``(score, entry)`` pairs, best match first.
        """
        keywords = [
            kw for kw in query.lower().split() if len(kw) >= _MIN_KEYWORD_LENGTH
        ]
        exact_id = query.strip()
        scored: list[tuple[int, RuleEntry]] = []
        for entry in self.rules:
            score = _ID_MATCH_SCORE if exact_id and entry.id == exact_id else 0
            if keywords:
                score += _keyword_score(entry, keywords)
            if score > 0:
                scored.append((score, entry))
        scored.sort(key=lambda item: (-item[0], item[1].title, item[1].path))
        return scored[:max_results]

    def to_json(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""
        return {
            "schema_version": INDEX_SCHEMA_VERSION,
            "generated_at": self.generated_at.isoformat(),
            "source_commit": self.source_commit,
            "rules": [asdict(entry) for entry in self.rules],
            "logsources": {
                key: asdict(stats) for key, stats in self.logsources.items()
            },
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> RuleIndex:
        """Inverse of :meth:`to_json`.

        Raises:
            ValueError: *data* has a different schema version.
            KeyError, TypeError: *data* is malformed.
        """
        if data.get("schema_version") != INDEX_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported index schema version {data.get('schema_version')!r}"
            )
        return cls(
            generated_at=datetime.fromisoformat(data["generated_at"]),
            source_commit=data["source_commit"],
            rules=[RuleEntry(**entry) for entry in data["rules"]],
            logsources={
                key: LogsourceStats(**stats)
                for key, stats in data["logsources"].items()
            },
        )


def _keyword_score(entry: RuleEntry, keywords: list[str]) -> int:
    title = entry.title.lower()
    tags = " ".join(entry.tags).lower()
    text = entry.search_text()
    score = 0
    for kw in keywords:
        if kw in title:
            score += _TITLE_WEIGHT
        elif kw in tags:
            score += _TAG_WEIGHT
        elif kw in text:
            score += _TEXT_WEIGHT
    return score


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------


def logsource_key(
    product: str | None, category: str | None, service: str | None
) -> str:
    """Return the statistics key of a logsource, e.g. ``windows/process_creation``.

    The present parts are joined with ``/`` in the order product, category,
    service.  A logsource without any of them is keyed ``unknown``.
    """
    parts = [part for part in (product, category, service) if part]
    return "/".join(parts) if parts else "unknown"


def extract_detection_fields(detection: object) -> set[str]:
    """Return the field names referenced in a rule's ``detection`` section.

    Field modifiers are stripped (``CommandLine|contains`` → ``CommandLine``).
    Keyword detections (plain lists of values) reference no field.  Filters
    count as well, because a processing pipeline has to map their fields too.
    """
    fields: set[str] = set()
    if not isinstance(detection, dict):
        return fields
    for name, value in detection.items():
        if name in _NON_FIELD_DETECTION_KEYS:
            continue
        items = value if isinstance(value, list) else [value]
        for item in items:
            if isinstance(item, dict):
                for field_name in item:
                    base = str(field_name).split("|", 1)[0].strip()
                    if base:
                        fields.add(base)
    return fields


def iter_rule_files(rules_root: Path) -> Iterator[Path]:
    """Yield all rule files below *rules_root* in a stable order."""
    for path in sorted(rules_root.rglob("*")):
        if path.is_file() and path.suffix.lower() in _RULE_SUFFIXES:
            yield path


def parse_rule_file(path: Path, rules_root: Path) -> list[RuleEntry]:
    """Parse one rule file into index entries.

    Files that are not valid YAML, or YAML documents that are not Sigma rules
    (no ``title``, or neither ``logsource`` nor ``correlation``), produce no
    entries.
    """
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            documents = list(yaml.safe_load_all(fh))
    except yaml.YAMLError:
        return []
    relative = path.relative_to(rules_root).as_posix()
    rule_set = relative.split("/", 1)[0]
    entries: list[RuleEntry] = []
    for doc in documents:
        entry = _entry_from_document(doc, relative, rule_set)
        if entry is not None:
            entries.append(entry)
    return entries


def _entry_from_document(doc: object, path: str, rule_set: str) -> RuleEntry | None:
    if not isinstance(doc, dict) or "title" not in doc:
        return None
    if "correlation" in doc:
        kind = "correlation"
    elif isinstance(doc.get("logsource"), dict):
        kind = "rule"
    else:
        return None
    raw_logsource = doc.get("logsource")
    logsource: dict[str, str] = {}
    if isinstance(raw_logsource, dict):
        logsource = {
            key: str(raw_logsource[key])
            for key in _LOGSOURCE_KEYS
            if raw_logsource.get(key)
        }
    raw_tags = doc.get("tags")
    tags = [str(tag) for tag in raw_tags] if isinstance(raw_tags, list) else []
    return RuleEntry(
        id=_text(doc.get("id")),
        title=_text(doc.get("title")),
        description=_text(doc.get("description")),
        status=_text(doc.get("status")),
        level=_text(doc.get("level")),
        author=_text(doc.get("author")),
        date=_text(doc.get("date")),
        tags=tags,
        logsource=logsource,
        fields=sorted(extract_detection_fields(doc.get("detection"))),
        path=path,
        rule_set=rule_set,
        kind=kind,
    )


def _text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return str(value).strip()


def build_index(
    rules_root: Path,
    source_commit: str | None = None,
    files: Iterable[Path] | None = None,
) -> RuleIndex:
    """Build the index from the rule files below *rules_root*.

    Args:
        rules_root: Directory holding the ``rules*`` directories.
        source_commit: Commit SHA of the snapshot, stored for reference.
        files: Rule files to index.  Defaults to all files below *rules_root*.
    """
    rules: list[RuleEntry] = []
    logsources: dict[str, LogsourceStats] = {}
    for path in files if files is not None else iter_rule_files(rules_root):
        for entry in parse_rule_file(path, rules_root):
            rules.append(entry)
            if entry.kind != "rule" or not entry.logsource:
                continue
            product = entry.logsource.get("product")
            category = entry.logsource.get("category")
            service = entry.logsource.get("service")
            key = logsource_key(product, category, service)
            stats = logsources.get(key)
            if stats is None:
                stats = LogsourceStats(key, product, category, service)
                logsources[key] = stats
            stats.rule_count += 1
            for field_name in entry.fields:
                stats.fields[field_name] = stats.fields.get(field_name, 0) + 1
    return RuleIndex(
        generated_at=datetime.now(timezone.utc),
        source_commit=source_commit,
        rules=rules,
        logsources=dict(sorted(logsources.items())),
    )


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def save_index(index: RuleIndex, path: Path) -> None:
    """Write *index* to *path* atomically (write to a temp file, then rename)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(index.to_json(), fh, ensure_ascii=False)
    os.replace(tmp, path)


def load_index(path: Path) -> RuleIndex | None:
    """Load an index written by :func:`save_index`.

    Returns ``None`` when the file is missing, unreadable, malformed or uses
    a different schema version.  The caller then rebuilds the index.
    """
    try:
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return None
        return RuleIndex.from_json(data)
    except (OSError, ValueError, KeyError, TypeError):
        return None
