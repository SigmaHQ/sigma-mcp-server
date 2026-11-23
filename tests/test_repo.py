"""Tests for sigma.mcp.repo (download and extraction of the SigmaHQ rules)."""

from __future__ import annotations

import zipfile
from pathlib import Path

import httpx
import pytest

from conftest import FIXTURE_COMMIT, build_fixture_zip
from sigma.mcp.repo import (
    SIGMA_ZIP_URL,
    download_rules,
    extract_rules,
    remove_leftovers,
)


def _client(payload: bytes, status_code: int = 200) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == SIGMA_ZIP_URL
        return httpx.Response(status_code, content=payload)

    return httpx.Client(transport=httpx.MockTransport(handler))


def _relative_files(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}


class TestExtractRules:
    def test_extracts_only_rule_directories(self, tmp_path: Path) -> None:
        archive = tmp_path / "sigma.zip"
        archive.write_bytes(build_fixture_zip())
        commit, count = extract_rules(archive, tmp_path / "out")
        files = _relative_files(tmp_path / "out")
        assert commit == FIXTURE_COMMIT
        assert count == len(files) == 9
        assert "rules/windows/process_creation/" in "".join(sorted(files))
        assert any(f.startswith("rules-emerging-threats/") for f in files)
        assert any(f.startswith("rules-threat-hunting/") for f in files)
        assert not any(f.startswith("deprecated/") for f in files)
        assert "rules/README.md" not in files

    def test_comment_without_commit(self, tmp_path: Path) -> None:
        archive = tmp_path / "sigma.zip"
        archive.write_bytes(build_fixture_zip(comment=b"not a sha"))
        commit, _ = extract_rules(archive, tmp_path / "out")
        assert commit is None

    def test_skips_unsafe_and_shallow_entries(self, tmp_path: Path) -> None:
        archive = tmp_path / "sigma.zip"
        archive.write_bytes(
            build_fixture_zip(
                extra={
                    "sigma-master/rules/../../escape.yml": b"title: x",
                    "/sigma-master/rules/absolute.yml": b"title: x",
                    "sigma-master/top_level.yml": b"title: x",
                    "sigma-master/rules/upper.YAML": b"title: x",
                }
            )
        )
        _, count = extract_rules(archive, tmp_path / "out")
        files = _relative_files(tmp_path / "out")
        assert "rules/upper.YAML" in files
        assert count == 10
        assert not (tmp_path / "escape.yml").exists()
        assert not any("absolute" in f or "top_level" in f for f in files)


class TestDownloadRules:
    def test_download_into_new_directory(self, tmp_path: Path) -> None:
        target = tmp_path / "data" / "sigma-rules"
        with _client(build_fixture_zip()) as client:
            snapshot = download_rules(target, client=client)
        assert snapshot.path == target
        assert snapshot.commit == FIXTURE_COMMIT
        assert snapshot.rule_files == 9
        assert (target / "rules" / "linux").is_dir()
        # No temporary download directories are left behind.
        assert sorted(p.name for p in target.parent.iterdir()) == ["sigma-rules"]

    def test_replaces_existing_directory(self, tmp_path: Path) -> None:
        target = tmp_path / "sigma-rules"
        (target / "rules").mkdir(parents=True)
        (target / "rules" / "removed_upstream.yml").write_text("title: old")
        with _client(build_fixture_zip()) as client:
            download_rules(target, client=client)
        assert not (target / "rules" / "removed_upstream.yml").exists()
        assert (target / "rules" / "linux").is_dir()
        assert sorted(p.name for p in tmp_path.iterdir()) == ["sigma-rules"]

    def test_http_error_keeps_existing_directory(self, tmp_path: Path) -> None:
        target = tmp_path / "sigma-rules"
        target.mkdir()
        (target / "keep.yml").write_text("title: keep")
        with _client(b"gone", status_code=503) as client:
            with pytest.raises(httpx.HTTPStatusError):
                download_rules(target, client=client)
        assert (target / "keep.yml").read_text() == "title: keep"
        assert sorted(p.name for p in tmp_path.iterdir()) == ["sigma-rules"]

    def test_invalid_zip(self, tmp_path: Path) -> None:
        with _client(b"<html>not a zip</html>") as client:
            with pytest.raises(zipfile.BadZipFile):
                download_rules(tmp_path / "sigma-rules", client=client)
        assert not (tmp_path / "sigma-rules").exists()

    def test_creates_and_closes_own_client(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        created: list[httpx.Client] = []
        real_client = httpx.Client

        def factory(**kwargs: object) -> httpx.Client:
            assert kwargs["follow_redirects"] is True
            client = real_client(
                transport=httpx.MockTransport(
                    lambda _: httpx.Response(200, content=build_fixture_zip())
                )
            )
            created.append(client)
            return client

        monkeypatch.setattr("httpx.Client", factory)
        snapshot = download_rules(tmp_path / "sigma-rules")
        assert snapshot.rule_files == 9
        assert len(created) == 1 and created[0].is_closed


class TestRemoveLeftovers:
    def test_removes_interrupted_downloads(self, tmp_path: Path) -> None:
        target = tmp_path / "sigma-rules"
        (target / "rules").mkdir(parents=True)
        (tmp_path / ".download-abc" / "rules").mkdir(parents=True)
        (tmp_path / ".sigma-rules.old-123").mkdir()
        (tmp_path / ".download-file").write_text("not a directory")
        (tmp_path / "index.json").write_text("{}")
        assert remove_leftovers(target) == 2
        assert sorted(p.name for p in tmp_path.iterdir()) == [
            ".download-file",
            "index.json",
            "sigma-rules",
        ]

    def test_missing_parent(self, tmp_path: Path) -> None:
        assert remove_leftovers(tmp_path / "missing" / "sigma-rules") == 0
