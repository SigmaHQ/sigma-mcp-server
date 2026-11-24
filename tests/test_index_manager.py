"""Tests for sigma.mcp.index_manager (background refresh and file lock)."""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from conftest import FIXTURE_COMMIT
from sigma.mcp import index_manager as manager_module
from sigma.mcp.index import RuleIndex, build_index, save_index
from sigma.mcp.index_manager import FileLock, IndexManager, IndexStatus
from sigma.mcp.repo import RepoSnapshot

Downloader = Callable[[Path], RepoSnapshot]


def _manager(downloader: Downloader, **kwargs: float) -> IndexManager:
    return IndexManager(downloader=downloader, lock_poll_interval=0.01, **kwargs)


def _saved_index(rules_root: Path, age: timedelta = timedelta(0)) -> RuleIndex:
    index = build_index(rules_root, FIXTURE_COMMIT)
    index.generated_at = datetime.now(timezone.utc) - age
    save_index(index, IndexManager.paths().index_file)
    return index


def _failing(_: Path) -> RepoSnapshot:
    raise OSError("network unreachable")


def _wait_until(condition: Callable[[], bool], timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition not reached in time"
        time.sleep(0.01)


def _waiting_for_lock(manager: IndexManager) -> Callable[[], bool]:
    return lambda: "another sigma-mcp-server process" in manager.unavailable_message()


class TestFileLock:
    def test_acquire_release(self, tmp_path: Path) -> None:
        lock = FileLock(tmp_path / "sub" / "x.lock")
        assert lock.try_acquire()
        assert lock.path.read_text().strip() == str(os.getpid())
        assert not FileLock(lock.path).try_acquire()
        lock.release()
        assert not lock.path.exists()
        lock.release()  # releasing twice is harmless

    def test_acquire_times_out(self, tmp_path: Path) -> None:
        holder = FileLock(tmp_path / "x.lock")
        assert holder.try_acquire()
        assert not FileLock(holder.path).acquire(timeout=0.05, poll_interval=0.01)

    def test_acquire_waits_for_release(self, tmp_path: Path) -> None:
        holder = FileLock(tmp_path / "x.lock")
        assert holder.try_acquire()
        timer = threading.Timer(0.05, holder.release)
        timer.start()
        assert FileLock(holder.path).acquire(timeout=5, poll_interval=0.01)
        timer.join()

    def test_old_lock_is_stale(self, tmp_path: Path) -> None:
        path = tmp_path / "x.lock"
        path.write_text(f"{os.getpid()}\n")
        old = time.time() - 3600
        os.utime(path, (old, old))
        assert FileLock(path, stale_after=timedelta(minutes=30)).try_acquire()

    @pytest.mark.skipif(os.name != "posix", reason="PID check is POSIX only")
    def test_lock_of_dead_process_is_stale(self, tmp_path: Path) -> None:
        path = tmp_path / "x.lock"
        path.write_text("999999999\n")
        assert FileLock(path).try_acquire()

    def test_lock_of_running_process_is_kept(self, tmp_path: Path) -> None:
        path = tmp_path / "x.lock"
        path.write_text(f"{os.getpid()}\n")
        assert not FileLock(path).try_acquire()

    def test_lock_without_pid_is_kept(self, tmp_path: Path) -> None:
        path = tmp_path / "x.lock"
        path.write_bytes(b"\xff\xfe")
        assert not FileLock(path).try_acquire()

    def test_lock_vanishing_while_checking(self, tmp_path: Path) -> None:
        lock = FileLock(tmp_path / "x.lock")
        assert lock._is_stale() is False

    def test_process_alive_checks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def denied(pid: int, sig: int) -> None:
            raise PermissionError

        assert manager_module._process_alive(os.getpid()) is True
        monkeypatch.setattr("os.kill", denied)
        assert manager_module._process_alive(1) is True
        monkeypatch.setattr("os.name", "nt")
        assert manager_module._process_alive(999999999) is True


class TestRefresh:
    def test_success(self, fake_downloader: Downloader, isolated_index: Path) -> None:
        manager = _manager(fake_downloader)
        assert manager.describe()["status"] == "not_started"
        assert manager.start_refresh()
        manager.wait(10)
        assert manager.status is IndexStatus.READY
        index = manager.get_index()
        assert index is not None and index.source_commit == FIXTURE_COMMIT
        assert (isolated_index / "index.json").is_file()
        assert (isolated_index / "sigma-rules" / "rules").is_dir()
        assert not (isolated_index / ".refresh.lock").exists()

    def test_cleans_up_interrupted_download(
        self, fake_downloader: Downloader, isolated_index: Path
    ) -> None:
        leftover = isolated_index / ".download-interrupted"
        leftover.mkdir(parents=True)
        manager = _manager(fake_downloader)
        manager.start_refresh()
        manager.wait(10)
        assert manager.status is IndexStatus.READY
        assert not leftover.exists()

    def test_status_visible_before_thread_runs(self) -> None:
        release = threading.Event()

        def slow(target: Path) -> RepoSnapshot:
            release.wait(10)
            raise OSError("stopped")

        manager = _manager(slow)
        assert manager.start_refresh()
        assert manager.status is IndexStatus.DOWNLOADING
        assert manager.refreshing
        assert not manager.start_refresh()  # already running
        assert "being built" in manager.unavailable_message()
        release.set()
        manager.wait(10)
        assert not manager.refreshing

    def test_indexing_state(
        self, fake_downloader: Downloader, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[IndexStatus] = []
        manager = _manager(fake_downloader)
        original = build_index

        def spy(root: Path, commit: str | None = None) -> RuleIndex:
            seen.append(manager.status)
            return original(root, commit)

        monkeypatch.setattr("sigma.mcp.index_manager.build_index", spy)
        manager.start_refresh()
        manager.wait(10)
        assert seen == [IndexStatus.INDEXING]

    def test_failure_without_index(self, isolated_index: Path) -> None:
        manager = _manager(_failing)
        manager.start_refresh()
        manager.wait(10)
        assert manager.status is IndexStatus.FAILED
        assert manager.get_index() is None
        message = manager.unavailable_message()
        assert "network unreachable" in message
        assert "update_sigma_repository" in message
        assert not (isolated_index / ".refresh.lock").exists()

    def test_failure_keeps_previous_index(
        self, fake_downloader: Downloader, rules_root: Path
    ) -> None:
        previous = _saved_index(rules_root)
        manager = _manager(_failing)
        assert manager.get_index() == previous
        manager.start_refresh()
        manager.wait(10)
        assert manager.status is IndexStatus.FAILED
        assert manager.get_index() == previous
        assert manager.describe()["last_error"] == "OSError: network unreachable"

    def test_waits_for_other_process_and_reuses_its_index(
        self, rules_root: Path
    ) -> None:
        downloads: list[Path] = []

        def must_not_download(target: Path) -> RepoSnapshot:
            downloads.append(target)
            raise AssertionError("should reuse the other process's index")

        other = FileLock(IndexManager.paths().lock_file)
        assert other.try_acquire()
        manager = _manager(must_not_download)
        manager.start_refresh()
        _wait_until(_waiting_for_lock(manager))
        fresh = _saved_index(rules_root)  # the other process finishes ...
        other.release()  # ... and releases the lock
        manager.wait(10)
        assert downloads == []
        assert manager.status is IndexStatus.READY
        assert manager.get_index() == fresh

    def test_downloads_after_wait_if_other_process_left_no_index(
        self, fake_downloader: Downloader
    ) -> None:
        other = FileLock(IndexManager.paths().lock_file)
        assert other.try_acquire()
        manager = _manager(fake_downloader)
        manager.start_refresh()
        _wait_until(_waiting_for_lock(manager))
        other.release()
        manager.wait(10)
        assert manager.status is IndexStatus.READY

    def test_lock_timeout(self, fake_downloader: Downloader) -> None:
        other = FileLock(IndexManager.paths().lock_file)
        assert other.try_acquire()
        manager = _manager(fake_downloader, lock_timeout=0.05)
        manager.start_refresh()
        manager.wait(10)
        assert manager.status is IndexStatus.FAILED
        assert "Timed out" in manager.unavailable_message()
        other.release()


class TestWarmup:
    def test_without_saved_index_starts_refresh(
        self, fake_downloader: Downloader
    ) -> None:
        manager = _manager(fake_downloader)
        assert manager.start_warmup()
        manager.wait(10)
        assert manager.status is IndexStatus.READY

    def test_fresh_saved_index_is_used(self, rules_root: Path) -> None:
        saved = _saved_index(rules_root)
        manager = _manager(_failing)
        assert not manager.start_warmup()
        assert manager.status is IndexStatus.READY
        assert manager.get_index() == saved

    def test_stale_saved_index_is_served_while_refreshing(
        self, fake_downloader: Downloader, rules_root: Path
    ) -> None:
        saved = _saved_index(rules_root, age=timedelta(days=30))
        manager = _manager(fake_downloader)
        assert manager.is_stale(saved)
        assert manager.start_warmup()
        assert manager.get_index() is not None
        manager.wait(10)
        refreshed = manager.get_index()
        assert refreshed is not None and refreshed.generated_at > saved.generated_at

    def test_refresh_disabled_by_max_age_zero(
        self, rules_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SIGMA_MCP_INDEX_MAX_AGE_DAYS", "0")
        saved = _saved_index(rules_root, age=timedelta(days=365))
        manager = _manager(_failing)
        assert not manager.is_stale(saved)
        assert not manager.start_warmup()


class TestReporting:
    def test_not_started(self, isolated_index: Path) -> None:
        manager = _manager(_failing)
        info = manager.describe()
        assert info["status"] == "not_started"
        assert info["has_index"] is False
        assert info["data_dir"] == str(isolated_index)
        assert "has not been built yet" in info["message"]

    def test_ready(self, rules_root: Path) -> None:
        _saved_index(rules_root)
        info = _manager(_failing).describe()
        assert info["status"] == "ready"
        assert info["source_commit"] == FIXTURE_COMMIT
        assert info["rule_count"] == 8
        assert info["logsource_count"] == 4
        assert info["stale"] is False
        assert "message" not in info
