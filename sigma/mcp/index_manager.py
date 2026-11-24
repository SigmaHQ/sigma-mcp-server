"""Background building and serving of the SigmaHQ rule index.

Downloading the rules and building the index can take minutes, while MCP
clients often time out tool calls after seconds.  The :class:`IndexManager`
therefore builds the index in a background thread and never blocks a tool
call on it:

* At server start (:meth:`IndexManager.start_warmup`) an index saved by an
  earlier run is loaded at once.  A refresh starts in the background when no
  index exists or the saved one is older than the configured maximum age.
* Tools call :meth:`IndexManager.get_index`.  While no index is available
  they report the current state (:meth:`IndexManager.unavailable_message`)
  instead of waiting.  During a refresh the previous index keeps being
  served.
* A lock file in the data directory makes sure only one server process
  downloads at a time.  A process that had to wait for the lock loads the
  index the other process has just written instead of downloading again.

States::

    not_started → downloading → indexing → ready
                                         ↘ failed
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from sigma.mcp import config
from sigma.mcp.index import RuleIndex, build_index, load_index, save_index
from sigma.mcp.repo import RepoSnapshot, download_rules, remove_leftovers

log = logging.getLogger(__name__)

RULES_DIR_NAME = "sigma-rules"
INDEX_FILE_NAME = "index.json"
LOCK_FILE_NAME = ".refresh.lock"


class IndexStatus(str, Enum):
    """Lifecycle state of the rule index."""

    NOT_STARTED = "not_started"
    DOWNLOADING = "downloading"
    INDEXING = "indexing"
    READY = "ready"
    FAILED = "failed"


class FileLock:
    """A lock file shared between processes, created with ``O_EXCL``.

    The file holds the owner's process ID.  It counts as stale, and is
    removed, when the owner no longer runs (checked on POSIX systems only) or
    when the file is older than *stale_after*.  This keeps a server that was
    stopped during a download from blocking the next start.
    """

    def __init__(self, path: Path, stale_after: timedelta = timedelta(minutes=30)):
        self.path = path
        self.stale_after = stale_after

    def try_acquire(self) -> bool:
        """Acquire the lock without waiting.  Returns ``True`` on success."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            if self._is_stale():
                log.warning("Removing stale lock file %s", self.path)
                self.path.unlink(missing_ok=True)
                return self.try_acquire()
            return False
        with os.fdopen(fd, "w") as fh:
            fh.write(f"{os.getpid()}\n")
        return True

    def acquire(self, timeout: float, poll_interval: float = 1.0) -> bool:
        """Wait up to *timeout* seconds for the lock.  Returns ``True`` on success."""
        deadline = time.monotonic() + timeout
        while not self.try_acquire():
            if time.monotonic() >= deadline:
                return False
            time.sleep(poll_interval)
        return True

    def release(self) -> None:
        """Release the lock."""
        self.path.unlink(missing_ok=True)

    def _is_stale(self) -> bool:
        try:
            mtime = self.path.stat().st_mtime
            owner = self.path.read_text(encoding="ascii").strip()
        except FileNotFoundError:
            return False
        except (OSError, UnicodeDecodeError):
            owner = ""
        if time.time() - mtime > self.stale_after.total_seconds():
            return True
        return owner.isdigit() and not _process_alive(int(owner))


def _process_alive(pid: int) -> bool:
    """Return ``False`` only if process *pid* certainly does not exist.

    Only POSIX systems can check this safely (``os.kill`` with signal 0).
    Elsewhere the process is assumed to be alive.
    """
    if os.name != "posix":
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


Downloader = Callable[[Path], RepoSnapshot]


@dataclass(frozen=True)
class _Paths:
    data_dir: Path
    rules_dir: Path
    index_file: Path
    lock_file: Path


class IndexManager:
    """Owns the rule index and its background refresh.

    Args:
        downloader: Function that downloads the rules into the given
            directory.  Replaceable for tests.
        lock_timeout: Seconds to wait for another process's refresh.
        lock_poll_interval: Seconds between attempts to get the lock.
    """

    def __init__(
        self,
        downloader: Downloader = download_rules,
        lock_timeout: float = 30 * 60,
        lock_poll_interval: float = 1.0,
    ) -> None:
        self.downloader = downloader
        self.lock_timeout = lock_timeout
        self.lock_poll_interval = lock_poll_interval
        self._mutex = threading.Lock()
        self._thread: threading.Thread | None = None
        self.reset()

    def reset(self) -> None:
        """Forget all state.  Used by tests; does not touch files on disk."""
        self._status = IndexStatus.NOT_STARTED
        self._detail: str | None = None
        self._index: RuleIndex | None = None
        self._error: str | None = None

    # -- paths ---------------------------------------------------------------

    @staticmethod
    def paths() -> _Paths:
        """Return the file locations, derived from the current configuration."""
        base = config.data_dir()
        return _Paths(
            data_dir=base,
            rules_dir=base / RULES_DIR_NAME,
            index_file=base / INDEX_FILE_NAME,
            lock_file=base / LOCK_FILE_NAME,
        )

    # -- state ---------------------------------------------------------------

    @property
    def status(self) -> IndexStatus:
        """Current lifecycle state."""
        return self._status

    @property
    def refreshing(self) -> bool:
        """``True`` while a background refresh is running."""
        return self._thread is not None and self._thread.is_alive()

    def get_index(self) -> RuleIndex | None:
        """Return the current index without blocking on a refresh.

        If nothing has been started yet (warm-up disabled), an index saved by
        an earlier run is loaded from disk.
        """
        with self._mutex:
            if self._index is None and self._status is IndexStatus.NOT_STARTED:
                self._index = load_index(self.paths().index_file)
                if self._index is not None:
                    self._status = IndexStatus.READY
            return self._index

    def is_stale(self, index: RuleIndex) -> bool:
        """Return ``True`` when *index* is older than the configured maximum age."""
        max_age = config.index_max_age()
        if max_age is None:
            return False
        return datetime.now(timezone.utc) - index.generated_at > max_age

    def start_warmup(self) -> bool:
        """Load a saved index and refresh it in the background if needed.

        Returns:
            ``True`` if a background refresh was started.
        """
        index = self.get_index()
        if index is not None and not self.is_stale(index):
            return False
        return self.start_refresh()

    def start_refresh(self) -> bool:
        """Start downloading the rules and rebuilding the index in the background.

        Returns:
            ``False`` if a refresh is already running, else ``True``.
        """
        with self._mutex:
            if self.refreshing:
                return False
            # Set before the thread runs, so a tool call right after this one
            # already sees that a refresh is under way.
            self._status = IndexStatus.DOWNLOADING
            self._detail = "starting"
            self._thread = threading.Thread(
                target=self._refresh, name="sigma-rule-index", daemon=True
            )
            self._thread.start()
            return True

    def wait(self, timeout: float | None = None) -> None:
        """Block until a running refresh has finished (for tests and scripts)."""
        thread = self._thread
        if thread is not None:
            thread.join(timeout)

    # -- refresh ---------------------------------------------------------------

    def _set(self, status: IndexStatus, detail: str | None = None) -> None:
        with self._mutex:
            self._status = status
            self._detail = detail

    def _refresh(self) -> None:
        paths = self.paths()
        started_at = datetime.now(timezone.utc)
        lock = FileLock(paths.lock_file)
        self._set(IndexStatus.DOWNLOADING, "waiting for the update lock")
        had_to_wait = not lock.try_acquire()
        if had_to_wait:
            self._set(
                IndexStatus.DOWNLOADING,
                "waiting for another sigma-mcp-server process to finish updating",
            )
            if not lock.acquire(self.lock_timeout, self.lock_poll_interval):
                self._fail(
                    "Timed out waiting for another sigma-mcp-server process to "
                    f"release {paths.lock_file}"
                )
                return
        try:
            if had_to_wait:
                fresh = load_index(paths.index_file)
                if fresh is not None and fresh.generated_at >= started_at:
                    self._succeed(fresh)
                    return
            remove_leftovers(paths.rules_dir)
            self._set(IndexStatus.DOWNLOADING, "downloading the SigmaHQ rules")
            snapshot = self.downloader(paths.rules_dir)
            self._set(
                IndexStatus.INDEXING, f"indexing {snapshot.rule_files} rule files"
            )
            index = build_index(snapshot.path, snapshot.commit)
            save_index(index, paths.index_file)
            self._succeed(index)
        except Exception as exc:  # noqa: BLE001 - reported to the client
            log.exception("Refreshing the SigmaHQ rule index failed")
            self._fail(f"{type(exc).__name__}: {exc}")
        finally:
            lock.release()

    def _succeed(self, index: RuleIndex) -> None:
        with self._mutex:
            self._index = index
            self._error = None
            self._status = IndexStatus.READY
            self._detail = None
        log.info("SigmaHQ rule index ready: %d rules", len(index.rules))

    def _fail(self, error: str) -> None:
        with self._mutex:
            self._error = error
            self._status = IndexStatus.FAILED
            self._detail = None

    # -- reporting -------------------------------------------------------------

    def unavailable_message(self) -> str:
        """Explain to the client why no index is available and what to do."""
        status = self._status
        if status in (IndexStatus.DOWNLOADING, IndexStatus.INDEXING):
            return (
                "The SigmaHQ rule index is being built in the background "
                f"({self._detail or status.value}). This takes a few minutes on "
                "the first run. Try again shortly; get_index_status shows the "
                "progress."
            )
        if status is IndexStatus.FAILED:
            return (
                f"Building the SigmaHQ rule index failed: {self._error}. "
                "Call update_sigma_repository to try again."
            )
        return (
            "The SigmaHQ rule index has not been built yet. Call "
            "update_sigma_repository to download the rules and build it."
        )

    def describe(self) -> dict[str, Any]:
        """Return the state as a JSON-serialisable dict for ``get_index_status``."""
        index = self.get_index()
        info: dict[str, Any] = {
            "status": self._status.value,
            "refreshing": self.refreshing,
            "detail": self._detail,
            "last_error": self._error,
            "has_index": index is not None,
            "data_dir": str(self.paths().data_dir),
        }
        if index is not None:
            info.update(
                generated_at=index.generated_at.isoformat(),
                source_commit=index.source_commit,
                rule_count=len(index.rules),
                logsource_count=len(index.logsources),
                stale=self.is_stale(index),
            )
        else:
            info["message"] = self.unavailable_message()
        return info


index_manager = IndexManager()
"""The process-wide index manager used by the MCP tools."""
