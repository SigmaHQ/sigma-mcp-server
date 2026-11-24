"""Pytest configuration for sigma-mcp-server tests."""

import dataclasses
import io
import shutil
import zipfile
from collections.abc import Callable, Generator
from pathlib import Path

import pytest

from sigma.mcp.repo import RepoSnapshot

FIXTURE_REPO = Path(__file__).parent / "tests" / "data" / "sigma-repo"
"""Miniature copy of the SigmaHQ repository layout used by the index tests."""

FIXTURE_COMMIT = "0123456789abcdef0123456789abcdef01234567"


@pytest.fixture
def anyio_backend() -> str:
    """Run async tests with asyncio."""
    return "asyncio"


@pytest.fixture(autouse=True)
def clear_session_cache() -> Generator[None, None, None]:
    """Clear the session state variables before each test to ensure test isolation."""
    import sigma.mcp.tools.rules as rules_module

    rules_module._current_validator_names = None
    rules_module._current_exclusions = []

    yield

    # Clear again after test
    rules_module._current_validator_names = None
    rules_module._current_exclusions = []


@pytest.fixture(autouse=True)
def isolated_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Generator[Path, None, None]:
    """Give every test its own data directory and an idle index manager.

    Warm-up is disabled so that connecting a client never starts a real
    download.  Tests that exercise the warm-up re-enable it explicitly.
    """
    from sigma.mcp.index_manager import index_manager
    from sigma.mcp.repo import download_rules

    data_dir = tmp_path / "data"
    monkeypatch.setenv("SIGMA_MCP_DATA_DIR", str(data_dir))
    monkeypatch.setenv("SIGMA_MCP_NO_WARMUP", "1")
    monkeypatch.delenv("SIGMA_MCP_INDEX_MAX_AGE_DAYS", raising=False)
    index_manager.reset()
    yield data_dir
    index_manager.wait(timeout=10)
    index_manager.reset()
    index_manager.downloader = download_rules


@pytest.fixture(autouse=True)
def reference_data_ready() -> Generator[None, None, None]:
    """Treat the MITRE reference data as loaded, so tests never wait for it.

    The tag validators still run and use pySigma's own data handling.
    """
    from sigma.mcp.reference_data import DatasetStatus, reference_data

    original = reference_data.datasets
    reference_data.datasets = [
        dataclasses.replace(dataset, status=DatasetStatus.READY) for dataset in original
    ]
    yield
    reference_data.wait(timeout=10)
    reference_data.datasets = original


def copy_fixture_rules(target: Path) -> int:
    """Copy the ``rules*`` directories of the fixture repo to *target*.

    Mirrors what :func:`sigma.mcp.repo.download_rules` extracts.  Returns the
    number of copied ``.yml`` files.
    """
    target.mkdir(parents=True, exist_ok=True)
    for directory in FIXTURE_REPO.iterdir():
        if directory.is_dir() and directory.name.startswith("rules"):
            shutil.copytree(directory, target / directory.name, dirs_exist_ok=True)
    return sum(1 for _ in target.rglob("*.yml"))


@pytest.fixture
def fake_downloader() -> Callable[[Path], RepoSnapshot]:
    """A downloader that copies the fixture rules instead of using the network."""

    def _download(target: Path) -> RepoSnapshot:
        count = copy_fixture_rules(target)
        return RepoSnapshot(path=target, commit=FIXTURE_COMMIT, rule_files=count)

    return _download


@pytest.fixture
def rules_root(tmp_path: Path) -> Path:
    """The fixture rules as they look after a download."""
    root = tmp_path / "rules-root"
    copy_fixture_rules(root)
    return root


def build_fixture_zip(
    comment: bytes = FIXTURE_COMMIT.encode(),
    extra: dict[str, bytes] | None = None,
) -> bytes:
    """Return a ZIP of the whole fixture repo laid out like a GitHub archive."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("sigma-master/", b"")
        for path in sorted(FIXTURE_REPO.rglob("*")):
            name = "sigma-master/" + path.relative_to(FIXTURE_REPO).as_posix()
            if path.is_dir():
                zf.writestr(name + "/", b"")
            else:
                zf.write(path, name)
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
        zf.comment = comment
    return buffer.getvalue()
