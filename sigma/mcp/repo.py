"""Download the SigmaHQ rule repository as a ZIP archive.

Only the rule directories (``rules``, ``rules-emerging-threats``,
``rules-threat-hunting`` and the other ``rules*`` directories) are extracted.
The download goes to a temporary directory next to the target and replaces
the previous copy only once extraction has succeeded, so a failed download
never leaves a half-written rule directory behind.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import httpx

SIGMA_ZIP_URL = "https://codeload.github.com/SigmaHQ/sigma/zip/refs/heads/master"
"""Archive of the default branch of SigmaHQ/sigma."""

RULE_DIR_PREFIX = "rules"
"""Top-level repository directories starting with this prefix are extracted."""

_RULE_SUFFIXES = (".yml", ".yaml")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DOWNLOAD_TIMEOUT = httpx.Timeout(30.0, read=120.0)


@dataclass(frozen=True)
class RepoSnapshot:
    """Result of a successful download.

    Attributes:
        path: Directory holding the extracted rule directories.
        commit: Commit SHA of the downloaded revision, taken from the archive
            comment that GitHub writes into every ZIP download, or ``None``
            if the archive carries no such comment.
        rule_files: Number of extracted rule files.
    """

    path: Path
    commit: str | None
    rule_files: int


def remove_leftovers(target: Path) -> int:
    """Delete temporary directories that an interrupted download left behind.

    Only call this while holding the update lock, so no other download is
    using them.

    Returns:
        The number of removed directories.
    """
    removed = 0
    if not target.parent.is_dir():
        return removed
    patterns = (".download-*", f".{target.name}.old-*")
    for pattern in patterns:
        for leftover in target.parent.glob(pattern):
            if leftover.is_dir():
                shutil.rmtree(leftover, ignore_errors=True)
                removed += 1
    return removed


def download_rules(
    target: Path,
    url: str = SIGMA_ZIP_URL,
    client: httpx.Client | None = None,
) -> RepoSnapshot:
    """Download the SigmaHQ rules from *url* and place them in *target*.

    An existing *target* directory is replaced atomically after the new copy
    has been extracted completely.

    Args:
        target: Destination directory for the rule directories.
        url: URL of a GitHub ZIP archive of the repository.
        client: HTTP client to use.  A new client is created when omitted.

    Returns:
        Description of the downloaded snapshot.

    Raises:
        httpx.HTTPError: The download failed.
        zipfile.BadZipFile: The response was not a valid ZIP archive.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target.parent, prefix=".download-") as tmp:
        archive = Path(tmp) / "sigma.zip"
        _download(url, archive, client)
        staging = Path(tmp) / "rules"
        commit, count = extract_rules(archive, staging)
        _replace_dir(staging, target)
    return RepoSnapshot(path=target, commit=commit, rule_files=count)


def _download(url: str, destination: Path, client: httpx.Client | None) -> None:
    """Stream *url* into *destination*."""
    own_client = client is None
    http = client or httpx.Client(follow_redirects=True, timeout=_DOWNLOAD_TIMEOUT)
    try:
        with http.stream("GET", url) as response:
            response.raise_for_status()
            with destination.open("wb") as fh:
                for chunk in response.iter_bytes():
                    fh.write(chunk)
    finally:
        if own_client:
            http.close()


def extract_rules(archive: Path, destination: Path) -> tuple[str | None, int]:
    """Extract the rule files from a GitHub repository archive.

    GitHub archives contain a single top-level directory (for example
    ``sigma-master/``).  It is stripped, so ``sigma-master/rules/x.yml`` ends
    up as ``destination/rules/x.yml``.  Entries with absolute paths or ``..``
    components are skipped.

    Args:
        archive: Path to the ZIP file.
        destination: Directory to extract into.  It is created if needed.

    Returns:
        Tuple of the commit SHA from the archive comment (or ``None``) and
        the number of extracted rule files.
    """
    destination.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(archive) as zf:
        comment = zf.comment.decode("ascii", errors="replace").strip()
        commit = comment if _COMMIT_RE.match(comment) else None
        for info in zf.infolist():
            relative = _rule_member_path(info)
            if relative is None:
                continue
            out_file = destination.joinpath(*relative.parts)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, out_file.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            count += 1
    return commit, count


def _rule_member_path(info: zipfile.ZipInfo) -> PurePosixPath | None:
    """Return the destination path of a rule file entry, or ``None`` to skip it."""
    if info.is_dir():
        return None
    name = PurePosixPath(info.filename)
    parts = name.parts
    # <archive root>/<rules dir>/.../<file>
    if len(parts) < 3 or name.is_absolute() or ".." in parts:
        return None
    if not parts[1].startswith(RULE_DIR_PREFIX):
        return None
    if name.suffix.lower() not in _RULE_SUFFIXES:
        return None
    return PurePosixPath(*parts[1:])


def _replace_dir(source: Path, target: Path) -> None:
    """Move *source* to *target*, replacing an existing *target* directory."""
    if target.exists():
        retired = target.with_name(f".{target.name}.old-{uuid.uuid4().hex}")
        target.rename(retired)
        source.rename(target)
        shutil.rmtree(retired, ignore_errors=True)
    else:
        source.rename(target)
