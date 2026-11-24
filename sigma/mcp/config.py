"""Runtime configuration read from environment variables.

All values are read on every call (not at import time), so tests and
embedding applications can change them without reloading modules.
"""

from __future__ import annotations

import os
import sys
from datetime import timedelta
from pathlib import Path

ENV_DATA_DIR = "SIGMA_MCP_DATA_DIR"
"""Directory for downloaded SigmaHQ rules and the rule index."""

ENV_NO_WARMUP = "SIGMA_MCP_NO_WARMUP"
"""Set to ``1``/``true``/``yes`` to skip building the rule index at startup."""

ENV_INDEX_MAX_AGE_DAYS = "SIGMA_MCP_INDEX_MAX_AGE_DAYS"
"""Age in days after which the rule index is refreshed at startup (``0`` = never)."""

DEFAULT_INDEX_MAX_AGE_DAYS = 7.0

_APP_DIR_NAME = "sigma-mcp-server"
_TRUE_VALUES = {"1", "true", "yes", "on"}


def data_dir() -> Path:
    """Return the directory where the server keeps downloaded data.

    ``SIGMA_MCP_DATA_DIR`` takes precedence.  Otherwise the platform's user
    cache directory is used: ``%LOCALAPPDATA%`` on Windows,
    ``~/Library/Caches`` on macOS and ``$XDG_CACHE_HOME`` (default
    ``~/.cache``) elsewhere.
    """
    configured = os.environ.get(ENV_DATA_DIR)
    if configured:
        return Path(configured).expanduser()
    home = Path.home()
    if sys.platform == "win32":
        local_app_data = os.environ.get("LOCALAPPDATA")
        base = Path(local_app_data) if local_app_data else home / "AppData" / "Local"
    elif sys.platform == "darwin":
        base = home / "Library" / "Caches"
    else:
        xdg_cache = os.environ.get("XDG_CACHE_HOME")
        base = Path(xdg_cache) if xdg_cache else home / ".cache"
    return base / _APP_DIR_NAME


def warmup_enabled() -> bool:
    """Return ``False`` when ``SIGMA_MCP_NO_WARMUP`` is set to a true value."""
    return os.environ.get(ENV_NO_WARMUP, "").strip().lower() not in _TRUE_VALUES


def index_max_age() -> timedelta | None:
    """Return the maximum age of the rule index before it is refreshed.

    Returns ``None`` when automatic refreshing is disabled
    (``SIGMA_MCP_INDEX_MAX_AGE_DAYS=0`` or a negative value).  Values that
    cannot be parsed fall back to :data:`DEFAULT_INDEX_MAX_AGE_DAYS`.
    """
    raw = os.environ.get(ENV_INDEX_MAX_AGE_DAYS)
    try:
        days = float(raw) if raw else DEFAULT_INDEX_MAX_AGE_DAYS
    except ValueError:
        days = DEFAULT_INDEX_MAX_AGE_DAYS
    if days <= 0:
        return None
    return timedelta(days=days)
