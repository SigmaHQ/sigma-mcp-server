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

ENV_TRANSPORT = "SIGMA_MCP_TRANSPORT"
"""``stdio`` (default) or ``http`` (Streamable HTTP)."""

ENV_HOST = "SIGMA_MCP_HOST"
"""Interface the HTTP transport binds to."""

ENV_PORT = "SIGMA_MCP_PORT"
"""Port of the HTTP transport.  ``PORT`` (set by most hosting platforms) is
used when this is not set."""

ENV_PUBLIC = "SIGMA_MCP_PUBLIC"
"""Set to ``1``/``true``/``yes`` to harden the server for public access."""

ENV_MAX_INPUT_BYTES = "SIGMA_MCP_MAX_INPUT_BYTES"
"""Maximum size of a tool call's arguments in public mode."""

ENV_RATE_LIMIT = "SIGMA_MCP_RATE_LIMIT"
"""Sustained requests per second and client in public mode (``0`` = off)."""

ENV_MAX_CONCURRENT_TOOLS = "SIGMA_MCP_MAX_CONCURRENT_TOOLS"
"""Number of tool calls running at the same time in public mode."""

ENV_TOOL_TIME_LIMIT = "SIGMA_MCP_TOOL_TIME_LIMIT"
"""Seconds after which pipeline coverage, pipeline application and event
matching stop with partial results (``0`` = no limit)."""

DEFAULT_INDEX_MAX_AGE_DAYS = 7.0
DEFAULT_TRANSPORT = "stdio"
TRANSPORTS = ("stdio", "http")
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
DEFAULT_MAX_INPUT_BYTES = 512 * 1024
DEFAULT_RATE_LIMIT = 5.0
DEFAULT_MAX_CONCURRENT_TOOLS = 4
DEFAULT_TOOL_TIME_LIMIT = 20.0

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


def _number(name: str, default: float) -> float:
    """Return the environment variable *name* as a number, or *default*."""
    raw = os.environ.get(name, "").strip()
    try:
        return float(raw) if raw else default
    except ValueError:
        return default


def transport() -> str:
    """Return the configured transport, ``stdio`` or ``http``.

    Unknown values fall back to :data:`DEFAULT_TRANSPORT`.
    """
    value = os.environ.get(ENV_TRANSPORT, "").strip().lower()
    return value if value in TRANSPORTS else DEFAULT_TRANSPORT


def host() -> str:
    """Return the interface the HTTP transport binds to."""
    return os.environ.get(ENV_HOST, "").strip() or DEFAULT_HOST


def port() -> int:
    """Return the HTTP port: ``SIGMA_MCP_PORT``, else ``PORT``, else 8000."""
    for name in (ENV_PORT, "PORT"):
        raw = os.environ.get(name, "").strip()
        if raw.isdigit() and 0 < int(raw) < 65536:
            return int(raw)
    return DEFAULT_PORT


def public_mode() -> bool:
    """Return ``True`` when ``SIGMA_MCP_PUBLIC`` is set to a true value."""
    return os.environ.get(ENV_PUBLIC, "").strip().lower() in _TRUE_VALUES


def max_input_bytes() -> int:
    """Return the maximum size of tool arguments in public mode (``0`` = off)."""
    return max(int(_number(ENV_MAX_INPUT_BYTES, DEFAULT_MAX_INPUT_BYTES)), 0)


def rate_limit() -> float:
    """Return the sustained requests per second and client (``0`` = off)."""
    return max(_number(ENV_RATE_LIMIT, DEFAULT_RATE_LIMIT), 0.0)


def max_concurrent_tools() -> int:
    """Return how many tool calls may run at once in public mode (at least 1)."""
    return max(int(_number(ENV_MAX_CONCURRENT_TOOLS, DEFAULT_MAX_CONCURRENT_TOOLS)), 1)


def tool_time_limit() -> float | None:
    """Return the time budget of long-running tools in seconds (``None`` = off).

    The default stays below the 30 seconds a tool call waits for a free
    slot in public mode, so a few expensive calls cannot keep every slot
    busy for long.
    """
    seconds = _number(ENV_TOOL_TIME_LIMIT, DEFAULT_TOOL_TIME_LIMIT)
    return seconds if seconds > 0 else None
