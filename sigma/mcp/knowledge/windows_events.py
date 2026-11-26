"""Windows Security Auditing event reference data.

The event index (channel → event ID → title) is bundled with the package in
``sigma/mcp/data/windows_event_index.json``.  Full event documentation is
fetched on demand from a GitHub mirror of the Microsoft documentation and
cached for the server's lifetime.
"""

from __future__ import annotations

import importlib.resources
import json
import re

from sigma.mcp.knowledge.specification import fetch_cached

WIN_EVENTS_RAW_BASE = (
    "https://raw.githubusercontent.com/duckxing/windows-itpro-docs/master/"
    "windows/keep-secure/"
)
_win_event_content_cache: dict[str, str] = {}
WIN_EVENT_INDEX: dict[str, dict[str, str]] = json.loads(
    importlib.resources.files("sigma.mcp")
    .joinpath("data/windows_event_index.json")
    .read_text(encoding="utf-8")
)


def parse_win_event_title(markdown: str) -> str:
    """Extract the H1 title from a Windows event markdown document.

    Args:
        markdown: Raw Markdown text of an ``event-NNNN.md`` file.

    Returns:
        The text of the first H1 heading, or an empty string if not found.
    """
    m = re.search(r"^# (.+)$", markdown, re.MULTILINE)
    if not m:
        return ""
    title = m.group(1).strip()
    # Strip leading "NNNN(X): " prefix (e.g. "4624(S): ")
    title = re.sub(r"^\d+\([^)]+\):\s*", "", title)
    return title


def parse_win_event_channel(markdown: str) -> str:
    """Extract the Windows event log channel from the embedded XML snippet.

    Args:
        markdown: Raw Markdown text of an ``event-NNNN.md`` file.

    Returns:
        Lowercased channel name (e.g. ``"security"``), or ``"security"`` as
        the default when the ``<Channel>`` element is absent.
    """
    m = re.search(r"<Channel>([^<]+)</Channel>", markdown, re.IGNORECASE)
    return m.group(1).strip().lower() if m else "security"


async def fetch_windows_event(event_id: str) -> str:
    """Return the Markdown documentation for the Windows event *event_id*.

    The document is fetched from ``WIN_EVENTS_RAW_BASE`` on first access and
    cached in ``_win_event_content_cache`` for the server's lifetime.

    Args:
        event_id: Numeric event ID string, e.g. ``4624``.

    Returns:
        Raw Markdown text of the event documentation page.
    """
    url = f"{WIN_EVENTS_RAW_BASE}event-{event_id}.md"
    return await fetch_cached(_win_event_content_cache, event_id, url)
