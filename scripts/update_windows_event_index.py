"""Regenerate sigma/mcp/data/windows_event_index.json.

Run from the repository root::

    poetry run python scripts/update_windows_event_index.py

The script fetches the file tree of the ``duckxing/windows-itpro-docs``
GitHub mirror, downloads every ``event-NNNN.md`` file concurrently, and
writes an updated ``windows_event_index.json`` to ``sigma/mcp/data/``.

The produced JSON has the structure::

    {
      "<channel>": {
        "<event_id>": "<title>",
        ...
      },
      ...
    }

where *channel* is the lowercased Windows event log channel (e.g.
``"security"``) and *event_id* is the numeric event ID as a string (e.g.
``"4624"``).
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path

import httpx

from sigma.mcp.main import _parse_win_event_channel, _parse_win_event_title

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TREE_API_URL = (
    "https://api.github.com/repos/duckxing/windows-itpro-docs/git/trees/"
    "master?recursive=1"
)
_RAW_BASE = (
    "https://raw.githubusercontent.com/duckxing/windows-itpro-docs/master/"
    "windows/keep-secure/"
)
_OUTPUT_PATH = (
    Path(__file__).parent.parent / "sigma" / "mcp" / "data" / "windows_event_index.json"
)
_CONCURRENCY = 20
_EVENT_FILE_RE = re.compile(r"windows/keep-secure/event-(\d+)\.md$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _fetch_text(
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
) -> str:
    async with semaphore:
        response = await client.get(url)
        response.raise_for_status()
        return response.text


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main() -> None:
    # 1. Enumerate event files via GitHub tree API
    print("Fetching file tree from GitHub API …", file=sys.stderr)
    async with httpx.AsyncClient(follow_redirects=True, timeout=30) as client:
        tree_response = await client.get(
            _TREE_API_URL,
            headers={"Accept": "application/vnd.github.v3+json"},
        )
        tree_response.raise_for_status()
        tree_data: dict[str, object] = tree_response.json()

    event_ids: list[str] = []
    for item in tree_data.get("tree", []):  # type: ignore[union-attr]
        path = item.get("path", "") if isinstance(item, dict) else ""  # type: ignore[union-attr]
        m = _EVENT_FILE_RE.search(str(path))
        if m:
            event_ids.append(m.group(1))

    print(f"Found {len(event_ids)} event files.", file=sys.stderr)

    # 2. Fetch all event files concurrently
    semaphore = asyncio.Semaphore(_CONCURRENCY)
    print(
        f"Downloading event files (concurrency={_CONCURRENCY}) …", file=sys.stderr
    )
    async with httpx.AsyncClient(follow_redirects=True, timeout=30) as client:
        tasks: dict[str, asyncio.Task[str]] = {
            event_id: asyncio.create_task(
                _fetch_text(client, f"{_RAW_BASE}event-{event_id}.md", semaphore)
            )
            for event_id in event_ids
        }
        results: dict[str, str] = {}
        for event_id, task in tasks.items():
            try:
                results[event_id] = await task
            except Exception as exc:
                print(
                    f"  Warning: failed to fetch event {event_id}: {exc}",
                    file=sys.stderr,
                )

    # 3. Build index: channel -> {event_id -> title}
    index: dict[str, dict[str, str]] = {}
    for event_id, markdown in results.items():
        title = _parse_win_event_title(markdown)
        channel = _parse_win_event_channel(markdown)
        index.setdefault(channel, {})[event_id] = title

    # Sort channels alphabetically; sort event IDs numerically within each channel
    sorted_index: dict[str, dict[str, str]] = {
        channel: dict(
            sorted(events.items(), key=lambda kv: int(kv[0]))
        )
        for channel, events in sorted(index.items())
    }

    # 4. Write output
    _OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _OUTPUT_PATH.write_text(
        json.dumps(sorted_index, indent=2) + "\n", encoding="utf-8"
    )
    total = sum(len(v) for v in sorted_index.values())
    print(
        f"Wrote {total} events across {len(sorted_index)} channel(s) to {_OUTPUT_PATH}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    asyncio.run(main())
